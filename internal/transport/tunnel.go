package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"dmesh/internal/core"

	"github.com/flynn/noise"
)

// 编译期确认 Tunnel 满足 core.Tunnel 契约。
var _ core.Tunnel = (*Tunnel)(nil)

// SessionInfo 是握手完成后的会话侧信息（邻居表/消息层接线用）。
type SessionInfo struct {
	// Identity 是对端经密钥确认绑定的身份公钥（core.Roster 的键）。
	Identity core.PubKey
	// GroupID 是双方共同确认的群锚。
	GroupID [32]byte
	// WG 是对端 Noise 静态公钥（= 白名单条目 wg_pub）。
	WG core.WGPub
	// Algs 是对端自报的已注册 sig_alg 集（v16 能力协商）。
	Algs []string
	// Pattern 为 "IK"（静态密钥预知）或 "XX"（互未知退化握手）。
	Pattern string
	// Inbound 标记该隧道由入站握手建立。
	Inbound bool
	// Blacklisted 标记对端在黑名单——仅当本端是解禁权限者时握手才会成功，
	// 该隧道只能承载「to 指向本机」的定向申诉消息（消息层据此 enforcement）。
	Blacklisted bool
	// Peer 是对端 UDP 地址（NAT 漫游后会更新）。
	Peer *net.UDPAddr
	// RemoteTS 是对端 conf 帧自报时间（毫秒）。
	RemoteTS int64
}

// Tunnel 是一条已完成 Noise IK/XX 握手、密钥确认 + 身份绑定、通过黑名单
// 准入判定并处于 ChaCha20Poly1305 加密下的 UDP 信道（实现 core.Tunnel）。
//
// Send 写出一个完整帧（超长自动分片/对端重组）；OnData 注册的回调在收到
// 完整帧时被调用（在 Endpoint 读循环协程内，回调应尽快返回）。
type Tunnel struct {
	e      *Endpoint
	sess   *session
	sid    []byte
	sidStr string

	mu        sync.Mutex
	peer      *net.UDPAddr
	peerKey   string
	send      *noise.CipherState
	recv      *noise.CipherState
	sendNonce uint64
	replayW   replay
	reasm     *Reassembler
	closed    bool
	closeErr  error
	onDataFn  func([]byte)
	pending   [][]byte
	lastAct   time.Time
	info      SessionInfo
}

func newTunnel(e *Endpoint, s *session, conf *handshake, send, recv *noise.CipherState, black bool, pattern string) *Tunnel {
	peer := s.peerAddr()
	var gid [32]byte
	copy(gid[:], conf.Group)
	var wg core.WGPub
	copy(wg[:], conf.WG[:])
	return &Tunnel{
		e:         e,
		sess:      s,
		sid:       s.sid,
		sidStr:    s.sidStr,
		peer:      peer,
		peerKey:   peerKeyOf(peer),
		send:      send,
		recv:      recv,
		sendNonce: 1, // nonce 0 保留，便于区分会话起点
		reasm:     NewReassembler(),
		lastAct:   time.Now(),
		info: SessionInfo{
			Identity:    conf.ID,
			GroupID:     gid,
			WG:          wg,
			Algs:        append([]string(nil), conf.Algs...),
			Pattern:     pattern,
			Inbound:     !s.initiator,
			Blacklisted: black,
			Peer:        peer,
			RemoteTS:    conf.TS,
		},
	}
}

func peerKeyOf(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// RemotePub 返回对端身份公钥（core.Tunnel 契约）。
func (t *Tunnel) RemotePub() core.PubKey { return t.info.Identity }

// Info 返回会话侧信息副本（WG 密钥、群、模式、黑名单标记等）。
func (t *Tunnel) Info() SessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	info := t.info
	info.Peer = t.peer
	return info
}

// PeerAddr 返回当前对端 UDP 地址（可能因 NAT 漫游更新）。
func (t *Tunnel) PeerAddr() *net.UDPAddr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peer
}

func (t *Tunnel) peerAddrNow() *net.UDPAddr { return t.PeerAddr() }

// OnData 注册数据回调（并发安全；重复注册以最后一次为准）。
func (t *Tunnel) OnData(fn func([]byte)) {
	t.mu.Lock()
	t.onDataFn = fn
	pend := t.pending
	t.pending = nil
	t.mu.Unlock()
	for _, p := range pend {
		fn(p)
	}
}

// Send 把一个完整帧加密（分片）发往对端。
func (t *Tunnel) Send(b []byte) error {
	if len(b) == 0 {
		return errors.New("transport: empty frame")
	}
	if len(b) > t.e.cfg.MaxFrameSize {
		return ErrProtocol
	}
	total := splitFragments(len(b), maxFragBody)
	if total > maxFragTotal {
		return ErrProtocol
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		if t.closeErr != nil {
			return t.closeErr
		}
		return ErrClosed
	}
	if t.peer == nil {
		return ErrClosed
	}
	for i := 0; i < total; i++ {
		lo := i * maxFragBody
		hi := lo + maxFragBody
		if hi > len(b) {
			hi = len(b)
		}
		pt := encodeFramePlain(uint16(i), uint16(total), b[lo:hi])
		n := t.sendNonce
		t.sendNonce++
		hdr := make([]byte, 1+sidLen+nonceLen)
		hdr[0] = tagData
		copy(hdr[1:], t.sid)
		putBe64(hdr[1+sidLen:], n)
		t.send.SetNonce(n)
		ct, err := t.send.Encrypt(nil, hdr, pt)
		if err != nil {
			return err
		}
		frame := make([]byte, 0, len(hdr)+len(ct))
		frame = append(frame, hdr...)
		frame = append(frame, ct...)
		if _, err := t.e.conn.WriteTo(frame, t.peer); err != nil {
			return err
		}
	}
	t.lastAct = time.Now()
	return nil
}

// Close 关闭隧道（发送 close 帧并停止收发）。幂等。
func (t *Tunnel) Close() error {
	t.closeWith(reasonNormal)
	return nil
}

func (t *Tunnel) closeWith(reason byte) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.closeErr = ErrClosed
	peer := t.peer
	t.mu.Unlock()
	if peer != nil {
		_, _ = t.e.conn.WriteTo(makePlainClose(t.sidStr, reason), peer)
	}
	t.e.unregisterTunnel(t)
}

// markClosed 仅做簿记关闭（Endpoint.Close / 顶替时用），不发帧。
func (t *Tunnel) markClosed() {
	t.mu.Lock()
	t.closed = true
	if t.closeErr == nil {
		t.closeErr = ErrClosed
	}
	t.mu.Unlock()
	t.e.unregisterTunnel(t)
}

// remoteClosed 处理对端 close。
func (t *Tunnel) remoteClosed(reason byte) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.closeErr = closeErrFor(reason)
	t.mu.Unlock()
	t.e.unregisterTunnel(t)
}

func (t *Tunnel) lastActivity() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastAct
}

// onPacket 由 Endpoint 读循环投递（conf/data/close 帧）。
func (t *Tunnel) onPacket(pkt packet, addr *net.UDPAddr) {
	switch pkt.tag {
	case tagData:
		t.handleData(pkt.raw, addr)
	case tagClose:
		reason := byte(reasonNormal)
		if len(pkt.raw) > 1+sidLen {
			reason = pkt.raw[1+sidLen]
		}
		t.mu.Lock()
		samePeer := t.peer != nil && addr != nil && t.peer.String() == addr.String()
		t.mu.Unlock()
		if samePeer {
			t.remoteClosed(reason)
		}
	case tagHS, tagConf:
		// 对已建立会话重放的握手/确认帧：忽略（对端若重启会先 punch 并用
		// 新 sid 开新会话）。
	}
}

func (t *Tunnel) handleData(raw []byte, addr *net.UDPAddr) {
	if len(raw) < 1+sidLen+nonceLen+16 {
		return
	}
	n := be64(raw[1+sidLen : 1+sidLen+nonceLen])
	ct := raw[1+sidLen+nonceLen:]
	ad := raw[:1+sidLen+nonceLen]
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	// 快速预筛过旧重放，省一次解密。
	if n < t.replayW.next && t.replayW.next-n > 63 {
		t.mu.Unlock()
		return
	}
	// nonce 显式随帧传输：解密前把 recv 状态钉到线上 nonce（持锁保证
	// SetNonce+Decrypt 原子，乱序包也能正确解密）。
	t.recv.SetNonce(n)
	pt, err := t.recv.Decrypt(nil, ad, ct)
	if err != nil {
		t.mu.Unlock()
		return
	}
	if len(pt) < 4 {
		t.mu.Unlock()
		return
	}
	idx := binary.BigEndian.Uint16(pt)
	total := binary.BigEndian.Uint16(pt[2:])
	frame, ok, rerr := t.reasm.Add(n, idx, total, pt[4:])
	if rerr != nil {
		t.mu.Unlock()
		return
	}
	if !t.replayW.accept(n) {
		t.mu.Unlock()
		return // 重放：吞掉（重组副作用仅限本帧，无安全影响）
	}
	t.lastAct = time.Now()
	if addr != nil {
		t.peer = addr
		t.peerKey = peerKeyOf(addr)
		t.info.Peer = addr
	}
	cb := t.onDataFn
	t.mu.Unlock()
	if ok {
		if cb != nil {
			cb(frame)
		} else {
			t.mu.Lock()
			if !t.closed && len(t.pending) < 64 {
				t.pending = append(t.pending, frame)
			}
			t.mu.Unlock()
		}
	}
}

// ErrRemoteClosed 包装对端关闭原因，供调用方判定。
var ErrRemoteClosed = errors.New("transport: closed by peer")

var _ = time.Now
