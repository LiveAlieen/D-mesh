package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dmesh/internal/core"

	"github.com/flynn/noise"
)

// Noise msg1 线上长度（空载荷，flynn/noise 语义）：XX = e(32)（尚无密钥，
// 载荷原样且为空）；IK = e(32) + enc(s)(32+16) + 空载荷 tag(16) = 96。
// 响应端据此自动识别模式；发起端按是否已知对端 wg_pub（白名单条目 /
// join_req 携带）选 IK 或 XX。
const (
	noiseMsg1Min = 32
	noiseXXMsg1  = 32
	noiseIKMsg1  = 96
)

// cipherSuite：X25519 + ChaCha20Poly1305 + SHA-256。
// transport 帧即用其中的 ChaCha20Poly1305 over UDP。
func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// handshakePrologue 双端可独立重构的唯一原文（含随机数会破坏对称性，
// 会话独特性由 Noise 临时密钥天然保证）。
var handshakePrologue = []byte(protocolVersion)

// session 是一次进行中的握手（完成即升级为 Tunnel 或被销毁）。
// in/done 通道只写不关；peer/last/closed 由 mu 保护。
type session struct {
	e         *Endpoint
	sid       []byte
	sidStr    string
	initiator bool

	mu     sync.Mutex
	peer   *net.UDPAddr
	last   time.Time
	closed bool

	in   chan packet
	done chan struct{}
	once sync.Once
}

func (s *session) setPeer(a *net.UDPAddr) {
	s.mu.Lock()
	s.peer = a
	s.mu.Unlock()
}

func (s *session) peerAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

func (s *session) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

func (s *session) lastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.done)
	})
}

// ---------- 出站：Dial / Connect ----------

// Dial 与 addr 处对端完成 Noise IK（remote.WG 已知）或 XX（未知）握手、
// 密钥确认 + 身份绑定与黑名单准入判定，全部通过后返回 core.Tunnel。
func (e *Endpoint) Dial(ctx context.Context, addr *net.UDPAddr, remote Remote) (core.Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// 出站准入：黑名单一律拒连；唯一例外——本机是解禁权限者（定向申诉）。
	if !e.authority() && e.cfg.Roster.IsBlacklisted(remote.Identity) {
		return nil, ErrBlacklisted
	}
	sid := make([]byte, sidLen)
	if _, err := io.ReadFull(e.rand, sid); err != nil {
		return nil, err
	}
	pattern := "XX"
	cfg := noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      handshakePrologue,
		StaticKeypair: noise.DHKey{Private: e.priv[:], Public: e.staticK},
		Random:        e.rand,
	}
	if !remote.WG.IsZero() {
		pattern = "IK"
		cfg.Pattern = noise.HandshakeIK
		cfg.PeerStatic = append([]byte(nil), remote.WG[:]...)
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: new handshake: %w", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ErrClosed
	}
	s := e.newSessionLocked(sid, true)
	s.setPeer(addr)
	e.mu.Unlock()

	if err := e.sendPlain(s, tagHS, append([]byte{1}, msg1...)); err != nil {
		e.abort(s, reasonInternal)
		return nil, err
	}

	timer := time.NewTimer(e.cfg.HandshakeTimeout)
	defer timer.Stop()

	var (
		send, recv *noise.CipherState
		peerConf   *handshake
		binding    [32]byte
		remoteStat [32]byte
		early      []packet
	)
	for send == nil || peerConf == nil {
		var pkt packet
		select {
		case <-ctx.Done():
			e.abort(s, reasonNormal)
			return nil, ctx.Err()
		case <-timer.C:
			e.abort(s, reasonTimeout)
			return nil, ErrTimeout
		case <-s.done:
			return nil, ErrClosed
		case p := <-s.in:
			pkt = p
		}
		switch pkt.tag {
		case tagHS:
			body := pkt.raw[1+sidLen:]
			if len(body) < 1 {
				e.abort(s, reasonProtocol)
				return nil, ErrProtocol
			}
			if send != nil || body[0] != 2 || hs.MessageIndex() != 1 {
				e.abort(s, reasonProtocol)
				return nil, ErrProtocol
			}
			// Split 输出全局有序：cs1=发起方发送键，cs2=响应方发送键。
			_, cs1, cs2, err := hs.ReadMessage(nil, body[1:])
			if err != nil {
				e.abort(s, reasonProtocol)
				return nil, ErrProtocol
			}
			if cs1 == nil || cs2 == nil {
				// XX：握手尚未完成，补发 msg3 收尾。
				if hs.MessageIndex() != 2 {
					e.abort(s, reasonProtocol)
					return nil, ErrProtocol
				}
				m3, w1, w2, werr := hs.WriteMessage(nil, nil)
				if werr != nil {
					e.abort(s, reasonInternal)
					return nil, werr
				}
				if hs.MessageIndex() != 3 || w1 == nil || w2 == nil {
					e.abort(s, reasonProtocol)
					return nil, ErrProtocol
				}
				cs1, cs2 = w1, w2
				if err := e.sendPlain(s, tagHS, append([]byte{3}, m3...)); err != nil {
					e.abort(s, reasonInternal)
					return nil, err
				}
			} else if hs.MessageIndex() != 2 {
				e.abort(s, reasonProtocol)
				return nil, ErrProtocol
			}
			send, recv = cs1, cs2 // 发起方用 cs1 发、cs2 收
			b := sessionBinding(cs1, cs2)
			binding = b
			if ps := hs.PeerStatic(); len(ps) == 32 {
				copy(remoteStat[:], ps)
			}
			hb := e.makeHandshake(b, true)
			if hb == nil {
				e.abort(s, reasonInternal)
				return nil, ErrClosed
			}
			if err := e.sendPlain(s, tagConf, hb); err != nil {
				e.abort(s, reasonInternal)
				return nil, err
			}
		case tagConf:
			h, err := parseHandshake(pkt.raw[1+sidLen:])
			if err != nil {
				e.abort(s, reasonProtocol)
				return nil, err
			}
			peerConf = h
		case tagData:
			early = append(early, pkt)
		case tagClose:
			reason := reasonInternal
			if len(pkt.raw) > 1+sidLen {
				reason = pkt.raw[1+sidLen]
			}
			e.mu.Lock()
			e.closeSessionLocked(s)
			e.mu.Unlock()
			return nil, closeErrFor(reason)
		}
	}

	// 密钥确认 + 身份绑定校验 + 群锚 + 名单一致性（对端是响应方）。
	if err := verifyHandshake(e, peerConf, false, binding, remoteStat); err != nil {
		e.abort(s, reasonBadBinding)
		return nil, err
	}
	// 复核准入（握手期间名单可能已更新）。
	black := e.cfg.Roster.IsBlacklisted(peerConf.ID)
	if black && !e.authority() {
		e.abort(s, reasonBlacklisted)
		return nil, ErrBlacklisted
	}
	t := newTunnel(e, s, peerConf, send, recv, black, pattern)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ErrClosed
	}
	e.registerTunnelLocked(t)
	e.mu.Unlock()
	for _, p := range early {
		t.onPacket(p, t.peerAddrNow())
	}
	return t, nil
}

// Connect 先打洞（后台突发，不阻塞）再 Dial。对称 NAT 下打洞失败即 Dial
// 超时失败——不设中继，接受失败（PLAN 关键风险 2）。
func (e *Endpoint) Connect(ctx context.Context, addr *net.UDPAddr, remote Remote) (core.Tunnel, error) {
	go e.Punch(addr)
	return e.Dial(ctx, addr, remote)
}

// ---------- 入站握手 ----------

// startResponder 处理指向未知 sid 的握手首包：按长度自动识别 IK/XX 模式，
// 驱动入站握手；密钥确认与准入判定通过后送入 Accept 队列。
func (e *Endpoint) startResponder(addr *net.UDPAddr, sidStr string, msg1 []byte) {
	sid, err := hex.DecodeString(sidStr)
	if err != nil || len(sid) != sidLen {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	if _, dup := e.sessions[sidStr]; dup {
		e.mu.Unlock()
		return
	}
	s := e.newSessionLocked(sid, false)
	s.setPeer(addr)
	e.mu.Unlock()
	go e.runResponder(s, msg1)
}

func (e *Endpoint) runResponder(s *session, msg1 []byte) {
	fail := func(reason byte) {
		e.abort(s, reason)
	}
	// msg1 携 1 字节类型前缀（=1，发起方首包标记），进 Noise 前须剥除。
	if len(msg1) < 2 || msg1[0] != 1 {
		return
	}
	msg1 = msg1[1:]
	var (
		pattern string
		hs      *noise.HandshakeState
	)
	if len(msg1) == noiseIKMsg1 {
		if h, err := e.responderState(noise.HandshakeIK, msg1); err == nil {
			hs, pattern = h, "IK"
		}
	}
	if hs == nil {
		h, err := e.responderState(noise.HandshakeXX, msg1)
		if err != nil {
			if pattern != "" {
				fail(reasonProtocol)
				return
			}
			// 静默丢弃：可能是无关流量抢先占位，回 close 反而放大攻击面。
			return
		}
		hs, pattern = h, "XX"
	}
	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		fail(reasonInternal)
		return
	}
	if err := e.sendPlain(s, tagHS, append([]byte{2}, msg2...)); err != nil {
		fail(reasonInternal)
		return
	}

	var (
		send, recv *noise.CipherState
		binding    [32]byte
		remoteStat [32]byte
	)
	if cs1 != nil && cs2 != nil {
		// IK：msg2 即完成握手（响应方以 cs2 发、cs1 收），直接出自报 conf。
		if hs.MessageIndex() != 2 {
			fail(reasonProtocol)
			return
		}
		send, recv = cs2, cs1
		binding = sessionBinding(cs1, cs2)
		if ps := hs.PeerStatic(); len(ps) == 32 {
			copy(remoteStat[:], ps)
		}
		hb := e.makeHandshake(binding, false)
		if hb == nil {
			fail(reasonInternal)
			return
		}
		if err := e.sendPlain(s, tagConf, hb); err != nil {
			fail(reasonInternal)
			return
		}
	}

	timer := time.NewTimer(e.cfg.HandshakeTimeout)
	defer timer.Stop()

	var (
		peerConf *handshake
		early    []packet
	)
	for peerConf == nil {
		var pkt packet
		select {
		case <-s.done:
			return
		case <-e.done:
			fail(reasonShutdown)
			return
		case <-timer.C:
			fail(reasonTimeout)
			return
		case p := <-s.in:
			pkt = p
		}
		switch pkt.tag {
		case tagHS:
			// XX：读入 msg3 完成握手并出自报 conf。
			body := pkt.raw[1+sidLen:]
			if len(body) < 1 {
				fail(reasonProtocol)
				return
			}
			if send != nil || body[0] != 3 || hs.MessageIndex() != 2 {
				fail(reasonProtocol)
				return
			}
			_, cs1, cs2, err := hs.ReadMessage(nil, body[1:])
			if err != nil {
				fail(reasonProtocol)
				return
			}
			if hs.MessageIndex() != 3 || cs1 == nil || cs2 == nil {
				fail(reasonProtocol)
				return
			}
			send, recv = cs2, cs1 // 响应方用 cs2 发、cs1 收
			binding = sessionBinding(cs1, cs2)
			if ps := hs.PeerStatic(); len(ps) == 32 {
				copy(remoteStat[:], ps)
			}
			hb := e.makeHandshake(binding, false)
			if hb == nil {
				fail(reasonInternal)
				return
			}
			if err := e.sendPlain(s, tagConf, hb); err != nil {
				fail(reasonInternal)
				return
			}
		case tagConf:
			h, err := parseHandshake(pkt.raw[1+sidLen:])
			if err != nil {
				fail(reasonProtocol)
				return
			}
			peerConf = h
		case tagData:
			early = append(early, pkt)
		case tagClose:
			return
		}
	}

	if err := verifyHandshake(e, peerConf, true, binding, remoteStat); err != nil {
		e.abort(s, reasonBadBinding)
		return
	}
	// 准入判定：黑名单拒连；唯一例外——本机是解禁权限者（定向申诉通道）。
	black := e.cfg.Roster.IsBlacklisted(peerConf.ID)
	if black && !e.authority() {
		e.abort(s, reasonBlacklisted)
		return
	}
	t := newTunnel(e, s, peerConf, send, recv, black, pattern)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.registerTunnelLocked(t)
	e.mu.Unlock()
	for _, p := range early {
		t.onPacket(p, t.peerAddrNow())
	}
	select {
	case e.acceptCh <- t:
	default:
		t.closeWith(reasonInternal)
	}
}

func (e *Endpoint) responderState(pattern noise.HandshakePattern, msg1 []byte) (*noise.HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       pattern,
		Initiator:     false,
		Prologue:      handshakePrologue,
		StaticKeypair: noise.DHKey{Private: e.priv[:], Public: e.staticK},
		Random:        e.rand,
	})
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, err
	}
	return hs, nil
}

// ---------- 密钥确认 + 身份绑定帧（conf） ----------

// handshake 是 conf 帧载荷：群锚 + 身份公钥 + 声明的 wg_pub + 本机已注册
// sig_alg 集（v16 能力协商）+ 会话绑定摘要 + 身份私钥对其原文的签名。
// 载荷明文传输但被身份签名钉死：签名覆盖 sessionBinding（transport 密钥
// 摘要），因此「验签通过」同时完成密钥确认与身份↔静态密钥绑定。
type handshake struct {
	V     string      `json:"v"`
	Group []byte      `json:"group"`
	ID    core.PubKey `json:"id"`
	WG    core.WGPub  `json:"wg"`
	Algs  []string    `json:"algs"`
	Init  bool        `json:"init"`
	Sess  []byte      `json:"sess"`
	TS    int64       `json:"ts"`
	Sig   []byte      `json:"sig,omitempty"`
}

// makeHandshake 生成并签署本端 conf。调用方须已完成 Noise 握手。
func (e *Endpoint) makeHandshake(binding [32]byte, initiator bool) []byte {
	h := &handshake{
		V:     protocolVersion,
		Group: e.cfg.GroupIDs[0][:],
		ID:    e.cfg.Identity.Pub(),
		WG:    e.LocalWG(),
		Algs:  registeredAlgNames(),
		Init:  initiator,
		Sess:  binding[:],
		TS:    time.Now().UnixMilli(),
	}
	payload, err := h.canonicalPayload()
	if err != nil {
		return nil
	}
	sig, err := e.cfg.Identity.Sign(payload)
	if err != nil {
		return nil
	}
	h.Sig = sig
	b, err := core.CanonicalJSON(h)
	if err != nil {
		return nil
	}
	return b
}

func parseHandshake(b []byte) (*handshake, error) {
	if len(b) == 0 || len(b) > confMaxLen {
		return nil, ErrProtocol
	}
	var h handshake
	if err := decodeJSON(b, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (h *handshake) canonicalPayload() ([]byte, error) {
	c := *h
	c.Sig = nil
	return core.CanonicalJSON(c)
}

// verifyHandshake 核对对端 conf：
//   - 版本 / 发起方角色 / 群锚（错群拒连）
//   - sess 必须等于本端算出的会话绑定摘要（密钥确认）
//   - 声明 wg_pub == Noise 实际认证的对端静态密钥（身份↔传输密钥绑定）
//   - 白名单已含该身份时条目 wg_pub 必须一致（防「报 A 的 ID 用 B 的钥匙」）
//   - 身份验签：sig_alg 未注册 → ErrUnknownAlg 包裹进 ErrBinding，一律拒
func verifyHandshake(e *Endpoint, h *handshake, peerIsInitiator bool, binding [32]byte, remoteStat [32]byte) error {
	if h == nil {
		return ErrBinding
	}
	if h.V != protocolVersion {
		return fmt.Errorf("%w: version %q", ErrBinding, h.V)
	}
	if h.Init != peerIsInitiator {
		return fmt.Errorf("%w: initiator flag mismatch", ErrBinding)
	}
	if _, ok := matchGroup(e, h.Group); !ok {
		return fmt.Errorf("%w: peer group not accepted", ErrBinding)
	}
	if !bytes.Equal(h.Sess, binding[:]) {
		return fmt.Errorf("%w: session binding mismatch", ErrBinding)
	}
	if !bytes.Equal(h.WG[:], remoteStat[:]) {
		return fmt.Errorf("%w: declared wg != noise static", ErrBinding)
	}
	if m, found := e.cfg.Roster.Member(h.ID); found && !m.WG.IsZero() && m.WG != h.WG {
		return fmt.Errorf("%w: roster wg mismatch for identity", ErrBinding)
	}
	payload, err := h.canonicalPayload()
	if err != nil {
		return err
	}
	if err := core.Verify(h.ID, payload, h.Sig); err != nil {
		if core.IsUnknownAlg(err) {
			return fmt.Errorf("%w: unknown sig_alg %q", ErrBinding, h.ID.Alg)
		}
		return fmt.Errorf("%w: %v", ErrBinding, err)
	}
	return nil
}

// sessionBinding：按 Noise Split 的全局键序（cs1=发起方发送键 || cs2=响应方
// 发送键）摘要 transport 密钥对，作为身份签名的会话钉（防重放、完成密钥确认）。
// 双端对同一对 cs 返回值计算，天然得到相同摘要。
func sessionBinding(cs1, cs2 *noise.CipherState) [32]byte {
	k1 := cs1.UnsafeKey()
	k2 := cs2.UnsafeKey()
	h := sha256.New()
	h.Write([]byte("dmesh-transport-bind-v1"))
	h.Write(k1[:])
	h.Write(k2[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func matchGroup(e *Endpoint, raw []byte) ([32]byte, bool) {
	var g [32]byte
	if len(raw) != 32 {
		return g, false
	}
	copy(g[:], raw)
	for _, want := range e.cfg.GroupIDs {
		if want == g {
			return g, true
		}
	}
	return g, false
}

func registeredAlgNames() []string {
	algs := core.RegisteredAlgs()
	out := make([]string, 0, len(algs))
	for _, a := range algs {
		out = append(out, string(a))
	}
	return out
}

// sendPlain 组一个明文控制帧（tag|sid|payload）发到会话当前对端地址。
func (e *Endpoint) sendPlain(s *session, tag byte, payload []byte) error {
	addr := s.peerAddr()
	if addr == nil {
		return ErrClosed
	}
	p := make([]byte, 1+sidLen+len(payload))
	p[0] = tag
	copy(p[1:], s.sid)
	copy(p[1+sidLen:], payload)
	s.touch()
	_, err := e.conn.WriteTo(p, addr)
	return err
}

// abort 关闭会话（从 sid 表摘除）并尽力通知对端原因。
func (e *Endpoint) abort(s *session, reason byte) {
	e.mu.Lock()
	e.closeSessionLocked(s)
	e.mu.Unlock()
	p := makePlainClose(s.sidStr, reason)
	if addr := s.peerAddr(); addr != nil {
		_, _ = e.conn.WriteTo(p, addr)
	}
}
