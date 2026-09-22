package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dmesh/internal/core"

	"golang.org/x/crypto/curve25519"
)

// 协议版本（进握手 prologue 与身份绑定原文）。
const protocolVersion = "dmesh-transport-v1"

// 帧/包结构常量。
const (
	sidLen        = 8 // 会话 ID 长度（字节）
	nonceLen      = 8 // 显式 nonce（uint64 大端）长度
	maxDatagram   = 2048
	maxFragBody   = 1400 // 单分片密文载荷上限（整帧保持在一个常见 MTU 内）
	maxFrameSize  = 8 << 20
	maxFragTotal  = 4096
	reassemblerSz = 512
	confMaxLen    = 2048
)

// 数据报首字节标签。
const (
	tagPunch byte = 'P' // UDP 打洞填充包（无载荷语义，收到即回一发）
	tagHS    byte = 'H' // Noise 握手消息（载荷为原始 noise 报文）
	tagConf  byte = 'C' // 握手完成后的密钥确认+身份绑定帧（transport 密钥加密）
	tagData  byte = 'D' // 业务数据帧（transport 密钥加密，可分片）
	tagClose byte = 'X' // 关闭帧：sid + 1 字节 reason
)

// 关闭/拒绝原因码。
const (
	reasonNormal       byte = 0
	reasonBlacklisted  byte = 1
	reasonBadBinding   byte = 2
	reasonProtocol     byte = 3
	reasonInternal     byte = 4
	reasonTimeout      byte = 5
	reasonShutdown     byte = 6
	reasonFrameTooBig  byte = 7
	reasonReplayWindow byte = 8
)

// 准入/协议错误。调用方用 errors.Is 判定。
var (
	// ErrClosed 信道已关闭（本端或对端）。
	ErrClosed = fmt.Errorf("transport: tunnel closed")
	// ErrBlacklisted 对端身份在黑名单且非「解禁权限者定向申诉」例外。
	ErrBlacklisted = fmt.Errorf("transport: peer blacklisted")
	// ErrBinding 握手后的密钥确认/身份绑定校验失败（伪签、未知 sig_alg、
	// 错群、声明 WG 与握手静态密钥不符、签名者名单条目 WG 不符等）。
	ErrBinding = fmt.Errorf("transport: handshake binding invalid")
	// ErrProtocol 对端帧格式/状态机违例。
	ErrProtocol = fmt.Errorf("transport: protocol error")
	// ErrTimeout 握手/确认超时。
	ErrTimeout = fmt.Errorf("transport: handshake timeout")
	// ErrRejected 对端以拒绝原因关闭握手。
	ErrRejected = fmt.Errorf("transport: peer rejected handshake")
	// ErrNoGroup 未配置可接受的群。
	ErrNoGroup = fmt.Errorf("transport: no group configured")
	// ErrBadConfig Config 缺必填字段。
	ErrBadConfig = fmt.Errorf("transport: bad config")
)

// closeErrFor 把对端 close 帧的原因码映射成包内哨兵错误。
func closeErrFor(reason byte) error {
	switch reason {
	case reasonBlacklisted:
		return fmt.Errorf("%w (by peer)", ErrBlacklisted)
	case reasonBadBinding:
		return fmt.Errorf("%w (by peer)", ErrBinding)
	case reasonTimeout:
		return ErrTimeout
	case reasonFrameTooBig, reasonReplayWindow, reasonProtocol:
		return ErrProtocol
	default:
		return fmt.Errorf("%w: reason=%d", ErrRejected, reason)
	}
}

// Remote 是对端的路由信息：身份公钥 + X25519 传输公钥。
// WG 为零值时 Dial 退化为 XX 式握手（静态密钥互未知）。
type Remote struct {
	Identity core.PubKey
	WG       core.WGPub
}

// NewRemoteFromRoster 从名单构造路由信息：成员条目的 WG 即其传输静态公钥。
// 不在白名单（如仅携 join_req 的新人）时返回零 WG（走 XX 路径）。
func NewRemoteFromRoster(r core.Roster, id core.PubKey) Remote {
	rem := Remote{Identity: id}
	if r != nil {
		if e, ok := r.Member(id); ok {
			rem.WG = e.WG
		}
	}
	return rem
}

// Config 是 Endpoint 的接线配置。
type Config struct {
	// Conn 已绑定的 UDP socket；为 nil 时用 BindAddr（nil=127.0.0.1:0）ListenUDP。
	Conn     net.PacketConn
	BindAddr *net.UDPAddr
	// Static 是本机 X25519 传输静态私钥（32B，Noise s；公钥即本机 wg_pub）。
	Static [32]byte
	// Identity 是本机身份签名器（core.Signer，identity 包实现，自带 sig_alg）。
	Identity core.Signer
	// Roster 提供准入判定（IsBlacklisted/HasPerm/TierOf）与成员 WG 查询。
	Roster core.Roster
	// GroupIDs 是本机接受的群锚；出站固定用 GroupIDs[0]，入站要求对端声明
	// 其中之一（错群拒连）。
	GroupIDs [][32]byte
	// Rand 随机源，nil 时 crypto/rand。
	Rand io.Reader
	// HandshakeTimeout 单次 Dial/入站握手+确认超时，默认 10s。
	HandshakeTimeout time.Duration
	// PunchCount/PunchInterval 打洞突发参数，默认 6 发、25ms。
	PunchCount    int
	PunchInterval time.Duration
	// TunnelIdleTimeout 无收发隧道的回收时限，默认 10min。
	TunnelIdleTimeout time.Duration
	// AcceptQueue Accept 缓冲深度，默认 16。
	AcceptQueue int
	// MaxFrameSize 单帧明文上限，默认 8MiB。
	MaxFrameSize int
}

// Endpoint 是一个 UDP 传输端点：UDP 打洞 + Noise IK/XX 握手 +
// ChaCha20Poly1305 加密帧 + 黑名单准入 + core.Tunnel 抽象。
// 对称 NAT 打洞失败不设中继，直接接受失败（由邻居层换候选补偿）。
type Endpoint struct {
	cfg     Config
	conn    net.PacketConn
	priv    [32]byte
	staticK []byte // 本机 X25519 静态公钥（wg_pub）
	rand    io.Reader

	mu         sync.Mutex
	sessions   map[string]*session // key: sid hex
	tunnels    map[string]*Tunnel  // key: peer addr.String()
	tunBySID   map[string]*Tunnel  // key: sid hex（支持 NAT 地址漫游）
	punchEcho  map[string]time.Time
	closeReply map[string]time.Time
	closed     bool

	acceptCh chan *Tunnel
	done     chan struct{}
}

// Listen 按 cfg 创建并启动一个 Endpoint（后台读循环 + 回收协程）。
func Listen(cfg Config) (*Endpoint, error) {
	conn := cfg.Conn
	if conn == nil {
		addr := cfg.BindAddr
		if addr == nil {
			addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("transport: listen udp: %w", err)
		}
		conn = c
	}
	return newEndpoint(cfg, conn)
}

func newEndpoint(cfg Config, conn net.PacketConn) (*Endpoint, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("%w: Identity required", ErrBadConfig)
	}
	if cfg.Roster == nil {
		return nil, fmt.Errorf("%w: Roster required (admission)", ErrBadConfig)
	}
	if len(cfg.GroupIDs) == 0 {
		return nil, fmt.Errorf("%w: GroupIDs empty", ErrNoGroup)
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.PunchCount <= 0 {
		cfg.PunchCount = 6
	}
	if cfg.PunchInterval <= 0 {
		cfg.PunchInterval = 25 * time.Millisecond
	}
	if cfg.TunnelIdleTimeout <= 0 {
		cfg.TunnelIdleTimeout = 10 * time.Minute
	}
	if cfg.AcceptQueue <= 0 {
		cfg.AcceptQueue = 16
	}
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = maxFrameSize
	}
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &cfg.Static)
	e := &Endpoint{
		cfg:        cfg,
		conn:       conn,
		priv:       cfg.Static,
		staticK:    pub[:],
		rand:       cfg.Rand,
		sessions:   map[string]*session{},
		tunnels:    map[string]*Tunnel{},
		tunBySID:   map[string]*Tunnel{},
		punchEcho:  map[string]time.Time{},
		closeReply: map[string]time.Time{},
		done:       make(chan struct{}),
	}
	e.acceptCh = make(chan *Tunnel, cfg.AcceptQueue)
	go e.readLoop()
	go e.reaper()
	return e, nil
}

// LocalAddr 是本机 UDP 监听地址。
func (e *Endpoint) LocalAddr() net.Addr { return e.conn.LocalAddr() }

// Accept 阻塞等待入站握手完成且通过准入判定的隧道（配 AcceptQueue）。
// ctx 取消、端点关闭时返回相应错误。
func (e *Endpoint) Accept(ctx context.Context) (*Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.done:
		return nil, ErrClosed
	case t := <-e.acceptCh:
		return t, nil
	}
}

// LocalWG 返回本机传输静态公钥（wg_pub）。
func (e *Endpoint) LocalWG() core.WGPub {
	var w core.WGPub
	copy(w[:], e.staticK)
	return w
}

// Close 关闭端点：回收全部隧道与会话并关闭 socket。
func (e *Endpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	tunnels := make([]*Tunnel, 0, len(e.tunnels))
	for _, t := range e.tunnels {
		tunnels = append(tunnels, t)
	}
	sessions := make([]*session, 0, len(e.sessions))
	for _, s := range e.sessions {
		sessions = append(sessions, s)
	}
	e.tunnels = map[string]*Tunnel{}
	e.tunBySID = map[string]*Tunnel{}
	e.sessions = map[string]*session{}
	e.mu.Unlock()

	close(e.done)
	for _, s := range sessions {
		s.close()
	}
	for _, t := range tunnels {
		t.closeWith(reasonShutdown)
	}
	return e.conn.Close()
}

// ---------- 数据报分发 ----------

func (e *Endpoint) readLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := e.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		e.handlePacket(pkt, ua)
	}
}

func (e *Endpoint) handlePacket(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) < 1+sidLen {
		return
	}
	tag := pkt[0]
	sidStr := hex.EncodeToString(pkt[1 : 1+sidLen])
	body := pkt[1+sidLen:]
	switch tag {
	case tagPunch:
		e.handlePunch(sidStr, addr)
	case tagHS:
		hs := append([]byte(nil), body...)
		e.route(sidStr, packet{tag: tagHS, raw: pkt}, hs, addr)
	case tagConf, tagData, tagClose:
		e.route(sidStr, packet{tag: tag, raw: pkt}, body, addr)
	}
}

// route 按 sid 把数据报投递给会话状态机、已建立隧道，或对首握手包spawn 入站
// 会话；全部未知时对数据帧回 close、对握手首包按长度/序号判定是否可开局。
func (e *Endpoint) route(sidStr string, pkt packet, hs []byte, addr *net.UDPAddr) {
	e.mu.Lock()
	if s := e.sessions[sidStr]; s != nil && !s.isClosed() {
		s.touch()
		select {
		case s.in <- pkt:
		default: // 背压丢弃（UDP 语义，握手侧有超时）
		}
		e.mu.Unlock()
		return
	}
	if t := e.tunBySID[sidStr]; t != nil {
		e.mu.Unlock()
		t.onPacket(pkt, addr)
		return
	}
	t := e.tunnels[addr.String()]
	e.mu.Unlock()
	if t != nil {
		t.onPacket(pkt, addr)
		return
	}
	if pkt.tag == tagHS && len(hs) > 0 && hs[0] == 1 && len(hs) >= noiseMsg1Min {
		e.startResponder(addr, sidStr, hs)
		return
	}
	e.replyClose(pkt.tag, sidStr, addr)
}

// handlePunch：收到打洞包即回一发（每地址 10s 冷却，防反射风暴），
// 让双向 NAT 映射同时打开。
func (e *Endpoint) handlePunch(sidStr string, addr *net.UDPAddr) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	now := time.Now()
	if last, ok := e.punchEcho[addr.String()]; ok && now.Sub(last) < 10*time.Second {
		e.mu.Unlock()
		return
	}
	e.punchEcho[addr.String()] = now
	e.mu.Unlock()
	reply := make([]byte, 1+sidLen+8)
	reply[0] = tagPunch
	if b, err := hex.DecodeString(sidStr); err == nil && len(b) == sidLen {
		copy(reply[1:], b)
	}
	if _, err := e.rand.Read(reply[1+sidLen:]); err != nil {
		return
	}
	_, _ = e.conn.WriteTo(reply, addr)
}

// replyClose 对指向未知会话的数据帧回明文 close，促使对端停止重发。
func (e *Endpoint) replyClose(tag byte, sidStr string, addr *net.UDPAddr) {
	if tag != tagData {
		return
	}
	e.mu.Lock()
	now := time.Now()
	if last, ok := e.closeReply[addr.String()]; ok && now.Sub(last) < 5*time.Second {
		e.mu.Unlock()
		return
	}
	e.closeReply[addr.String()] = now
	e.mu.Unlock()
	p := makePlainClose(sidStr, reasonProtocol)
	_, _ = e.conn.WriteTo(p, addr)
}

func (e *Endpoint) reaper() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case now := <-t.C:
			var deadT []*Tunnel
			var deadS []*session
			e.mu.Lock()
			if e.closed {
				e.mu.Unlock()
				return
			}
			for k, tun := range e.tunnels {
				if now.Sub(tun.lastActivity()) > e.cfg.TunnelIdleTimeout {
					deadT = append(deadT, tun)
					delete(e.tunnels, k)
					delete(e.tunBySID, tun.sidStr)
				}
			}
			for k, s := range e.sessions {
				if now.Sub(s.lastActivity()) > e.cfg.HandshakeTimeout*2 {
					s.close()
					deadS = append(deadS, s)
					delete(e.sessions, k)
				}
			}
			for k, v := range e.punchEcho {
				if now.Sub(v) > time.Minute {
					delete(e.punchEcho, k)
				}
			}
			for k, v := range e.closeReply {
				if now.Sub(v) > time.Minute {
					delete(e.closeReply, k)
				}
			}
			e.mu.Unlock()
			for _, tun := range deadT {
				tun.closeWith(reasonTimeout)
			}
			for _, s := range deadS {
				e.sendPlainClose(s, reasonTimeout)
			}
		}
	}
}

// ---------- 会话/隧道簿记（由 handshake.go / tunnel.go 调用） ----------

func (e *Endpoint) newSessionLocked(sid []byte, initiator bool) *session {
	s := &session{
		e:         e,
		sid:       sid,
		sidStr:    hex.EncodeToString(sid),
		initiator: initiator,
		in:        make(chan packet, 64),
		done:      make(chan struct{}),
		last:      time.Now(),
	}
	e.sessions[s.sidStr] = s
	return s
}

// closeSessionLocked 从 sid 表摘除并关闭会话（须持 e.mu）。
func (e *Endpoint) closeSessionLocked(s *session) {
	if cur := e.sessions[s.sidStr]; cur == s {
		delete(e.sessions, s.sidStr)
	}
	s.close()
}

// registerTunnelLocked 把完成握手的会话升级为隧道（须持 e.mu）。
func (e *Endpoint) registerTunnelLocked(t *Tunnel) {
	if cur := e.tunnels[t.peerKey]; cur != nil && cur != t {
		cur.markClosed()
	}
	e.tunnels[t.peerKey] = t
	e.tunBySID[t.sidStr] = t
	if cur := e.sessions[t.sidStr]; cur == t.sess {
		delete(e.sessions, t.sidStr)
		cur.close()
	}
}

func (e *Endpoint) unregisterTunnel(t *Tunnel) {
	e.mu.Lock()
	if cur := e.tunnels[t.peerKey]; cur == t {
		delete(e.tunnels, t.peerKey)
	}
	if cur := e.tunBySID[t.sidStr]; cur == t {
		delete(e.tunBySID, t.sidStr)
	}
	e.mu.Unlock()
}

// sendPlainClose 向会话当前对端地址发明文 close（尚无 transport 密钥时）。
func (e *Endpoint) sendPlainClose(s *session, reason byte) {
	addr := s.peerAddr()
	if addr == nil {
		return
	}
	p := make([]byte, 1+sidLen+1)
	p[0] = tagClose
	copy(p[1:], s.sid)
	p[1+sidLen] = reason
	_, _ = e.conn.WriteTo(p, addr)
}

func makePlainClose(sidStr string, reason byte) []byte {
	p := make([]byte, 1+sidLen+1)
	p[0] = tagClose
	if b, err := hex.DecodeString(sidStr); err == nil && len(b) == sidLen {
		copy(p[1:], b)
	}
	p[1+sidLen] = reason
	return p
}

// packet 是一个原始数据报（tag+sid+载荷）。
type packet struct {
	tag byte
	raw []byte
}
