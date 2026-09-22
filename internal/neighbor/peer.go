package neighbor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"time"

	"dmesh/internal/core"
)

// keepalive 控制帧：邻居表自己拥有、自己终结，不会转发给消息层。
// 两侧都运行本包，因此帧格式无需 CanonicalJSON（不参与任何签名域）。
const ctlKind = "dmesh.neighbor.ctl"

const (
	ctlSubPing = "ping"
	ctlSubAck  = "ack"
)

type controlFrame struct {
	Kind  string `json:"kind"`
	Sub   string `json:"sub"`
	TSns  int64  `json:"ts_ns"`
	Nonce string `json:"nonce"`
}

// encodeControl 序列化一个控制帧（静态结构，marshal 不会失败）。
func encodeControl(sub string, tsNS int64, nonce string) []byte {
	b, err := json.Marshal(controlFrame{Kind: ctlKind, Sub: sub, TSns: tsNS, Nonce: nonce})
	if err != nil {
		return nil
	}
	return b
}

// parseControl 识别控制帧；非控制帧（消息层的普通 JSON）返回 false 原样转发。
func parseControl(data []byte) (controlFrame, bool) {
	if len(data) == 0 || data[0] != '{' {
		return controlFrame{}, false
	}
	var f controlFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return controlFrame{}, false
	}
	if f.Kind != ctlKind {
		return controlFrame{}, false
	}
	return f, true
}

// newNonce 生成 8 字节随机数 hex 串，用于 ping/ack 配对。
func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read 在Go运行时熵源下不应失败；失败时退化为时间戳。
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b[:])
}

// addrIsIPv6 报告 "ip:port" 形式的地址是否 IPv6（无地址 = false）。
func addrIsIPv6(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil && strings.Contains(ip.String(), ":")
}

// peer 是一条活跃邻居连接的内部状态。所有字段由 Table.mu 保护，
// 唯一例外是 handleData 在调用配置回调时不持锁（见 Table 方法注释）。
type peer struct {
	tab      *Table
	t        core.Tunnel
	pub      core.PubKey
	addr     string
	ipv6     bool
	joinedAt time.Time
	lastSeen time.Time

	rtt      time.Duration // 平滑 RTT（EWMA）
	rttKnown bool

	miss     int // 连续未决 ping / 发送失败计数，达 MaxFail 即断开
	sendErrs int
	inFrames int
	outFrame int

	pending map[string]time.Time // nonce -> 发送时刻
	closed  bool
}

// scoreMs 越小越优。未知 RTT 记 UnknownRTTMs；IPv4 加罚分（IPv6 优先，M5）；
// 每次连续失败加 1000ms；在场表在线的按 roster 加减分（展示性偏好）。
func (p *peer) scoreMs(cfg *Config, now time.Time) int64 {
	rtt := cfg.UnknownRTTMs
	if p.rttKnown {
		rtt = p.rtt.Milliseconds()
	}
	if !p.ipv6 {
		rtt += cfg.IPv4PenaltyMs
	}
	rtt += int64(p.miss) * 1000
	return rtt
}

// handleData 是挂在 core.Tunnel.OnData 上的接收入口：
//   - keepalive ping → 立刻回 ack（对端也运行本包）
//   - keepalive ack  → 配对 pending、更新 EWMA RTT、清零 miss
//   - 其余帧         → 原样转发给 Config.Receive（消息层）
func (p *peer) handleData(data []byte) {
	nt := p.tab
	now := nt.cfg.Now()

	f, isCtl := parseControl(data)
	nt.mu.Lock()
	if p.closed {
		nt.mu.Unlock()
		return
	}
	p.lastSeen = now
	var ack []byte
	if isCtl {
		switch f.Sub {
		case ctlSubPing:
			p.outFrame++
			ack = encodeControl(ctlSubAck, f.TSns, f.Nonce)
		case ctlSubAck:
			if sent, ok := p.pending[f.Nonce]; ok {
				delete(p.pending, f.Nonce)
				sample := now.Sub(sent)
				if sample < 0 {
					sample = 0
				}
				if !p.rttKnown {
					p.rtt = sample
					p.rttKnown = true
				} else {
					p.rtt = p.rtt*7/8 + sample/8
				}
				p.miss = 0
			}
		}
		nt.mu.Unlock()
		if ack != nil {
			// Send 必须在锁外：假 Tunnel/transport 可能同步回调 OnData。
			_ = p.t.Send(ack)
		}
		return
	}
	p.inFrames++
	recv := nt.cfg.Receive
	nt.mu.Unlock()

	if recv != nil {
		recv(p.pub, data)
	}
}
