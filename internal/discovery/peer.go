package discovery

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Origin 标示一个端点是通过哪条发现渠道拿到的。来源决定可信度权重（见 OriginRank），
// 也决定「PEX 是否真的在生效」这一退化判据。
type Origin string

const (
	// OriginDHT：公共 DHT 的 get_peers 回包或 announce 期间收到的 peer 列表。
	OriginDHT Origin = "dht"
	// OriginPEX：已与某 peer 建立 BT 连接，由其 peer exchange 扩展消息告知的端点。
	OriginPEX Origin = "pex"
	// OriginTracker：tracker 回包（种子自带 announce-list 时可能出现）。
	OriginTracker Origin = "tracker"
	// OriginSeed：种子/磁力链自带的直连地址（x.pe）或调用方注入的已知端点。
	OriginSeed Origin = "seed"
	// OriginManual：调用方手动注入（如 join 事件里携带的地址、CLI 参数）。
	OriginManual Origin = "manual"
	// OriginUnknown：来源不明（映射不到已知渠道时的兜底，权重最低）。
	OriginUnknown Origin = "unknown"
)

// 各类来源的默认可信度权重（同一端点多源出现时保留权重高的来源；快照排序也用它）。
// 排序：手动注入 > 种子自带 > DHT > PEX > tracker > unknown —— 前两者是我们主动给的线索，
// 网络渠道里 DHT 又比 PEX 更权威（PEX 是邻居自报，可能被打洞噪声污染）。
func originRank(s Origin) int {
	switch s {
	case OriginManual:
		return 5
	case OriginSeed:
		return 4
	case OriginDHT:
		return 3
	case OriginPEX:
		return 2
	case OriginTracker:
		return 1
	default:
		return 0
	}
}

// Rank 返回来源权重（见 originRank 的说明）。
func (s Origin) Rank() int { return originRank(s) }

// String 实现 fmt.Stringer。
func (s Origin) String() string {
	if s == "" {
		return string(OriginUnknown)
	}
	return string(s)
}

// Peer 是发现层输出的最小单元：一个规范化后的 IP:port 端点及其发现上下文。
//
// Addr 一律为 net.JoinHostPort 形式：IPv4 "1.2.3.4:5678"、IPv6 "[2001:db8::1]:5678"，
// 可直接交给 net.Dial / transport 层握手，无需再解析。
type Peer struct {
	Addr     string `json:"addr"`
	Origin   Origin `json:"source"`
	LastSeen int64  `json:"last_seen"` // Unix 毫秒（0 表示未知，由容器补当前时钟）
}

// ErrInvalidAddr 表示地址不是合法的可连接 IP:port。
var ErrInvalidAddr = errors.New("discovery: invalid peer address")

// NormalizeAddr 把 "host:port" 规范化：去掉首尾空白与多余方括号，校验 IP 与端口范围，
// 并按 net.JoinHostPort 重排（IPv6 必带方括号、前导零去除）。
//
// 允许环回与私网地址（本机多实例联调、局域网直连路径都要用），只拒绝：
// 无法拆分 host/port、IP 不可解析（含带 zone 的链路本地地址）、端口越界。
func NormalizeAddr(addr string) (string, error) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return "", fmt.Errorf("%w: empty address", ErrInvalidAddr)
	}
	host, portStr, err := splitHostPort(s)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("%w: bad port in %q", ErrInvalidAddr, addr)
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return "", fmt.Errorf("%w: unparseable ip in %q", ErrInvalidAddr, addr)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

// splitHostPort 拆 "host:port"，把 net 的错误统一收敛成 ErrInvalidAddr（含「缺端口」提示）。
func splitHostPort(s string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return "", "", fmt.Errorf("%w: %q missing port", ErrInvalidAddr, s)
		}
		return "", "", fmt.Errorf("%w: %q (%v)", ErrInvalidAddr, s, err)
	}
	return host, port, nil
}

// NewPeer 构造一个规范化端点；地址非法时返回 error（调用方按「忽略该条」处理）。
// src 为空时记为 OriginUnknown；now 为 Unix 毫秒（<=0 时留 0，由容器补时钟）。
func NewPeer(addr string, src Origin, now int64) (Peer, error) {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return Peer{}, err
	}
	if src == "" {
		src = OriginUnknown
	}
	return Peer{Addr: norm, Origin: src, LastSeen: now}, nil
}

// MustPeer 仅用于测试与常量构造：地址非法时 panic。
func MustPeer(addr string, src Origin) Peer {
	p, err := NewPeer(addr, src, 0)
	if err != nil {
		panic(err)
	}
	return p
}

// Host 返回规范化地址里的 IP 字符串（Addr 非法时返回空）。
func (p Peer) Host() string {
	host, _, err := net.SplitHostPort(p.Addr)
	if err != nil {
		return ""
	}
	return host
}

// IP 返回端点 IP（无法解析时返回 nil）。
func (p Peer) IP() net.IP { return net.ParseIP(p.Host()) }

// Port 返回端点端口（无法解析时返回 0）。
func (p Peer) Port() int {
	_, portStr, err := net.SplitHostPort(p.Addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return n
}

// Is6 报告端点是否为 IPv6。
func (p Peer) Is6() bool {
	ip := p.IP()
	return ip != nil && ip.To4() == nil
}

// Validate 报告端点是否可用（地址已规范化、端口合法）。
func (p Peer) Validate() error {
	_, err := NormalizeAddr(p.Addr)
	return err
}

// String 供日志使用。
func (p Peer) String() string {
	return fmt.Sprintf("%s(%s@%d)", p.Addr, p.Origin.String(), p.LastSeen)
}

// SortPeers 原地稳定排序：来源权重降序 → LastSeen 降序（新的优先）→ Addr 升序（决定性）。
// 快照与对外输出前都走它，保证同一集合在任何节点上得到同一顺序。
func SortPeers(ps []Peer) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if ra, rb := a.Origin.Rank(), b.Origin.Rank(); ra != rb {
			return ra > rb
		}
		if a.LastSeen != b.LastSeen {
			return a.LastSeen > b.LastSeen
		}
		return a.Addr < b.Addr
	})
}

// ParsePeers 把一批地址字符串解析成端点（用于 Config 的候选注入、测试环回地址表）。
// 非法条目跳过并作为错误返回（返回值里只含合法项），errors 只汇总第一条。
func ParsePeers(addrs []string, src Origin, now int64) ([]Peer, error) {
	out := make([]Peer, 0, len(addrs))
	var firstErr error
	for _, a := range addrs {
		p, err := NewPeer(a, src, now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, p)
	}
	return out, firstErr
}
