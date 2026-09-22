package discovery

import (
	"sync"
	"time"
)

// 默认容量与过期策略。
const (
	// DefaultMaxPeers 是单个种子保留的端点上限（超出按「最差」淘汰，见 evict）。
	DefaultMaxPeers = 4096
	// DefaultPeerTTL 是端点保鲜期：超过这么久没再见到就从集合里剔除。
	// 0 表示不过期（默认取 0——swarm 会持续刷新 LastSeen，过期只对「注入后长期不再出现」
	// 的线索有意义，调用方可按需设）。
	DefaultPeerTTL time.Duration = 0
)

// PeerSet 是一个并发安全的端点集合：按规范化地址去重、合并多源结果、限容、可选 TTL。
//
// 它是发现层里唯一持有状态的地方，也是纯逻辑（时钟可注入），单测覆盖去重/合并/淘汰；
// 真实网络源只负责把 []Peer 交给它。
type PeerSet struct {
	mu    sync.Mutex
	peers map[string]Peer
	max   int
	ttl   time.Duration
	now   func() int64 // Unix 毫秒
}

// NewPeerSet 建集合。max<=0 用 DefaultMaxPeers；ttl 见 DefaultPeerTTL 语义。
func NewPeerSet(max int, ttl time.Duration) *PeerSet {
	if max <= 0 {
		max = DefaultMaxPeers
	}
	return &PeerSet{
		peers: make(map[string]Peer),
		max:   max,
		ttl:   ttl,
		now:   defaultNow,
	}
}

func defaultNow() int64 { return time.Now().UnixMilli() }

// SetClock 注入时钟（Unix 毫秒），供单测控制 TTL 与 LastSeen。返回自身便于链式调用。
func (s *PeerSet) SetClock(now func() int64) *PeerSet {
	if now == nil {
		now = defaultNow
	}
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
	return s
}

// touchLocked 补齐时间戳并按 TTL 收敛。
func (s *PeerSet) stampLocked(p *Peer) {
	if p.LastSeen <= 0 {
		p.LastSeen = s.now()
	}
}

// Add 加入一个端点。
//
// 去重键是规范化后的地址；同一地址再次加入时只前进不回退：
//   - LastSeen 取更大值（新的覆盖旧的）；
//   - Origin 在「更可信（Rank 更高）」或「本次时间更新」时替换。
//
// 返回 whether 该地址是首次出现（增量回调据此发新端点）。集合已满时按最差项淘汰后腾位。
func (s *PeerSet) Add(p Peer) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addLocked(p)
}

func (s *PeerSet) addLocked(p Peer) bool {
	s.stampTTL()
	if s.peers == nil { // 防御 zero-value 使用
		s.peers = make(map[string]Peer)
	}
	if p.Origin == "" {
		p.Origin = OriginUnknown
	}
	s.stampLocked(&p)
	old, ok := s.peers[p.Addr]
	if ok {
		merged := old
		if p.LastSeen > merged.LastSeen {
			merged.LastSeen = p.LastSeen
		}
		if p.Origin.Rank() >= old.Origin.Rank() && p.LastSeen >= old.LastSeen {
			merged.Origin = p.Origin
		}
		s.peers[p.Addr] = merged
		return false
	}
	if s.max > 0 && len(s.peers) >= s.max {
		if !s.evictLocked(p) {
			return false // 新来的还不如集合里最差的，直接不收
		}
	}
	s.peers[p.Addr] = p
	return true
}

// worse 报告端点 a 是否比 b「更差」（应被优先淘汰）。它把发现层的已知好序收敛成
// 一个可复用的比较函数，与 SortPeers 的 best-first 顺序完全一致：
//   - 来源可信度权重高者更好（Origin.Rank 降序）；
//   - 同权重时最后见到时间新者更好（LastSeen 降序）；
//   - 权重与新鲜度都相同时 IPv6 优先——邻居选择偏好 IPv6（见 PLAN「邻居表：RTT/IPv6 优先」）。
//
// 说明：RTT 不属于端点集合（Peer 只有 Addr/Origin/LastSeen），它由 neighbor 层持有并
// 参与连接期排序；本层只能以「来源可信度 + 新鲜度 + 协议族偏好」近似刻画好序。
// 两项在上述各维度上完全等价时返回 false（不区分先后，保持决定性）。
func worse(a, b Peer) bool {
	if ra, rb := a.Origin.Rank(), b.Origin.Rank(); ra != rb {
		return ra < rb // 权重低的更差
	}
	if a.LastSeen != b.LastSeen {
		return a.LastSeen < b.LastSeen // 更早见到的更差
	}
	if a.Is6() != b.Is6() {
		return !a.Is6() // 同为 IPv4 才不区分；a 是 IPv4、b 是 IPv6 → a 更差
	}
	return false
}

// evictLocked 在集合已满时决定能否为新来者腾一个位置：淘汰「最差」的既有条目
// （见 worse——来源权重最低、其次 LastSeen 最早、再其次 IPv4），若新来者不比它好则不淘汰。
func (s *PeerSet) evictLocked(incoming Peer) bool {
	var worstAddr string
	var worst Peer
	for addr, p := range s.peers {
		if worstAddr == "" || worse(p, worst) {
			worstAddr, worst = addr, p
		}
	}
	if worstAddr == "" {
		return true
	}
	// 只有当新来者严格优于「最差项」时才淘汰；否则（等价或更差）不收，
	// 避免把还不如它的老 peer 挤掉。
	if !worse(worst, incoming) {
		return false
	}
	delete(s.peers, worstAddr)
	return true
}

// stampTTL 按 TTL 剔除过期项，返回剔除条数（ttl<=0 时恒返回 0）。
func (s *PeerSet) stampTTL() int {
	if s.ttl <= 0 || s.peers == nil {
		return 0
	}
	cutoff := s.now() - s.ttl.Milliseconds()
	dropped := 0
	for addr, p := range s.peers {
		if p.LastSeen < cutoff {
			delete(s.peers, addr)
			dropped++
		}
	}
	return dropped
}

// AddAll 批量加入，返回首次出现的端点（已合并后的值，供增量回调）。
func (s *PeerSet) AddAll(ps []Peer) []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var added []Peer
	for _, p := range ps {
		if err := p.Validate(); err != nil {
			continue
		}
		if s.addLocked(p) {
			added = append(added, s.peers[p.Addr])
		}
	}
	return added
}

// Merge 把另一个集合的端点并进本集合（多种子/多源汇总用），返回首次出现的端点。
func (s *PeerSet) Merge(other *PeerSet) []Peer {
	if other == nil {
		return nil
	}
	return s.AddAll(other.Snapshot())
}

// Snapshot 返回全部端点的稳定排序副本（见 SortPeers）。
func (s *PeerSet) Snapshot() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	out := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	SortPeers(out)
	return out
}

// Addrs 返回稳定排序后的地址列表（transport/neighbor 只要 IP:port 时用）。
func (s *PeerSet) Addrs() []string {
	snap := s.Snapshot()
	out := make([]string, len(snap))
	for i, p := range snap {
		out[i] = p.Addr
	}
	return out
}

// Has 报告地址（自动规范化）是否已在集合中。
func (s *PeerSet) Has(addr string) bool {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	_, ok := s.peers[norm]
	return ok
}

// Get 取某个端点的当前视图。
func (s *PeerSet) Get(addr string) (Peer, bool) {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return Peer{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	p, ok := s.peers[norm]
	return p, ok
}

// Remove 删除一个端点（邻居层断连除名时可用来拉黑地址，返回是否删了）。
func (s *PeerSet) Remove(addr string) bool {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.peers[norm]; !ok {
		return false
	}
	delete(s.peers, norm)
	return true
}

// Len 返回当前端点数（已过一遍 TTL）。
func (s *PeerSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	return len(s.peers)
}

// CountOrigin 返回某来源的端点数——「PEX 有没有真的在生效」的判据就取这个值。
func (s *PeerSet) CountOrigin(src Origin) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	n := 0
	for _, p := range s.peers {
		if p.Origin == src {
			n++
		}
	}
	return n
}

// Sources 返回各来源的端点数分布（快照日志/统计用）。
func (s *PeerSet) Origins() map[Origin]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampTTL()
	out := make(map[Origin]int, 6)
	for _, p := range s.peers {
		out[p.Origin]++
	}
	return out
}
