// Package neighbor 实现 D-Mesh 的邻居表状态机（PLAN v16 · M2）。
//
// 职责：
//   - 维持 MinNeighbors~MaxNeighbors（默认 3~8）条活跃 core.Tunnel；
//   - 周期性 keepalive（默认 25s）：控制帧由本包自己拥有并终结，
//     不计入 gossip、不转发给消息层；ping/ack 往返平滑出 RTT；
//   - 打分与替换：RTT 越小越优、IPv6 地址优先（可配罚分）、连续失败重罚，
//     满员时更优的新连接可顶替最差邻居（宁多勿断，低于下限绝不主动断）；
//   - 候选补充：AddCandidate 登记 {pub, wg, addr}，Run 循环在活跃数低于
//     下限时按 Config.Dial 回调自动拨通（拨号退避可配）；
//   - 除名断连：HandleRosterEvent 收到 remove/kick 等名单事件后对相应
//     pubkey 即时断连；注入 Config.Roster 后循环还会按黑名单兜底清扫
//     （申诉通道等定向连接由上层另管，不入本表）。
//   - 广播/flood 投递入口：Broadcast / Flood / BroadcastExcept / SendTo，
//     供 message 包在建立去重后调用。
//
// 解耦约定（core 契约第 1 条）：本包只 import dmesh/internal/core；
// transport 的拨号、message 的收帧回调、group 的名单查询全部经
// Config 注入的接口/回调接线，具体实现在 cmd/dmesh 组装。
package neighbor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"dmesh/internal/core"
)

// Reason 是断连原因标签（OnLeave 回调与内部统计用）。
type Reason string

const (
	ReasonRemove      Reason = "remove"         // remove 事件（本人退群）
	ReasonKick        Reason = "kick"           // kick 事件（除名进黑名单）
	ReasonBlacklisted Reason = "blacklisted"    // 黑名单兜底清扫命中
	ReasonUnhealthy   Reason = "unhealthy"      // keepalive 无应答/发送连续失败
	ReasonReplaced    Reason = "replaced"       // 被更优邻居顶替
	ReasonDuplicate   Reason = "duplicate"      // 同 pubkey 重复接入，后来者被拒
	ReasonRejected    Reason = "rejected"       // 满员且不如现有最差邻居
	ReasonSelf        Reason = "self"           // 试图连接本机自身
	ReasonLocalClosed Reason = "local_shutdown" // 本表关闭
	ReasonRemoteClose Reason = "remote_close"   // 上层主动断开
)

// 契约级错误。
var (
	ErrClosed        = errors.New("neighbor: table closed")
	ErrBadConfig     = errors.New("neighbor: bad config")
	ErrAlreadyExists = errors.New("neighbor: pubkey already an active neighbor")
	ErrSelfConnect   = errors.New("neighbor: refusing to neighbor with own pubkey")
	ErrNoCapacity    = errors.New("neighbor: full and newcomer not better than worst")
	ErrNoDialer      = errors.New("neighbor: no Dial configured for auto candidate dial")
	ErrNotNeighbor   = errors.New("neighbor: pubkey is not an active neighbor")
)

// 默认参数（PLAN 定值：活跃邻居 3~8、keepalive 25s）。
const (
	DefaultMinNeighbors  = 3
	DefaultMaxNeighbors  = 8
	DefaultKeepalive     = 25 * time.Second
	DefaultTick          = time.Second
	DefaultMaxFail       = 3
	DefaultDialInterval  = 2 * time.Second
	DefaultCandidateTTL  = 30 * time.Minute
	DefaultMaxCandidates = 64
	DefaultUnknownRTTMs  = int64(500)
	DefaultIPv4PenaltyMs = int64(200)
)

// Config 全部字段可留零值走默认；回调均在 Table 的锁外调用，
// 回调内可安全重入 Table 的任何导出方法。
type Config struct {
	MinNeighbors  int // 活跃邻居下限（默认 3）
	MaxNeighbors  int // 活跃邻居上限（默认 8）；候选拨号封顶到该值
	Keepalive     time.Duration
	Tick          time.Duration // 状态机巡检周期（默认 1s）
	MaxFail       int           // 连续 ping 无应答/发送失败次数上限，达到即断
	DialInterval  time.Duration // 两次候选拨号之间的最小间隔
	CandidateTTL  time.Duration
	MaxCandidates int

	UnknownRTTMs  int64 // 尚无 RTT 样本时的代入值
	IPv4PenaltyMs int64 // 非 IPv6（或未知地址）罚分，体现 IPv6 优先
	OnlineBonusMs int64 // 预留：注入 Roster 后在线成员在候选排序中的加分暂未启用（-1 关闭）

	// LocalPub 本机身份（可选）：防止把自签 remove 等事件应用到自己身上断连。
	LocalPub core.PubKey

	// Roster 只读用途：IsBlacklisted 兜底清扫 + Presence 在线偏好。nil = 关闭。
	Roster core.Roster

	// Dial 由 transport 提供：对候选端点（含 "ip:port" 地址）完成握手并
	// 返回 Tunnel。nil 时候选池仅登记、不自动拨号（外部经 Add 接入）。
	Dial func(c Candidate) (core.Tunnel, error)

	// Receive 收到非控制帧时的上行入口（消息层在建立去重/验签的接帧口）。
	Receive func(remote core.PubKey, data []byte)

	OnJoin  func(remote core.PubKey)
	OnLeave func(remote core.PubKey, reason Reason)

	// Now 可注入时钟（单测用），默认 time.Now。
	Now func() time.Time
}

func (cfg Config) normalize() (Config, error) {
	c := cfg
	if c.MinNeighbors == 0 {
		c.MinNeighbors = DefaultMinNeighbors
	}
	if c.MaxNeighbors == 0 {
		c.MaxNeighbors = DefaultMaxNeighbors
	}
	if c.MinNeighbors < 0 || c.MaxNeighbors <= 0 {
		return c, fmt.Errorf("%w: neighbor bounds", ErrBadConfig)
	}
	if c.MinNeighbors > c.MaxNeighbors {
		c.MinNeighbors = c.MaxNeighbors // 宁多勿断：上限优先
	}
	if c.Keepalive <= 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.Tick <= 0 {
		c.Tick = DefaultTick
	}
	if c.MaxFail <= 0 {
		c.MaxFail = DefaultMaxFail
	}
	if c.DialInterval <= 0 {
		c.DialInterval = DefaultDialInterval
	}
	if c.CandidateTTL <= 0 {
		c.CandidateTTL = DefaultCandidateTTL
	}
	if c.MaxCandidates <= 0 {
		c.MaxCandidates = DefaultMaxCandidates
	}
	switch {
	case c.UnknownRTTMs == 0:
		c.UnknownRTTMs = DefaultUnknownRTTMs
	case c.UnknownRTTMs < 0:
		c.UnknownRTTMs = 0 // 显式关闭代入值
	}
	switch {
	case c.IPv4PenaltyMs == 0:
		c.IPv4PenaltyMs = DefaultIPv4PenaltyMs
	case c.IPv4PenaltyMs < 0:
		c.IPv4PenaltyMs = 0 // 显式关闭 IPv6 优先
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

// Candidate 是潜在邻居端点（discovery/白名单条目合成）。
type Candidate struct {
	Pub  core.PubKey
	WG   core.WGPub
	Addr string // "ip:port"，可空（空则 Dial 需自备寻址）
}

// candidate 是待拨号/待观察的潜在邻居。
type candidate struct {
	pub    core.PubKey
	wg     core.WGPub
	addr   string
	added  time.Time
	fails  int
	nextAt time.Time
}

// Table 是邻居表状态机本体。导出方法全部并发安全。
type Table struct {
	cfg Config

	mu    sync.Mutex
	peers map[string]*peer      // pubKey() -> 活跃邻居
	cands map[string]*candidate // pubKey() -> 候选池

	lastDial  time.Time
	closed    bool
	closeOnce sync.Once
	stop      chan struct{}
}

// New 构建邻居表；配置非法（负数边界等）返回 ErrBadConfig。
func New(cfg Config) (*Table, error) {
	c, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Table{
		cfg:   c,
		peers: map[string]*peer{},
		cands: map[string]*candidate{},
		stop:  make(chan struct{}),
	}, nil
}

// Config 返回生效配置（含默认值填充结果）。
func (nt *Table) Config() Config { return nt.cfg }

// Run 驱动状态机巡检（keepalive、超时判死、候选拨号、黑名单清扫），
// 直到 ctx 取消或 Close 被调用后返回。通常以 goroutine 运行。
func (nt *Table) Run(ctx context.Context) error {
	t := time.NewTicker(nt.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-nt.stop:
			return nil
		case <-t.C:
			nt.cycle()
		}
	}
}

// Close 停掉 Run 并断开全部邻居（OnLeave 携 ReasonLocalClosed）。
func (nt *Table) Close() error {
	nt.closeOnce.Do(func() {
		close(nt.stop)
		nt.mu.Lock()
		nt.closed = true
		nt.mu.Unlock()
		for _, ps := range nt.Snapshot() {
			nt.Drop(ps.Pub, ReasonLocalClosed)
		}
	})
	return nil
}

func (nt *Table) isClosed() bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	return nt.closed
}

// cycle 执行一轮状态机巡检。结构：锁内取快照/做判定，锁外做
// Send/Close/拨号/回调，避免 transport 同步回调 OnData 造成死锁。
func (nt *Table) cycle() {
	if nt.isClosed() {
		return
	}
	now := nt.cfg.Now()

	type pingJob struct {
		p     *peer
		nonce string
		frame []byte
	}
	var pings []pingJob
	var dead []dropJob

	nt.mu.Lock()
	for _, p := range nt.peers {
		if p.closed {
			continue
		}
		// 无应答超时：最老的 pending 超过 Keepalive+宽限仍未回 → miss++
		for nonce, sent := range p.pending {
			if now.Sub(sent) > nt.cfg.Keepalive+nt.cfg.Tick {
				delete(p.pending, nonce)
				p.miss++
			}
		}
		if p.miss >= nt.cfg.MaxFail {
			dead = append(dead, dropJob{p, ReasonUnhealthy})
			p.closed = true
			continue
		}
		if p.pending == nil || len(p.pending) == 0 {
			if now.Sub(p.lastSeen) >= nt.cfg.Keepalive || !p.rttKnown {
				nonce := newNonce()
				frame := encodeControl(ctlSubPing, now.UnixNano(), nonce)
				if p.pending == nil {
					p.pending = map[string]time.Time{}
				}
				p.pending[nonce] = now
				pings = append(pings, pingJob{p, nonce, frame})
			}
		}
	}
	// 过期候选清理
	for k, c := range nt.cands {
		if now.Sub(c.added) > nt.cfg.CandidateTTL {
			delete(nt.cands, k)
		}
	}
	nt.mu.Unlock()

	// 锁外发 keepalive ping（假隧道可能同步回 ack → handleData 需要拿锁）
	for _, j := range pings {
		if err := j.p.t.Send(j.frame); err != nil {
			nt.mu.Lock()
			delete(j.p.pending, j.nonce)
			j.p.miss++
			j.p.sendErrs++
			nt.mu.Unlock()
		}
	}

	// 锁外断开死邻居
	for _, d := range dead {
		nt.finishDrop(d.p, d.reason)
	}

	// 黑名单兜底清扫（仅当注入了 Roster；申诉类定向连接由上层不入本表）
	if nt.cfg.Roster != nil {
		for _, ps := range nt.Snapshot() {
			if nt.cfg.Roster.IsBlacklisted(ps.Pub) {
				nt.Drop(ps.Pub, ReasonBlacklisted)
			}
		}
	}

	// 活跃数未达 Max 且有 Dial 能力 → 择优拨号候选
	nt.dialCandidates(now)
}

// dialCandidates 在活跃数 < MaxNeighbors 时按分数从优拨号候选池，
// 每轮巡检最多拨 1 个且遵守 DialInterval 退避。
func (nt *Table) dialCandidates(now time.Time) {
	dial := nt.cfg.Dial
	if dial == nil {
		return
	}
	nt.mu.Lock()
	if nt.closed || len(nt.peers) >= nt.cfg.MaxNeighbors {
		nt.mu.Unlock()
		return
	}
	if now.Sub(nt.lastDial) < nt.cfg.DialInterval {
		nt.mu.Unlock()
		return
	}
	type scored struct {
		c     *candidate
		value int64
	}
	var list []scored
	for _, c := range nt.cands {
		if _, exists := nt.peers[c.pub.Key()]; exists {
			continue
		}
		if now.Before(c.nextAt) {
			continue
		}
		v := nt.cfg.UnknownRTTMs + int64(c.fails)*1000
		if !addrIsIPv6(c.addr) {
			v += nt.cfg.IPv4PenaltyMs
		}
		list = append(list, scored{c, v})
	}
	nt.mu.Unlock()

	if len(list) == 0 {
		return
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].value != list[j].value {
			return list[i].value < list[j].value
		}
		return list[i].c.added.Before(list[j].c.added)
	})
	best := list[0].c

	nt.mu.Lock()
	nt.lastDial = now
	nt.mu.Unlock()

	t, err := dial(Candidate{Pub: best.pub, WG: best.wg, Addr: best.addr})
	if err != nil || t == nil {
		nt.mu.Lock()
		if c, ok := nt.cands[best.pub.Key()]; ok {
			c.fails++
			c.nextAt = now.Add(nt.cfg.DialInterval * time.Duration(1<<min(c.fails, 5)))
		}
		nt.mu.Unlock()
		return
	}
	_ = nt.Add(t, best.addr)
}
