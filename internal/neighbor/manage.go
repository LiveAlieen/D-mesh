package neighbor

import (
	"sort"
	"time"

	"dmesh/internal/core"
)

// dropJob 是 cycle 在锁外执行断连的内部条目。
type dropJob struct {
	p      *peer
	reason Reason
}

// Add 接入一条已握手的 Tunnel 成为活跃邻居（accept 路径与 Dial 路径共用）。
// addr 为对端 "ip:port"（可空，用于 IPv6 优先打分）。
//
// 语义：
//   - pubkey 与本机相同 → ErrSelfConnect，隧道被关闭；
//   - 同 pubkey 已有活跃隧道 → 保留先到者，后来者被关闭并回收，返回 ErrAlreadyExists；
//   - 未达 MaxNeighbors → 直接接纳；
//   - 已满员 → 打分顶替：新隧道分数严格优于现有最差邻居才顶替（IPv6 与
//     低 RTT 优先，未知 RTT 记 UnknownRTTMs），否则新隧道被关闭，返回 ErrNoCapacity。
//
// 注意 OnData 在持锁前注册（回调内要拿本表锁，避免自锁）。
func (nt *Table) Add(t core.Tunnel, addr string) error {
	if t == nil {
		return ErrBadConfig
	}
	now := nt.cfg.Now()
	pub := t.RemotePub()
	key := pub.Key()

	if !nt.cfg.LocalPub.IsZero() && nt.cfg.LocalPub.Equal(pub) {
		_ = t.Close()
		return ErrSelfConnect
	}

	p := &peer{
		tab:      nt,
		t:        t,
		pub:      pub,
		addr:     addr,
		ipv6:     addrIsIPv6(addr),
		joinedAt: now,
		lastSeen: now,
		pending:  map[string]time.Time{},
	}
	// 先注册再接管；失败路径把 p 标记 closed，handleData 自行静默。
	t.OnData(p.handleData)

	nt.mu.Lock()
	if nt.closed {
		p.closed = true
		nt.mu.Unlock()
		_ = t.Close()
		return ErrClosed
	}
	if old, ok := nt.peers[key]; ok && !old.closed {
		p.closed = true
		nt.mu.Unlock()
		_ = t.Close()
		return ErrAlreadyExists
	}

	var replaced *peer
	if len(nt.peers) >= nt.cfg.MaxNeighbors {
		worst := nt.worstPeerLocked(now)
		newScore := p.scoreMs(&nt.cfg, now)
		if worst == nil || newScore >= worst.scoreMs(&nt.cfg, now) {
			p.closed = true
			nt.mu.Unlock()
			_ = t.Close()
			return ErrNoCapacity
		}
		worst.closed = true
		delete(nt.peers, worst.pub.Key())
		replaced = worst
	}
	// 候选池里同 pubkey 的条目转正后移除
	delete(nt.cands, key)
	nt.peers[key] = p
	joinCb := nt.cfg.OnJoin
	leaveCb := nt.cfg.OnLeave
	nt.mu.Unlock()

	if replaced != nil {
		_ = replaced.t.Close()
		if leaveCb != nil {
			leaveCb(replaced.pub, ReasonReplaced)
		}
	}
	if joinCb != nil {
		joinCb(pub)
	}
	return nil
}

// worstPeerLocked 返回当前分数最差（scoreMs 最大）的活跃邻居；平分时取
// 最近加入者（新连接更可能抖动，倾向保留稳定老邻居）。须持锁调用。
func (nt *Table) worstPeerLocked(now time.Time) *peer {
	var worst *peer
	var worstScore int64
	keys := make([]string, 0, len(nt.peers))
	for k := range nt.peers {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 遍历序稳定，结果可测
	for _, k := range keys {
		p := nt.peers[k]
		if p.closed {
			continue
		}
		s := p.scoreMs(&nt.cfg, now)
		if worst == nil || s > worstScore || (s == worstScore && p.joinedAt.After(worst.joinedAt)) {
			worst, worstScore = p, s
		}
	}
	return worst
}

// Drop 立即断开 pubkey 对应的活跃邻居；无此邻居返回 false。
// reason 透传给 OnLeave 回调供上层（spam 评分等）参考。
func (nt *Table) Drop(pub core.PubKey, reason Reason) bool {
	nt.mu.Lock()
	p, ok := nt.peers[pub.Key()]
	if !ok || p.closed {
		nt.mu.Unlock()
		return false
	}
	p.closed = true
	delete(nt.peers, pub.Key())
	nt.mu.Unlock()

	_ = p.t.Close()
	if cb := nt.cfg.OnLeave; cb != nil {
		cb(p.pub, reason)
	}
	return true
}

// finishDrop 锁外关隧道并回调 OnLeave（cycle 判死路径用）。
func (nt *Table) finishDrop(p *peer, reason Reason) bool {
	_ = p.t.Close()
	if cb := nt.cfg.OnLeave; cb != nil {
		cb(p.pub, reason)
	}
	return true
}

// Count 返回当前活跃邻居数。
func (nt *Table) Count() int {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	n := 0
	for _, p := range nt.peers {
		if !p.closed {
			n++
		}
	}
	return n
}

// PublicNeighbors 返回全部活跃邻居 pubkey（稳定顺序），用于去重后的
// flood 目标枚举与状态展示。
func (nt *Table) PublicNeighbors() []core.PubKey {
	out := make([]core.PubKey, 0, nt.Count())
	for _, ps := range nt.Snapshot() {
		out = append(out, ps.Pub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Stat 是对外暴露的邻居运行指标（状态面板 / spam 评分用）。
type Stat struct {
	Pub       core.PubKey
	Addr      string
	IPv6      bool
	RTT       time.Duration // 平滑 RTT；无样本为 0
	RTTKnown  bool
	Misses    int
	SendErrs  int
	InFrames  int
	OutFrames int
	JoinedAt  time.Time
	LastSeen  time.Time
}

// Snapshot 导出当前全部活跃邻居指标（按 pubkey 稳定排序）。
func (nt *Table) Snapshot() []Stat {
	nt.mu.Lock()
	stats := make([]Stat, 0, len(nt.peers))
	for _, p := range nt.peers {
		if p.closed {
			continue
		}
		stats = append(stats, Stat{
			Pub:       p.pub,
			Addr:      p.addr,
			IPv6:      p.ipv6,
			RTT:       p.rtt,
			RTTKnown:  p.rttKnown,
			Misses:    p.miss,
			SendErrs:  p.sendErrs,
			InFrames:  p.inFrames,
			OutFrames: p.outFrame,
			JoinedAt:  p.joinedAt,
			LastSeen:  p.lastSeen,
		})
	}
	nt.mu.Unlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].Pub.Key() < stats[j].Pub.Key() })
	return stats
}

// CandidateCount 返回候选池大小（测试与状态面板用）。
func (nt *Table) CandidateCount() int {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	return len(nt.cands)
}
