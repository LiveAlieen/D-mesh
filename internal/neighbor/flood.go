package neighbor

import (
	"dmesh/internal/core"
)

// 本文件是 message 包（及任何上层）的投递入口。邻居表只负责「把帧送到
// 活跃隧道」，msg_id 去重、TTL、验签都在 message 层做；本表提供
// Flood/BroadcastExcept 以便按来源抑制（收到帧的来路邻居不再回送）。

// Broadcast 把已序列化帧发给全部活跃邻居，返回成功/失败数。
// 发送失败的邻居记 miss，达 MaxFail 由巡检循环判死。
func (nt *Table) Broadcast(data []byte) (sent, failed int) {
	nt.mu.Lock()
	peers := make([]*peer, 0, len(nt.peers))
	for _, p := range nt.peers {
		if !p.closed {
			peers = append(peers, p)
		}
	}
	nt.mu.Unlock()
	return nt.sendTo(peers, data)
}

// Flood 做「来源抑制」广播：除 from 之外的全部活跃邻居都收到（from 为
// 帧的来源 pubkey；本地自发消息传零值 PubKey 等价于 Broadcast）。
func (nt *Table) Flood(from core.PubKey, data []byte) (sent, failed int) {
	return nt.BroadcastExcept([]core.PubKey{from}, data)
}

// BroadcastExcept 除 excludes 列表中全部 pubkey 外广播。
func (nt *Table) BroadcastExcept(excludes []core.PubKey, data []byte) (sent, failed int) {
	skip := make(map[string]struct{}, len(excludes))
	for _, e := range excludes {
		skip[e.Key()] = struct{}{}
	}
	nt.mu.Lock()
	peers := make([]*peer, 0, len(nt.peers))
	for _, p := range nt.peers {
		if p.closed {
			continue
		}
		if _, ok := skip[p.pub.Key()]; ok {
			continue
		}
		peers = append(peers, p)
	}
	nt.mu.Unlock()
	return nt.sendTo(peers, data)
}

// SendTo 定向发送给某一活跃邻居；非邻居返回 ErrNoCapacity 之外的明确错误。
func (nt *Table) SendTo(pub core.PubKey, data []byte) error {
	nt.mu.Lock()
	p, ok := nt.peers[pub.Key()]
	if !ok || p.closed {
		nt.mu.Unlock()
		return ErrNotNeighbor
	}
	nt.mu.Unlock()
	err := p.t.Send(data)
	nt.mu.Lock()
	if err != nil {
		p.miss++
		p.sendErrs++
	} else {
		p.outFrame++
	}
	nt.mu.Unlock()
	return err
}

// sendTo 锁外向给定 peer 集合写帧，失败计入 miss/sendErrs。
func (nt *Table) sendTo(peers []*peer, data []byte) (sent, failed int) {
	for _, p := range peers {
		err := p.t.Send(data)
		nt.mu.Lock()
		if err != nil {
			p.miss++
			p.sendErrs++
			failed++
		} else {
			p.outFrame++
			sent++
		}
		nt.mu.Unlock()
	}
	return sent, failed
}
