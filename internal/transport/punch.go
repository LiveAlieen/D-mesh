package transport

import (
	"io"
	"net"
	"time"

	"dmesh/internal/core"
)

// Punch 向 addr 发 UDP 打洞突发：连续 PunchCount 发 'P' 标签短包
// （间隔 PunchInterval），让双向 NAT 映射同时打开。失败不重试不设中继
// （PLAN 关键风险 2：对称 NAT 接受失败，由邻居层换候选补偿）。
func (e *Endpoint) Punch(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	pkt := make([]byte, 1+sidLen+8)
	pkt[0] = tagPunch
	if _, err := io.ReadFull(e.rand, pkt[1:]); err != nil {
		return
	}
	for i := 0; i < e.cfg.PunchCount; i++ {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if closed {
			return
		}
		_, _ = e.conn.WriteTo(pkt, addr)
		if i+1 < e.cfg.PunchCount {
			time.Sleep(e.cfg.PunchInterval)
		}
	}
}

// authority 报告本机是否为具解禁权限的成员（创建者/群主/持 kick 或 unban
// 权限位）——黑名单准入判定对它的定向申诉例外通道（PLAN v16：被拉黑者仅能
// 与这些成员握手互发申诉消息，其余成员一律拒连拒转）。
func (e *Endpoint) authority() bool {
	if e.cfg.Roster == nil || e.cfg.Identity == nil {
		return false
	}
	pub := e.cfg.Identity.Pub()
	if e.cfg.Roster.HasPerm(pub, core.PermUnban) || e.cfg.Roster.HasPerm(pub, core.PermKick) {
		return true
	}
	return e.cfg.Roster.TierOf(pub) >= core.TierOwner
}
