package netdisk

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// TestRebalanceAfterKick 除名/退群善后（PLAN v14）：某成员消失（其块全灭）→
// PlanRebalance 只针对其承载的块生成 recover 动作 → ExecutePlan 异或重建并迁移
// → 数据不丢、下载完整。
func TestRebalanceAfterKick(t *testing.T) {
	gid := sha256.Sum256([]byte("kick-test"))
	net := newSimNet(t)
	var signers []*tsigner
	var mgrs []*Manager
	for i := 0; i < 4; i++ {
		s := newSigner(t, string(rune('a'+i)))
		h := net.add(s, 1<<20)
		signers = append(signers, s)
		mgrs = append(mgrs, newMgr(t, gid, s, net, h.store))
	}
	infos := hostsInfo(1<<20, signers...)
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
	content := randBytes(129) // 5 stripes × 3 slots（K=2，blockSize=16）
	mf, err := mgrs[0].Upload("k.bin", content)
	mustOK(t, err)

	// —— kick 掉布局中的最后一个配额成员 ——
	victim := mf.Hosts[len(mf.Hosts)-1]
	net.hosts[victim.Key()].online = false
	kicked := infos
	for i := range kicked {
		if kicked[i].Pub.Equal(victim) {
			kicked[i].QuotaBytes = 0
		}
	}
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(kicked))
	}

	// 读取者绝不能恰好是被 kick 的 victim：simNet 只能让 victim 在网络层
	// 离线，而 victim 自己的 Manager 读本地定额目录不走网络（listRemote 的
	// self 分支），「其块全灭」的前提对它不成立，丢失槽位会被整体掩蔽
	// （TestSingleMemberLossReconstruct 同样跳过 i==j 的读者）。密钥随机
	// 决定 mf.Hosts 排序，固定取 mgrs[1] 约有 1/3 概率命中 victim → 必红。
	var reader *Manager
	for _, m := range mgrs {
		if !m.self.Equal(victim) {
			reader = m
			break
		}
	}
	if reader == nil {
		t.Fatal("no surviving host left to act as reader")
	}
	// victim 按写入时布局确实承载块（n=4、K=2、5 条带下 (pos+stripe)%4==3
	// 恒有解），不承载则本测试前提不成立，直接报错而非静默假绿。
	layOld := Layout{Hosts: mf.Hosts, K: mf.K}
	idxVictim := len(mf.Hosts) - 1
	carried := 0
	for s := 0; s < mf.Stripes; s++ {
		for p := 0; p < mf.Strides(); p++ {
			i, err := layOld.IndexFor(s, p)
			mustOK(t, err)
			if i == idxVictim {
				carried++
			}
		}
	}
	if carried == 0 {
		t.Fatal("kicked host carries no slots, test premise broken")
	}

	ps, err := reader.CollectPlacements(mf)
	mustOK(t, err)
	missing := MissingByStripe(mf, ps)
	if len(missing) == 0 {
		t.Fatal("expected some lost slots after kick")
	}
	actions, err := reader.PlanRebalance(mf, ps)
	mustOK(t, err)
	var nRec, nMove int
	for _, a := range actions {
		switch a.Kind {
		case ActionRecover:
			nRec++
		case ActionMove:
			nMove++
			// move 不允许从已消失成员搬（拿不到）。
			if a.From.Equal(victim) {
				t.Fatal("move from kicked host impossible")
			}
		}
		if a.To.Equal(victim) {
			t.Fatal("must not place blocks on kicked member")
		}
	}
	if nRec == 0 {
		t.Fatal("kicked member's slots must produce recover actions")
	}
	mustOK(t, reader.ExecutePlan(mf, actions))

	// 重建落盘后：victim 彻底拔线也不影响下载，且不再有降级槽位。
	ps2, err := reader.CollectPlacements(mf)
	mustOK(t, err)
	if miss := MissingByStripe(mf, ps2); len(miss) != 0 {
		t.Fatalf("after rebalance still missing: %v", miss)
	}
	acts2, err := reader.PlanRebalance(mf, ps2)
	mustOK(t, err)
	if len(acts2) != 0 {
		// 只允许因 n 变化导致的纯放置搬移，不允许再有 recover。
		for _, a := range acts2 {
			if a.Kind == ActionRecover {
				t.Fatalf("unexpected recover after rebalance: %+v", a)
			}
		}
		mustOK(t, reader.ExecutePlan(mf, acts2))
	}
	got, err := reader.Download(mf)
	mustOK(t, err)
	if string(got) != string(content) {
		t.Fatal("content lost after kick+rebalance")
	}
}

// TestRebalanceOnJoin 新配额成员上线：只发生「搬移补缺」（ActionMove），
// 不重建内容（无 recover），且终局放置与轮转公式完全一致。
func TestRebalanceOnJoin(t *testing.T) {
	gid := sha256.Sum256([]byte("join-test"))
	net := newSimNet(t)
	var signers []*tsigner
	var mgrs []*Manager
	for i := 0; i < 3; i++ {
		s := newSigner(t, string(rune('p'+i)))
		h := net.add(s, 1<<20)
		signers = append(signers, s)
		mgrs = append(mgrs, newMgr(t, gid, s, net, h.store))
	}
	infos := hostsInfo(1<<20, signers...)
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
	content := randBytes(80)
	mf, err := mgrs[0].Upload("j.bin", content)
	mustOK(t, err)

	// —— 第 4 名成员带着配额上线 ——
	s4 := newSigner(t, "q9")
	h4 := net.add(s4, 1<<20)
	mgr4 := newMgr(t, gid, s4, net, h4.store)
	infos2 := append(hostsInfo(1<<20, signers...), HostInfo{Pub: s4.Pub(), QuotaBytes: 1 << 20})
	all := append(append([]*Manager{}, mgrs...), mgr4)
	for _, m := range all {
		mustOK(t, m.SetHosts(infos2))
	}
	ps, err := mgr4.CollectPlacements(mf)
	mustOK(t, err)
	actions, err := mgr4.PlanRebalance(mf, ps)
	mustOK(t, err)
	if len(actions) == 0 {
		t.Fatal("join must trigger rebalance moves")
	}
	for _, a := range actions {
		if a.Kind != ActionMove {
			t.Fatalf("join should only move existing blocks, got %v", a.Kind)
		}
	}
	mustOK(t, mgr4.ExecutePlan(mf, actions))

	// 终局：每条带每槽位都在新轮转公式指向的成员上，且内容仍可完整读出。
	lay := Layout{Hosts: all[0].Layout().Hosts, K: mf.K}
	have, err := mgr4.CollectPlacements(mf)
	mustOK(t, err)
	for s := 0; s < mf.Stripes; s++ {
		for p := 0; p < mf.Strides(); p++ {
			want, err := lay.HostFor(s, p)
			mustOK(t, err)
			var found *Placement
			for i := range have {
				if have[i].Stripe == s && have[i].Pos == p {
					found = &have[i]
				}
			}
			if found == nil {
				t.Fatalf("slot (%d,%d) vanished during rebalance", s, p)
			}
			if !found.Host.Equal(want) {
				t.Fatalf("slot (%d,%d) on %s, rotation says %s", s, p, found.Host, want)
			}
		}
	}
	if _, err := mgr4.Download(mf); err != nil {
		t.Fatal(err)
	}
	// 再跑一次计划应为空（收敛）。
	acts2, err := mgr4.PlanRebalance(mf, have)
	mustOK(t, err)
	if len(acts2) != 0 {
		t.Fatalf("rebalance not converged: %+v", acts2)
	}
}

// TestRebalanceTooManyMissing 同条双灭时 PlanRebalance 直接拒绝而非生成坏计划。
func TestRebalanceTooManyMissing(t *testing.T) {
	gid := sha256.Sum256([]byte("double-loss"))
	net := newSimNet(t)
	var signers []*tsigner
	var mgrs []*Manager
	for i := 0; i < 4; i++ {
		s := newSigner(t, string(rune('x'+i)))
		h := net.add(s, 1<<20)
		signers = append(signers, s)
		mgrs = append(mgrs, newMgr(t, gid, s, net, h.store))
	}
	infos := hostsInfo(1<<20, signers...)
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
	mf, err := mgrs[0].Upload("d.bin", randBytes(64))
	mustOK(t, err)
	// 物理删除 stripe0 的两个块（校验 + 数据1）。
	mustOK(t, net.hosts[mf.Hosts[0].Key()].store.Delete(mf.FileID, 0, 0))
	lay := Layout{Hosts: mf.Hosts, K: mf.K}
	h2, err := lay.HostFor(0, 1)
	mustOK(t, err)
	mustOK(t, net.hosts[h2.Key()].store.Delete(mf.FileID, 0, 1))
	ps, err := mgrs[1].CollectPlacements(mf)
	mustOK(t, err)
	if _, err := mgrs[1].PlanRebalance(mf, ps); !errors.Is(err, ErrTooManyMissing) {
		t.Fatalf("want ErrTooManyMissing, got %v", err)
	}
}
