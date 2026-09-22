package discovery

import "testing"

// fixedClock 返回恒定 Unix 毫秒的假时钟，供去重/合并/TTL 测试控制时间。
func fixedClock(ms int64) func() int64 { return func() int64 { return ms } }

func TestPeerSetDedupByNormalizedAddr(t *testing.T) {
	ps := NewPeerSet(0, 0).SetClock(fixedClock(1000))
	first := MustPeer("1.2.3.4:5678", OriginDHT)
	if !ps.Add(first) {
		t.Fatal("首次加入应报告为新增")
	}
	if ps.Add(first) {
		t.Fatal("同一地址重复加入不应报告为新增")
	}
	// 前后空白规范化后应命中同一去重键（IPv4 前导零被 net.ParseIP 拒绝，不作为等价形式）。
	if ps.Add(MustPeer("  1.2.3.4:5678 ", OriginDHT)) {
		t.Fatal("规范化后同址应视为重复")
	}
	if ps.Len() != 1 {
		t.Fatalf("去重后应只剩 1 个端点，实际 %d", ps.Len())
	}
}

func TestPeerSetMergeKeepsHigherOriginAndForwardLastSeen(t *testing.T) {
	ps := NewPeerSet(0, 0).SetClock(fixedClock(100))
	ps.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 100})
	// 高权重来源升级。
	ps.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginManual, LastSeen: 100})
	if p, _ := ps.Get("1.1.1.1:1"); p.Origin != OriginManual {
		t.Fatalf("更高权重来源应覆盖，实际 %s", p.Origin)
	}
	// 低权重来源不得降级已有条目。
	ps.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginPEX, LastSeen: 100})
	if p, _ := ps.Get("1.1.1.1:1"); p.Origin != OriginManual {
		t.Fatalf("低权重来源不应降级条目，实际 %s", p.Origin)
	}
	// LastSeen 只前进不回退。
	ps.Add(Peer{Addr: "2.2.2.2:2", Origin: OriginDHT, LastSeen: 200})
	ps.Add(Peer{Addr: "2.2.2.2:2", Origin: OriginDHT, LastSeen: 100})
	if p, _ := ps.Get("2.2.2.2:2"); p.LastSeen != 200 {
		t.Fatalf("更旧的 LastSeen 不得覆盖更新值，实际 %d", p.LastSeen)
	}
}

func TestPeerSetEvictionDropsWorstOnlyIfIncomingBetter(t *testing.T) {
	ps := NewPeerSet(2, 0).SetClock(fixedClock(100))
	a := Peer{Addr: "3.3.3.3:1", Origin: OriginManual, LastSeen: 100} // rank5
	b := Peer{Addr: "3.3.3.3:2", Origin: OriginDHT, LastSeen: 100}    // rank3 —— 集合里最差
	ps.Add(a)
	ps.Add(b)
	// 更差的新来者（rank1）不得挤掉最差项。
	if ps.Add(Peer{Addr: "3.3.3.3:3", Origin: OriginTracker, LastSeen: 100}) {
		t.Fatal("权重更低的新端点不应挤占已满集合")
	}
	if ps.Len() != 2 {
		t.Fatalf("拒绝后仍应为 2，实际 %d", ps.Len())
	}
	// 更好的新来者（rank5）应淘汰最差项 b。
	if !ps.Add(Peer{Addr: "3.3.3.3:4", Origin: OriginManual, LastSeen: 100}) {
		t.Fatal("优于最差项的新端点应被淘汰腾位后加入")
	}
	if ps.Has(b.Addr) {
		t.Fatal("最差项 b 应已被淘汰")
	}
	if !ps.Has(a.Addr) {
		t.Fatal("更好的 a 应保留")
	}
	if ps.Len() != 2 {
		t.Fatalf("淘汰后仍应为 2，实际 %d", ps.Len())
	}
}

func TestPeerSetEvictionPrefersIPv6(t *testing.T) {
	ps := NewPeerSet(1, 0).SetClock(fixedClock(100))
	ps.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 100}) // IPv4
	// 同权重同新鲜度的 IPv6 应淘汰 IPv4（IPv6 优先）。
	if !ps.Add(Peer{Addr: "[2001:db8::1]:1", Origin: OriginDHT, LastSeen: 100}) {
		t.Fatal("IPv6 端点应凭协议族偏好腾位成功")
	}
	if ps.Has("1.1.1.1:1") {
		t.Fatal("IPv4 端点应被淘汰")
	}
}

func TestWorseComparison(t *testing.T) {
	v6 := Peer{Addr: "[2001:db8::1]:1", Origin: OriginDHT, LastSeen: 100}
	v4 := Peer{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 100}
	if worse(v6, v4) {
		t.Fatal("同权重同新鲜度下 IPv6 不应比 IPv4 更差")
	}
	if !worse(v4, v6) {
		t.Fatal("同权重同新鲜度下 IPv4 应比 IPv6 更差")
	}
	low := Peer{Addr: "1.1.1.1:9", Origin: OriginPEX, LastSeen: 100}
	high := Peer{Addr: "1.1.1.2:9", Origin: OriginManual, LastSeen: 100}
	if !worse(low, high) || worse(high, low) {
		t.Fatal("来源权重应主导好坏")
	}
	old := Peer{Addr: "1.1.1.3:9", Origin: OriginDHT, LastSeen: 50}
	nw := Peer{Addr: "1.1.1.4:9", Origin: OriginDHT, LastSeen: 100}
	if !worse(old, nw) || worse(nw, old) {
		t.Fatal("同权重下更早见到的更差")
	}
	if worse(nw, nw) {
		t.Fatal("自身不应比自身更差")
	}
}

func TestSortPeersOrder(t *testing.T) {
	ps := []Peer{
		{Addr: "5.5.5.5:5", Origin: OriginPEX, LastSeen: 1},
		{Addr: "1.1.1.1:1", Origin: OriginManual, LastSeen: 1},
		{Addr: "3.3.3.3:3", Origin: OriginDHT, LastSeen: 99},
		{Addr: "4.4.4.4:4", Origin: OriginDHT, LastSeen: 1},
	}
	SortPeers(ps)
	want := []string{"1.1.1.1:1", "3.3.3.3:3", "4.4.4.4:4", "5.5.5.5:5"}
	for i := range want {
		if ps[i].Addr != want[i] {
			t.Fatalf("位次 %d 应为 %s，实际 %s", i, want[i], ps[i].Addr)
		}
	}
}

func TestPeerSetTTLExpiry(t *testing.T) {
	cur := int64(1000)
	ps := NewPeerSet(0, 5000).SetClock(func() int64 { return cur })
	ps.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 1000})
	ps.Add(Peer{Addr: "2.2.2.2:2", Origin: OriginDHT, LastSeen: 1000})
	if ps.Len() != 2 {
		t.Fatalf("未过期应有 2 个，实际 %d", ps.Len())
	}
	cur = 6001 // cutoff=1001，两枚 lastseen=1000 均过期
	if ps.Len() != 0 {
		t.Fatalf("过期后应清空，实际 %d", ps.Len())
	}
}

func TestPeerSetMergeAndOriginCounts(t *testing.T) {
	a := NewPeerSet(0, 0).SetClock(fixedClock(100))
	a.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 100})
	b := NewPeerSet(0, 0).SetClock(fixedClock(100))
	b.Add(Peer{Addr: "1.1.1.1:1", Origin: OriginManual, LastSeen: 100})
	b.Add(Peer{Addr: "2.2.2.2:2", Origin: OriginDHT, LastSeen: 100})
	added := a.Merge(b)
	if a.Len() != 2 {
		t.Fatalf("合并后应有 2 个，实际 %d", a.Len())
	}
	if p, _ := a.Get("1.1.1.1:1"); p.Origin != OriginManual {
		t.Fatalf("合并应保留更高权重来源，实际 %s", p.Origin)
	}
	if len(added) != 1 || added[0].Addr != "2.2.2.2:2" {
		t.Fatalf("Merge 只应回传首次出现的端点，实际 %+v", added)
	}
	if a.CountOrigin(OriginDHT) != 1 || a.CountOrigin(OriginManual) != 1 {
		t.Fatalf("来源分布统计错误: %+v", a.Origins())
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"  1.2.3.4:5 ", "1.2.3.4:5", true},
		{"[2001:0db8::0001]:80", "[2001:db8::1]:80", true},
		{"1.2.3.4", "", false},       // 缺端口
		{"1.2.3.4:99999", "", false}, // 端口越界
		{"not-an-ip:1", "", false},   // IP 不可解析
	}
	for _, c := range cases {
		got, err := NormalizeAddr(c.in)
		if c.ok && err != nil {
			t.Fatalf("NormalizeAddr(%q) 意外报错: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("NormalizeAddr(%q) 应报错，却得到 %q", c.in, got)
		}
		if c.ok && got != c.want {
			t.Fatalf("NormalizeAddr(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestParsePeersSkipsInvalid(t *testing.T) {
	peers, err := ParsePeers([]string{"1.1.1.1:1", "bad", "2.2.2.2:2"}, OriginSeed, 5)
	if err == nil {
		t.Fatal("含非法地址时应返回第一条错误")
	}
	if len(peers) != 2 {
		t.Fatalf("应只保留合法端点 2 个，实际 %d", len(peers))
	}
	for _, p := range peers {
		if p.Origin != OriginSeed || p.LastSeen != 5 {
			t.Fatalf("端点上下文错误: %+v", p)
		}
	}
}
