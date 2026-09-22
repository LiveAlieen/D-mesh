package discovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/anacrolix/torrent"
)

// mockSrc 是离线 Source（可选实现 Feeder），用于驱动 Manager 的去重/合并/退化逻辑。
type mockSrc struct {
	name      string
	mu        sync.Mutex
	peers     []Peer
	feedCalls int
	feedTotal int
	closed    bool
	fetchErr  error
}

func (m *mockSrc) Name() string { return m.name }

func (m *mockSrc) Fetch(context.Context) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrSourceClosed
	}
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	return append([]Peer(nil), m.peers...), nil
}

func (m *mockSrc) Feed(ps []Peer) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedCalls++
	m.feedTotal += len(ps)
	return len(ps)
}

func (m *mockSrc) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockSrc) feeds() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.feedCalls, m.feedTotal
}

// TestManagerDegradesToDHTOnlyWhenNoPEX 验证：窗口内 PEX 零产出 → 挂纯 DHT 退化源并合并其结果。
func TestManagerDegradesToDHTOnlyWhenNoPEX(t *testing.T) {
	full := &mockSrc{name: "full", peers: []Peer{{Addr: "10.0.0.1:1", Origin: OriginDHT, LastSeen: 100}}}
	dhtOnly := &mockSrc{name: "dhtonly", peers: []Peer{{Addr: "10.0.0.2:2", Origin: OriginDHT, LastSeen: 100}}}
	factory := func(_ Seed, mode Mode) (Source, error) {
		if mode == ModeDHTOnly {
			return dhtOnly, nil
		}
		return full, nil
	}
	cur := int64(1000)
	m, err := New(Config{
		Factory:      factory,
		DegradeAfter: time.Second,
		PollInterval: time.Second,
		Clock:        func() int64 { return cur },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	h := testHash(0x09)
	if err := m.Track(Seed{InfoHash: h}); err != nil {
		t.Fatal(err)
	}
	cur = 3000 // 越过退化窗口
	if err := m.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 报错: %v", err)
	}
	st, ok := m.Status(h)
	if !ok {
		t.Fatal("Status 应命中")
	}
	if !st.Degraded {
		t.Fatal("PEX 零产出且过窗口后应退化")
	}
	if len(st.Sources) != 2 {
		t.Fatalf("退化后应有两个活动源，实际 %+v", st.Sources)
	}
	if got := len(m.Peers(h)); got != 2 {
		t.Fatalf("合并全量+退化源后应有 2 端点，实际 %d", got)
	}
	if !peersContain(m, h, "10.0.0.2:2") {
		t.Fatal("退化源发现的端点应被合并进来")
	}
	// 回灌滚雪球：源应收到 Feed。
	if calls, _ := full.feeds(); calls == 0 {
		t.Fatal("发现新端点后应回灌（滚雪球）")
	}
}

// peersContain 是测试辅助：报告某地址是否在种子当前端点里。
func peersContain(m *Manager, h [InfoHashLen]byte, addr string) bool {
	for _, p := range m.Peers(h) {
		if p.Addr == addr {
			return true
		}
	}
	return false
}

// TestManagerNoDegradeWhenPEXAlive 验证 PEX 有产出即永不挂退化源。
func TestManagerNoDegradeWhenPEXAlive(t *testing.T) {
	full := &mockSrc{name: "full", peers: []Peer{{Addr: "10.1.0.1:1", Origin: OriginPEX, LastSeen: 100}}}
	degradeCalled := false
	factory := func(_ Seed, mode Mode) (Source, error) {
		if mode == ModeDHTOnly {
			degradeCalled = true
			return nil, errors.New("不应触发退化")
		}
		return full, nil
	}
	cur := int64(1000)
	m, err := New(Config{Factory: factory, DegradeAfter: time.Second, Clock: func() int64 { return cur }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	h := testHash(0x0a)
	if err := m.Track(Seed{InfoHash: h}); err != nil {
		t.Fatal(err)
	}
	cur = 99999
	if err := m.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 报错: %v", err)
	}
	if degradeCalled {
		t.Fatal("PEX 有产出时不得调用退化工厂")
	}
	if st, _ := m.Status(h); st.Degraded {
		t.Fatal("PEX 有产出时不得标记退化")
	}
}

// TestManagerManualPeersWinOverFetched 验证手工注入（OriginManual，权重最高）
// 不被后续 DHT 拉取结果降级，且来源/新鲜度合并正确。
func TestManagerManualPeersWinOverFetched(t *testing.T) {
	src := &mockSrc{name: "s", peers: []Peer{{Addr: "7.7.7.7:1", Origin: OriginDHT, LastSeen: 100}}}
	factory := func(Seed, Mode) (Source, error) { return src, nil }
	cur := int64(1001)
	m, err := New(Config{Factory: factory, DegradeAfter: time.Hour, Clock: func() int64 { return cur }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	h := testHash(0x0b)
	if err := m.Track(Seed{InfoHash: h}); err != nil {
		t.Fatal(err)
	}
	if err := m.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 注入 manual。
	if n, err := m.AddPeers(h, []string{"7.7.7.7:1"}); err != nil || n < 0 {
		t.Fatalf("AddPeers 异常: n=%d err=%v", n, err)
	}
	if p, ok := findPeer(m.Peers(h), "7.7.7.7:1"); !ok || p.Origin != OriginManual {
		t.Fatalf("手工注入应为最高权重来源，实际 %+v ok=%v", p, ok)
	}
	// 再拉一轮，DHT 结果不得把 manual 降级。
	if err := m.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p, _ := findPeer(m.Peers(h), "7.7.7.7:1"); p.Origin != OriginManual {
		t.Fatalf("后续拉取不得降级手工来源，实际 %s", p.Origin)
	}
	// 未知种子应报错。
	if _, err := m.AddPeers(testHash(0xee), []string{"8.8.8.8:8"}); err == nil {
		t.Fatal("对未跟踪种子 AddPeers 应报错")
	}
}

func findPeer(ps []Peer, addr string) (Peer, bool) {
	for _, p := range ps {
		if p.Addr == addr {
			return p, true
		}
	}
	return Peer{}, false
}

// TestMultiSourceMergesDedups 验证多源合并去重并保留高权重来源、按好序输出。
func TestMultiSourceMergesDedups(t *testing.T) {
	a := NewFuncSource("a", func(context.Context) ([]Peer, error) {
		return []Peer{
			{Addr: "1.1.1.1:1", Origin: OriginDHT, LastSeen: 100},
			{Addr: "2.2.2.2:2", Origin: OriginPEX, LastSeen: 100},
		}, nil
	})
	b := NewFuncSource("b", func(context.Context) ([]Peer, error) {
		return []Peer{{Addr: "1.1.1.1:1", Origin: OriginManual, LastSeen: 100}}, nil
	})
	ms := NewMultiSource("ms", a, b)
	got, err := ms.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("去重后应为 2，实际 %+v", got)
	}
	if got[0].Addr != "1.1.1.1:1" || got[0].Origin != OriginManual {
		t.Fatalf("首位应为升级后的 manual，实际 %+v", got[0])
	}
	if got[1].Addr != "2.2.2.2:2" {
		t.Fatalf("次位应为 PEX 端点，实际 %+v", got[1])
	}
}

// TestDecideDegradePure 覆盖退化判定的纯函数边界。
func TestDecideDegradePure(t *testing.T) {
	if !decideDegrade(2000, 1000, 0, time.Second) {
		t.Fatal("无 PEX 且过窗口应退化")
	}
	if decideDegrade(2000, 1000, 1, time.Second) {
		t.Fatal("有 PEX 端点不得退化")
	}
	if decideDegrade(1500, 1000, 0, time.Second) {
		t.Fatal("未过窗口不得退化")
	}
	if decideDegrade(99999, 1000, 0, 0) {
		t.Fatal("after<=0 表示禁用退化")
	}
}

// TestPeerInfoMapping 覆盖 anacrolix PeerInfo 与本包端点的双向映射（环回地址，不碰网络）。
func TestPeerInfoMapping(t *testing.T) {
	pi := torrent.PeerInfo{Addr: torrent.StringAddr("127.0.0.1:6881"), Source: torrent.PeerSourcePex}
	p, ok := peerInfoToPeer(pi, 7)
	if !ok {
		t.Fatal("合法 PeerInfo 应映射成功")
	}
	if p.Addr != "127.0.0.1:6881" || p.Origin != OriginPEX || p.LastSeen != 7 {
		t.Fatalf("映射结果异常: %+v", p)
	}
	if _, ok := peerInfoToPeer(torrent.PeerInfo{}, 0); ok {
		t.Fatal("nil 地址应映射失败")
	}
	back, ok := peerInfoFromPeer(Peer{Addr: "127.0.0.1:6881", Origin: OriginDHT})
	if !ok || back.Addr.String() != "127.0.0.1:6881" || back.Source != torrent.PeerSourceDirect {
		t.Fatalf("反向映射异常: %+v ok=%v", back, ok)
	}
	if mapPeerSource(torrent.PeerSourceDhtGetPeers) != OriginDHT {
		t.Fatal("DHT 来源映射错误")
	}
	if mapPeerSource(torrent.PeerSourceTracker) != OriginTracker {
		t.Fatal("tracker 来源映射错误")
	}
	if mapPeerSource(torrent.PeerSource("weird")) != OriginUnknown {
		t.Fatal("未知来源应归 OriginUnknown")
	}
}
