package neighbor

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"dmesh/internal/core"
)

func TestNormalizeDefaultsAndBounds(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		want  func(Config) bool
		isErr bool
	}{
		{"all-zero gets 3~8 & 25s", Config{}, func(c Config) bool {
			return c.MinNeighbors == 3 && c.MaxNeighbors == 8 && c.Keepalive == 25*time.Second &&
				c.MaxFail == 3 && c.Tick > 0 && c.Now != nil
		}, false},
		{"min>max clamps to max", Config{MinNeighbors: 10, MaxNeighbors: 4}, func(c Config) bool {
			return c.MinNeighbors == 4 && c.MaxNeighbors == 4
		}, false},
		{"negative bounds rejected", Config{MinNeighbors: -1}, nil, true},
		{"max zero means default", Config{MaxNeighbors: 0}, func(c Config) bool {
			return c.MaxNeighbors == DefaultMaxNeighbors
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.normalize()
			if tc.isErr {
				if !errors.Is(err, ErrBadConfig) {
					t.Fatalf("want ErrBadConfig, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !tc.want(got) {
				t.Fatalf("unexpected config %+v", got)
			}
		})
	}
}

func TestAddrIsIPv6(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"[2001:db8::1]:9999", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"1.2.3.4:9999", false},
		{"1.2.3.4", false},
		{"", false},
		{"not-an-address", false},
	}
	for _, tc := range cases {
		if got := addrIsIPv6(tc.addr); got != tc.want {
			t.Errorf("addrIsIPv6(%q)=%v want %v", tc.addr, got, tc.want)
		}
	}
}

// 上限 + 打分顶替：满员时 IPv6 新邻居顶掉最差的 IPv4 邻居；
// 不如现有最差者则被拒绝并关闭。
func TestCapacityAndReplacement(t *testing.T) {
	clk := testClockAt(time.Unix(1700000, 0))
	var left []core.PubKey
	nt := mustTable(t, Config{
		MinNeighbors: 1, MaxNeighbors: 2,
		Keepalive: time.Hour, // 本测试不触发 keepalive
		Now:       clk.Now,
		OnLeave:   func(p core.PubKey, _ Reason) { left = append(left, p) },
	})

	a := newFake('A', false)
	b := newFake('B', false)
	c := newFake('C', false) // IPv6，未知 RTT → 分数优于 IPv4 未知 RTT
	d := newFake('D', false) // IPv4 → 不比任何人差但也非严格更优 → 拒绝

	if err := nt.Add(a, "10.0.0.1:5000"); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Millisecond) // 制造加入先后
	if err := nt.Add(b, "10.0.0.2:5000"); err != nil {
		t.Fatal(err)
	}
	if nt.Count() != 2 {
		t.Fatalf("count=%d want 2", nt.Count())
	}
	// B 后加入、同分（700 vs 700）→ B 是被顶替对象
	if err := nt.Add(c, "[2001:db8::3]:5000"); err != nil {
		t.Fatalf("IPv6 newcomer should replace: %v", err)
	}
	if !b.isClosed() {
		t.Fatal("replaced tunnel must be closed")
	}
	if nt.Count() != 2 {
		t.Fatalf("count=%d want 2 (cap holds)", nt.Count())
	}
	if len(left) != 1 || !left[0].Equal(b.pub) {
		t.Fatalf("OnLeave want replaced B, got %+v", left)
	}
	// 满员且 D 无优势 → ErrNoCapacity，D 被关闭，现有邻居不动
	if err := nt.Add(d, "10.0.0.4:5000"); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("want ErrNoCapacity, got %v", err)
	}
	if !d.isClosed() {
		t.Fatal("rejected tunnel must be closed")
	}
	if nt.Count() != 2 {
		t.Fatalf("count=%d want 2", nt.Count())
	}

	// 满员后新人无优势（同为未知 RTT 的 IPv4，700 vs 700 平手）→ 拒绝
	e := newFake('E', false)
	if err := nt.Add(e, "10.0.0.5:5000"); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("tie should reject newcomer, got %v", err)
	}
}

func TestAddDuplicateAndSelf(t *testing.T) {
	nt := mustTable(t, Config{MaxNeighbors: 4})
	local := core.PubKey{Alg: core.SigEd25519, Bytes: []byte("me")}
	nt.cfg.LocalPub = local

	self := &fakeTunnel{pub: local}
	if err := nt.Add(self, "1.1.1.1:1"); !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("want ErrSelfConnect got %v", err)
	}
	if !self.isClosed() {
		t.Fatal("self tunnel must be closed")
	}

	a := newFake('A', false)
	a2 := newFake('A', false)
	if err := nt.Add(a, ""); err != nil {
		t.Fatal(err)
	}
	if err := nt.Add(a2, ""); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists got %v", err)
	}
	if !a2.isClosed() || a.isClosed() {
		t.Fatal("dup newcomer closed, incumbent kept")
	}
	if nt.Count() != 1 {
		t.Fatalf("count=%d want 1", nt.Count())
	}
}

// keepalive：到达周期发 ping（自动 ack 回环测得 RTT），控制帧不上抛给
// 消息层；普通帧上抛。无应答达 MaxFail 判死并 OnLeave。
func TestKeepaliveRTTAndControlIsolation(t *testing.T) {
	clk := testClockAt(time.Unix(1700000, 0))
	var received [][]byte
	nt := mustTable(t, Config{
		MinNeighbors: 1, MaxNeighbors: 4,
		Keepalive: 25 * time.Second,
		Now:       clk.Now,
		Receive:   func(_ core.PubKey, data []byte) { received = append(received, data) },
	})
	f := newFake('A', true)
	if err := nt.Add(f, "1.2.3.4:5"); err != nil {
		t.Fatal(err)
	}

	nt.cycle() // 新邻居无 RTT → 立即探测
	if f.sentCount() != 1 {
		t.Fatalf("want 1 ping, got %d", f.sentCount())
	}
	st := nt.Snapshot()
	if len(st) != 1 || !st[0].RTTKnown {
		t.Fatalf("RTT should be learned: %+v", st)
	}
	if len(received) != 0 {
		t.Fatalf("control frames must not reach Receive, got %d", len(received))
	}

	// 未到 keepalive 周期 → 不再 ping
	clk.Advance(24 * time.Second)
	nt.cycle()
	if f.sentCount() != 1 {
		t.Fatalf("ping fired early: %d", f.sentCount())
	}
	// 到周期 → 再 ping；对端主动 ping 也不上抛且会被自动回 ack
	clk.Advance(2 * time.Second)
	nt.cycle()
	if f.sentCount() != 2 {
		t.Fatalf("want 2 pings, got %d", f.sentCount())
	}
	f.inject(encodeControl(ctlSubPing, clk.Now().UnixNano(), "deadbeef"))
	if f.sentCount() != 3 {
		t.Fatalf("want auto-ack sent, got %d", f.sentCount())
	}
	last, _ := f.lastSent()
	if fr, ok := parseControl(last); !ok || fr.Sub != ctlSubAck || fr.Nonce != "deadbeef" {
		t.Fatalf("bad auto ack frame %q", last)
	}
	if len(received) != 0 {
		t.Fatal("remote ping must not be forwarded to Receive")
	}
	// 普通数据帧 → 原样上抛
	f.inject([]byte(`{"msg_id":"m1"}`))
	if len(received) != 1 || string(received[0]) != `{"msg_id":"m1"}` {
		t.Fatalf("data frame not forwarded: %q", received)
	}
}

func TestUnhealthyPeerDropped(t *testing.T) {
	clk := testClockAt(time.Unix(1700000, 0))
	var reasons []Reason
	nt := mustTable(t, Config{
		MinNeighbors: 1, MaxNeighbors: 4,
		Keepalive: 25 * time.Second, Tick: time.Second, MaxFail: 3,
		Now:     clk.Now,
		OnLeave: func(_ core.PubKey, r Reason) { reasons = append(reasons, r) },
	})
	f := newFake('A', false) // 永不回 ack
	if err := nt.Add(f, "1.2.3.4:5"); err != nil {
		t.Fatal(err)
	}
	nt.cycle() // ping #1 入 pending
	for i := 0; i < 3; i++ {
		clk.Advance(30 * time.Second) // > Keepalive+Tick → pending 超时 miss++
		nt.cycle()
	}
	if nt.Count() != 0 {
		t.Fatalf("unresponsive peer should be dead, count=%d", nt.Count())
	}
	if !f.isClosed() {
		t.Fatal("dead peer tunnel must be closed")
	}
	if len(reasons) != 1 || reasons[0] != ReasonUnhealthy {
		t.Fatalf("reasons=%v", reasons)
	}
	// 低于下限不主动踢健康邻居：这里 count 已 0，补一条候选（无 Dial 则不动作）
	nt.cycle()
}

func TestSendFailureCountsMiss(t *testing.T) {
	clk := testClockAt(time.Unix(1700000, 0))
	nt := mustTable(t, Config{MaxNeighbors: 2, Keepalive: time.Hour, Now: clk.Now})
	f := newFake('A', false)
	if err := nt.Add(f, ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.sendFail = errors.New("boom")
	f.mu.Unlock()
	nt.cfg.MaxFail = 1
	if sent, failed := nt.Broadcast([]byte("x")); sent != 0 || failed != 1 {
		t.Fatalf("sent=%d failed=%d", sent, failed)
	}
	st := nt.Snapshot()
	if len(st) != 1 || st[0].SendErrs != 1 || st[0].Misses != 1 {
		t.Fatalf("send failure not accounted: %+v", st)
	}
	nt.cycle() // miss>=MaxFail → 判死
	if nt.Count() != 0 {
		t.Fatalf("peer should be dropped, count=%d", nt.Count())
	}
}

func TestFloodAndSendTo(t *testing.T) {
	nt := mustTable(t, Config{MaxNeighbors: 4})
	a, b, c := newFake('A', false), newFake('B', false), newFake('C', false)
	for _, f := range []*fakeTunnel{a, b, c} {
		if err := nt.Add(f, ""); err != nil {
			t.Fatal(err)
		}
	}
	if sent, failed := nt.Broadcast([]byte("m")); sent != 3 || failed != 0 {
		t.Fatalf("broadcast sent=%d failed=%d", sent, failed)
	}
	// 来源抑制：来自 A 的帧不再回给 A
	if sent, _ := nt.Flood(a.pub, []byte("m2")); sent != 2 {
		t.Fatalf("flood sent=%d want 2", sent)
	}
	if a.sentCount() != 1 || b.sentCount() != 2 || c.sentCount() != 2 {
		t.Fatalf("flood leaked to source: %d/%d/%d", a.sentCount(), b.sentCount(), c.sentCount())
	}
	if _, failed := nt.BroadcastExcept([]core.PubKey{a.pub, b.pub}, []byte("m3")); failed != 0 {
		t.Fatalf("failed=%d", failed)
	}
	if c.sentCount() != 3 {
		t.Fatalf("C should have 3 frames, got %d", c.sentCount())
	}
	if err := nt.SendTo(b.pub, []byte("direct")); err != nil {
		t.Fatal(err)
	}
	if err := nt.SendTo(newFake('Z', false).pub, []byte("x")); !errors.Is(err, ErrNotNeighbor) {
		t.Fatalf("want ErrNotNeighbor got %v", err)
	}
	if got := len(nt.PublicNeighbors()); got != 3 {
		t.Fatalf("PublicNeighbors=%d want 3", got)
	}
}

// remove → 断 sender；kick（多种 body 载荷编码）→ 断目标；unban/text → 不动。

// evMsg 造一条 v26 事件消息：kind 由名字查注册表，payload 装进 body 的标签位；
// payload 本身不是合法 JSON 时按字符串装（宽松解析用例正是走这条路）。
func evMsg(name string, sender core.PubKey, payload string, to *core.PubKey) core.Message {
	kind, ok := core.KindOf(name)
	if !ok {
		panic("unknown body name " + name)
	}
	b, err := core.MakeBody(name, json.RawMessage(payload))
	if err != nil {
		if b, err = core.MakeBody(name, payload); err != nil {
			panic(err)
		}
	}
	return core.Message{Kind: kind, Sender: sender, Body: b, To: to}
}

func TestEventDisconnect(t *testing.T) {
	targetB := core.PubKey{Alg: core.SigEd25519, Bytes: []byte("BB")}
	cases := []struct {
		name             string
		msg              core.Message
		wantSenderClosed bool
		wantTargetClosed bool
	}{
		{"remove disconnects sender",
			evMsg(core.NameRemove, pubA(), "null", nil), true, false},
		{"kick pub-field json",
			evMsg(core.NameKick, pubA(), string(mustPubJSON(targetB)), nil), false, true},
		{"kick target field json",
			evMsg(core.NameKick, pubA(), string(mustTargetJSON(targetB)), nil), false, true},
		{"kick plain alg:hex payload",
			evMsg(core.NameKick, pubA(), `"`+targetB.String()+`"`, nil), false, true},
		{"kick via To fallback",
			evMsg(core.NameKick, pubA(), "null", &targetB), false, true},
		{"unban no-op",
			evMsg(core.NameUnban, pubA(), "null", nil), false, false},
		{"text no-op",
			evMsg(core.NameText, pubA(), `"hi"`, nil), false, false},
		{"kick unparseable keeps everyone",
			evMsg(core.NameKick, pubA(), "garbage", nil), false, false},
		{"kind 谎报（cmd 标成 msg）不断任何人",
			kindLie(evMsg(core.NameKick, pubA(), string(mustPubJSON(targetB)), nil)), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nt := mustTable(t, Config{MaxNeighbors: 4})
			a := newFake('A', false) // pub == {ed25519,[65 65]} == pubA()
			b := &fakeTunnel{pub: targetB}
			if err := nt.Add(a, ""); err != nil {
				t.Fatal(err)
			}
			if err := nt.Add(b, ""); err != nil {
				t.Fatal(err)
			}
			nt.HandleRosterEvent(tc.msg)
			if a.isClosed() != tc.wantSenderClosed {
				t.Fatalf("sender closed=%v want %v", a.isClosed(), tc.wantSenderClosed)
			}
			if b.isClosed() != tc.wantTargetClosed {
				t.Fatalf("target closed=%v want %v", b.isClosed(), tc.wantTargetClosed)
			}
		})
	}
}

func pubA() core.PubKey { return core.PubKey{Alg: core.SigEd25519, Bytes: []byte{65, 65}} }

// kindLie 把大类改成 msg（body 仍写着 kick）：HandleRosterEvent 只认 body 标签，
// 消息层的 kind 互校由 engine/roster 负责，这里钉住「按 body 判别」这一条。
func kindLie(m core.Message) core.Message {
	m.Kind = core.KindMessage
	return m
}

func mustPubJSON(p core.PubKey) []byte {
	b, _ := json.Marshal(map[string]any{"pub": p})
	return b
}

func mustTargetJSON(p core.PubKey) []byte {
	b, _ := json.Marshal(map[string]any{"target_pub": p, "ts": 1})
	return b
}

// 候选池 + 自动拨号：IPv6 候选优先；达到 Max 封顶；Dial 失败退避。
func TestCandidateDial(t *testing.T) {
	clk := testClockAt(time.Unix(1700000, 0))
	var dialed []string
	nt := mustTable(t, Config{
		MinNeighbors: 1, MaxNeighbors: 2,
		Keepalive: time.Hour, DialInterval: time.Second, Now: clk.Now,
		Dial: func(c Candidate) (core.Tunnel, error) {
			dialed = append(dialed, c.Addr)
			return newFake(byte(len(dialed)+60), true), nil
		},
	})
	nt.AddCandidate(pubA(), core.WGPub{1}, "10.0.0.1:5")      // IPv4
	nt.AddCandidate(pubB(), core.WGPub{2}, "[2001:db8::2]:5") // IPv6 → 应先拨
	nt.AddCandidate(pubC(), core.WGPub{3}, "")                // 无地址按 IPv4 计

	nt.cycle() // 拨最优：IPv6 的 B
	nt.cycle() // 间隔内 → 不拨（DialInterval 未到）
	if len(dialed) != 1 {
		t.Fatalf("dial should honor interval, dialed=%v", dialed)
	}
	clk.Advance(2 * time.Second)
	nt.cycle() // 拨 A 或 C（同分按加入先后 → A 先登记）
	if len(dialed) != 2 {
		t.Fatalf("dialed=%v", dialed)
	}
	if nt.Count() != 2 {
		t.Fatalf("count=%d want 2 (cap)", nt.Count())
	}
	// 满员 → 第 3 个候选不拨
	clk.Advance(2 * time.Second)
	nt.cycle()
	if len(dialed) != 2 {
		t.Fatalf("must not dial beyond MaxNeighbors, dialed=%v", dialed)
	}
	// 活跃邻居的 pubkey 再登记候选应被忽略
	nt.AddCandidate(pubB(), core.WGPub{9}, "10.9.9.9:1")
	if nt.Count() != 2 {
		t.Fatalf("active pubkey should not churn table: %d", nt.Count())
	}
}

func pubB() core.PubKey { return core.PubKey{Alg: core.SigEd25519, Bytes: []byte{66, 66}} }
func pubC() core.PubKey { return core.PubKey{Alg: core.SigEd25519, Bytes: []byte{67, 67}} }

// 注入 Roster 后，巡检按黑名单兜底断连（拉黑即时断连的第二条路径）。
func TestBlacklistSweep(t *testing.T) {
	r := newFakeRoster()
	var reasons []Reason
	nt := mustTable(t, Config{MaxNeighbors: 4, Keepalive: time.Hour, Roster: r,
		OnLeave: func(_ core.PubKey, reason Reason) { reasons = append(reasons, reason) }})
	a, b := newFake('A', false), newFake('B', false)
	if err := nt.Add(a, ""); err != nil {
		t.Fatal(err)
	}
	if err := nt.Add(b, ""); err != nil {
		t.Fatal(err)
	}
	r.ban(b.pub)
	nt.cycle()
	if nt.Count() != 1 || !b.isClosed() || a.isClosed() {
		t.Fatalf("blacklisted peer should be swept: count=%d", nt.Count())
	}
	if len(reasons) != 1 || reasons[0] != ReasonBlacklisted {
		t.Fatalf("reasons=%v", reasons)
	}
}

// Close 断全部邻居。
func TestCloseDropsAll(t *testing.T) {
	nt := mustTable(t, Config{MaxNeighbors: 4})
	f := newFake('A', false)
	if err := nt.Add(f, ""); err != nil {
		t.Fatal(err)
	}
	if err := nt.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.isClosed() || nt.Count() != 0 {
		t.Fatal("Close must drop all neighbors")
	}
	if err := nt.Add(newFake('B', false), ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed got %v", err)
	}
}

// base64 编解码由 core.PubKey 的默认 JSON 形态隐式使用（mustPubJSON）。
