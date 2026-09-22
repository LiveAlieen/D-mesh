package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"dmesh/internal/core"
)

// ---------- 测试夹具：ed25519 身份 + 双名单 stub ----------

var registerOnce sync.Once

func registerVerifier(t *testing.T) {
	t.Helper()
	registerOnce.Do(func() {
		core.Register(core.SigEd25519, func(pub core.PubKey, msg, sig []byte) bool {
			return len(pub.Bytes) == ed25519.PublicKeySize && ed25519.Verify(pub.Bytes, msg, sig)
		})
	})
}

type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return &testSigner{priv: priv, pub: pub}
}

func (s *testSigner) Alg() core.SigAlg { return core.SigEd25519 }

func (s *testSigner) Pub() core.PubKey {
	return core.PubKey{Alg: core.SigEd25519, Bytes: append([]byte(nil), s.pub...)}
}

func (s *testSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// testRoster 是 core.Roster 的最小内存实现（准入判定 + 成员 WG 查询）。
type testRoster struct {
	mu      sync.RWMutex
	members map[string]core.MemberEntry
	black   map[string]bool
	perms   map[string]map[string]bool
	tiers   map[string]int
}

func newTestRoster() *testRoster {
	return &testRoster{
		members: map[string]core.MemberEntry{},
		black:   map[string]bool{},
		perms:   map[string]map[string]bool{},
		tiers:   map[string]int{},
	}
}

func (r *testRoster) IsBlacklisted(p core.PubKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.black[p.Key()]
}

func (r *testRoster) Member(p core.PubKey) (core.MemberEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.members[p.Key()]
	return e, ok
}

func (r *testRoster) ApplyEvent(m core.Message) error { return nil }

func (r *testRoster) TierOf(p core.PubKey) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t, ok := r.tiers[p.Key()]; ok {
		return t
	}
	if _, ok := r.members[p.Key()]; ok {
		return core.TierMember
	}
	return core.TierNonMember
}

func (r *testRoster) HasPerm(p core.PubKey, perm string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.perms[p.Key()][perm]
}

func (r *testRoster) Presence(p core.PubKey) core.PresenceEntry {
	return core.PresenceEntry{Pub: p}
}

func (r *testRoster) Snapshot() ([]core.MemberEntry, []core.BlacklistEntry, core.PubKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ms []core.MemberEntry
	for _, m := range r.members {
		ms = append(ms, m)
	}
	return ms, nil, core.PubKey{}
}

func (r *testRoster) addMember(p core.PubKey, wg core.WGPub, tier int, perms ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.members[p.Key()] = core.MemberEntry{Pub: p, WG: wg, Role: core.RoleOfTier(tier), Perms: perms}
	r.tiers[p.Key()] = tier
	if len(perms) > 0 {
		if r.perms[p.Key()] == nil {
			r.perms[p.Key()] = map[string]bool{}
		}
		for _, pm := range perms {
			r.perms[p.Key()][pm] = true
		}
	}
}

func (r *testRoster) blacklist(p core.PubKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.black[p.Key()] = true
}

// ---------- 端点搭建 ----------

type testNode struct {
	e      *Endpoint
	signer *testSigner
	roster *testRoster
	group  [32]byte
}

func newTestNode(t *testing.T, group [32]byte) *testNode {
	t.Helper()
	registerVerifier(t)
	var static [32]byte
	if _, err := rand.Read(static[:]); err != nil {
		t.Fatalf("static key: %v", err)
	}
	n := &testNode{signer: newTestSigner(t), roster: newTestRoster(), group: group}
	e, err := Listen(Config{
		Static:           static,
		Identity:         n.signer,
		Roster:           n.roster,
		GroupIDs:         [][32]byte{group},
		HandshakeTimeout: 8 * time.Second,
		PunchCount:       2,
		PunchInterval:    5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n.e = e
	t.Cleanup(func() { _ = e.Close() })
	return n
}

// mesh 双向把对方登记进白名单（wg_pub = 对端 Noise 静态公钥）。
func mesh(a, b *testNode) {
	a.roster.addMember(b.signer.Pub(), b.e.LocalWG(), core.TierMember, core.PermSpeak)
	b.roster.addMember(a.signer.Pub(), a.e.LocalWG(), core.TierMember, core.PermSpeak)
}

func udpAddr(t *testing.T, e *Endpoint) *net.UDPAddr {
	t.Helper()
	a, ok := e.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local addr not UDP: %v", e.LocalAddr())
	}
	return a
}

func testGroupID() [32]byte {
	var g [32]byte
	copy(g[:], []byte("dmesh-test-group-aaaaaaaaaaaaaa"))
	return g
}

// ---------- 握手 + echo 环回测试 ----------

// runEchoPair 建 A→B 隧道（useIK 决定静态密钥是否预知），双向 echo 收发，
// 含一个跨多分片的大帧。返回前校验会话侧信息。
func runEchoPair(t *testing.T, useIK bool) {
	g := testGroupID()
	a := newTestNode(t, g)
	b := newTestNode(t, g)
	mesh(a, b)

	remote := Remote{Identity: b.signer.Pub()}
	if useIK {
		remote.WG = b.e.LocalWG()
	}

	accepted := make(chan *Tunnel, 1)
	go func() {
		tun, err := b.e.Accept(context.Background())
		if err != nil {
			t.Errorf("accept: %v", err)
			close(accepted)
			return
		}
		tun.OnData(func(frame []byte) {
			_ = tun.Send(frame) // echo 原帧回发
		})
		accepted <- tun
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := a.e.Dial(ctx, udpAddr(t, b.e), remote)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tunA, ok := tx.(*Tunnel)
	if !ok {
		t.Fatalf("Dial returned %T, want *Tunnel", tx)
	}
	gotTunA := <-accepted
	if gotTunA == nil {
		t.Fatal("accept failed")
	}

	wantPattern := "XX"
	if useIK {
		wantPattern = "IK"
	}
	if p := tunA.Info().Pattern; p != wantPattern {
		t.Errorf("initiator pattern = %q, want %q", p, wantPattern)
	}
	if p := gotTunA.Info().Pattern; p != wantPattern {
		t.Errorf("responder pattern = %q, want %q", p, wantPattern)
	}
	if !tunA.Info().Identity.Equal(b.signer.Pub()) {
		t.Errorf("bound identity mismatch: %v", tunA.Info().Identity)
	}
	if !gotTunA.Info().Identity.Equal(a.signer.Pub()) {
		t.Errorf("bound identity mismatch (responder): %v", gotTunA.Info().Identity)
	}
	if tunA.Info().Blacklisted || gotTunA.Info().Blacklisted {
		t.Error("unexpected blacklisted flag")
	}

	// 双向 echo：小帧 + 大帧（跨分片）。
	echo := make(chan []byte, 8)
	tunA.OnData(func(frame []byte) { echo <- append([]byte(nil), frame...) })

	for _, msg := range [][]byte{
		[]byte("ping"),
		bytes.Repeat([]byte("0123456789abcdef"), 200), // 3200B > 单片 1400B，走分片重组
	} {
		if err := tunA.Send(msg); err != nil {
			t.Fatalf("send: %v", err)
		}
		select {
		case got := <-echo:
			if !bytes.Equal(got, msg) {
				t.Fatalf("echo mismatch: got %d bytes, want %d bytes", len(got), len(msg))
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("echo timeout (%d bytes)", len(msg))
		}
	}

	// 关闭后不可再发。
	tunA.Close()
	if err := tunA.Send([]byte("after close")); !errors.Is(err, ErrClosed) {
		t.Errorf("send after close: err = %v, want ErrClosed", err)
	}
}

func TestDialAcceptIKLoopback(t *testing.T) { runEchoPair(t, true) }
func TestDialAcceptXXLoopback(t *testing.T) { runEchoPair(t, false) }

// ---------- 准入与拒连负例 ----------

// 黑名单成员：非解禁权限者出站即拒（Dial 前置准入判定）。
func TestBlacklistedRejected(t *testing.T) {
	g := testGroupID()
	a := newTestNode(t, g) // 被拉黑者
	b := newTestNode(t, g) // 普通成员，把 a 拉黑
	mesh(a, b)
	b.roster.blacklist(a.signer.Pub())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := b.e.Dial(ctx, udpAddr(t, a.e), Remote{Identity: a.signer.Pub(), WG: a.e.LocalWG()})
	if !errors.Is(err, ErrBlacklisted) {
		t.Fatalf("dial blacklisted: err = %v, want ErrBlacklisted", err)
	}
}

// 解禁权限者接受黑名单成员的定向申诉握手（唯一例外通道）。
func TestAuthorityAcceptsBlacklistedAppeal(t *testing.T) {
	g := testGroupID()
	a := newTestNode(t, g) // 被拉黑者，发起定向申诉
	b := newTestNode(t, g) // 具 unban 权限者
	mesh(a, b)
	b.roster.blacklist(a.signer.Pub())
	b.roster.addMember(b.signer.Pub(), b.e.LocalWG(), core.TierMember, core.PermUnban)

	accepted := make(chan *Tunnel, 1)
	go func() {
		tun, err := b.e.Accept(context.Background())
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- tun
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunA, err := a.e.Dial(ctx, udpAddr(t, b.e), Remote{Identity: b.signer.Pub(), WG: b.e.LocalWG()})
	if err != nil {
		t.Fatalf("appeal dial: %v", err)
	}
	tunB := <-accepted
	if !tunB.Info().Blacklisted {
		t.Error("responder tunnel should carry Blacklisted=true")
	}
	echo := make(chan []byte, 1)
	tunB.OnData(func(f []byte) { _ = tunB.Send(f) })
	tunA.OnData(func(f []byte) { echo <- f })
	if err := tunA.Send([]byte("appeal")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-echo:
		if string(got) != "appeal" {
			t.Fatalf("echo = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("appeal echo timeout")
	}
}

// 错群锚：拒连（ErrBinding 通道）。
func TestWrongGroupRejected(t *testing.T) {
	g1, g2 := testGroupID(), [32]byte{}
	copy(g2[:], []byte("dmesh-test-group-bbbbbbbbbbbbbbb"))
	a := newTestNode(t, g1)
	b := newTestNode(t, g2)

	go func() {
		tun, err := b.e.Accept(context.Background())
		if err == nil {
			t.Errorf("accept should fail for wrong group; got tunnel %v", tun)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := a.e.Dial(ctx, udpAddr(t, b.e), Remote{Identity: b.signer.Pub()})
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("dial wrong group: err = %v, want ErrBinding", err)
	}
}

// ---------- 纯逻辑单测 ----------

func TestFrameRoundtripAndReplay(t *testing.T) {
	// 分片重组表驱动：单片 / 乱序多片（非终片必须满尺寸，终片可短）。
	r := NewReassembler()
	if f, ok, err := r.Add(1, 0, 1, []byte("solo")); err != nil || !ok || string(f) != "solo" {
		t.Fatalf("single frag: %q %v %v", f, ok, err)
	}
	head := bytes.Repeat([]byte("x"), maxFragBody)
	mid := bytes.Repeat([]byte("y"), maxFragBody)
	// 同帧分片占连续 nonce：idx i ↔ base+i。先到的是中间片（孤儿）。
	if _, ok, err := r.Add(5, 1, 3, mid); err != nil || ok {
		t.Fatalf("orphan out-of-order first part: %v %v", ok, err)
	}
	if _, ok, _ := r.Add(6, 2, 3, []byte("tail")); ok {
		t.Fatal("should be incomplete")
	}
	f, ok, err := r.Add(4, 0, 3, head)
	if err != nil || !ok || !bytes.Equal(f, append(append(append([]byte{}, head...), mid...), []byte("tail")...)) {
		t.Fatalf("reassembly: ok=%v err=%v len=%d", ok, err, len(f))
	}
	if _, _, err := r.Add(10, 0, 2, []byte("short-nonfinal")); err == nil {
		t.Fatal("non-final short fragment must error")
	}
	rw := &replay{}
	seq := []struct {
		n    uint64
		want bool
	}{
		{1, true}, {1, false}, // 重复拒绝
		{0, true}, {0, false}, // 窗口内乱序接受一次
		{3, true}, {3, false}, {2, true}, {2, false},
		{66, true}, {3, false}, // 窗口外过旧拒绝
	}
	for i, c := range seq {
		if got := rw.accept(c.n); got != c.want {
			t.Fatalf("replay.accept(%d) step %d = %v, want %v", c.n, i, got, c.want)
		}
	}
}

func TestConnectPunchAndDial(t *testing.T) {
	// Connect = 打洞突发 + Dial：确认打洞包不干扰握手。
	g := testGroupID()
	a := newTestNode(t, g)
	b := newTestNode(t, g)
	mesh(a, b)

	accepted := make(chan *Tunnel, 1)
	go func() {
		tun, err := b.e.Accept(context.Background())
		if err == nil {
			accepted <- tun
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunA, err := a.e.Connect(ctx, udpAddr(t, b.e), Remote{Identity: b.signer.Pub(), WG: b.e.LocalWG()})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tunB := <-accepted
	echo := make(chan []byte, 1)
	tunB.OnData(func(f []byte) { _ = tunB.Send(f) })
	tunA.OnData(func(f []byte) { echo <- f })
	if err := tunA.Send([]byte("pinged")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-echo:
		if string(got) != "pinged" {
			t.Fatalf("echo = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("echo timeout")
	}
}
