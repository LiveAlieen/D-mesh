package neighbor

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"dmesh/internal/core"
)

// fakeTunnel 是 core.Tunnel 的内存实现：记录发出的帧，可自动回 keepalive
// ack（autoAck=true 时在 Send 内同步回调 OnData，专门用来验证生产代码
// 「锁外 Send」的约定——若有持锁回调会立刻死锁暴露）。
type fakeTunnel struct {
	pub     core.PubKey
	autoAck bool

	mu       sync.Mutex
	sent     [][]byte
	onData   func([]byte)
	closed   bool
	sendFail error
}

func newFake(pub byte, autoAck bool) *fakeTunnel {
	return &fakeTunnel{
		pub:     core.PubKey{Alg: core.SigEd25519, Bytes: []byte{pub, pub}},
		autoAck: autoAck,
	}
}

func (f *fakeTunnel) Send(b []byte) error {
	f.mu.Lock()
	if f.sendFail != nil {
		err := f.sendFail
		f.mu.Unlock()
		return err
	}
	f.sent = append(f.sent, append([]byte(nil), b...))
	var ack []byte
	if f.autoAck {
		if fr, ok := parseControl(b); ok && fr.Sub == ctlSubPing {
			ack = encodeControl(ctlSubAck, fr.TSns, fr.Nonce)
		}
	}
	h := f.onData
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return fmt.Errorf("fakeTunnel: send after close")
	}
	if ack != nil && h != nil {
		h(ack) // 同步回调：模拟对端秒回（RTT=0）
	}
	return nil
}

func (f *fakeTunnel) OnData(fn func([]byte)) {
	f.mu.Lock()
	f.onData = fn
	f.mu.Unlock()
}

func (f *fakeTunnel) RemotePub() core.PubKey { return f.pub }

func (f *fakeTunnel) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeTunnel) inject(data []byte) {
	f.mu.Lock()
	h := f.onData
	f.mu.Unlock()
	if h != nil {
		h(data)
	}
}

func (f *fakeTunnel) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeTunnel) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeTunnel) lastSent() ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil, false
	}
	return f.sent[len(f.sent)-1], true
}

// fakeRoster 只实现本包用到的方法（准入清扫），其余为契约完整性的零值桩。
type fakeRoster struct {
	mu          sync.Mutex
	blacklisted map[string]bool
	tiers       map[string]int
}

func newFakeRoster() *fakeRoster {
	return &fakeRoster{blacklisted: map[string]bool{}, tiers: map[string]int{}}
}

func (r *fakeRoster) ban(p core.PubKey) {
	r.mu.Lock()
	r.blacklisted[p.Key()] = true
	r.mu.Unlock()
}

func (r *fakeRoster) IsBlacklisted(p core.PubKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blacklisted[p.Key()]
}

func (r *fakeRoster) Member(core.PubKey) (core.MemberEntry, bool) {
	return core.MemberEntry{}, false
}

func (r *fakeRoster) ApplyEvent(core.Message) error { return nil }

func (r *fakeRoster) TierOf(p core.PubKey) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tiers[p.Key()]; ok {
		return t
	}
	return core.TierNonMember
}

func (r *fakeRoster) HasPerm(core.PubKey, string) bool { return false }

func (r *fakeRoster) Presence(core.PubKey) core.PresenceEntry {
	return core.PresenceEntry{}
}

func (r *fakeRoster) Snapshot() ([]core.MemberEntry, []core.BlacklistEntry, core.PubKey) {
	return nil, nil, core.PubKey{}
}

// testClock 可拨动的假时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func mustTable(t *testing.T, cfg Config) *Table {
	t.Helper()
	if cfg.Now == nil {
		cfg.Now = (testClockAt(time.Unix(1_700_000_000, 0))).Now
	}
	nt, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = nt.Close() })
	return nt
}

func testClockAt(tm time.Time) *testClock {
	return &testClock{now: tm}
}
