package spam

import (
	"errors"
	"sync"
	"testing"
)

// fakeClock 是可注入的假时钟（Unix 毫秒），供速率/过期类测试。
type fakeClock struct {
	mu  sync.Mutex
	ms  int64
	seq []int64 // 预留：按序弹出（简化起见本测试只用 ms+步进）
}

func newFakeClock(start int64) *fakeClock { return &fakeClock{ms: start} }

func (c *fakeClock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ms
}

func (c *fakeClock) advance(ms int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ms += ms
}

func TestLimiterBurstAndRefill(t *testing.T) {
	clk := newFakeClock(1000)
	// 每 100ms 一条，突发 3
	l := NewLimiter(RateConfig{MillisPerMsg: 100, Burst: 3}, clk.now)

	tests := []struct {
		name    string
		advance int64 // 申请前时钟推进
		want    bool
	}{
		{"burst 1", 0, true},
		{"burst 2", 0, true},
		{"burst 3", 0, true},
		{"burst exhausted", 0, false},
		{"still empty after 99ms", 99, false}, // 差 1ms 不满一个令牌
		{"refill at 100ms", 1, true},
		{"empty again", 0, false},
		{"partial refill does not double count", 50, false}, // 只攒了 0.5 个
		{"refill completes at next 50ms", 50, true},
		{"long idle caps at burst", 10_000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk.advance(tc.advance)
			if got := l.Allow("alice"); got != tc.want {
				t.Fatalf("Allow = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLimiterCapsAtBurst(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(RateConfig{MillisPerMsg: 10, Burst: 4}, clk.now)
	l.Allow("k")         // 建立桶并消耗 1 → 3
	clk.advance(100_000) // 理论上可回满：应封顶 4
	l.Allow("k")         // 4 - 1 = 3（若未封顶会远大于 4）
	if got := l.Remaining("k"); got != 3 {
		t.Fatalf("Remaining = %d, want 3 (refill must cap at burst)", got)
	}
}

func TestLimiterAllowNAtomic(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(RateConfig{MillisPerMsg: 100, Burst: 5}, clk.now)
	if !l.AllowN("g", 3) {
		t.Fatalf("AllowN(3) denied with full burst")
	}
	if l.AllowN("g", 3) {
		t.Fatalf("AllowN(3) allowed with only 2 tokens — must not consume partially")
	}
	if got := l.Remaining("g"); got != 2 {
		t.Fatalf("Remaining = %d, want 2 (failed AllowN must not consume)", got)
	}
	if !l.AllowN("g", 0) {
		t.Fatalf("AllowN(0) should always pass")
	}
}

func TestLimiterPerKeyIsolation(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(RateConfig{MillisPerMsg: 100, Burst: 1}, clk.now)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatalf("key a burst behavior wrong")
	}
	if !l.Allow("b") {
		t.Fatalf("key b must have its own bucket")
	}
	if l.Keys() != 2 {
		t.Fatalf("Keys = %d, want 2", l.Keys())
	}
}

func TestLimiterRetryAfter(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(RateConfig{MillisPerMsg: 200, Burst: 1}, clk.now)
	if got := l.RetryAfterMS("x"); got != 0 {
		t.Fatalf("RetryAfter on fresh key = %d, want 0", got)
	}
	l.Allow("x")
	if got := l.RetryAfterMS("x"); got != 200 {
		t.Fatalf("RetryAfter after consuming = %d, want 200", got)
	}
	clk.advance(150)
	if got := l.RetryAfterMS("x"); got != 50 {
		t.Fatalf("RetryAfter mid-refill = %d, want 50", got)
	}
	clk.advance(50)
	if got := l.RetryAfterMS("x"); got != 0 {
		t.Fatalf("RetryAfter full = %d, want 0", got)
	}
}

func TestLimiterCleanup(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(RateConfig{MillisPerMsg: 100, Burst: 2}, clk.now)
	l.Allow("idle-full") // 消耗 1
	l.Allow("idle-full") // 消耗第 2 个 —— 现在 0 令牌
	l.Allow("busy")      // 消耗 1
	l.AllowN("busy", 0)  // 不消耗
	clk.advance(500)     // idle-full 回满 2；busy 也回满
	// busy 再消耗使其非满
	l.Allow("busy")
	removed := l.Cleanup(200)
	if removed != 1 {
		t.Fatalf("Cleanup removed %d, want 1 (only idle-full is full+idle)", removed)
	}
	if l.Keys() != 1 {
		t.Fatalf("Keys after cleanup = %d, want 1", l.Keys())
	}
}

func TestLimiterRejectError(t *testing.T) {
	clk := newFakeClock(0)
	l := NewLimiter(ChatRate(), clk.now)
	if err := l.Reject("u", 1); err != nil {
		t.Fatalf("first Reject: %v", err)
	}
	n := ChatRate().Burst
	for i := 0; i < n; i++ {
		l.Allow("u")
	}
	if err := l.Reject("u", 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Reject err = %v, want ErrRateLimited", err)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	clk := newFakeClock(0) // 冻结时钟：总放行数必须恰好等于 burst，无算token竞态
	l := NewLimiter(RateConfig{MillisPerMsg: 1000, Burst: 1000}, clk.now)
	var wg sync.WaitGroup
	var allowed int64
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local int64
			for j := 0; j < 500; j++ {
				if l.Allow("race") {
					local++
				}
			}
			mu.Lock()
			allowed += local
			mu.Unlock()
		}()
	}
	wg.Wait()
	if allowed != 1000 {
		t.Fatalf("allowed %d, want exactly 1000 (frozen clock, 2000 attempts)", allowed)
	}
}
