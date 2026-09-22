package spam

import (
	"math"
	"sync"
)

// RateConfig 是一类消息的速率参数：稳态每 MillisPerMsg 毫秒允许 1 条，
// 突发容量 Burst（桶容量）。取反语义便于配置（如「每 200ms 一条，突发 5 条」）。
type RateConfig struct {
	MillisPerMsg int64 // 平均间隔（毫秒/条），<=0 视为 1
	Burst        int   // 桶容量（瞬时可放条数），<=0 视为 1
}

// ratePerMS 返回每毫秒补充令牌数。
func (c RateConfig) ratePerMS() float64 {
	mpm := c.MillisPerMsg
	if mpm <= 0 {
		mpm = 1
	}
	return 1.0 / float64(mpm)
}

func (c RateConfig) burst() float64 {
	if c.Burst <= 0 {
		return 1
	}
	return float64(c.Burst)
}

// 常用预置（PLAN：presence 心跳限速防风暴；join_req 中继需更严；聊天适中）。
func ChatRate() RateConfig     { return RateConfig{MillisPerMsg: 250, Burst: 8} }
func PresenceRate() RateConfig { return RateConfig{MillisPerMsg: 60 * 1000, Burst: 2} }
func JoinReqRate() RateConfig  { return RateConfig{MillisPerMsg: 30 * 1000, Burst: 3} }

// bucket 是单个 key 的令牌桶。lastMS 只服务补充计算，touchedMS 记录最近一次
// 放行申请（只被 Allow/AllowN 刷新，读类方法不续命），供 Cleanup 判闲置。
type bucket struct {
	tokens    float64
	lastMS    int64
	touchedMS int64
}

// Limiter 是按 key（一般是 core.PubKey.Key() 或 "pub|type"）分桶的令牌桶集合。
// 单调时间由注入的 now（Unix 毫秒）提供；并发安全。
type Limiter struct {
	mu  sync.Mutex
	cfg RateConfig
	now func() int64
	bs  map[string]*bucket
}

// NewLimiter 创建速率限制器。now 为 Unix 毫秒时钟（测试可注入假时钟）。
func NewLimiter(cfg RateConfig, now func() int64) *Limiter {
	if now == nil {
		now = unixNowMS
	}
	return &Limiter{cfg: cfg, now: now, bs: map[string]*bucket{}}
}

// Allow 报告 key 本毫秒可否放行一条（并消耗令牌）。
func (l *Limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// AllowN 一次申请 n 个令牌；不足则不消耗、返回 false。
func (l *Limiter) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.bs[key]
	if !ok {
		b = &bucket{tokens: l.cfg.burst(), lastMS: now, touchedMS: now}
		l.bs[key] = b
	}
	l.refill(b, now)
	b.touchedMS = now
	need := float64(n)
	if b.tokens >= need {
		b.tokens -= need
		return true
	}
	return false
}

// Reject 与 AllowN 相反：返回 error 形式（errors.Is(ErrRateLimited) 可判）。
func (l *Limiter) Reject(key string, n int) error {
	if !l.AllowN(key, n) {
		return ErrRateLimited
	}
	return nil
}

// Remaining 返回 key 当前可用令牌数（向下取整），用于状态面板。
func (l *Limiter) Remaining(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bs[key]
	if !ok {
		return int(l.cfg.burst())
	}
	l.refill(b, l.now())
	return int(math.Floor(b.tokens))
}

// RetryAfterMS 返回 key 再攒够 1 个令牌还需多少毫秒（0=现在可放行）。
func (l *Limiter) RetryAfterMS(key string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.bs[key]
	if !ok {
		return 0
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		return 0
	}
	deficit := 1 - b.tokens
	ms := int64(math.Ceil(deficit / l.cfg.ratePerMS()))
	if ms < 1 {
		ms = 1
	}
	return ms
}

// Cleanup 删除闲置超过 idleMS 且已回满的桶，防 key 基数膨胀泄漏内存。
// 返回删除数。
func (l *Limiter) Cleanup(idleMS int64) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	removed := 0
	for k, b := range l.bs {
		l.refill(b, now)
		if now-b.touchedMS >= idleMS && b.tokens >= l.cfg.burst() {
			delete(l.bs, k)
			removed++
		}
	}
	return removed
}

// Keys 返回当前有桶的 key 数（状态面板用）。
func (l *Limiter) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.bs)
}

// refill 按流逝时间补令牌，封顶 burst。调用方须持锁；同时刷新 lastMS。
func (l *Limiter) refill(b *bucket, now int64) {
	dt := now - b.lastMS
	if dt > 0 {
		b.tokens += float64(dt) * l.cfg.ratePerMS()
		if maxTok := l.cfg.burst(); b.tokens > maxTok {
			b.tokens = maxTok
		}
		b.lastMS = now
	}
}
