package message

import (
	"sync"
	"time"

	"dmesh/internal/core"
)

// DefaultDedupTTL 是去重缓存的默认保留时长：超过该时长的 msg_id 视为可 Forget
// （flood 收敛远快于此值；回灌/核查路径不经这里，不受 TTL 影响）。
const DefaultDedupTTL = 10 * time.Minute

// defaultDedupCap 是缓存条数上限，越界时先清过期、再随机逐出（防内存放大的最后闸门）。
const defaultDedupCap = 65536

// DedupResult 是 Observe 的三态结果。
type DedupResult int

const (
	// DedupFresh：首次（或已过期）见到该 msg_id —— 记录来源，允许投递 + flood 转发。
	DedupFresh DedupResult = iota
	// DedupSameSource：同一来源再次推送 —— 静默吞掉（来源抑制，防风暴），绝不回送该来源。
	DedupSameSource
	// DedupOtherSource：不同来源推送已知消息 —— 静默吞掉（去重），不转发不投递。
	DedupOtherSource
)

// String 便于日志与测试断言。
func (r DedupResult) String() string {
	switch r {
	case DedupFresh:
		return "fresh"
	case DedupSameSource:
		return "same-source"
	case DedupOtherSource:
		return "other-source"
	default:
		return "unknown"
	}
}

type dedupRec struct {
	src    string // 首次来源（PubKey.Key()），空串表示不关心来源
	expire time.Time
}

// Deduper 是 msg_id 去重缓存：msg_id + TTL + 来源抑制。
// 并发安全；时钟可注入以便测试。
type Deduper struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	cap   int
	seen  map[string]dedupRec
	ticks int
}

// NewDeduper 构造去重缓存。ttl<=0 用 DefaultDedupTTL；now 为 nil 用 time.Now；
// cap<=0 用 defaultDedupCap。
func NewDeduper(ttl time.Duration, cap int, now func() time.Time) *Deduper {
	if ttl <= 0 {
		ttl = DefaultDedupTTL
	}
	if cap <= 0 {
		cap = defaultDedupCap
	}
	if now == nil {
		now = time.Now
	}
	return &Deduper{ttl: ttl, now: now, cap: cap, seen: make(map[string]dedupRec)}
}

// Observe 记录并判定 msgID（自 src 到达）。
func (d *Deduper) Observe(msgID string, src core.PubKey) DedupResult {
	return d.observe(msgID, src.Key())
}

// ObserveAnon 做纯 msg_id 去重（不记录有效来源，重复即吞），用于 join_req 中继防风暴。
func (d *Deduper) ObserveAnon(msgID string) DedupResult {
	if r := d.observe(msgID, ""); r != DedupFresh {
		return DedupOtherSource
	}
	return DedupFresh
}

func (d *Deduper) observe(msgID, srcKey string) DedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if rec, ok := d.seen[msgID]; ok && now.Before(rec.expire) {
		if rec.src == srcKey {
			return DedupSameSource
		}
		return DedupOtherSource
	}
	d.seen[msgID] = dedupRec{src: srcKey, expire: now.Add(d.ttl)}
	d.ticks++
	if d.ticks&255 == 0 || len(d.seen) > d.cap {
		d.purgeExpiredLocked(now)
	}
	if n := len(d.seen); n > d.cap {
		// 仍越界：随机逐出多余条目（map 迭代序天然随机，等效近似 LRU-随机混合）。
		for k := range d.seen {
			delete(d.seen, k)
			if len(d.seen) <= d.cap {
				break
			}
		}
	}
	return DedupFresh
}

// Forget 主动移除一个 msg_id（回灌/核查阶段可作为「不再视为重复」的钩子）。
func (d *Deduper) Forget(msgID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seen, msgID)
}

// Contains 报告 msgID 是否在缓存且未过期（只读，不改动记录）。
func (d *Deduper) Contains(msgID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, ok := d.seen[msgID]
	if !ok {
		return false
	}
	if !d.now().Before(rec.expire) {
		delete(d.seen, msgID)
		return false
	}
	return true
}

// Len 返回当前缓存条目数（含未清理的过期项，仅用于观测/测试）。
func (d *Deduper) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

func (d *Deduper) purgeExpiredLocked(now time.Time) {
	for k, rec := range d.seen {
		if !now.Before(rec.expire) {
			delete(d.seen, k)
		}
	}
}
