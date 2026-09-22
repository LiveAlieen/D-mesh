package spam

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"dmesh/internal/core"
)

// BlockEntry 是本地屏蔽条目。注意：这与群黑名单（core.BlacklistEntry，
// 签名事件驱动、全群一致）完全不同——它只是本机的静音/回避开关：
// 屏蔽后本端不再显示其消息、不再为其转发、回灌/核查不再选它当源，
// 但绝不改变群名单语义，也不影响其他节点。
type BlockEntry struct {
	Pub     core.PubKey `json:"pub"`
	Reason  string      `json:"reason,omitempty"`
	AddedMS int64       `json:"added_ms"`
	UntilMS int64       `json:"until_ms"` // 0 = 永久（直到手解除）
}

// expired 报告条目在 now 时刻是否已过期。
func (e BlockEntry) expired(now int64) bool {
	return e.UntilMS > 0 && now >= e.UntilMS
}

// Blocklist 是并发安全的本地屏蔽列表，过期条目在读取时惰性清理。
type Blocklist struct {
	mu      sync.RWMutex
	entries map[string]BlockEntry
	now     func() int64
}

// NewBlocklist 创建空列表；now 为 Unix 毫秒时钟（nil 用系统时钟）。
func NewBlocklist(now func() int64) *Blocklist {
	if now == nil {
		now = unixNowMS
	}
	return &Blocklist{entries: map[string]BlockEntry{}, now: now}
}

// Add 屏蔽某公钥；durMS<=0 表示永久。重复 Add 同一 key 覆盖旧条目（可续期/改原因）。
func (b *Blocklist) Add(pub core.PubKey, reason string, durMS int64) BlockEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	e := BlockEntry{Pub: pub, Reason: reason, AddedMS: now}
	if durMS > 0 {
		e.UntilMS = now + durMS
	}
	b.entries[pub.Key()] = e
	return e
}

// Remove 解除屏蔽；返回是否确实删掉过条目。
func (b *Blocklist) Remove(pub core.PubKey) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.entries[pub.Key()]
	if ok {
		delete(b.entries, pub.Key())
	}
	return ok
}

// Blocked 报告该公钥当前是否被屏蔽（含过期判定与惰性删除）。
// 空公钥（IsZero）永远不屏蔽。
func (b *Blocklist) Blocked(pub core.PubKey) bool {
	if pub.IsZero() {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[pub.Key()]
	if !ok {
		return false
	}
	if e.expired(b.now()) {
		delete(b.entries, pub.Key())
		return false
	}
	return true
}

// Lookup 返回条目（若存在且未过期）。
func (b *Blocklist) Lookup(pub core.PubKey) (BlockEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[pub.Key()]
	if !ok {
		return BlockEntry{}, false
	}
	if e.expired(b.now()) {
		delete(b.entries, pub.Key())
		return BlockEntry{}, false
	}
	return e, true
}

// List 返回当前有效条目（已滤掉过期项），按 AddedMS 升序、同值按 key 字典序，
// 保证序列化确定性。
func (b *Blocklist) List() []BlockEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := make([]BlockEntry, 0, len(b.entries))
	for k, e := range b.entries {
		if e.expired(now) {
			delete(b.entries, k)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AddedMS != out[j].AddedMS {
			return out[i].AddedMS < out[j].AddedMS
		}
		return out[i].Pub.Key() < out[j].Pub.Key()
	})
	return out
}

// Size 返回有效条目数。
func (b *Blocklist) Size() int { return len(b.List()) }

// MarshalJSON 序列化当前有效条目（持久化到本地设置文件）。
func (b *Blocklist) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version int          `json:"version"`
		Entries []BlockEntry `json:"entries"`
	}{Version: 1, Entries: b.List()})
}

// LoadBlocklist 从 MarshalJSON 产物恢复；now 时钟同 NewBlocklist。
func LoadBlocklist(data []byte, now func() int64) (*Blocklist, error) {
	var s struct {
		Version int          `json:"version"`
		Entries []BlockEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("spam: load blocklist: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("spam: unsupported blocklist version %d", s.Version)
	}
	b := NewBlocklist(now)
	for _, e := range s.Entries {
		if e.Pub.IsZero() {
			return nil, fmt.Errorf("spam: blocklist entry with zero pub")
		}
		b.entries[e.Pub.Key()] = e
	}
	return b, nil
}

// unixNowMS 是本包默认时钟（Unix 毫秒）。
func unixNowMS() int64 { return time.Now().UnixMilli() }
