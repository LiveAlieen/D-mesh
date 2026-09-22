package spam

import (
	"fmt"
	"sort"
	"sync"

	"dmesh/internal/core"
)

// ScoreEvent 是评分事件类型（正负两类），由 message/backfill/audit 侧上报。
type ScoreEvent string

const (
	// —— 负分事件（差评）——
	// EvBadSignature 伪签：验签失败的签名/proof（alg 已注册却验不过）。重罚。
	EvBadSignature ScoreEvent = "bad_signature"
	// EvRepeatViolation 重复违规：同类坏行为再次发生（按累计次数递增重罚）。
	EvRepeatViolation ScoreEvent = "repeat_violation"
	// EvConflictingData 多源比对不一致：其提供的数据与其他源矛盾（回灌/核查）。
	EvConflictingData ScoreEvent = "conflicting_data"
	// EvSpam 速率超限/PoW 不合格等垃圾行为。
	EvSpam ScoreEvent = "spam"
	// EvUnknownAlg 未知 sig_alg：拒绝采纳 + 轻差评（v16：可能是本地尚未注册
	// 该算法，绝不按伪签同等处罚——core.IsUnknownAlg 的区分正落到这里）。
	EvUnknownAlg ScoreEvent = "unknown_alg"

	// —— 正分事件（好评）——
	// EvValidRoster 提供完整可验的双名单副本。
	EvValidRoster ScoreEvent = "valid_roster"
	// EvMajorityAgree 回灌/核查区间与多数派一致。
	EvMajorityAgree ScoreEvent = "majority_agree"
	// EvTimelyData 及时递送有效数据（中继 join_req、补 proof 等）。
	EvTimelyData ScoreEvent = "timely_data"
)

// ScoreConfig 是评分引擎参数。零值无效，请用 DefaultScoreConfig。
type ScoreConfig struct {
	Initial         int   // 新 key 起始分
	Min             int   // 分数下限
	Max             int   // 分数上限
	GoodThreshold   int   // >= 此分才算可靠源（回灌选源、核查投票）
	DropThreshold   int   // <= 此分即应剔除/断连的坏源
	DecayIntervalMS int64 // 无新事件经过该时长，分数向 Initial 回移一步、违规计数 -1
	RepeatCap       int   // 重复违规罚分放大倍数的封顶（第 N 次罚 base*min(N,RepeatCap)）
}

// DefaultScoreConfig 返回默认参数（0~100 制，50 起步）。
func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{
		Initial:         50,
		Min:             0,
		Max:             100,
		GoodThreshold:   65,
		DropThreshold:   20,
		DecayIntervalMS: 10 * 60 * 1000,
		RepeatCap:       5,
	}
}

// 各事件的基准罚/奖分（负数为罚分）。
var eventDelta = map[ScoreEvent]int{
	EvBadSignature:    -25,
	EvRepeatViolation: -10, // 与 violations 计数相乘放大，见 Penalize
	EvConflictingData: -20,
	EvSpam:            -10,
	EvUnknownAlg:      -5,
	EvValidRoster:     +8,
	EvMajorityAgree:   +5,
	EvTimelyData:      +3,
}

// violationEvents 计为「违规次数」的事件（驱动 EvRepeatViolation 递增罚分）。
var violationEvents = map[ScoreEvent]bool{
	EvBadSignature:    true,
	EvRepeatViolation: true,
	EvConflictingData: true,
	EvSpam:            true,
}

// ScoreSnapshot 是单 key 的评分快照（状态面板/诊断用）。
type ScoreSnapshot struct {
	Key        string `json:"key"`
	Score      int    `json:"score"`
	Violations int    `json:"violations"`
}

// String 便于日志输出。
func (s ScoreSnapshot) String() string {
	return fmt.Sprintf("score(%s)=%d viol=%d", s.Key, s.Score, s.Violations)
}

type scoreState struct {
	score       int
	violations  int
	lastEventMS int64
}

// ScoreTracker 是邻居/来源评分表：伪签重罚、重复违规递增罚分、未知算法轻罚、
// 好评回升，长期无事件向初值衰减。并发安全；时间全部走注入的 now（Unix 毫秒）。
type ScoreTracker struct {
	mu     sync.Mutex
	cfg    ScoreConfig
	now    func() int64
	states map[string]*scoreState
}

// NewScoreTracker 创建评分表；cfg 零值（Initial==0&&Max==0）时用默认配置，
// now 为 nil 时用系统时钟。
func NewScoreTracker(cfg ScoreConfig, now func() int64) *ScoreTracker {
	if cfg.Max == 0 && cfg.Initial == 0 {
		cfg = DefaultScoreConfig()
	}
	if cfg.DecayIntervalMS <= 0 {
		cfg.DecayIntervalMS = DefaultScoreConfig().DecayIntervalMS
	}
	if cfg.RepeatCap <= 0 {
		cfg.RepeatCap = DefaultScoreConfig().RepeatCap
	}
	if now == nil {
		now = unixNowMS
	}
	return &ScoreTracker{cfg: cfg, now: now, states: map[string]*scoreState{}}
}

// Config 返回生效配置副本（状态面板展示阈值）。
func (t *ScoreTracker) Config() ScoreConfig { return t.cfg }

// PenalizePub / RewardPub 以 core.PubKey 为 key 的便捷包装。
func (t *ScoreTracker) PenalizePub(p core.PubKey, ev ScoreEvent) int {
	return t.Penalize(p.Key(), ev)
}

// RewardPub 好评（见 Reward）。
func (t *ScoreTracker) RewardPub(p core.PubKey, ev ScoreEvent) int {
	return t.Reward(p.Key(), ev)
}

// Penalize 记一次差评，返回罚后分值。未知事件类型按 EvSpam 罚。
// EvRepeatViolation（或任何违规类事件累计到第 N 次）时罚分按 base*min(N,RepeatCap)
// 递增——对端反复伪造签名会被快速压到 DropThreshold 以下。
func (t *ScoreTracker) Penalize(key string, ev ScoreEvent) int {
	return t.apply(key, ev, true)
}

// Reward 记一次好评，返回奖后分值。违规计数不因好评清零（只随时间衰减）。
func (t *ScoreTracker) Reward(key string, ev ScoreEvent) int {
	return t.apply(key, ev, false)
}

func (t *ScoreTracker) apply(key string, ev ScoreEvent, penalize bool) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	st := t.getLocked(key, now)
	delta, ok := eventDelta[ev]
	if !ok {
		if !penalize {
			return st.score // 未知的正分事件直接忽略
		}
		delta = eventDelta[EvSpam] // 未知的差评事件按 spam 罚
	}
	if penalize && delta > 0 {
		delta = -delta // 表里配错了符号也按罚分处理
	}
	if !penalize && delta < 0 {
		delta = -delta
	}
	if penalize && violationEvents[ev] {
		st.violations++
		if ev == EvRepeatViolation {
			// 重复违规递增罚分：第 N 次罚 base*min(N,RepeatCap)
			mult := st.violations
			if mult > t.cfg.RepeatCap {
				mult = t.cfg.RepeatCap
			}
			delta *= mult
		}
	}
	st.score += delta
	st.score = clamp(st.score, t.cfg.Min, t.cfg.Max)
	st.lastEventMS = now
	return st.score
}

// Score 返回当前分值（无记录返回 Initial）。
func (t *ScoreTracker) Score(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getLocked(key, t.now()).score
}

// ScorePub 以公钥为 key 的便捷包装。
func (t *ScoreTracker) ScorePub(p core.PubKey) int { return t.Score(p.Key()) }

// Violations 返回累计违规次数。
func (t *ScoreTracker) Violations(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getLocked(key, t.now()).violations
}

// GoodSource 报告该源是否够格被回灌/核查选为可信源（score>=GoodThreshold）。
func (t *ScoreTracker) GoodSource(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getLocked(key, t.now()).score >= t.cfg.GoodThreshold
}

// ShouldDrop 报告该源是否应被剔除/断连（score<=DropThreshold）。
func (t *ScoreTracker) ShouldDrop(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getLocked(key, t.now()).score <= t.cfg.DropThreshold
}

// Advance 显式推进时钟做一次全局衰减（每 DecayIntervalMS 无事件向 Initial 回移
// 一步、violation 计数 -1）。读取类方法内部已惰性衰减，此方法供状态面板定时调用。
func (t *ScoreTracker) Advance() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, st := range t.states {
		t.decayLocked(st, now)
	}
}

// Snapshot 返回全部 key 的评分快照，按分数升序（坏源在前，供状态面板/断连决策）。
func (t *ScoreTracker) Snapshot() []ScoreSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]ScoreSnapshot, 0, len(t.states))
	for k, st := range t.states {
		t.decayLocked(st, now)
		out = append(out, ScoreSnapshot{Key: k, Score: st.score, Violations: st.violations})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score < out[j].Score
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// getLocked 取（或初始化）状态并先做惰性衰减。调用方须持锁。
func (t *ScoreTracker) getLocked(key string, now int64) *scoreState {
	st, ok := t.states[key]
	if !ok {
		st = &scoreState{score: t.cfg.Initial, lastEventMS: now}
		t.states[key] = st
		return st
	}
	t.decayLocked(st, now)
	return st
}

// decayLocked 按「距上次事件经过的完整衰减周期数」逐步向 Initial 回移，
// 违规计数每周期 -1（不低于 0）。回移只朝向 Initial：低于初值则升、高于则降。
func (t *ScoreTracker) decayLocked(st *scoreState, now int64) {
	if t.cfg.DecayIntervalMS <= 0 || now <= st.lastEventMS {
		return
	}
	periods := int((now - st.lastEventMS) / t.cfg.DecayIntervalMS)
	for i := 0; i < periods; i++ {
		if st.score < t.cfg.Initial {
			st.score++
		} else if st.score > t.cfg.Initial {
			st.score--
		}
		if st.violations > 0 {
			st.violations--
		}
		if st.score == t.cfg.Initial && st.violations == 0 {
			break
		}
	}
	st.lastEventMS += int64(periods) * t.cfg.DecayIntervalMS
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
