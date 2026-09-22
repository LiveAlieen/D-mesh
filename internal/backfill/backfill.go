// Package backfill 实现 v11「重上线自动回灌」与「按需一致性核查(/audit)」。
//
// 设计要点（PLAN.md「回灌」「按需一致性核查」两节为最高权威）：
//
//  1. 握手恢复即自动触发（NotifyReconnect / Trigger），按「先名单、后消息」补齐：
//     先向邻居拉双名单副本（白名单条目+proof / 黑名单条目+封禁证明），逐条独立
//     验证 proof 后合并（黑名单优先拉齐；缺 proof 的条目向其他源补齐）；
//     再向 ≥MinSources(默认3) 个邻居请求本机 max_ts 之后的增量消息，按 msg_id
//     去重交叉比对：各源不一致、仅单源出现或验签失败 → 丢弃 + 来源差评。
//     scope 可配：仅增量（默认）/ 全部 / 最近 N 天 / 不同步（跳过自动回灌）。
//     发言权按「接收时名单」判定（本包在投递时刻查 core.Roster）。
//  2. 按需核查 Audit：多邻居交换白/黑名单条目集与 msg_id 集，缺的条目补 proof
//     验证后采纳；伪签/越权/偏离多数派 → 丢弃 + 差评，差评累计越过阈值的邻居
//     触发断连回调并冷却。
//
// 本包只 import dmesh/internal/core；邻居应答能力抽象成 Source 接口、本地消息
// 视图抽象成 Store 接口，由 Integration 在 cmd/dmesh 接线到 transport/store。
package backfill

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"dmesh/internal/core"
)

// ScopeMode 是回灌范围（PLAN：默认仅增量；另选 全部 / 最近 N 天 / 不同步）。
type ScopeMode string

const (
	ScopeIncremental ScopeMode = "incremental" // 只拉本机 max_ts 之后的增量（默认）
	ScopeAll         ScopeMode = "all"         // 全量重拉并交叉比对
	ScopeRecentDays  ScopeMode = "recent_days" // 最近 Days 天
	ScopeNone        ScopeMode = "none"        // 不同步：跳过自动回灌（/audit 仍可用）
)

// Config 是回灌/核查的行为参数。
type Config struct {
	// Scope 消息回灌范围；零值按 ScopeIncremental。
	Scope ScopeMode
	// Days Scope=ScopeRecentDays 时的窗口天数（<=0 视为 7）。
	Days int
	// MinSources 消息交叉比对要求的最少应答邻居数（默认 3，PLAN「≥3 邻居」）。
	MinSources int
	// MinAgree 一条消息至少被几个应答源一致提供才可采纳（默认 2；
	// 仅单源出现 → 丢弃 + 差评）。MinAgree<=1 关闭多源门槛（不建议）。
	MinAgree int
	// BadScoreThreshold 差评累计到该值（含）以下即触发断连回调并冷却（默认 -6）。
	BadScoreThreshold int
	// Cooldown 被断连邻居的再评估冷却时长（默认 10 分钟）。
	Cooldown time.Duration
}

// Defaults 返回补齐零值后的配置。
func (c Config) Defaults() Config {
	if c.Scope == "" {
		c.Scope = ScopeIncremental
	}
	if c.Days <= 0 {
		c.Days = 7
	}
	if c.MinSources <= 0 {
		c.MinSources = 3
	}
	if c.MinAgree <= 0 {
		c.MinAgree = 2
	}
	if c.BadScoreThreshold == 0 {
		c.BadScoreThreshold = -6
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 10 * time.Minute
	}
	return c
}

// Snapshot 是邻居对「双名单副本」请求的应答（core.Roster.Snapshot 的线格式）。
//
// Owner 指针仅随快照传输；采纳与否由名单事件（transfer 等）经 ApplyEvent 决定，
// 本包不直接改写 owner（core.Roster 未暴露 SetOwner，见返回 issue 注记）。
type Snapshot struct {
	Members []core.MemberEntry
	Banned  []core.BlacklistEntry
	Owner   core.PubKey
}

// Query 是增量消息请求：AfterTS 为「只要 ts_ms 不早于它」的下界。
type Query struct {
	AfterTS int64
}

// Source 是一个可比对的邻居（Integration 用 Tunnel + message 包的请求/应答
// 协议实现；测试用内存实现）。所有方法必须可并发调用、可被 ctx 取消。
type Source interface {
	// ID 返回邻居身份（差评/断连按此记账）。
	ID() core.PubKey
	// FetchSnapshot 拉取对方维护的双名单副本。
	FetchSnapshot(ctx context.Context) (Snapshot, error)
	// FetchMessages 返回同一区间（AfterTS 之后）的消息集。
	FetchMessages(ctx context.Context, q Query) ([]core.Message, error)
	// FetchMsgIDs 返回本机（对方）msg_id 集合的下界投影，用于 /audit 比对。
	FetchMsgIDs(ctx context.Context, afterTS int64) ([]string, error)
	// FetchByMsgIDs 按 msg_id 精确取消息（audit 中补拉缺失项）。
	FetchByMsgIDs(ctx context.Context, ids []string) ([]core.Message, error)
}

// Store 是本地消息存储的可测视图（store 包实现）。
type Store interface {
	// MaxTS 返回本机已存消息的最大 ts_ms（增量回灌下界）。
	MaxTS() int64
	// Has 报告 msg_id 是否已在本机（去重）。
	Has(msgID string) bool
	// Get 按 msg_id 取本机消息（audit 复核签名用）。
	Get(msgID string) (core.Message, bool)
	// Append 追加一条已通过交叉比对的消息。
	Append(m core.Message) error
	// MsgIDs 返回 ts_ms 不早于 afterTS 的本机 msg_id 集合。
	MsgIDs(afterTS int64) []string
	// Reject 软剔除一条被证实为伪签/偏离多数派的本机消息。
	Reject(msgID string, reason string) error
}

// Cleaner 是可选的本机名单条目剔除钩子（group 包实现；audit 发现本机副本被
// 删改伪造时调用。未提供时仅记入报告，不改动名单）。
type Cleaner interface {
	DropMember(p core.PubKey, reason string)
	DropBan(p core.PubKey, reason string)
}

// Deps 是 Engine 的依赖注入集。
type Deps struct {
	Roster  core.Roster     // 双名单（group 包实现），必需
	Store   Store           // 本地消息视图，必需
	Cleaner Cleaner         // 可选：audit 剔除本机被伪造的名单条目
	Sources func() []Source // 必需：返回当前活跃邻居源（邻居包 + Tunnel 接线）
	Config  Config          // 行为参数
	Now     func() int64    // Unix 毫秒时钟，默认 time.Now；测试可注入
	// Penalize / Disconnect 是差评与断连的对外通知钩子（可选；Engine 内部
	// 评分与冷却始终进行，钩子仅用于 spam 包/UI 联动）。
	Penalize   func(peer core.PubKey, reason DropReason, detail string)
	Disconnect func(peer core.PubKey, reason string)
}

// 契约级错误。
var (
	// ErrTooFewSources 应答源少于 MinSources，无法多源交叉比对，消息阶段被跳过。
	ErrTooFewSources = errors.New("backfill: too few responding sources")
	// ErrNilDeps 必需依赖缺失。
	ErrNilDeps = errors.New("backfill: nil required dependency")
)

// Engine 是回灌/核查引擎。方法并发安全。
type Engine struct {
	roster   core.Roster
	store    Store
	cleaner  Cleaner
	sourcesF func() []Source
	now      func() int64
	cfg      Config

	onPenalize   func(peer core.PubKey, reason DropReason, detail string)
	onDisconnect func(peer core.PubKey, reason string)

	mu       sync.Mutex
	scores   map[string]int   // peer key -> 评分（0 起步，差评递减）
	cooldown map[string]int64 // peer key -> 冷却截止（unix ms）

	runMu sync.Mutex // Trigger 去重：同一时刻只跑一轮自动回灌
}

// New 构造 Engine。Roster/Store/Sources 任一为 nil 返回 ErrNilDeps。
func New(d Deps) (*Engine, error) {
	if d.Roster == nil || d.Store == nil || d.Sources == nil {
		return nil, fmt.Errorf("%w: Roster/Store/Sources are required", ErrNilDeps)
	}
	now := d.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &Engine{
		roster:       d.Roster,
		store:        d.Store,
		cleaner:      d.Cleaner,
		sourcesF:     d.Sources,
		now:          now,
		cfg:          d.Config.Defaults(),
		onPenalize:   d.Penalize,
		onDisconnect: d.Disconnect,
		scores:       map[string]int{},
		cooldown:     map[string]int64{},
	}, nil
}

// Config 返回生效配置（补齐默认值后）。
func (e *Engine) Config() Config { return e.cfg }

// Score 返回邻居当前评分（无记录为 0）。
func (e *Engine) Score(peer core.PubKey) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scores[peer.Key()]
}

// penalize 记一次差评；越阈值则断连 + 冷却。幂等无关，按次累计。
func (e *Engine) penalize(peer core.PubKey, reason DropReason, detail string) {
	if peer.IsZero() {
		return
	}
	e.mu.Lock()
	k := peer.Key()
	e.scores[k]--
	s := e.scores[k]
	var fire bool
	if s <= e.cfg.BadScoreThreshold {
		if until, ok := e.cooldown[k]; !ok || until <= e.now() {
			fire = true
			e.cooldown[k] = e.now() + e.cfg.Cooldown.Milliseconds()
			e.scores[k] = 0 // 断连后重新计数，避免永久拉死
		}
	}
	e.mu.Unlock()
	if e.onPenalize != nil {
		e.onPenalize(peer, reason, detail)
	}
	if fire && e.onDisconnect != nil {
		e.onDisconnect(peer, string(reason)+": "+detail)
	}
}

// activeSources 返回去掉冷却中邻居后的源列表（保持来源顺序稳定：按 ID 排序）。
func (e *Engine) activeSources() []Source {
	all := e.sourcesF()
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Source, 0, len(all))
	for _, s := range all {
		if until, ok := e.cooldown[s.ID().Key()]; ok && until > now {
			continue
		}
		out = append(out, s)
	}
	return out
}

// NotifyReconnect 在成员握手恢复时被调用：后台触发一轮自动回灌（若已有回灌
// 在途则合并跳过，不并发跑两轮）。返回是否真正启动了一轮。
func (e *Engine) NotifyReconnect(ctx context.Context) bool { return e.Trigger(ctx) }

// Trigger 异步执行一次 RunOnce，同一时刻至多一轮。
func (e *Engine) Trigger(ctx context.Context) bool {
	if !e.runMu.TryLock() {
		return false
	}
	go func() {
		defer e.runMu.Unlock()
		_, _ = e.RunOnce(ctx)
	}()
	return true
}

// Report 是一轮自动回灌的结果汇总。
type Report struct {
	Scope            ScopeMode
	Skipped          bool // ScopeNone：整轮跳过
	AfterTS          int64
	SourcesAsked     int
	SourcesResponded int
	Merge            *MergeResult // 双名单合并阶段
	MsgPhaseSkipped  string       // 非空表示消息阶段未做交叉比对的原因
	Accepted         int          // 采纳并落盘的消息数
	Drops            []Drop       // 被丢弃/差评记录（消息阶段）
}

// RunOnce 同步执行一轮「先双名单、后增量消息」的自动回灌并返回报告。
// 供测试与 Integration 的手动触发使用；握手恢复走 NotifyReconnect。
func (e *Engine) RunOnce(ctx context.Context) (*Report, error) {
	rep := &Report{Scope: e.cfg.Scope}
	if e.cfg.Scope == ScopeNone {
		rep.Skipped = true
		return rep, nil
	}
	srcs := e.activeSources()
	rep.SourcesAsked = len(srcs)

	// ---- 阶段 1：双名单副本（黑名单优先拉齐）----
	replies := fetchSnapshots(ctx, srcs)
	rep.SourcesResponded = len(replies)
	rep.Merge = mergeSnapshots(replies, e.roster, e.penalize)

	// ---- 阶段 2：增量消息多源交叉比对 ----
	after := e.windowAfterTS()
	rep.AfterTS = after
	if len(replies) < e.cfg.MinSources {
		rep.MsgPhaseSkipped = fmt.Sprintf("%v: %d responding < %d required", ErrTooFewSources, len(replies), e.cfg.MinSources)
		return rep, nil
	}
	msgs := fetchMessages(ctx, srcs, Query{AfterTS: after})
	cr := crossCheck(msgs, e.roster, e.store, e.cfg, after, e.penalize)
	rep.Accepted = len(cr.Accepted)
	rep.Drops = cr.Drops
	e.deliver(cr.Accepted)
	return rep, nil
}

// windowAfterTS 按 scope 计算消息拉取下界。
func (e *Engine) windowAfterTS() int64 {
	switch e.cfg.Scope {
	case ScopeAll:
		return 0
	case ScopeRecentDays:
		w := e.now() - int64(e.cfg.Days)*24*int64(time.Hour/time.Millisecond)
		if m := e.store.MaxTS(); m < w {
			return m // 本机更旧时以本机为准，避免重复拉取已存区间之外的数据
		}
		return w
	default: // ScopeIncremental
		return e.store.MaxTS()
	}
}

// deliver 把通过比对的消息落盘。名单事件已在 crossCheck 内经 ApplyEvent 应用，
// 这里只补 Store.Append（store 负责聊天流显示/隐藏等后续语义）。
func (e *Engine) deliver(msgs []core.Message) {
	for _, m := range msgs {
		if e.store.Has(m.MsgID) {
			continue
		}
		_ = e.store.Append(m)
	}
}

// ---- 并发拉取辅助 ----

func fetchSnapshots(ctx context.Context, srcs []Source) []snapReply {
	out := make([]snapReply, 0, len(srcs))
	type res struct {
		r  snapReply
		ok bool
	}
	ch := make(chan res, len(srcs))
	var wg sync.WaitGroup
	for _, s := range srcs {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			snap, err := s.FetchSnapshot(ctx)
			if err != nil {
				return
			}
			ch <- res{r: snapReply{Src: s.ID(), Snap: snap}, ok: true}
		}(s)
	}
	wg.Wait()
	close(ch)
	for r := range ch {
		if r.ok {
			out = append(out, r.r)
		}
	}
	sortSnapReplies(out)
	return out
}

func fetchMessages(ctx context.Context, srcs []Source, q Query) []srcMsgs {
	out := make([]srcMsgs, 0, len(srcs))
	type res struct {
		r  srcMsgs
		ok bool
	}
	ch := make(chan res, len(srcs))
	var wg sync.WaitGroup
	for _, s := range srcs {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			ms, err := s.FetchMessages(ctx, q)
			if err != nil {
				return
			}
			ch <- res{r: srcMsgs{Src: s.ID(), Msgs: ms}, ok: true}
		}(s)
	}
	wg.Wait()
	close(ch)
	for r := range ch {
		if r.ok {
			out = append(out, r.r)
		}
	}
	sortMsgReplies(out)
	return out
}
