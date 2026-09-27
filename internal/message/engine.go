package message

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"dmesh/internal/core"
)

// Transport 是 transport/neighbor 包注入的发送通道：向指定邻居 pubkey 写一个完整帧。
// 实现必须并发安全；对未连接/被拒的邻居返回 error（消息层只记数，不重试——
// flood 本身多路径，重试归 backfill）。
type Transport interface {
	Send(to core.PubKey, frame []byte) error
}

// PeerSource 注入当前活跃邻居列表（neighbor 包实现）。flood 与 join_req 中继都以此为扇出集。
type PeerSource interface {
	Peers() []core.PubKey
}

// Kind 是消息被受理后的投递类别（决定进哪个 UI 面板；聊天流只显示 KindChat）。
type Kind int

const (
	KindNone Kind = iota
	KindChat
	KindRosterEvent      // 名单事件：同路广播、聊天流不显示
	KindHide             // hide 事件本体（聊天流不显示）
	KindAppeal           // 黑名单成员的定向申诉（仅解禁权限者可见）
	KindJoinReq          // 入群请求（递送给 carry 权限者，聊天流不显示）
	KindTransferProposal // transfer 联署提案（v17①：定向 to=新 owner、EndorseSig 为空）
)

// String 供日志与断言。
func (k Kind) String() string {
	switch k {
	case KindChat:
		return "chat"
	case KindRosterEvent:
		return "roster_event"
	case KindHide:
		return "hide"
	case KindAppeal:
		return "appeal"
	case KindJoinReq:
		return "join_req"
	case KindTransferProposal:
		return "transfer_proposal"
	default:
		return "none"
	}
}

// RejectReason 是拒收原因（同时作为来源差评的理由标签，供 spam 包邻居评分使用）。
type RejectReason string

const (
	ReasonNone        RejectReason = ""
	ReasonMalformed   RejectReason = "malformed_frame"
	ReasonUnknownAlg  RejectReason = "unknown_sig_alg"     // v16：本地未注册 alg → 拒绝采纳 + 差评
	ReasonBadSig      RejectReason = "invalid_signature"   // 伪签
	ReasonDuplicate   RejectReason = "duplicate"           // 去重命中（不差评，只抑制）
	ReasonBlacklisted RejectReason = "blacklisted_sender"  // 黑名单且非合法申诉通道
	ReasonNotMember   RejectReason = "not_member"          // 非成员发聊天/事件
	ReasonNoSpeak     RejectReason = "no_speak_perm"       // 无 speak 权限
	ReasonOverreach   RejectReason = "event_not_permitted" // 越权事件（层级/自签规则不满足）
	ReasonBadEvent    RejectReason = "event_rejected"      // ApplyEvent 的其他失败
	ReasonHideSelf    RejectReason = "hide_invalid"        // hide 规则不满足（目标异主 / hide 被 hide）
	ReasonUnknownName RejectReason = "unknown_name"        // body 名不在注册表 / 与 kind 不符
)

// Outcome 是一次 Ingest/Publish 的结果。
type Outcome struct {
	Accepted  bool         // 已受理（投递且可转发）
	Delivered bool         // 已交给本机 Handlers（定向消息发给别人时为 false 但仍转发）
	Flooded   int          // 实际推送到的邻居数（flood 或 carry 中继）
	Duplicate bool         // 去重命中：静默吞掉，不投递、不转发、不差评
	Kind      Kind         // 投递类别
	Reason    RejectReason // 拒收原因（Accepted 时为 ReasonNone；Duplicate 时记 ReasonDuplicate）
	Err       error
}

// Handlers 是本机上层（store/ui/group/spam）注入的回调；全部允许为 nil（吞掉即可）。
// 回调在 Ingest 的调用栈内同步执行，须尽快返回（UI 应投递到 channel）。
type Handlers struct {
	Chat        func(core.Message) // text（To 为空或指向本机才显示）
	RosterEvent func(core.Message) // 名单事件（聊天流不显示）
	Hide        func(core.Message) // hide 事件本体
	Appeal      func(core.Message) // 黑名单成员发给本机的定向申诉
	JoinReq     func(core.Message) // 本机具 carry 权限时受理的入群请求
	// TransferProposal 本机收到的 v17① 联署提案（To=本机、EndorseSig 为空、
	// 签名者已核为现任 owner/创建者）；宿主入收件箱展示，批准时补联署广播。
	TransferProposal func(core.Message)
	SoftDelete       func(targetMsgID string)
	// Lookup 查本机已知消息（store 提供）；hide 校验「target 与原发送者同 pubkey」
	// 与「hide 不可被 hide」用。nil 或查不到 → 进入短期待补队列，目标到达时再校验。
	Lookup func(msgID string) (core.Message, bool)
	// Penalty 来源差评：验签失败/未知 alg/黑名单/越权等一律先丢弃再回调。
	Penalty func(from core.PubKey, reason RejectReason, m *core.Message, err error)
	// PeerOnline 可选：覆盖在场判定（如邻居表掌握实时连接状态）；nil 时用 Roster.Presence。
	PeerOnline func(pub core.PubKey) bool
}

// Engine 是消息层核心：接收解码 → 验签（core.Verify，未知 alg 拒绝+差评）→
// 去重（msg_id + TTL + 来源抑制）→ 名单/权限判定 → 投递 → flood 转发（排除来源）。
//
// 零值不可直接用，请用 NewEngine；Self/Roster/Transport/Peers 之外的字段可留默认。
// Roster 为 nil 时进入「纯逻辑模式」：跳过黑名单/权限/ApplyEvent，只验签与去重
// （供单测与尚未接线名单的启动早期使用）。
type Engine struct {
	GroupID  [32]byte
	Self     core.PubKey
	Roster   core.Roster
	Trans    Transport
	Peers    PeerSource
	Handlers Handlers

	DedupTTL       time.Duration // 去重 TTL，默认 DefaultDedupTTL
	JoinRelayTTL   time.Duration // join_req 中继防风暴缓存 TTL，默认同 DedupTTL
	DedupCap       int           // 去重缓存条数上限，默认 65536
	NoForward      bool          // true = 只投递不转发（叶子节点/调试）
	PendingHideTTL time.Duration // hide 待补队列 TTL，默认 1 小时
	Now            func() time.Time

	mu      sync.Mutex
	once    sync.Once
	dedup   *Deduper
	relay   *Deduper
	pending *pendingHides
}

// NewEngine 装配消息引擎；必填 GroupID/Self，其余接口可 nil（见 Engine 文档）。
func NewEngine(groupID [32]byte, self core.PubKey, roster core.Roster, tr Transport, peers PeerSource, h Handlers) *Engine {
	return &Engine{
		GroupID:  groupID,
		Self:     self,
		Roster:   roster,
		Trans:    tr,
		Peers:    peers,
		Handlers: h,
	}
}

func (e *Engine) init() {
	e.once.Do(func() {
		now := e.Now
		if now == nil {
			now = time.Now
		}
		e.dedup = NewDeduper(e.DedupTTL, e.DedupCap, now)
		ttl := e.JoinRelayTTL
		if ttl <= 0 {
			ttl = e.DedupTTL
		}
		e.relay = NewDeduper(ttl, e.DedupCap, now)
		pttl := e.PendingHideTTL
		if pttl <= 0 {
			pttl = time.Hour
		}
		e.pending = newPendingHides(pttl, now)
	})
}

func (e *Engine) nowMS() int64 {
	if e.Now != nil {
		return e.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// Ingest 处理一个从邻居 from 收到的帧。返回 Outcome 供上层观测（不强制处理）。
func (e *Engine) Ingest(from core.PubKey, data []byte) Outcome {
	e.init()
	m, err := DecodeFrame(data)
	if err != nil {
		return e.reject(nil, from, ReasonMalformed, err)
	}
	return e.process(from, data, &m)
}

// IngestMessage 处理已解码的消息（store/backfill 复验同一条规则时复用）。
func (e *Engine) IngestMessage(from core.PubKey, m core.Message) Outcome {
	e.init()
	raw, err := json.Marshal(m)
	if err != nil {
		return e.reject(&m, from, ReasonMalformed, err)
	}
	return e.process(from, raw, &m)
}

func (e *Engine) process(from core.PubKey, raw []byte, m *core.Message) Outcome {
	// 0. 结构：必须属于本群。
	if m.GroupID != e.GroupID {
		return e.reject(m, from, ReasonMalformed, fmt.Errorf("%w: group_id mismatch", core.ErrMalformed))
	}
	// 1. 验签（core.Verify 按 sig_alg 分派；未知 alg → 拒绝采纳 + 差评，绝不误信）。
	if err := VerifyMessage(*m); err != nil {
		reason := ReasonBadSig
		if core.IsUnknownAlg(err) {
			reason = ReasonUnknownAlg
		} else if errors.Is(err, core.ErrMalformed) {
			reason = ReasonMalformed
		}
		return e.reject(m, from, reason, err)
	}
	// body 名先行解析，仅供下面的 transfer 提案判定使用；kind↔name 交叉校验
	// 留在第 4 步路由之前做，保证去重登记与差评的时机与 v25 完全一致。
	name, _ := core.BodyName(m.Body)
	// 1.5 v17① transfer 联署提案（定向 to=新 owner、EndorseSig 为空）：
	//     必须先去重登记之前截获——提案与联署完成后的生效事件共享 msg_id
	//     （联署绑定原文含 MsgID），若让提案进主 dedup，生效事件会被各节点
	//     当重复包吞掉，移交永远无法生效。
	if name == core.NameTransfer && m.To != nil && len(m.EndorseSig) == 0 {
		return e.handleTransferProposal(m, raw, from)
	}
	// 2. 去重（验签后才记录，防止攻击者用伪造 msg_id 投毒缓存）：
	//    命中即静默吞掉 —— 不投递、不转发、不差评（防 flood 风暴）。
	switch e.dedup.Observe(m.MsgID, from) {
	case DedupSameSource, DedupOtherSource:
		return Outcome{Duplicate: true, Reason: ReasonDuplicate}
	}
	// 3. 黑名单准入：唯一例外 = To 指向本机且本机具解禁权限的定向申诉；
	//    被拒者不 flood（其他成员「不收也不转发」）。
	if e.Roster != nil && e.Roster.IsBlacklisted(m.Sender) {
		if m.To != nil && m.To.Equal(e.Self) && e.selfCanUnban() {
			if h := e.Handlers.Appeal; h != nil {
				h(*m)
			}
			return Outcome{Accepted: true, Delivered: true, Kind: KindAppeal}
		}
		return e.reject(m, from, ReasonBlacklisted, fmt.Errorf("%w: sender %s is blacklisted", core.ErrNotPermitted, m.Sender))
	}
	// 4. 按具体消息名路由。kind↔name 交叉校验在此复检：把名单命令伪装成 msg
	//    （想绕过名单权限检查）在受理前即被挡下并差评。
	if _, err := core.CheckBody(m.Kind, m.Body); err != nil {
		return e.reject(m, from, ReasonUnknownName, err)
	}
	switch name {
	case core.NameJoinReq:
		return e.handleJoinReq(m, raw, from)
	case core.NameHide:
		return e.handleHide(m, raw, from)
	case core.NameText:
		return e.handleText(m, raw, from)
	default:
		if IsRosterEvent(name) {
			return e.handleRosterEvent(m, raw, from)
		}
		return e.reject(m, from, ReasonUnknownName, fmt.Errorf("%w: name %q", core.ErrMalformed, name))
	}
}

// handleText：成员 + speak 权限（发言权按「接收时名单」判定）；定向 To 只投递给目标；
// 受理后 flood。
func (e *Engine) handleText(m *core.Message, raw []byte, from core.PubKey) Outcome {
	if e.Roster != nil {
		if e.Roster.TierOf(m.Sender) < 0 {
			return e.reject(m, from, ReasonNotMember, fmt.Errorf("%w: %s not a member", core.ErrNotPermitted, m.Sender))
		}
		if !e.Roster.HasPerm(m.Sender, core.PermSpeak) {
			return e.reject(m, from, ReasonNoSpeak, fmt.Errorf("%w: %s lacks speak", core.ErrNotPermitted, m.Sender))
		}
	}
	directed := m.To != nil && !m.To.Equal(e.Self)
	if !directed {
		if h := e.Handlers.Chat; h != nil {
			h(*m)
		}
		e.flushPendingHides(m)
	}
	n := e.flood(raw, m, from)
	return Outcome{Accepted: true, Delivered: !directed, Flooded: n, Kind: KindChat}
}

// handleRosterEvent：交 core.Roster.ApplyEvent（内部完成层级 + 自签 + proof 校验），
// 通过则投递（聊天流不显示）+ flood；失败 → 丢弃 + 来源差评。
func (e *Engine) handleRosterEvent(m *core.Message, raw []byte, from core.PubKey) Outcome {
	if e.Roster != nil {
		if err := e.Roster.ApplyEvent(*m); err != nil {
			reason := ReasonBadEvent
			if core.IsNotPermitted(err) {
				reason = ReasonOverreach
			} else if core.IsUnknownAlg(err) {
				reason = ReasonUnknownAlg
			}
			return e.reject(m, from, reason, err)
		}
	}
	if h := e.Handlers.RosterEvent; h != nil {
		h(*m)
	}
	e.flushPendingHides(m)
	n := e.flood(raw, m, from)
	return Outcome{Accepted: true, Delivered: true, Flooded: n, Kind: KindRosterEvent}
}

// handleJoinReq：无许可中继——不 flood 全员，而是定向转给在场在线、具 carry 权限的
// 邻居；本机有 carry 权限则先受理。同一 join_req 只中继一轮（relay 去重防风暴）。
func (e *Engine) handleJoinReq(m *core.Message, raw []byte, from core.PubKey) Outcome {
	if e.relay.ObserveAnon(m.MsgID) != DedupFresh {
		return Outcome{Duplicate: true, Reason: ReasonDuplicate, Kind: KindJoinReq}
	}
	if e.selfCarries() {
		if h := e.Handlers.JoinReq; h != nil {
			h(*m)
		}
	}
	relayed := 0
	if e.Trans != nil && e.Peers != nil && !e.NoForward {
		now := e.nowMS()
		for _, p := range e.Peers.Peers() {
			if p.Equal(from) || p.Equal(m.Sender) || p.Equal(e.Self) {
				continue
			}
			if !e.peerCarriesAndOnline(p, now) {
				continue
			}
			if err := e.Trans.Send(p, raw); err == nil {
				relayed++
			}
		}
	}
	return Outcome{Accepted: true, Delivered: e.selfCarries(), Flooded: relayed, Kind: KindJoinReq}
}

// handleTransferProposal：v17① 联署提案的收件与定向递送。规则——
//  1. 签名者必须是当前具 transfer 权限的 owner/创建者（层级+权限在收时即核，
//     伪提案直接拒+差评），名单状态以接收时为准；
//  2. To=本机 → 交 Handlers.TransferProposal 入收件箱（绝不喂 ApplyEvent，
//     缺联署的原文进 ApplyEvent 只会误伤签发者信誉）；To=他人 → 经 relay
//     匿名去重定向转发一轮（防风暴，且不污染主 dedup——生效事件与其同 id）；
//  3. 提案本身永不被本机 ApplyEvent；生效走联署完成后的正式 transfer 事件。
func (e *Engine) handleTransferProposal(m *core.Message, raw []byte, from core.PubKey) Outcome {
	if e.Roster != nil {
		if e.Roster.IsBlacklisted(m.Sender) {
			return e.reject(m, from, ReasonBlacklisted, fmt.Errorf("%w: proposal sender %s is blacklisted", core.ErrNotPermitted, m.Sender))
		}
		if e.Roster.TierOf(m.Sender) < core.TierOwner || !e.Roster.HasPerm(m.Sender, core.PermTransfer) {
			return e.reject(m, from, ReasonOverreach, fmt.Errorf("%w: transfer proposal signer is not a current owner", core.ErrNotPermitted))
		}
	}
	delivered := false
	if m.To.Equal(e.Self) {
		delivered = true
		if h := e.Handlers.TransferProposal; h != nil {
			h(*m)
		}
	}
	relayed := 0
	if !delivered && e.relay.ObserveAnon(m.MsgID) == DedupFresh {
		relayed = e.flood(raw, m, from)
	}
	return Outcome{Accepted: true, Delivered: delivered, Flooded: relayed, Kind: KindTransferProposal}
}

// handleHide：target 必须与原消息同 pubkey；hide 不可被 hide；本机软删除 + flood。
// 目标未达时先挂起（pendingHide），目标到达时再校验执行——乱序不丢 hide。
func (e *Engine) handleHide(m *core.Message, raw []byte, from core.PubKey) Outcome {
	hc, err := DecodeHideBody(m.Body)
	if err != nil {
		return e.reject(m, from, ReasonMalformed, err)
	}
	if hc.TargetMsgID == m.MsgID {
		return e.reject(m, from, ReasonHideSelf, fmt.Errorf("%w: hide targets itself", core.ErrMalformed))
	}
	if tgt, ok := e.lookupTarget(hc.TargetMsgID); ok {
		if name, _ := core.BodyName(tgt.Body); name == core.NameHide {
			return e.reject(m, from, ReasonHideSelf, fmt.Errorf("%w: hide cannot target a hide", core.ErrNotPermitted))
		}
		if !tgt.Sender.Equal(m.Sender) {
			return e.reject(m, from, ReasonHideSelf, fmt.Errorf("%w: hide target sender mismatch", core.ErrNotPermitted))
		}
		e.softDelete(hc.TargetMsgID)
	} else {
		e.pending.add(pendingHide{
			targetID: hc.TargetMsgID,
			hideID:   m.MsgID,
			sender:   m.Sender,
			expire:   e.now().Add(e.effectivePendingTTL()),
		})
	}
	if h := e.Handlers.Hide; h != nil {
		h(*m)
	}
	n := e.flood(raw, m, from)
	return Outcome{Accepted: true, Delivered: true, Flooded: n, Kind: KindHide}
}

// Publish 把本机已签名的消息推给全部邻居，并在本机去重缓存登记
// （后续任何邻居回推同一条都会被来源抑制吞掉）。不回调本机 Handlers——
// 落盘/显示由调用方（store/ui）自己完成。
func (e *Engine) Publish(m core.Message) (int, error) {
	e.init()
	if m.GroupID != e.GroupID {
		return 0, fmt.Errorf("%w: group_id mismatch on publish", core.ErrMalformed)
	}
	if err := VerifyMessage(m); err != nil {
		return 0, err
	}
	raw, err := EncodeFrame(m)
	if err != nil {
		return 0, err
	}
	e.dedup.Observe(m.MsgID, e.Self)
	return e.flood(raw, &m, e.Self), nil
}

// PublishProposal v17①：现任 owner 定向广播 transfer 联署提案（To=新 owner、
// EndorseSig 为空）。与 Publish 的两点区别——
//  1. 不登记主 dedup：提案与生效事件共享 msg_id（联署绑定原文含 MsgID），
//     登记后新 owner 补联署回推的生效事件会被本机自己吞掉；
//  2. 不本地 ApplyEvent：缺联署原文进 ApplyEvent 必被拒，本机坐等生效事件
//     返回即可。
func (e *Engine) PublishProposal(m core.Message) (int, error) {
	e.init()
	if m.GroupID != e.GroupID {
		return 0, fmt.Errorf("%w: group_id mismatch on publish", core.ErrMalformed)
	}
	if name, err := core.CheckBody(m.Kind, m.Body); err != nil || name != core.NameTransfer || m.To == nil || len(m.EndorseSig) != 0 {
		return 0, fmt.Errorf("%w: not a transfer proposal (need cmd/transfer, to set, empty endorse_sig)", core.ErrMalformed)
	}
	if err := VerifyMessage(m); err != nil {
		return 0, err
	}
	raw, err := EncodeFrame(m)
	if err != nil {
		return 0, err
	}
	return e.flood(raw, &m, e.Self), nil
}

// flood 把原始帧推给除 excludeFrom（来向那一跳）与本机外的所有邻居（每源一跳
// + msg_id 去重 = 全网收敛）。注意不得按 m.Sender 排除：v17① 联署 transfer 的
// 生效事件 Sender=原提案者、由新 owner 发布，必须能送达原提案者本人；
// 回声由去重缓存兜底，不构成风暴。
func (e *Engine) flood(raw []byte, m *core.Message, excludeFrom core.PubKey) int {
	if e.NoForward || e.Trans == nil || e.Peers == nil {
		return 0
	}
	n := 0
	for _, p := range e.Peers.Peers() {
		if p.Equal(excludeFrom) || p.Equal(e.Self) {
			continue
		}
		if err := e.Trans.Send(p, raw); err == nil {
			n++
		}
	}
	return n
}

// Seen 报告 msg_id 是否已在去重缓存（backfill/store 判增量用；只读不记录）。
func (e *Engine) Seen(msgID string) bool {
	e.init()
	return e.dedup.Contains(msgID)
}

// Forget 清除某 msg_id 的去重记录（一致性核查重新采纳时使用）。
func (e *Engine) Forget(msgID string) {
	e.init()
	e.dedup.Forget(msgID)
}

func (e *Engine) selfCarries() bool {
	return e.Roster == nil || e.Roster.HasPerm(e.Self, core.PermCarry)
}

func (e *Engine) selfCanUnban() bool {
	if e.Roster == nil {
		return true
	}
	if e.Roster.HasPerm(e.Self, core.PermUnban) || e.Roster.HasPerm(e.Self, core.PermKick) {
		return true
	}
	return e.Roster.TierOf(e.Self) >= core.TierOwner
}

func (e *Engine) peerCarriesAndOnline(p core.PubKey, nowMS int64) bool {
	if e.Handlers.PeerOnline != nil {
		if !e.Handlers.PeerOnline(p) {
			return false
		}
	} else if e.Roster != nil {
		if !e.Roster.Presence(p).Online(nowMS) {
			return false
		}
	}
	if e.Roster == nil {
		return true // 纯逻辑模式：无名单则不做 carry 判定，全部邻居皆可中继
	}
	return e.Roster.HasPerm(p, core.PermCarry)
}

func (e *Engine) lookupTarget(id string) (core.Message, bool) {
	if e.Handlers.Lookup == nil {
		return core.Message{}, false
	}
	return e.Handlers.Lookup(id)
}

func (e *Engine) softDelete(targetMsgID string) {
	if h := e.Handlers.SoftDelete; h != nil {
		h(targetMsgID)
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) effectivePendingTTL() time.Duration {
	if e.PendingHideTTL > 0 {
		return e.PendingHideTTL
	}
	return time.Hour
}

// flushPendingHides 在目标消息到达时兑现挂起的 hide（仍守 hide 规则：
// hide 不可被 hide、目标须同 pubkey）。
func (e *Engine) flushPendingHides(m *core.Message) {
	name, _ := core.BodyName(m.Body)
	for _, ph := range e.pending.takeFor(m.MsgID) {
		if name == core.NameHide || !ph.sender.Equal(m.Sender) {
			continue
		}
		e.softDelete(m.MsgID)
		break
	}
}

// reject 统一「丢弃 + 来源差评」出口。
func (e *Engine) reject(m *core.Message, from core.PubKey, reason RejectReason, err error) Outcome {
	if h := e.Handlers.Penalty; h != nil {
		h(from, reason, m, err)
	}
	return Outcome{Reason: reason, Err: err}
}

// ---------- pendingHides ----------

type pendingHide struct {
	targetID string
	hideID   string
	sender   core.PubKey
	expire   time.Time
}

// pendingHides 是「目标未到」的 hide 短期待补队列（乱序容忍），带 TTL 防泄漏。
type pendingHides struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	byTarge map[string][]pendingHide // targetID -> 挂起的 hide
}

func newPendingHides(ttl time.Duration, now func() time.Time) *pendingHides {
	return &pendingHides{ttl: ttl, now: now, byTarge: make(map[string][]pendingHide)}
}

func (p *pendingHides) add(h pendingHide) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeLocked()
	p.byTarge[h.targetID] = append(p.byTarge[h.targetID], h)
}

func (p *pendingHides) takeFor(targetID string) []pendingHide {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.byTarge[targetID]
	delete(p.byTarge, targetID)
	return out
}

func (p *pendingHides) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, v := range p.byTarge {
		n += len(v)
	}
	return n
}

func (p *pendingHides) purgeLocked() {
	now := p.now()
	for k, list := range p.byTarge {
		keep := list[:0]
		for _, h := range list {
			if now.Before(h.expire) {
				keep = append(keep, h)
			}
		}
		if len(keep) == 0 {
			delete(p.byTarge, k)
		} else {
			p.byTarge[k] = keep
		}
	}
}

// PeersOf 对邻居做稳定排序（测试与确定性中继顺序用；PubKey 以 Key() 全序比较）。
func PeersOf(ps PeerSource) []core.PubKey {
	if ps == nil {
		return nil
	}
	out := append([]core.PubKey(nil), ps.Peers()...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
