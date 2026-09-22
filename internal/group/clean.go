// clean.go：v17 点 10c —— 本机脏条目的本地清洗（DropMember / DropBan）。
//
// 回灌/一致性核查多源比对发现**本机**白/黑名单条目是伪签、被篡改或偏离多数派
// 时，直接把该条脏数据从本机内存态删掉：
//
//   - 纯本地卫生操作：不产生任何网络事件、不写黑名单、不构成驱逐；
//   - 「删了等补」而非「删了即定」：清洗时一并忘掉该条目 proof 的 msg_id，
//     使多数派持有的正版事件能重新被采纳（否则会被幂等去重吞掉），
//     防本机被单源脏数据投毒后又被当成权威转发；
//   - 锚点保护：创建者条目由创世签名固定、当前 owner 指针所指向的条目
//     只在 transfer 事件链里变动，二者都拒绝被本机手滑剔掉（合法的剔除
//     只会以事件形式到来，届时指针自会推进）。
//
// 两方法签名与 backfill.Cleaner 一致，*Roster 直接满足该接口。
package group

import (
	"encoding/json"

	"dmesh/internal/core"
)

// 清洗记录的种类/动作常量（人读字符串，供审计与 UI 展示）。
const (
	DropKindMember = "member" // 白名单条目
	DropKindBan    = "ban"    // 黑名单条目

	DropActionDropped = "dropped"        // 已删除本机脏条目
	DropActionRefused = "refused-anchor" // 拒绝清洗（创建者/当前 owner 锚点）
	DropActionAbsent  = "absent"         // 本机无此条目（幂等，无需清洗）
)

// maxDropRecords 是清洗审计日志的环形上限（只为排障留痕，不构成历史）。
const maxDropRecords = 64

// DropRecord 是一条本机名单清洗的审计记录。
type DropRecord struct {
	Kind   string      `json:"kind"`   // DropKindMember / DropKindBan
	Action string      `json:"action"` // DropAction*
	Pub    core.PubKey `json:"pub"`
	Reason string      `json:"reason"`
	TSms   int64       `json:"ts_ms"`
}

// DropLog 返回本机清洗审计记录（时间升序副本）。
func (r *Roster) DropLog() []DropRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DropRecord, len(r.drops))
	copy(out, r.drops)
	return out
}

// recordDropLocked 追加一条审计记录（须持锁调用），超限丢最旧。
func (r *Roster) recordDropLocked(rec DropRecord) {
	rec.TSms = r.nowMS()
	r.drops = append(r.drops, rec)
	if len(r.drops) > maxDropRecords {
		r.drops = append([]DropRecord(nil), r.drops[len(r.drops)-maxDropRecords:]...)
	}
}

// DropMember 纯本地删除白名单条目（含其 proof），不产生网络事件、不进黑名单。
//
// 在场表条目**保留**：presence 是本人自签的展示性属性（v13.1），与被清洗的
// 权限条目无关，留着既不授予任何权限，也会在对方下一次心跳/发言时被自然刷新，
// 删它反而会让成员列表凭空显示「从未见过」。
//
// 创建者条目、以及当前 owner 指针所指向的条目拒绝清洗（防手滑剔锚）：
// 群主变更只经 transfer 事件链推进，退群/除名亦以事件形式到来。
//
// 该方法无返回值以匹配 backfill.Cleaner；结论（删了/拒了/本来就没有）连同
// reason 记入 DropLog，并以 RosterEvent（KindMemberDroppedLocal，纯本机通知）
// 交给宿主做持久化与展示。
func (r *Roster) DropMember(p core.PubKey, reason string) {
	var fired []RosterEvent
	r.mu.Lock()
	e, ok := r.members[p.Key()]
	rec := DropRecord{Kind: DropKindMember, Pub: clonePub(p), Reason: reason}
	switch {
	case !ok:
		rec.Action = DropActionAbsent
	case r.cfg.Creator.Equal(p):
		rec.Action = DropActionRefused
	case r.owner.Equal(p):
		rec.Action = DropActionRefused
	default:
		cp := memberCopy(*e)
		delete(r.members, cp.Pub.Key())
		r.forgetProofSeen(cp.Proof.Raw) // 删了等补：允许正版事件重新采纳
		rec.Action = DropActionDropped
		entry := cp
		fired = []RosterEvent{{Kind: KindMemberDroppedLocal, Pub: cp.Pub, Member: &entry, Reason: reason}}
	}
	r.recordDropLocked(rec)
	r.mu.Unlock()
	r.fire(fired)
}

// DropBan 纯本地删除黑名单条目（含封禁 proof）。
//
// 与 DropMember 不同，这里没有锚点豁免：创建者/群主「被封禁」的黑名单条目
// 本身就是最可疑的脏数据（合法路径上 kick 事件的层级校验根本不允许它生效），
// 而真实的封禁若存在，会由持有效 proof 的 kick 事件重新补回。
//
// 结论连同 reason 记入 DropLog，并以 KindBlacklistDroppedLocal 通知宿主。
func (r *Roster) DropBan(p core.PubKey, reason string) {
	var fired []RosterEvent
	r.mu.Lock()
	e, ok := r.blacklist[p.Key()]
	rec := DropRecord{Kind: DropKindBan, Pub: clonePub(p), Reason: reason}
	if !ok {
		rec.Action = DropActionAbsent
	} else {
		cp := blacklistCopy(*e)
		delete(r.blacklist, cp.Pub.Key())
		r.forgetProofSeen(cp.Proof.Raw) // 删了等补
		rec.Action = DropActionDropped
		entry := cp
		fired = []RosterEvent{{Kind: KindBlacklistDroppedLocal, Pub: cp.Pub, Banned: &entry, Reason: reason}}
	}
	r.recordDropLocked(rec)
	r.mu.Unlock()
	r.fire(fired)
}

// forgetProofSeen 忘掉某条目 proof（事件原文）的 msg_id，使同一条有效事件在
// 清洗之后能被重新验证并采纳，而不被 ApplyEvent 的幂等去重吞掉。
// proof.Raw = MessageSigPayload（含 msg_id），解不出来的静默跳过（保守：宁可
// 少补一次，也不因脏 raw 崩溃）。
func (r *Roster) forgetProofSeen(raw []byte) {
	if len(raw) == 0 {
		return
	}
	var hdr struct {
		MsgID string `json:"msg_id"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil || hdr.MsgID == "" {
		return
	}
	delete(r.seen, hdr.MsgID)
}
