package backfill

import (
	"context"
	"sort"

	"dmesh/internal/core"
)

// AuditReport 是一次按需一致性核查（/audit）的结果。
type AuditReport struct {
	SourcesAsked     int
	SourcesResponded int
	Merge            *MergeResult // 采纳远端缺失条目（补 proof 验证）的阶段结果
	Adopted          int          // 新采纳的名单条目数（bans+members）
	LocalEntryDrops  []Drop       // 本机名单副本中被证实伪签/越权的条目（已经 Cleaner 剔除或仅报告）
	LocalMsgDrops    []Drop       // 本机消息库中被剔除的伪签/无佐证条目
	Suspicious       []string     // 无法定论的可疑项说明（如本机条目因未注册算法暂无法复核）
}

// Audit 实现「按需一致性核查」：多邻居分别交换白/黑名单条目集与 msg_id 集合，
// 对比差异；缺的条目补 proof 验证，伪签/越权/偏离多数派 → 丢弃 + 差评/断连。
//
// 步骤：
//  1. 拉各邻居双名单副本，走与回灌相同的 mergeSnapshots 采纳本机缺失条目；
//  2. 复核本机名单副本每条 proof（单节点篡改本地文件即在此被揪出）：伪签/
//     越权条目经 Cleaner 剔除（未接线 Clean 仅报告）；
//  3. msg_id 集合比对：本机有、邻居全无且验签失败或全体缺席 → Reject 剔除；
//     本机缺、≥MinAgree 邻居有 → 精确补拉并走 crossCheck（多源交叉比对）。
func (e *Engine) Audit(ctx context.Context) (*AuditReport, error) {
	srcs := e.activeSources()
	rep := &AuditReport{SourcesAsked: len(srcs)}
	if len(srcs) < e.cfg.MinSources {
		return rep, ErrTooFewSources
	}

	// ---- 1. 名单条目集：采纳远端佐证差异 ----
	replies := fetchSnapshots(ctx, srcs)
	rep.SourcesResponded = len(replies)
	rep.Merge = mergeSnapshots(replies, e.roster, e.penalize)
	if rep.Merge != nil {
		rep.Adopted = rep.Merge.BansApplied + rep.Merge.MembersApplied
	}

	// ---- 2. 复核本机名单副本（篡改本地名单文件 → 揪出丢弃） ----
	members, banned, _ := e.roster.Snapshot()
	for _, me := range members {
		if err := applyEventProof(me.Proof, e.roster); err != nil {
			// 已应用过的事件重应用可能报「重复」类错误：仅对可判定的伪签/
			// 越权/结构错剔除，未知算法归可疑（本机暂未注册该 alg 而非条目坏）。
			switch reason := proofReason(err); reason {
			case DropUnknownAlg:
				rep.Suspicious = append(rep.Suspicious, "local member "+me.Pub.String()+": "+err.Error())
			case DropBadSig, DropMalformed, DropOverreach, DropEventRejected:
				d := Drop{Peer: me.Pub, Reason: reason, Detail: "local roster entry failed proof re-verify: " + err.Error()}
				if !e.reappliedCleanly(me.Proof, e.roster) {
					rep.LocalEntryDrops = append(rep.LocalEntryDrops, d)
					if e.cleaner != nil {
						e.cleaner.DropMember(me.Pub, string(reason)+": "+err.Error())
					}
				}
			}
		}
	}
	for _, be := range banned {
		if err := applyEventProof(be.Proof, e.roster); err != nil {
			switch reason := proofReason(err); reason {
			case DropUnknownAlg:
				rep.Suspicious = append(rep.Suspicious, "local ban "+be.Pub.String()+": "+err.Error())
			case DropBadSig, DropMalformed, DropOverreach, DropEventRejected:
				d := Drop{Peer: be.Pub, Reason: reason, Detail: "local blacklist entry failed proof re-verify: " + err.Error()}
				if !e.reappliedCleanly(be.Proof, e.roster) {
					rep.LocalEntryDrops = append(rep.LocalEntryDrops, d)
					if e.cleaner != nil {
						e.cleaner.DropBan(be.Pub, string(reason)+": "+err.Error())
					}
				}
			}
		}
	}

	// ---- 3. msg_id 集合比对 ----
	after := e.windowAfterTS()
	if e.cfg.Scope == ScopeAll {
		after = 0
	}
	localIDs := e.store.MsgIDs(after)
	sort.Strings(localIDs)
	remoteCount := map[string]int{}           // msg_id -> 有多少邻居声称持有
	remoteSrc := map[string]map[string]bool{} // msg_id -> srcKey 集合
	srcByKey := map[string]Source{}           // srcKey -> Source
	ok := 0
	for _, s := range srcs {
		ids, err := s.FetchMsgIDs(ctx, after)
		if err != nil {
			continue
		}
		ok++
		srcKey := s.ID().Key()
		srcByKey[srcKey] = s
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				continue // 同一源重复声明只算一票
			}
			seen[id] = true
			if remoteSrc[id] == nil {
				remoteSrc[id] = map[string]bool{}
			}
			remoteSrc[id][srcKey] = true
			remoteCount[id]++
		}
	}

	// 3a. 本机独有（全体邻居缺席）或验签失败 → 剔除本机副本。
	for _, id := range localIDs {
		m, have := e.store.Get(id)
		if !have {
			if err := e.store.Reject(id, "index without data"); err == nil {
				rep.LocalMsgDrops = append(rep.LocalMsgDrops, Drop{MsgID: id, Reason: DropMalformed, Detail: "index without data"})
			}
			continue
		}
		if err := verifyMessageSig(m); err != nil {
			if core.IsUnknownAlg(err) {
				rep.Suspicious = append(rep.Suspicious, "local msg "+id+": "+err.Error())
				continue
			}
			if err := e.store.Reject(id, err.Error()); err == nil {
				rep.LocalMsgDrops = append(rep.LocalMsgDrops, Drop{MsgID: id, Reason: DropBadSig, Detail: err.Error()})
			}
			continue
		}
		if ok >= e.cfg.MinSources && remoteCount[id] == 0 {
			// 验签通过但所有应答邻居都声称没有：偏离多数派（可能是.sender 私下
			// 塞给本机的越权/重放素材，或本机被诱导写入）→ 丢弃，无归属差评。
			if err := e.store.Reject(id, "absent from all responding peers"); err == nil {
				rep.LocalMsgDrops = append(rep.LocalMsgDrops, Drop{MsgID: id, Reason: DropMajorityAbsent, Detail: "no responding peer has this msg_id"})
			}
		}
	}

	// 3b. 本机缺失、远端有佐证的 msg_id → 精确补拉 + 复用 crossCheck 多源比对。
	var missing []string
	for id, n := range remoteCount {
		if n >= e.cfg.MinAgree && !e.store.Has(id) {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		bySrc := map[string][]string{}
		for _, id := range missing {
			for srcKey := range remoteSrc[id] {
				bySrc[srcKey] = append(bySrc[srcKey], id)
			}
		}
		keys := make([]string, 0, len(bySrc))
		for k := range bySrc {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var fetchReplies []srcMsgs
		for _, k := range keys {
			s := srcByKey[k]
			ms, err := s.FetchByMsgIDs(ctx, bySrc[k])
			if err != nil {
				continue
			}
			fetchReplies = append(fetchReplies, srcMsgs{Src: s.ID(), Msgs: ms})
		}
		sortMsgReplies(fetchReplies)
		if len(fetchReplies) > 0 {
			cr := crossCheck(fetchReplies, e.roster, e.store, e.cfg, 0, e.penalize)
			e.deliver(cr.Accepted)
			if rep.Merge != nil {
				rep.Merge.Drops = append(rep.Merge.Drops, cr.Drops...)
			}
		}
	}
	return rep, nil
}

// reappliedCleanly 判定一次「本机条目重应用失败」是否实为幂等假阳性：若重放
// 原事件本身能通过验证并幂等应用（返回 nil），说明条目合法、错误来自上层
// 「重复应用」类语义，保留之。
func (e *Engine) reappliedCleanly(pr core.Proof, r core.Roster) bool {
	m, err := eventFromProof(pr)
	if err != nil {
		return false
	}
	return r.ApplyEvent(m) == nil
}

// verifyMessageSig 独立复核一条已存消息的签名（audit 本机消息用）。
func verifyMessageSig(m core.Message) error {
	payload, err := core.MessageSigPayload(m)
	if err != nil {
		return err
	}
	if m.Alg != "" && m.Alg != m.Sender.Alg {
		return core.ErrInvalidSig
	}
	return core.Verify(m.Sender, payload, m.Sig)
}
