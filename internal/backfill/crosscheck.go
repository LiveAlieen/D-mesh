package backfill

import (
	"encoding/hex"
	"sort"

	"dmesh/internal/core"
)

// DropReason 是丢弃原因分类（同时是差评记账的原因码）。
type DropReason string

const (
	DropBadSig         DropReason = "bad_signature"        // 伪签：验签不通过 / alg 与公钥不符
	DropUnknownAlg     DropReason = "unknown_alg"          // 未注册 sig_alg：拒绝采纳+差评（v16）
	DropDiscrepancy    DropReason = "source_discrepancy"   // 同一 msg_id 各源内容不一致且无多数
	DropSelfConflict   DropReason = "source_self_conflict" // 同一源对同一 msg_id 给出多个不同有效版本
	DropSingleSource   DropReason = "single_source"        // 仅单源出现：丢弃（来源为唯一提供者时差评）
	DropNoSpeak        DropReason = "no_speak_perm"        // 接收时名单判定发送者无 speak 权限
	DropBlacklisted    DropReason = "blacklisted_sender"   // 发送者在黑名单且非定向申诉
	DropEventRejected  DropReason = "event_rejected"       // 名单事件被 Roster 验证拒绝（越权/自签违规等）
	DropOverreach      DropReason = "overreach"            // proof 有效但签发者层级/权限不足
	DropMalformed      DropReason = "malformed"            // 结构非法（空 msg_id、proof 无原文等）
	DropMissingProof   DropReason = "missing_proof"        // 条目缺 proof 且其他源也补不齐：丢弃不差评
	DropMajorityAbsent DropReason = "majority_absent"      // audit：本机条目无任何邻居佐证
)

// Drop 是一条丢弃记录：Peer 为被差评的来源（可为零值表示无归属）。
type Drop struct {
	MsgID  string
	Peer   core.PubKey
	Reason DropReason
	Detail string
}

// srcMsgs 是一个邻居对同一区间消息集的应答。
type srcMsgs struct {
	Src  core.PubKey
	Msgs []core.Message
}

func sortMsgReplies(v []srcMsgs) {
	sort.Slice(v, func(i, j int) bool { return v[i].Src.Key() < v[j].Src.Key() })
}

// CrossResult 是多源交叉比对的结论。
type CrossResult struct {
	Accepted []core.Message // 通过比对（名单事件已在比对时经 ApplyEvent 应用）
	Drops    []Drop
}

// crossCheck 是回灌消息阶段的核心纯逻辑（PLAN：≥3 邻居同区间、msg_id 去重、
// 多源交叉比对；不一致/仅单源/伪签 → 丢弃 + 来源差评；发言权按接收时名单判定）。
//
// replies 必须是同一 Query 区间的应答；nSources 取 len(replies)。
// afterTS 之前的消息视为越界，静默忽略（不差评：来源可能只是多带了旧数据）。
// 本机已有的 msg_id 直接跳过（去重，不参与比对也不重复应用）。
func crossCheck(
	replies []srcMsgs,
	r core.Roster,
	st Store,
	cfg Config,
	afterTS int64,
	penalize func(core.PubKey, DropReason, string),
) *CrossResult {
	type cpy struct {
		src core.PubKey
		m   core.Message
	}
	byID := map[string][]cpy{}
	res := &CrossResult{}

	for _, rp := range replies {
		for _, m := range rp.Msgs {
			if m.MsgID == "" {
				res.drop(rp.Src, "", DropMalformed, "empty msg_id", penalize)
				continue
			}
			if st != nil && st.Has(m.MsgID) {
				continue // 本机已有：去重跳过
			}
			if m.TSms < afterTS {
				continue // 区间外旧数据：忽略
			}
			byID[m.MsgID] = append(byID[m.MsgID], cpy{src: rp.Src, m: m})
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	nSources := len(replies)
	for _, id := range ids {
		copies := byID[id]
		// -- 逐份验签；按 (来源, 版本) 归组 --
		// variantBySrc[srcKey][variant] = 该来源给出的该版本
		variantBySrc := map[string]map[string]core.Message{}
		srcByKey := map[string]core.PubKey{}
		order := make([]string, 0, len(copies))
		for _, c := range copies {
			k := c.src.Key()
			if _, seen := srcByKey[k]; !seen {
				srcByKey[k] = c.src
				order = append(order, k)
			}
			payload, err := core.MessageSigPayload(c.m)
			if err != nil {
				res.drop(c.src, id, DropMalformed, err.Error(), penalize)
				continue
			}
			if c.m.Alg != "" && c.m.Alg != c.m.Sender.Alg {
				res.drop(c.src, id, DropBadSig, "sig_alg mismatch with sender", penalize)
				continue
			}
			if err := core.Verify(c.m.Sender, payload, c.m.Sig); err != nil {
				if core.IsUnknownAlg(err) {
					res.drop(c.src, id, DropUnknownAlg, err.Error(), penalize)
				} else {
					res.drop(c.src, id, DropBadSig, err.Error(), penalize)
				}
				continue
			}
			canon, err := core.CanonicalJSON(c.m)
			if err != nil {
				res.drop(c.src, id, DropMalformed, err.Error(), penalize)
				continue
			}
			vk := hex.EncodeToString(canon)
			if variantBySrc[k] == nil {
				variantBySrc[k] = map[string]core.Message{}
			}
			variantBySrc[k][vk] = c.m
		}

		// -- 按版本统计支持来源数（版本=整条消息的 CanonicalJSON） --
		support := map[string]map[string]bool{} // variant -> set(srcKey)
		witness := map[string]core.Message{}    // variant -> 任一有效副本
		for _, sk := range order {
			variants := variantBySrc[sk]
			if len(variants) > 1 {
				// 同一来源对同一 msg_id 自相矛盾地给出两个都验得过签的版本：
				// 数据不可信，该来源此条全部弃用并差评。
				res.drop(srcByKey[sk], id, DropSelfConflict, "same source gave conflicting signed variants", penalize)
				continue
			}
			for vk, m := range variants {
				if support[vk] == nil {
					support[vk] = map[string]bool{}
					witness[vk] = m
				}
				support[vk][sk] = true
			}
		}
		if len(support) == 0 {
			continue // 所有副本都已按原因丢弃并差评
		}

		// 选多数版本；并列即「各源不一致」→ 全部丢弃 + 所有涉事来源差评。
		vks := make([]string, 0, len(support))
		for vk := range support {
			vks = append(vks, vk)
		}
		sort.Slice(vks, func(i, j int) bool {
			ci, cj := len(support[vks[i]]), len(support[vks[j]])
			if ci != cj {
				return ci > cj
			}
			return vks[i] < vks[j]
		})
		if len(vks) > 1 && len(support[vks[0]]) == len(support[vks[1]]) {
			for _, vk := range vks {
				for sk := range support[vk] {
					res.drop(srcByKey[sk], id, DropDiscrepancy, "sources disagree, no majority", penalize)
				}
			}
			continue
		}
		best := vks[0]
		nSup := len(support[best])
		// 少数版本存在（多数唯一）：少数派来源差评，多数派继续走接收时名单判定。
		for _, vk := range vks[1:] {
			for sk := range support[vk] {
				res.drop(srcByKey[sk], id, DropDiscrepancy, "minority variant vs majority", penalize)
			}
		}
		// 多源门槛：应答源足够时，仅单源（<MinAgree）出现 → 丢弃；
		// 唯一来源被差评（伪造/扣留共谋的可疑信号）。
		if nSources >= cfg.MinSources && nSup < cfg.MinAgree {
			detail := "msg_id present in only one responding source"
			if nSup == 1 {
				for sk := range support[best] {
					res.drop(srcByKey[sk], id, DropSingleSource, detail, penalize)
				}
			} else {
				res.drop(core.PubKey{}, id, DropSingleSource, detail, nilSafe(penalize))
			}
			continue
		}

		m := witness[best]
		// -- 接收时名单判定（发言权 / 黑名单 / 事件验证） --
		appeal := false
		if r.IsBlacklisted(m.Sender) {
			if !directedAppeal(r, m) {
				for sk := range support[best] {
					res.drop(srcByKey[sk], id, DropBlacklisted, "sender blacklisted", penalize)
				}
				continue
			}
			appeal = true // 定向申诉唯一通道：仅放行给解禁权限者，不要求 speak
		}
		name, _ := core.BodyName(m.Body)
		switch name {
		case core.NameText, core.NameHide:
			if !appeal && !r.HasPerm(m.Sender, core.PermSpeak) {
				for sk := range support[best] {
					res.drop(srcByKey[sk], id, DropNoSpeak, "sender lacks speak at receive time", penalize)
				}
				continue
			}
		default:
			// 名单事件（含 presence）：与实时广播同一验证路径（验签+层级+自签规则）。
			if err := r.ApplyEvent(m); err != nil {
				reason := DropEventRejected
				if core.IsUnknownAlg(err) {
					reason = DropUnknownAlg
				} else if core.IsNotPermitted(err) {
					reason = DropOverreach
				}
				for sk := range support[best] {
					res.drop(srcByKey[sk], id, reason, err.Error(), penalize)
				}
				continue
			}
		}
		res.Accepted = append(res.Accepted, m)
	}
	return res
}

func (r *CrossResult) drop(peer core.PubKey, id string, reason DropReason, detail string, penalize func(core.PubKey, DropReason, string)) {
	r.Drops = append(r.Drops, Drop{MsgID: id, Peer: peer, Reason: reason, Detail: detail})
	if penalize != nil {
		penalize(peer, reason, detail)
	}
}

// nilSafe 兜底：penalize 理论上不会是 nil，防御性处理。
func nilSafe(f func(core.PubKey, DropReason, string)) func(core.PubKey, DropReason, string) {
	if f == nil {
		return func(core.PubKey, DropReason, string) {}
	}
	return f
}

// directedAppeal 判定黑名单发送者的消息是否为合规的定向申诉：To 指向具解禁
// 权限（kick/unban）的成员——PLAN「唯一通道」。
func directedAppeal(r core.Roster, m core.Message) bool {
	if m.To == nil {
		return false
	}
	return r.HasPerm(*m.To, core.PermUnban) || r.HasPerm(*m.To, core.PermKick)
}
