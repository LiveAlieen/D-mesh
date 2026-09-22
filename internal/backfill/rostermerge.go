package backfill

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"dmesh/internal/core"
)

// snapReply 是一个邻居的双名单副本应答。
type snapReply struct {
	Src  core.PubKey
	Snap Snapshot
}

func sortSnapReplies(v []snapReply) {
	sort.Slice(v, func(i, j int) bool { return v[i].Src.Key() < v[j].Src.Key() })
}

// MergeResult 是双名单副本合并的结论。
type MergeResult struct {
	BansApplied    int
	MembersApplied int
	ProofsFilled   int           // 缺 proof 的条目从其他源补齐成功的数量
	PendingJoin    []core.PubKey // proof 有效但目标仍在黑名单：待 unban 事件对齐，未差评
	Drops          []Drop
}

// mergeSnapshots 实现「先拉双名单副本合并（逐条验 proof，黑名单优先拉齐）」：
//
//  1. 黑名单阶段：收集所有源的黑名单条目，按 proof 独立复验（VerifyProof，
//     签名者=事件原文中的 sender）后经 ApplyEvent 应用——黑名单优先，先把封禁
//     拉齐，堵住「本地还没有黑名单」窗口期。
//  2. 白名单阶段：按公钥分组；缺 proof 的条目向其他源补齐；逐条验 proof 后
//     ApplyEvent。若条目对应的公钥此刻已被（本轮或其他源）拉黑且事件被拒，
//     记入 PendingJoin 且不差评对方（可能是 unban+新 join 而本机尚未对齐
//     unban 事件；安全裁决留给名单事件链本身，不以时间戳论真伪）。
//
// 合并只看签名与签名者层级（广播无许可原则），不要求条目多源一致；
// owner 指针不直接采纳（经 transfer 事件生效）。
func mergeSnapshots(
	replies []snapReply,
	r core.Roster,
	penalize func(core.PubKey, DropReason, string),
) *MergeResult {
	mr := &MergeResult{}

	// ---- 阶段 1：黑名单 ----
	type banCpy struct {
		src core.PubKey
		e   core.BlacklistEntry
	}
	var bans []banCpy
	for _, rp := range replies {
		for _, be := range rp.Snap.Banned {
			bans = append(bans, banCpy{src: rp.Src, e: be})
		}
	}
	sort.SliceStable(bans, func(i, j int) bool {
		if bans[i].e.TS != bans[j].e.TS {
			return bans[i].e.TS < bans[j].e.TS
		}
		return bans[i].e.Pub.Key() < bans[j].e.Pub.Key()
	})
	{
		done := map[string]bool{} // 本轮已拉齐（应用成功或本机已有）的封禁公钥
		for _, b := range bans {
			k := b.e.Pub.Key()
			if done[k] || r.IsBlacklisted(b.e.Pub) {
				done[k] = true
				continue // 幂等：已封禁无需重复应用，也不差评任何来源
			}
			if err := applyEventProof(b.e.Proof, r); err != nil {
				// 该源提供的这份封禁证明无效：丢弃 + 该源差评；
				// 同一公钥继续尝试其他源的证明（不被单源伪证挡住拉黑）。
				mr.dropBad(b.src, "", proofReason(err), err.Error(), penalize)
				continue
			}
			done[k] = true
			mr.BansApplied++
		}
	}

	// ---- 阶段 2：白名单 ----
	type memCpy struct {
		src core.PubKey
		e   core.MemberEntry
	}
	byPub := map[string][]memCpy{}
	pubOrder := []string{}
	for _, rp := range replies {
		for _, me := range rp.Snap.Members {
			k := me.Pub.Key()
			if _, ok := byPub[k]; !ok {
				pubOrder = append(pubOrder, k)
			}
			byPub[k] = append(byPub[k], memCpy{src: rp.Src, e: me})
		}
	}
	sort.Strings(pubOrder)
	for _, pk := range pubOrder {
		copies := byPub[pk]
		// 补齐 proof：优先取任一携带有效 proof 的同公钥条目。
		proofSrc := map[string]core.Proof{} // proof 指纹 -> proof（去重）
		witness := map[string]core.PubKey{} // proof 指纹 -> 提供来源
		for _, c := range copies {
			if len(c.e.Proof.Raw) == 0 {
				continue
			}
			vk := proofKey(c.e.Proof)
			if _, ok := proofSrc[vk]; !ok {
				proofSrc[vk] = c.e.Proof
				witness[vk] = c.src
			}
		}
		if len(proofSrc) == 0 {
			// 所有源都缺 proof：无法独立验证 → 丢弃（不差评：
			// 可能只是各源都按存储裁剪了原文；缺 proof 补齐机制已尽力）。
			mr.Drops = append(mr.Drops, Drop{
				Peer: copies[0].src, Reason: DropMissingProof,
				Detail: "member " + copies[0].e.Pub.String() + " has no proof in any source",
			})
			continue
		}
		// 缺 proof 的条目由其他源的证明补齐（计入 ProofsFilled）。
		for _, c := range copies {
			if len(c.e.Proof.Raw) == 0 {
				mr.ProofsFilled++
			}
		}
		vks := make([]string, 0, len(proofSrc))
		for vk := range proofSrc {
			vks = append(vks, vk)
		}
		sort.Strings(vks)
		for _, vk := range vks {
			pr := proofSrc[vk]
			src := witness[vk]
			m, err := eventFromProof(pr)
			if err != nil {
				mr.dropBad(src, m.MsgID, DropMalformed, err.Error(), penalize)
				continue
			}
			if err := core.VerifyProof(m.Sender, pr); err != nil {
				mr.dropBad(src, m.MsgID, proofReason(err), err.Error(), penalize)
				continue
			}
			if err := r.ApplyEvent(m); err != nil {
				if r.IsBlacklisted(copies[0].e.Pub) {
					// 黑名单优先 + 可能待 unban 对齐：不差评，留待事件链收敛。
					mr.PendingJoin = append(mr.PendingJoin, copies[0].e.Pub)
					continue
				}
				mr.dropBad(src, m.MsgID, proofReason(err), err.Error(), penalize)
				continue
			}
			mr.MembersApplied++
		}
	}
	return mr
}

func (mr *MergeResult) dropBad(peer core.PubKey, msgID string, reason DropReason, detail string, penalize func(core.PubKey, DropReason, string)) {
	mr.Drops = append(mr.Drops, Drop{MsgID: msgID, Peer: peer, Reason: reason, Detail: detail})
	if penalize != nil {
		penalize(peer, reason, detail)
	}
}

// eventFromProof 把 proof（事件原文+签名）还原成名单事件消息：Raw 是
// MessageSigPayload（Message 去掉 Sig/EndorseSig 的 CanonicalJSON），Sig/Alg
// 从 proof 回填后即可走 ApplyEvent/Verify 通路。
func eventFromProof(pr core.Proof) (core.Message, error) {
	if len(pr.Raw) == 0 {
		return core.Message{}, fmt.Errorf("%w: proof has no raw", core.ErrMalformed)
	}
	var m core.Message
	if err := json.Unmarshal(pr.Raw, &m); err != nil {
		return core.Message{}, fmt.Errorf("%w: proof raw not a message: %v", core.ErrMalformed, err)
	}
	m.Sig = pr.Sig
	if m.Alg == "" {
		m.Alg = pr.Alg
	}
	return m, nil
}

// applyEventProof 复验并应用一条 proof（黑名单条目用；验签=VerifyProof，
// 应用=ApplyEvent 的验签+层级+自签规则链）。
func applyEventProof(pr core.Proof, r core.Roster) error {
	m, err := eventFromProof(pr)
	if err != nil {
		return err
	}
	if err := core.VerifyProof(m.Sender, pr); err != nil {
		return err
	}
	return r.ApplyEvent(m)
}

// proofReason 把验证错误映射为差评原因。
func proofReason(err error) DropReason {
	switch {
	case errors.Is(err, core.ErrUnknownAlg):
		return DropUnknownAlg
	case errors.Is(err, core.ErrNotPermitted):
		return DropOverreach
	case errors.Is(err, core.ErrInvalidSig):
		return DropBadSig
	case errors.Is(err, core.ErrMalformed):
		return DropMalformed
	default:
		return DropEventRejected
	}
}

// proofKey 是 proof 的去重指纹（raw+sig 内容哈希即可，这里用 hex(raw|sig)）。
func proofKey(pr core.Proof) string {
	return hex.EncodeToString(pr.Raw) + "|" + string(pr.Alg) + "|" + hex.EncodeToString(pr.Sig)
}
