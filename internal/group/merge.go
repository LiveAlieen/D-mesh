package group

import (
	"fmt"

	"dmesh/internal/core"
)

// MergeResult 汇总一次副本合并的结果。
type MergeResult struct {
	MembersImported int
	MembersSkipped  int // 本地更新或黑名单优先而丢弃
	BannedImported  int
	BannedSkipped   int
	PresenceUpdated int
	OwnerAdopted    bool
	RejectedEntries int // proof 验不过的条目数
}

// MergeSnapshot 合并邻居应答的双名单副本（回灌/核查路径）：
// 逐条独立复验 proof（未知 alg / 伪签 → 整批拒绝并报错，来源应得差评），
// 黑名单优先（被拉黑的 pub 不入库；本地被拉黑者从白名单剔除），
// max-ts 合并（旧条目不覆盖新条目）。在场表只接受本人自签推进，
// 不经副本合并通道（防止代报），故此处不处理 presence 之外的来源校验——
// 传入的 presence 条目仅在该 pub 无记录时作种子填充。
func (r *Roster) MergeSnapshot(members []core.MemberEntry, banned []core.BlacklistEntry, presence []core.PresenceEntry, owner core.PubKey) (*MergeResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := &MergeResult{}

	// 先验并装载黑名单（黑名单优先）。
	for _, e := range banned {
		if e.Pub.IsZero() {
			return nil, fmt.Errorf("%w: blacklist entry with empty pub", core.ErrMalformed)
		}
		if err := verifyBlacklistProof(e); err != nil {
			return nil, fmt.Errorf("group: blacklist %s proof failed: %w", e.Pub, err)
		}
		key := e.Pub.Key()
		if cur, ok := r.blacklist[key]; ok && cur.TS >= e.TS {
			res.BannedSkipped++
			continue
		}
		cp := blacklistCopy(e)
		r.blacklist[key] = &cp
		delete(r.members, key)
		res.BannedImported++
	}

	// 再验并合并白名单。
	for _, e := range members {
		if e.Pub.IsZero() {
			return nil, fmt.Errorf("%w: member entry with empty pub", core.ErrMalformed)
		}
		if r.cfg.Creator.Equal(e.Pub) {
			res.MembersSkipped++ // 创建者条目以创世为准
			continue
		}
		if err := verifyMemberProof(e); err != nil {
			res.RejectedEntries++
			return nil, fmt.Errorf("group: member %s proof failed: %w", e.Pub, err)
		}
		key := e.Pub.Key()
		if _, bad := r.blacklist[key]; bad {
			res.MembersSkipped++ // 黑名单优先
			continue
		}
		if cur, ok := r.members[key]; ok && cur.TS >= e.TS {
			res.MembersSkipped++ // max-ts：旧不覆新
			continue
		}
		cp := memberCopy(e)
		r.members[key] = &cp
		res.MembersImported++
	}

	// owner 指针：仅当新 owner 已在（合并后的）白名单且达群主层级时采纳，
	// 且当前指针为空才采纳（转移竞态由 transfer 事件链裁决，不在此通道）。
	if !owner.IsZero() {
		if r.owner.IsZero() {
			if r.cfg.Creator.Equal(owner) {
				r.owner = clonePub(owner)
				res.OwnerAdopted = true
			} else if oe, ok := r.members[owner.Key()]; ok && core.TierOfRole(oe.Role) >= core.TierOwner {
				r.owner = clonePub(owner)
				res.OwnerAdopted = true
			}
		}
	}

	// 在场表种子填充（不覆盖已有记录；权威推进只走本人自签 presence 事件）。
	for _, e := range presence {
		if e.Pub.IsZero() {
			return nil, fmt.Errorf("%w: presence entry with empty pub", core.ErrMalformed)
		}
		key := e.Pub.Key()
		if _, ok := r.presence[key]; !ok {
			pe := e
			pe.Pub = clonePub(e.Pub)
			r.presence[key] = pe
			res.PresenceUpdated++
		}
	}
	return res, nil
}
