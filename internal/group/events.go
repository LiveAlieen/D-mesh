package group

import (
	"fmt"
	"sort"

	"dmesh/internal/core"
)

// RosterEvent 描述一次已验证事件的计划变更/生效通知。
// Notifier 回调在状态提交后被同步调用（回调内不得重入 Roster）。
type RosterEvent struct {
	Kind      RosterEventKind
	MsgID     string
	Pub       core.PubKey // 受影响的目标公钥
	Member    *core.MemberEntry
	Banned    *core.BlacklistEntry
	Presence  *core.PresenceEntry
	Owner     *core.PubKey
	NetdiskMB int
	Msg       *core.Message // KindJoinReqReceived 时携带原始 join_req
	Reason    string        // Kind*DroppedLocal（v17③ 本机清洗）时携带清洗原因
}

// RosterEventKind 是计划/通知类型。
type RosterEventKind int

// 计划类型常量。KindMemberDroppedLocal / KindBlacklistDroppedLocal 是
// v17③ 本机名单清洗的纯本地通知（不来自任何网络事件，仅用于宿主侧
// 同步删除持久化副本与刷新 UI）。
const (
	KindMemberUpsert RosterEventKind = iota
	KindMemberDelete
	KindBlacklistAdd
	KindBlacklistDelete
	KindPresenceSet
	KindOwnerChanged
	KindNetdiskChanged
	KindJoinReqReceived
	KindMemberDroppedLocal
	KindBlacklistDroppedLocal
)

// SetNotifier 注册状态变更回调（传 nil 取消）。
func (r *Roster) SetNotifier(f func(RosterEvent)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifier = f
}

func (r *Roster) fire(evs []RosterEvent) {
	r.mu.Lock()
	n := r.notifier
	r.mu.Unlock()
	if n == nil {
		return
	}
	for _, e := range evs {
		n(e)
	}
}

// commit 把已验证事件的计划落到状态（须持锁调用）。提交阶段再次执行
// 黑名单优先保护，防止缓存窗口内状态已被其他事件改变。
func (r *Roster) commit(evs []RosterEvent) {
	for _, e := range evs {
		switch e.Kind {
		case KindMemberUpsert:
			cp := memberCopy(*e.Member)
			if _, bad := r.blacklist[cp.Pub.Key()]; bad {
				continue
			}
			r.members[cp.Pub.Key()] = &cp
		case KindMemberDelete:
			delete(r.members, e.Pub.Key())
		case KindBlacklistAdd:
			cp := blacklistCopy(*e.Banned)
			r.blacklist[cp.Pub.Key()] = &cp
			delete(r.members, cp.Pub.Key())
			if r.owner.Equal(cp.Pub) && !r.cfg.Creator.Equal(cp.Pub) && !r.cfg.Creator.IsZero() {
				r.owner = r.cfg.Creator // 群主被除名：owner 指针回落创建者
			}
		case KindBlacklistDelete:
			delete(r.blacklist, e.Pub.Key())
		case KindPresenceSet:
			r.presence[e.Pub.Key()] = *e.Presence
		case KindOwnerChanged:
			r.owner = clonePub(*e.Owner)
		case KindNetdiskChanged:
			r.netdiskMB = e.NetdiskMB
			if r.haveCfg {
				r.cfg.NetdiskMB = e.NetdiskMB
			}
		case KindJoinReqReceived:
			if e.Msg == nil {
				continue
			}
			replaced := false
			for i, q := range r.joinReqs {
				if q.Sender.Equal(e.Pub) {
					r.joinReqs[i] = *e.Msg // 同一申请人只留最新
					replaced = true
					break
				}
			}
			if !replaced {
				r.joinReqs = append(r.joinReqs, *e.Msg)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// ApplyEvent 与乱序缓存
// ---------------------------------------------------------------------------

// ApplyEvent 验证并应用一个名单事件消息。任何一步不满足都返回 error 且
// 不改动状态（core.ErrUnknownAlg=未知算法；core.ErrInvalidSig=伪签；
// core.ErrNotPermitted=层级/权限不足；core.ErrMalformed=结构/取值非法）。
//
// 乱序处理：ts_ms 高于本地已应用水位的事件先进入短暂缓存（返回 nil），
// 由 FlushPending（水位衔接或超过重排窗口）按 ts 升序真正应用；低于
// 「低水位-宽限」的远古事件直接拒绝。已应用过的 msg_id 幂等吞掉（返回 nil）。
func (r *Roster) ApplyEvent(m core.Message) error {
	r.mu.Lock()
	evs, err := r.prepareEvent(m, false)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	held := false
	if evs != nil {
		if r.shouldHold(m) {
			r.holdPending(m)
			held = true
		} else {
			r.markSeen(m.MsgID)
			r.advanceWatermark(m.TSms)
			r.commit(evs)
		}
	}
	r.mu.Unlock()
	if !held {
		r.fire(evs)
	}
	return nil
}

// shouldHold 判定事件是否进乱序缓存：仅对「改变名单状态、有实际计划且 ts
// 高于水位」的事件生效；presence/join_req 走独立合并/收件箱，无需定序。
func (r *Roster) shouldHold(m core.Message) bool {
	if !r.heldMinInit {
		return false // 首个事件立即应用，建立水位基准
	}
	if m.TSms <= r.watermark {
		return false // 迟到（宽限内）按当前状态直接应用
	}
	if name, err := core.BodyName(m.Body); err == nil {
		switch name {
		case core.NamePresence, core.NameJoinReq:
			return false
		}
	}
	return true
}

func (r *Roster) holdPending(m core.Message) {
	if len(r.pending) >= r.opt.MaxPendingEvents {
		// 满员：按 ts 排出最老的一条腾位（防内存膨胀，事件可再被 flood 送达）。
		sort.SliceStable(r.pending, func(i, j int) bool { return r.pending[i].msg.TSms < r.pending[j].msg.TSms })
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, pendingEvent{msg: m, heldAtMS: r.nowMS()})
	r.markSeen(m.MsgID) // 防同 id 重复入队；出队应用时不再过 seen 门槛
}

// FlushPending 排空乱序缓存：ts 已被水位衔接、或滞留超过重排窗口的事件按
// ts 升序应用；应用前重跑校验，已失效的事件被丢弃并计入 failed。
func (r *Roster) FlushPending() (applied int, failed []core.Message) { return r.flush(false) }

// FlushAll 强制按 ts 升序排空全部缓存（忽略重排窗口），用于回灌收敛与测试。
func (r *Roster) FlushAll() (applied int, failed []core.Message) { return r.flush(true) }

func (r *Roster) flush(force bool) (applied int, failed []core.Message) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return 0, nil
	}
	// 按 ts 升序处理，保证事件按时间线衔接应用。
	sort.SliceStable(r.pending, func(i, j int) bool { return r.pending[i].msg.TSms < r.pending[j].msg.TSms })
	var keep []pendingEvent
	var evs []RosterEvent
	now := r.nowMS()
	for _, pe := range r.pending {
		if !force && pe.msg.TSms > r.watermark && now-pe.heldAtMS < r.opt.ReorderWindowMS {
			keep = append(keep, pe)
			continue
		}
		plan, err := r.prepareEvent(pe.msg, true)
		if err != nil || plan == nil {
			failed = append(failed, pe.msg)
			continue
		}
		r.advanceWatermark(pe.msg.TSms)
		r.commit(plan)
		evs = append(evs, plan...)
		applied++
	}
	r.pending = keep
	r.mu.Unlock()
	r.fire(evs)
	return applied, failed
}

// prepareEvent 完成全部校验并产出提交计划（不改动状态；须持锁调用）。
// drained=true 时跳过时间窗/seen 门槛（入缓存前已检过）。
func (r *Roster) prepareEvent(m core.Message, drained bool) ([]RosterEvent, error) {
	// 1. 结构粗检。
	if m.MsgID == "" {
		return nil, fmt.Errorf("%w: empty msg_id", core.ErrMalformed)
	}
	// v26 归一化：信封只有 kind + body，事件名取自 body 的唯一键并与 kind 互校。
	// 判别位住在 body 里、可被篡改，这里只「尽力解析」：解析失败不在本步报错，
	// 而是留到验签之后（3.5），使「正文被动过」依旧优先报 invalid signature，
	// 与 v25 的判序一致。
	name, nameErr := core.CheckBody(m.Kind, m.Body)
	if nameErr == nil {
		// transfer 是唯一可带 to 的名单事件（v17①：提案定向发给新 owner，
		// 新 owner 的联署原文含 to，故生效事件仍带 to=新 owner）；其余名单
		// 事件必须广播（to=nil）。
		if m.To != nil && name != core.NameTransfer {
			return nil, fmt.Errorf("%w: roster events must be broadcast (to must be nil)", core.ErrMalformed)
		}
		switch name {
		case core.NameJoinReq, core.NameJoin, core.NameRemove, core.NameKick, core.NameUnban,
			core.NamePerms, core.NameGrantAdmin, core.NameRevokeAdmin, core.NameTransfer,
			core.NamePresence, core.NameNetdisk:
		case core.NameText, core.NameHide, core.NameManifest:
			return nil, fmt.Errorf("%w: %q is not a roster event", core.ErrMalformed, name)
		default:
			return nil, fmt.Errorf("%w: unknown event name %q", core.ErrMalformed, name)
		}
	}
	if m.TSms < 0 {
		return nil, fmt.Errorf("%w: negative ts_ms", core.ErrMalformed)
	}
	// 2. 群绑定：种子已知时事件 group_id 必须一致。
	if r.haveCfg && r.groupID != m.GroupID {
		return nil, fmt.Errorf("%w: group_id mismatch", core.ErrMalformed)
	}
	// 3. 验签（按 sig_alg 分派；未知 alg → ErrUnknownAlg，一律丢弃）。
	payload, err := core.MessageSigPayload(m)
	if err != nil {
		return nil, fmt.Errorf("%w: sig payload: %v", core.ErrMalformed, err)
	}
	if err := verifyMessageSig(m.Sender, m.Alg, payload, m.Sig); err != nil {
		return nil, err
	}
	// 3.5 验签通过后才对判别位下权威结论（kind↔name 互校）。
	if nameErr != nil {
		return nil, nameErr
	}
	if !drained {
		// 4. 时间窗。
		now := r.nowMS()
		if m.TSms > now+r.opt.MaxClockSkewMS {
			return nil, fmt.Errorf("%w: ts_ms too far in future", core.ErrMalformed)
		}
		if r.heldMinInit && m.TSms < r.heldMin-r.opt.LowWaterGraceMS {
			return nil, fmt.Errorf("%w: event too old (ts_ms=%d)", core.ErrMalformed, m.TSms)
		}
		// 5. 幂等去重。
		if r.seen[m.MsgID] {
			return nil, nil // 已应用/已缓存：吞掉，不改状态
		}
	}
	// 6. 黑名单优先：被除名者的任何名单事件一律无效（unban 也不例外——
	// 解禁必须由仍在白名单上的权限者发起）。
	if _, bad := r.blacklist[m.Sender.Key()]; bad {
		return nil, fmt.Errorf("%w: sender is blacklisted", core.ErrNotPermitted)
	}
	// 7. 签名者必须已是成员（join_req 例外：申请人尚非成员，自签仅受理中继）。
	if name != core.NameJoinReq && r.tierOf(m.Sender) < 0 {
		return nil, fmt.Errorf("%w: sender is not a member", core.ErrNotPermitted)
	}
	return r.dispatch(m, name, payload)
}

// dispatch 按事件名（body 的唯一键）做层级/权限/自签校验并产出计划。
func (r *Roster) dispatch(m core.Message, name string, sigPayload []byte) ([]RosterEvent, error) {
	switch name {
	case core.NameJoinReq:
		return r.evJoinReq(m)
	case core.NameJoin:
		return r.evJoin(m)
	case core.NameRemove:
		return r.evRemove(m)
	case core.NameKick:
		return r.evKick(m)
	case core.NameUnban:
		return r.evUnban(m)
	case core.NamePerms:
		return r.evPerms(m)
	case core.NameGrantAdmin:
		return r.evGrantRevoke(m, true, name)
	case core.NameRevokeAdmin:
		return r.evGrantRevoke(m, false, name)
	case core.NameTransfer:
		return r.evTransfer(m, sigPayload)
	case core.NamePresence:
		return r.evPresence(m)
	case core.NameNetdisk:
		return r.evNetdisk(m)
	}
	return nil, fmt.Errorf("%w: unreachable event name %q", core.ErrMalformed, name)
}

// evJoinReq：新人自签申请。不改名单，只进收件箱供具 carry 权限者处理。
func (r *Roster) evJoinReq(m core.Message) ([]RosterEvent, error) {
	var c eventJoinReq
	if err := decodeEventBody(m, core.NameJoinReq, &c); err != nil {
		return nil, err
	}
	if !pubMatches(c.Pub, m.Sender) {
		return nil, fmt.Errorf("%w: join_req pub != sender (spoofed applicant)", core.ErrMalformed)
	}
	if c.WG.IsZero() {
		return nil, fmt.Errorf("%w: join_req without wg_pub", core.ErrMalformed)
	}
	key := m.Sender.Key()
	if _, isMember := r.members[key]; isMember {
		return nil, fmt.Errorf("%w: join_req from existing member", core.ErrNotPermitted)
	}
	if _, bad := r.blacklist[key]; bad {
		return nil, fmt.Errorf("%w: join_req from blacklisted pubkey", core.ErrNotPermitted)
	}
	cp := m
	return []RosterEvent{{Kind: KindJoinReqReceived, MsgID: m.MsgID, Pub: m.Sender, Msg: &cp}}, nil
}

// evJoin：只认 carry 权限者签名；新人自签一律无效；目标不得在黑名单；
// 新人按默认权限记入白名单（RoleMember，proof=本事件）。
// 注意：content.pub 是「目标新人」，签名者是 m.Sender（拉人者），二者必须不同。
func (r *Roster) evJoin(m core.Message) ([]RosterEvent, error) {
	var c eventJoin
	if err := decodeEventBody(m, core.NameJoin, &c); err != nil {
		return nil, err
	}
	target := c.Pub
	if target.IsZero() {
		return nil, fmt.Errorf("%w: join target pub empty", core.ErrMalformed)
	}
	if target.Equal(m.Sender) {
		return nil, fmt.Errorf("%w: self-signed join is always invalid", core.ErrNotPermitted)
	}
	if !r.hasPerm(m.Sender, core.PermCarry) {
		return nil, fmt.Errorf("%w: join signer lacks carry permission", core.ErrNotPermitted)
	}
	if c.WG.IsZero() {
		return nil, fmt.Errorf("%w: join with zero wg_pub", core.ErrMalformed)
	}
	if _, bad := r.blacklist[target.Key()]; bad {
		return nil, fmt.Errorf("%w: cannot join a blacklisted pubkey (unban first)", core.ErrNotPermitted)
	}
	if _, exists := r.members[target.Key()]; exists {
		return nil, fmt.Errorf("%w: join target already a member", core.ErrMalformed)
	}
	if err := checkPermsList(c.Perms); err != nil {
		return nil, err
	}
	// 新人以成员层级入列：敏感权限位不可随 join 发放（carry 由高一级授予
	// 的是拉人者自己的位，不能借 join 越级塞给新人）；群主以下的拉人者
	// 只能发放种子默认权限的子集。
	for _, p := range c.Perms {
		if tierGatedPerms[p] {
			return nil, fmt.Errorf("%w: tier-gated perm %q cannot be granted via join", core.ErrNotPermitted, p)
		}
	}
	if r.tierOf(m.Sender) < core.TierOwner && !permsSubset(c.Perms, r.cfg.DefaultPerms) {
		return nil, fmt.Errorf("%w: join perms exceed seed default perms", core.ErrNotPermitted)
	}
	proof, err := core.ProofOf(m)
	if err != nil {
		return nil, err
	}
	entry := &core.MemberEntry{
		Pub:   clonePub(target),
		WG:    c.WG,
		Role:  core.RoleMember,
		Perms: copyPerms(c.Perms),
		Proof: proof,
		TS:    m.TSms,
	}
	return []RosterEvent{{Kind: KindMemberUpsert, MsgID: m.MsgID, Pub: target, Member: entry}}, nil
}

// evRemove：仅本人自签 = 退群（删白名单，不进黑名单）；代签一律无效，
// 绝不升级为除名。
func (r *Roster) evRemove(m core.Message) ([]RosterEvent, error) {
	var c eventTarget
	if err := decodeEventBody(m, core.NameRemove, &c); err != nil {
		return nil, err
	}
	if !c.Target.Equal(m.Sender) {
		return nil, fmt.Errorf("%w: remove is only valid self-signed (never escalates to kick)", core.ErrNotPermitted)
	}
	if r.cfg.Creator.Equal(c.Target) {
		return nil, fmt.Errorf("%w: creator is permanent and cannot remove", core.ErrNotPermitted)
	}
	if _, ok := r.members[c.Target.Key()]; !ok {
		return nil, fmt.Errorf("%w: remove target not a member", core.ErrMalformed)
	}
	return []RosterEvent{{Kind: KindMemberDelete, MsgID: m.MsgID, Pub: c.Target}}, nil
}

// evKick：具 kick 权限者的显式除名事件 → 删白名单 + 进黑名单。
// 目标层级须严格低于签名者（创建者不可被除名；除名群主仅创建者可为）。
func (r *Roster) evKick(m core.Message) ([]RosterEvent, error) {
	var c eventTarget
	if err := decodeEventBody(m, core.NameKick, &c); err != nil {
		return nil, err
	}
	if c.Target.Equal(m.Sender) {
		return nil, fmt.Errorf("%w: kick target must differ from signer (use remove to leave)", core.ErrNotPermitted)
	}
	tgt, ok := r.members[c.Target.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: kick target not a member", core.ErrMalformed)
	}
	if !r.hasPerm(m.Sender, core.PermKick) {
		return nil, fmt.Errorf("%w: signer lacks kick permission", core.ErrNotPermitted)
	}
	if r.tierOf(m.Sender) <= r.tierOf(tgt.Pub) {
		return nil, fmt.Errorf("%w: kick requires strictly higher tier than target", core.ErrNotPermitted)
	}
	proof, err := core.ProofOf(m)
	if err != nil {
		return nil, err
	}
	banned := &core.BlacklistEntry{Pub: clonePub(c.Target), Proof: proof, TS: m.TSms}
	return []RosterEvent{
		{Kind: KindMemberDelete, MsgID: m.MsgID, Pub: c.Target},
		{Kind: KindBlacklistAdd, MsgID: m.MsgID, Pub: c.Target, Banned: banned},
	}, nil
}

// evUnban：具解禁权限者（unban 或 kick 权限位；群主/创建者条目自带）把
// 目标移出黑名单。目标不在黑名单时视为无效事件。
func (r *Roster) evUnban(m core.Message) ([]RosterEvent, error) {
	var c eventTarget
	if err := decodeEventBody(m, core.NameUnban, &c); err != nil {
		return nil, err
	}
	e, ok := r.members[m.Sender.Key()]
	if !ok || !(containsPerm(e.Perms, core.PermUnban) || containsPerm(e.Perms, core.PermKick)) {
		return nil, fmt.Errorf("%w: signer lacks unban/kick permission", core.ErrNotPermitted)
	}
	if _, bad := r.blacklist[c.Target.Key()]; !bad {
		return nil, fmt.Errorf("%w: unban target not blacklisted", core.ErrMalformed)
	}
	return []RosterEvent{{Kind: KindBlacklistDelete, MsgID: m.MsgID, Pub: c.Target}}, nil
}

// evPerms：改目标权限集——签名者层级须严格高于目标；敏感权限位只能由
// 层级达群主且本人持有该位的签发者赋予（授权不超出签发者自身）。
func (r *Roster) evPerms(m core.Message) ([]RosterEvent, error) {
	var c eventPerms
	if err := decodeEventBody(m, core.NamePerms, &c); err != nil {
		return nil, err
	}
	tgt, ok := r.members[c.Target.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: perms target not a member", core.ErrMalformed)
	}
	if err := checkPermsList(c.Perms); err != nil {
		return nil, err
	}
	st, tt := r.tierOf(m.Sender), r.tierOf(c.Target)
	if st <= tt {
		return nil, fmt.Errorf("%w: perms signer tier %d not strictly above target tier %d", core.ErrNotPermitted, st, tt)
	}
	for _, p := range c.Perms {
		if !tierGatedPerms[p] {
			continue
		}
		if st < core.TierOwner || !r.hasPerm(m.Sender, p) {
			return nil, fmt.Errorf("%w: cannot grant tier-gated perm %q (tier %d, holds=%v)",
				core.ErrNotPermitted, p, st, r.hasPerm(m.Sender, p))
		}
	}
	up := memberCopy(*tgt)
	up.Perms = copyPerms(c.Perms)
	up.TS = m.TSms
	// proof 保留原始来源证明（join/创世），perms 只改权限集。
	return []RosterEvent{{Kind: KindMemberUpsert, MsgID: m.MsgID, Pub: c.Target, Member: &up}}, nil
}

// evGrantRevoke：任命/收放管理权——仅群主/创建者可签，且目标层级严格更低。
func (r *Roster) evGrantRevoke(m core.Message, grant bool, name string) ([]RosterEvent, error) {
	var c eventTarget
	if err := decodeEventBody(m, name, &c); err != nil {
		return nil, err
	}
	verb := name // 错误消息里带上具体命令名（grant_admin / revoke_admin）
	if r.tierOf(m.Sender) < core.TierOwner {
		return nil, fmt.Errorf("%w: only owner/creator can sign %s", core.ErrNotPermitted, verb)
	}
	tgt, ok := r.members[c.Target.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: %s target not a member", core.ErrMalformed, verb)
	}
	if r.tierOf(m.Sender) <= r.tierOf(tgt.Pub) {
		return nil, fmt.Errorf("%w: %s requires strictly higher tier than target", core.ErrNotPermitted, verb)
	}
	want := core.RoleMember
	if grant {
		want = core.RoleAdmin
	}
	if tgt.Role == want {
		return nil, fmt.Errorf("%w: %s target already role %s", core.ErrMalformed, verb, want)
	}
	up := memberCopy(*tgt)
	up.Role = want
	up.TS = m.TSms
	return []RosterEvent{{Kind: KindMemberUpsert, MsgID: m.MsgID, Pub: c.Target, Member: &up}}, nil
}

// evTransfer：群主（或创建者）移交 + 新群主对同一原文联署（EndorseSig，
// 由新群主用自己的密钥与算法签 core.MessageSigPayload(m)）。
//
// v17① 定向语义：transfer 是唯一允许携带 to 的名单事件——提案阶段
// to=新 owner 定向送达（EndorseSig 为空，由集成层收件箱处理，不进本
// 路径）；联署完成后的生效事件原文含 to，故仍带 to=新 owner 广播，
// 各节点在此一并校验 to 与 new_owner 一致，防止借定向通道夹带任意目标。
func (r *Roster) evTransfer(m core.Message, payload []byte) ([]RosterEvent, error) {
	var c eventTransfer
	if err := decodeEventBody(m, core.NameTransfer, &c); err != nil {
		return nil, err
	}
	newOwner := c.NewOwner
	if m.To != nil && !m.To.Equal(newOwner) {
		return nil, fmt.Errorf("%w: transfer to=%s does not match new_owner", core.ErrMalformed, m.To)
	}
	if r.tierOf(m.Sender) < core.TierOwner {
		return nil, fmt.Errorf("%w: only owner/creator can sign transfer", core.ErrNotPermitted)
	}
	if !r.hasPerm(m.Sender, core.PermTransfer) {
		return nil, fmt.Errorf("%w: signer lacks transfer permission", core.ErrNotPermitted)
	}
	// 自领（v17 C.4）：仅创建者可签给自己收回群主位——创建者条目永久
	// 置顶，收回不涉及向下级移交；其余成员自我移交一律无效。
	isSelfClaim := newOwner.Equal(m.Sender)
	if isSelfClaim && !r.cfg.Creator.Equal(m.Sender) {
		return nil, fmt.Errorf("%w: transfer to self", core.ErrMalformed)
	}
	if newOwner.Equal(r.owner) {
		return nil, fmt.Errorf("%w: transfer target is already the owner", core.ErrMalformed)
	}
	tgt, ok := r.members[newOwner.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: transfer target not a member", core.ErrMalformed)
	}
	isCreatorTarget := r.cfg.Creator.Equal(newOwner)
	if !isCreatorTarget && r.tierOf(newOwner) >= core.TierOwner {
		return nil, fmt.Errorf("%w: transfer target already at owner tier", core.ErrMalformed)
	}
	if len(m.EndorseSig) == 0 {
		return nil, fmt.Errorf("%w: transfer requires new owner endorsement", core.ErrNotPermitted)
	}
	if err := core.Verify(clonePub(newOwner), payload, m.EndorseSig); err != nil {
		return nil, fmt.Errorf("group: transfer endorsement: %w", err)
	}
	ownerCopy := clonePub(newOwner)
	evs := []RosterEvent{{Kind: KindOwnerChanged, MsgID: m.MsgID, Pub: newOwner, Owner: &ownerCopy}}
	if !isCreatorTarget && tgt.Role != core.RoleOwner {
		up := memberCopy(*tgt)
		up.Role = core.RoleOwner
		up.TS = m.TSms
		evs = append(evs, RosterEvent{Kind: KindMemberUpsert, MsgID: m.MsgID, Pub: newOwner, Member: &up})
	}
	// 旧群主让位后降为管理（v17①）：降的是「当前 owner 指针持有者」而
	// 非只看签名者——创建者代签移交时，让位的同样是现任群主。创建者
	// 条目（RoleCreator）不受影响；新 owner 自然排除。
	for _, prev := range r.demoteCandidatesLocked(newOwner, m.Sender) {
		cur := r.members[prev.Key()]
		down := memberCopy(*cur)
		down.Role = core.RoleAdmin
		down.TS = m.TSms
		evs = append(evs, RosterEvent{Kind: KindMemberUpsert, MsgID: m.MsgID, Pub: down.Pub, Member: &down})
	}
	return evs, nil
}

// demoteCandidatesLocked 返回移交后应降为管理的公钥：当前 owner 指针
// 持有者与签名者中去重后的、在白名单上且 Role==RoleOwner 者（新 owner
// 除外）。
func (r *Roster) demoteCandidatesLocked(newOwner, sender core.PubKey) []core.PubKey {
	var out []core.PubKey
	for _, p := range [2]core.PubKey{clonePub(r.owner), clonePub(sender)} {
		if p.IsZero() || p.Equal(newOwner) {
			continue
		}
		known := false
		for _, q := range out {
			if q.Equal(p) {
				known = true
				break
			}
		}
		if known {
			continue
		}
		if e, ok := r.members[p.Key()]; ok && e.Role == core.RoleOwner {
			out = append(out, p)
		}
	}
	return out
}

// evPresence：仅本人自签推进；max 合并（旧值不覆盖新值）；不占白名单、
// 不参与权限判定。
func (r *Roster) evPresence(m core.Message) ([]RosterEvent, error) {
	var c eventPresence
	if err := decodeEventBody(m, core.NamePresence, &c); err != nil {
		return nil, err
	}
	if !pubMatches(c.Pub, m.Sender) {
		return nil, fmt.Errorf("%w: presence must be self-signed (proxy reports dropped)", core.ErrNotPermitted)
	}
	if c.OfflineAfter < 0 || c.LastMsgTS < 0 {
		return nil, fmt.Errorf("%w: negative presence fields", core.ErrMalformed)
	}
	if c.LastMsgTS > m.TSms {
		return nil, fmt.Errorf("%w: presence last_msg_ts after own ts_ms", core.ErrMalformed)
	}
	cur := r.presence[m.Sender.Key()]
	if c.LastMsgTS < cur.LastMsgTS {
		return nil, nil // max 合并：旧不覆新，幂等吞掉
	}
	ne := core.PresenceEntry{Pub: clonePub(m.Sender), LastMsgTS: c.LastMsgTS, OfflineAfter: c.OfflineAfter}
	return []RosterEvent{{Kind: KindPresenceSet, MsgID: m.MsgID, Pub: m.Sender, Presence: &ne}}, nil
}

// evNetdisk：群主/创建者改全局配额；越界（0~256 之外）直接拒绝。
func (r *Roster) evNetdisk(m core.Message) ([]RosterEvent, error) {
	var c eventNetdisk
	if err := decodeEventBody(m, core.NameNetdisk, &c); err != nil {
		return nil, err
	}
	if !core.ValidNetdiskMB(c.MB) {
		return nil, fmt.Errorf("%w: netdisk_mb %d out of range [%d,%d]",
			core.ErrMalformed, c.MB, core.NetdiskMinMB, core.NetdiskMaxMB)
	}
	if r.tierOf(m.Sender) < core.TierOwner {
		return nil, fmt.Errorf("%w: only owner/creator can change netdisk_mb", core.ErrNotPermitted)
	}
	if !r.hasPerm(m.Sender, core.PermNetdisk) {
		return nil, fmt.Errorf("%w: signer lacks netdisk permission", core.ErrNotPermitted)
	}
	if c.MB == r.netdiskMB {
		return nil, nil
	}
	return []RosterEvent{{Kind: KindNetdiskChanged, MsgID: m.MsgID, NetdiskMB: c.MB}}, nil
}
