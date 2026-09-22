// clean_test.go：v17③ 本机名单清洗（DropMember/DropBan）单测。
package group

import (
	"testing"

	"dmesh/internal/core"
)

// lastDrop 返回最近一条清洗审计记录。
func lastDrop(t *testing.T, r *Roster) DropRecord {
	t.Helper()
	log := r.DropLog()
	if len(log) == 0 {
		t.Fatal("drop log empty")
	}
	return log[len(log)-1]
}

// 找到指定种类的本机清洗通知（若没有则返回 nil）。
func findLocalDropNote(notes []RosterEvent, kind RosterEventKind) *RosterEvent {
	for i := range notes {
		if notes[i].Kind == kind {
			return &notes[i]
		}
	}
	return nil
}

func TestDropMemberLocalClean(t *testing.T) {
	e := newEnv(t, Options{})
	alice := mkSigner(t, 30)
	base := e.now - 40_000
	join := e.joinAs(e.creat, alice.Pub(), base, mkWG(30))
	e.mustApply(join)
	e.mustApply(e.ev(alice, core.TypePresence,
		eventPresence{Pub: alice.Pub(), LastMsgTS: base + 1, OfflineAfter: 60_000}, base+1))

	var notes []RosterEvent
	e.r.SetNotifier(func(ev RosterEvent) { notes = append(notes, ev) })

	// 未清洗前重复应用同一 join 事件被幂等去重吞掉（对照「删了等补」）。
	e.mustApply(join)

	e.r.DropMember(alice.Pub(), "audit: forged proof from single source")
	if _, ok := e.r.Member(alice.Pub()); ok {
		t.Fatal("dropped member entry should be gone")
	}
	// presence 是本人自签的展示性属性，清洗权限条目时刻意保留。
	if e.r.Presence(alice.Pub()).LastMsgTS == 0 {
		t.Fatal("presence should survive local drop")
	}
	n := findLocalDropNote(notes, KindMemberDroppedLocal)
	if n == nil || n.Reason != "audit: forged proof from single source" || !n.Pub.Equal(alice.Pub()) {
		t.Fatalf("local drop note missing/wrong: %+v", n)
	}
	rec := lastDrop(t, e.r)
	if rec.Kind != DropKindMember || rec.Action != DropActionDropped ||
		rec.Reason != "audit: forged proof from single source" {
		t.Fatalf("drop record = %+v", rec)
	}

	// 删了等补：清洗忘掉 proof 的 msg_id 后，同一条有效 join 事件能重新采纳。
	e.mustApply(join)
	if m, ok := e.r.Member(alice.Pub()); !ok || m.Role != core.RoleMember {
		t.Fatalf("valid join should re-adopt the entry after local drop: %+v", m)
	}

	// 本机没有的条目：absent 幂等记录，不改状态。
	e.r.DropMember(mkSigner(t, 31).Pub(), "nothing here")
	if rec := lastDrop(t, e.r); rec.Action != DropActionAbsent {
		t.Fatalf("absent drop record = %+v", rec)
	}
}

func TestDropMemberAnchorRefusals(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 40_000
	admin, ts := e.bootstrapAdmin(20, base, core.PermTransfer)

	// 创建者条目拒绝清洗（创世锚点）。
	e.r.DropMember(e.cfg.Creator, "oops")
	if _, ok := e.r.Member(e.cfg.Creator); !ok {
		t.Fatal("creator whitelist entry must survive DropMember")
	}
	if rec := lastDrop(t, e.r); rec.Action != DropActionRefused {
		t.Fatalf("creator drop record = %+v", rec)
	}

	// 当前 owner 指针持有的条目拒绝清洗。
	m := e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts)
	if err := EndorseEvent(&m, admin); err != nil {
		t.Fatal(err)
	}
	e.mustApply(m)
	e.r.DropMember(admin.Pub(), "oops")
	if got := e.r.TierOf(admin.Pub()); got != core.TierOwner {
		t.Fatalf("current owner entry must survive: tier=%d", got)
	}
	if rec := lastDrop(t, e.r); rec.Action != DropActionRefused {
		t.Fatalf("owner drop record = %+v", rec)
	}

	// 指针经 transfer 移走并降为管理后，前群主条目可正常清洗。
	carol := mkSigner(t, 45)
	e.mustApply(e.joinAs(e.creat, carol.Pub(), ts+1, mkWG(45)))
	m2 := e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: carol.Pub()}, ts+2)
	if err := EndorseEvent(&m2, carol); err != nil {
		t.Fatal(err)
	}
	e.mustApply(m2)
	if got := e.r.TierOf(admin.Pub()); got != core.TierAdmin {
		t.Fatalf("old owner should be demoted to admin by transfer: tier=%d", got)
	}
	e.r.DropMember(admin.Pub(), "dirty")
	if _, ok := e.r.Member(admin.Pub()); ok {
		t.Fatal("former owner (no longer pointer) should be droppable")
	}
}

func TestDropBanReacceptsKick(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 40_000
	bob := mkSigner(t, 33)
	e.mustApply(e.joinAs(e.creat, bob.Pub(), base, mkWG(33)))
	kick := e.ev(e.creat, core.TypeKick, eventTarget{Target: bob.Pub()}, base+1)
	e.mustApply(kick)
	if !e.r.IsBlacklisted(bob.Pub()) {
		t.Fatal("bob should be blacklisted")
	}

	var notes []RosterEvent
	e.r.SetNotifier(func(ev RosterEvent) { notes = append(notes, ev) })

	// 黑名单条目没有锚点豁免——即便目标是群主（合法路径上根本封不掉，
	// 出现即最可疑的脏数据）。
	e.r.DropBan(bob.Pub(), "audit: forged ban")
	if e.r.IsBlacklisted(bob.Pub()) {
		t.Fatal("ban entry should be gone")
	}
	n := findLocalDropNote(notes, KindBlacklistDroppedLocal)
	if n == nil || n.Reason != "audit: forged ban" || !n.Pub.Equal(bob.Pub()) {
		t.Fatalf("local ban drop note missing/wrong: %+v", n)
	}

	// 删了等补：成员身份被补回后，同一条有效 kick 事件重新被采纳。
	e.mustApply(e.joinAs(e.creat, bob.Pub(), base+2, mkWG(33)))
	e.mustApply(kick)
	if !e.r.IsBlacklisted(bob.Pub()) {
		t.Fatal("same kick event should re-adopt the ban after local drop")
	}

	// 本机没有的条目：absent 幂等记录。
	e.r.DropBan(mkSigner(t, 34).Pub(), "nothing here")
	if rec := lastDrop(t, e.r); rec.Action != DropActionAbsent {
		t.Fatalf("absent ban drop record = %+v", rec)
	}
}

// DropMember/DropBan 签名须与 backfill.Cleaner 一致（*Roster 直接满足）。
var _ interface {
	DropMember(p core.PubKey, reason string)
	DropBan(p core.PubKey, reason string)
} = (*Roster)(nil)
