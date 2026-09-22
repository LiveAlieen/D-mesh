package backfill

import (
	"reflect"
	"testing"

	"dmesh/internal/core"
)

func defaultCfg() Config { return Config{}.Defaults() }

func TestCrossCheckMultiSource(t *testing.T) {
	x := newSigner("carrier-x") // owner：carry+kick+speak
	y := newSigner("member-y")
	bad := newSigner("no-speak")
	ghost := newSigner("not-member")
	bl := newSigner("blacklisted")
	sm2 := newSigner("unknown-alg-sender")

	seedRoster := func() *testRoster {
		r := newTestRoster()
		r.addDirect(core.MemberEntry{Pub: x.pub(), Role: core.RoleOwner, Perms: []string{core.PermSpeak, core.PermReceive, core.PermCarry, core.PermKick}})
		r.addDirect(core.MemberEntry{Pub: y.pub(), Role: core.RoleMember, Perms: []string{core.PermSpeak, core.PermReceive}})
		r.addDirect(core.MemberEntry{Pub: bad.pub(), Role: core.RoleMember, Perms: []string{core.PermReceive}})
		r.addBanDirect(core.BlacklistEntry{Pub: bl.pub()})
		return r
	}

	sa := newSigner("peer-a")
	sb := newSigner("peer-b")
	sc := newSigner("peer-c")

	t.Run("三源一致采纳", func(t *testing.T) {
		m := makeText(t, y, "hello", 100, "m1")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{m}},
			{Src: sb.pub(), Msgs: []core.Message{m}},
			{Src: sc.pub(), Msgs: []core.Message{m}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if got := acceptIDs(cr); len(got) != 1 || got[0] != m.MsgID {
			t.Fatalf("accepted = %v, want one %s", got, m.MsgID)
		}
		if len(cr.Drops) != 0 || pt.total() != 0 {
			t.Fatalf("unexpected drops/penalties: %v %v", cr.Drops, pt.all)
		}
	})

	t.Run("仅单源出现丢弃并差评", func(t *testing.T) {
		shared := makeText(t, y, "shared", 100, "shared")
		sole := makeText(t, y, "fabricated", 101, "sole")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{shared, sole}},
			{Src: sb.pub(), Msgs: []core.Message{shared}},
			{Src: sc.pub(), Msgs: []core.Message{shared}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{shared.MsgID}) {
			t.Fatalf("accepted = %v, want only shared", acceptIDs(cr))
		}
		if len(cr.Drops) != 1 || cr.Drops[0].Reason != DropSingleSource {
			t.Fatalf("drops = %v", cr.Drops)
		}
		if pt.count(sa.pub()) != 1 {
			t.Fatalf("sole-source peer must get one penalty, got %d", pt.count(sa.pub()))
		}
	})

	t.Run("各源不一致按多数采纳少数差评", func(t *testing.T) {
		good := makeText(t, y, "v1", 100, "same-id")
		tampered := makeText(t, y, "v2-tampered", 100, "same-id") // 同 msg_id 不同内容
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{good}},
			{Src: sb.pub(), Msgs: []core.Message{good}},
			{Src: sc.pub(), Msgs: []core.Message{tampered}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{good.MsgID}) {
			t.Fatalf("accepted = %v, want majority variant", acceptIDs(cr))
		}
		if pt.count(sc.pub()) != 1 || !pt.has(sc.pub(), DropDiscrepancy) {
			t.Fatalf("minority source must be penalized once: %v", pt.all)
		}
	})

	t.Run("无多数差异全部丢弃", func(t *testing.T) {
		v1 := makeText(t, y, "v1", 100, "tie-id")
		v2 := makeText(t, y, "v2", 100, "tie-id")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{v1}},
			{Src: sb.pub(), Msgs: []core.Message{v2}},
			{Src: sc.pub(), Msgs: nil},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 {
			t.Fatalf("tied variants must not be accepted: %v", acceptIDs(cr))
		}
		if pt.count(sa.pub()) != 1 || pt.count(sb.pub()) != 1 {
			t.Fatalf("both disagreeing sources penalized: %v", pt.all)
		}
	})

	t.Run("伪签丢弃差评多数派仍采纳", func(t *testing.T) {
		good := makeText(t, y, "real", 100, "sig-check")
		broken := makeText(t, y, "real", 100, "sig-check")
		broken.Sig[0] ^= 0xff
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{broken}},
			{Src: sb.pub(), Msgs: []core.Message{good}},
			{Src: sc.pub(), Msgs: []core.Message{good}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{good.MsgID}) {
			t.Fatalf("accepted = %v", acceptIDs(cr))
		}
		if !pt.has(sa.pub(), DropBadSig) || len(cr.Drops) != 1 {
			t.Fatalf("drops = %v penalties = %v", cr.Drops, pt.all)
		}
	})

	t.Run("同源自相矛盾整源弃用", func(t *testing.T) {
		v1 := makeText(t, y, "a", 100, "self-conf")
		v2 := makeText(t, y, "b", 100, "self-conf")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{v1, v2}},
			{Src: sb.pub(), Msgs: []core.Message{v1}},
			{Src: sc.pub(), Msgs: nil},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 {
			t.Fatalf("nothing should survive: %v", acceptIDs(cr))
		}
		if !pt.has(sa.pub(), DropSelfConflict) {
			t.Fatalf("self-conflicting source must be penalized: %v", pt.all)
		}
		if !pt.has(sb.pub(), DropSingleSource) {
			t.Fatalf("left as sole supporter -> single-source rule: %v", pt.all)
		}
	})

	t.Run("未知sig_alg拒绝采纳并差评", func(t *testing.T) {
		m := makeText(t, sm2, "sm2 msg", 100, "sm2")
		m.Sender.Alg = core.SigAlg("sm2")
		m.Alg = core.SigAlg("sm2")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{m}},
			{Src: sb.pub(), Msgs: []core.Message{m}},
			{Src: sc.pub(), Msgs: []core.Message{m}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 || len(cr.Drops) != 3 {
			t.Fatalf("accepted=%v drops=%v", acceptIDs(cr), cr.Drops)
		}
		for _, d := range cr.Drops {
			if d.Reason != DropUnknownAlg {
				t.Fatalf("want unknown_alg drops, got %v", cr.Drops)
			}
		}
	})

	t.Run("接收时名单判定发言权", func(t *testing.T) {
		nospeak := makeText(t, bad, "quiet", 100, "nospeak")
		ghostMsg := makeText(t, ghost, "who", 101, "ghost")
		r := seedRoster()
		pt := newPenTracker()
		st := newMemStore()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{nospeak, ghostMsg}},
			{Src: sb.pub(), Msgs: []core.Message{nospeak, ghostMsg}},
			{Src: sc.pub(), Msgs: []core.Message{nospeak, ghostMsg}},
		}, r, st, defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 {
			t.Fatalf("no-speak & non-member must all drop: %v", acceptIDs(cr))
		}
		for _, d := range cr.Drops {
			if d.Reason != DropNoSpeak {
				t.Fatalf("want no_speak_perm, got %v", cr.Drops)
			}
		}
		if pt.count(sa.pub()) != 2 {
			t.Fatalf("each offending msg penalizes supporters: %v", pt.all)
		}
	})

	t.Run("黑名单发送者拒绝定向申诉放行", func(t *testing.T) {
		plain := makeText(t, bl, "spam", 100, "bl-plain")
		to := x.pub()
		// 定向申诉：To 在签名前写入（MessageSigPayload 原文含 to，签后改 To 即伪签）。
		appeal := makeMsgTo(t, bl, core.TypeText, "appeal", 101, "bl-appeal", &to)
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{plain, appeal}},
			{Src: sb.pub(), Msgs: []core.Message{plain, appeal}},
			{Src: sc.pub(), Msgs: []core.Message{plain, appeal}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{appeal.MsgID}) {
			t.Fatalf("accepted = %v, want only directed appeal", acceptIDs(cr))
		}
		for _, d := range cr.Drops {
			if d.Reason != DropBlacklisted {
				t.Fatalf("want blacklisted_sender drops, got %v", cr.Drops)
			}
		}
	})

	t.Run("定向申诉To指向无解禁权限者仍拒绝", func(t *testing.T) {
		to := y.pub() // 普通成员无 kick/unban：不构成「唯一通道」的目标
		appeal := makeMsgTo(t, bl, core.TypeText, "appeal-misdirected", 102, "bl-to-member", &to)
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{appeal}},
			{Src: sb.pub(), Msgs: []core.Message{appeal}},
			{Src: sc.pub(), Msgs: []core.Message{appeal}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 {
			t.Fatalf("misdirected appeal must not be accepted: %v", acceptIDs(cr))
		}
		for _, d := range cr.Drops {
			if d.Reason != DropBlacklisted {
				t.Fatalf("want blacklisted_sender drops, got %v", cr.Drops)
			}
		}
	})

	t.Run("名单事件经ApplyEvent采纳_新人自签join丢弃", func(t *testing.T) {
		newbie := newSigner("newbie")
		validJoin := makeJoin(t, x, newbie, []string{core.PermSpeak, core.PermReceive}, 90)
		selfJoin := makeJoin(t, newbie, newbie, []string{core.PermSpeak}, 91)
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{validJoin, selfJoin}},
			{Src: sb.pub(), Msgs: []core.Message{validJoin, selfJoin}},
			{Src: sc.pub(), Msgs: []core.Message{validJoin, selfJoin}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{validJoin.MsgID}) {
			t.Fatalf("accepted = %v, want carrier-signed join", acceptIDs(cr))
		}
		if _, ok := r.Member(newbie.pub()); !ok {
			t.Fatal("valid join must have been applied to roster")
		}
		for _, d := range cr.Drops {
			if d.Reason != DropEventRejected {
				t.Fatalf("self-joined must drop as event_rejected, got %v", cr.Drops)
			}
		}
	})

	t.Run("越权事件差评非权限持有者签的kick", func(t *testing.T) {
		illegalKick := makeKick(t, y, ghost.pub(), 95) // y 只是成员无 kick 权限
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{illegalKick}},
			{Src: sb.pub(), Msgs: []core.Message{illegalKick}},
			{Src: sc.pub(), Msgs: []core.Message{illegalKick}},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 {
			t.Fatalf("illegal kick must not be accepted")
		}
		for _, d := range cr.Drops {
			if d.Reason != DropOverreach {
				t.Fatalf("want overreach (ErrNotPermitted), got %v", cr.Drops)
			}
		}
	})

	t.Run("应答源不足MinSources时不做单源差评", func(t *testing.T) {
		m := makeText(t, y, "only-two", 100, "two-src")
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{m}},
			{Src: sb.pub(), Msgs: nil},
		}, r, newMemStore(), defaultCfg(), 0, pt.penalize)
		if !reflect.DeepEqual(acceptIDs(cr), []string{m.MsgID}) {
			t.Fatalf("audit 补拉路径允许少于 MinSources 的佐证: %v", acceptIDs(cr))
		}
	})

	t.Run("本机已有msg_id去重跳过", func(t *testing.T) {
		m := makeText(t, y, "dup", 100, "dup")
		st := newMemStore()
		_ = st.Append(m)
		r := seedRoster()
		pt := newPenTracker()
		cr := crossCheck([]srcMsgs{
			{Src: sa.pub(), Msgs: []core.Message{m}},
			{Src: sb.pub(), Msgs: []core.Message{m}},
			{Src: sc.pub(), Msgs: []core.Message{m}},
		}, r, st, defaultCfg(), 0, pt.penalize)
		if len(cr.Accepted) != 0 || len(cr.Drops) != 0 || pt.total() != 0 {
			t.Fatalf("already-stored msg must be silently skipped: %v %v", cr.Accepted, cr.Drops)
		}
	})
}
