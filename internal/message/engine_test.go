package message

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"dmesh/internal/core"
)

type recorder struct {
	mu            sync.Mutex
	chat          []core.Message
	events        []core.Message
	hides         []core.Message
	appeals       []core.Message
	joinReqs      []core.Message
	transferProps []core.Message // v17① 联署提案收件（Handlers.TransferProposal）
	deleted       []string
	penalties     []struct {
		from   core.PubKey
		reason RejectReason
	}
	store map[string]core.Message
}

func newRecorder() *recorder {
	return &recorder{store: map[string]core.Message{}}
}

func (r *recorder) handlers() Handlers {
	return Handlers{
		Chat:        func(m core.Message) { r.mu.Lock(); r.chat = append(r.chat, m); r.mu.Unlock() },
		RosterEvent: func(m core.Message) { r.mu.Lock(); r.events = append(r.events, m); r.mu.Unlock() },
		Hide:        func(m core.Message) { r.mu.Lock(); r.hides = append(r.hides, m); r.mu.Unlock() },
		Appeal:      func(m core.Message) { r.mu.Lock(); r.appeals = append(r.appeals, m); r.mu.Unlock() },
		JoinReq:     func(m core.Message) { r.mu.Lock(); r.joinReqs = append(r.joinReqs, m); r.mu.Unlock() },
		TransferProposal: func(m core.Message) {
			r.mu.Lock()
			r.transferProps = append(r.transferProps, m)
			r.mu.Unlock()
		},
		SoftDelete: func(id string) { r.mu.Lock(); r.deleted = append(r.deleted, id); r.mu.Unlock() },
		Lookup: func(id string) (core.Message, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			m, ok := r.store[id]
			return m, ok
		},
		Penalty: func(from core.PubKey, reason RejectReason, m *core.Message, err error) {
			r.mu.Lock()
			r.penalties = append(r.penalties, struct {
				from   core.PubKey
				reason RejectReason
			}{from, reason})
			r.mu.Unlock()
		},
	}
}

func (r *recorder) put(m core.Message) { r.store[m.MsgID] = m }

func (r *recorder) snapshotCounts() (chat, events, hides, appeals, jr int, deleted []string, pens []RejectReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.penalties {
		pens = append(pens, p.reason)
	}
	return len(r.chat), len(r.events), len(r.hides), len(r.appeals), len(r.joinReqs),
		append([]string(nil), r.deleted...), pens
}

type env struct {
	t     *testing.T
	eng   *Engine
	tr    *fakeTransport
	rec   *recorder
	ros   *fakeRoster
	me    *testSigner
	peers []core.PubKey
}

func newEnv(t *testing.T, useRoster bool) *env {
	t.Helper()
	e := &env{t: t, me: newTestSigner(), tr: newFakeTransport(), rec: newRecorder()}
	var ros core.Roster
	if useRoster {
		e.ros = newFakeRoster()
		e.ros.addMember(e.me.pub, core.RoleMember, core.PermSpeak, core.PermReceive, core.PermCarry)
		ros = e.ros
	}
	e.peers = []core.PubKey{pk(10), pk(20), pk(30)}
	e.eng = NewEngine(testGroupID, e.me.pub, ros, e.tr, fakePeers{e.peers}, e.rec.handlers())
	return e
}

func (e *env) otherMember() (*testSigner, core.PubKey) {
	s := newTestSigner()
	if e.ros != nil {
		e.ros.addMember(s.pub, core.RoleMember, core.PermSpeak, core.PermReceive)
	}
	return s, s.pub
}

// ---------- 文本 flood + 去重收敛 ----------

func TestIngestTextFloodsAllExceptSource(t *testing.T) {
	e := newEnv(t, true)
	s, sender := e.otherMember()
	m := mustText(t, s, 1700000000000, "hello group", "")
	out := e.eng.Ingest(sender, frameOf(t, m))
	if !out.Accepted || out.Kind != KindChat {
		t.Fatalf("outcome = %+v", out)
	}
	if chat, _, _, _, _, _, _ := e.rec.snapshotCounts(); chat != 1 {
		t.Fatalf("chat delivered %d, want 1", chat)
	}
	// 3 个邻居，来源是 sender（不在邻居表）→ 全收 3 份
	if got := e.tr.total(); got != 3 {
		t.Fatalf("flooded %d peers, want 3", got)
	}
	// 同一邻居再推 → 去重吞掉：不再投递、不再转发、不差评
	before := e.tr.total()
	out2 := e.eng.Ingest(e.peers[0], frameOf(t, m))
	if !out2.Duplicate || out2.Accepted {
		t.Fatalf("dup outcome = %+v", out2)
	}
	if after := e.tr.total(); after != before {
		t.Fatalf("duplicate was re-flooded")
	}
	if chat, _, _, _, _, _, pens := e.rec.snapshotCounts(); chat != 1 || len(pens) != 0 {
		t.Fatalf("dup must not deliver or penalize: chat=%d pens=%v", chat, pens)
	}
	// 不同来源推送同一条 → 同样吞掉（来源无关去重）
	out3 := e.eng.Ingest(e.peers[1], frameOf(t, m))
	if !out3.Duplicate {
		t.Fatalf("cross-source dup outcome = %+v", out3)
	}
}

func TestIngestNeverSendsBackToSource(t *testing.T) {
	e := newEnv(t, true)
	s, _ := e.otherMember()
	m := mustText(t, s, 1700000000000, "x", "")
	// 让 peers[1] 是发送来源
	out := e.eng.Ingest(e.peers[1], frameOf(t, m))
	if !out.Accepted {
		t.Fatalf("%+v", out)
	}
	if e.tr.countTo(e.peers[1]) != 0 {
		t.Fatal("flood sent back to source (风暴回环)")
	}
	if e.tr.countTo(e.peers[0]) != 1 || e.tr.countTo(e.peers[2]) != 1 {
		t.Fatal("flood missed other peers")
	}
}

// ---------- 验签拒绝 + 来源差评 ----------

func TestIngestVerifyRejectionsPenalize(t *testing.T) {
	e := newEnv(t, true)
	s, sender := e.otherMember()
	good := mustText(t, s, 1700000000000, "keep", "")

	cases := []struct {
		name       string
		mutate     func(*core.Message)
		wantReason RejectReason
	}{
		{"tampered body", func(m *core.Message) { m.Body = []byte(`{"text":"tampered!"}`) }, ReasonBadSig},
		{"unknown sig_alg (v16 拒绝采纳+差评)", func(m *core.Message) {
			m.Alg = core.SigAlg("sm9")
			m.Sender.Alg = m.Alg
		}, ReasonUnknownAlg},
		{"wrong group id", func(m *core.Message) { m.GroupID = [32]byte{9, 9} }, ReasonMalformed},
		{"stripped signature", func(m *core.Message) { m.Sig = nil }, ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env2 := newEnv(t, true)
			bad := good
			tc.mutate(&bad)
			out := env2.eng.Ingest(sender, frameOf(t, bad))
			if out.Accepted {
				t.Fatalf("must reject, got %+v", out)
			}
			if out.Reason != tc.wantReason {
				t.Fatalf("reason = %q want %q (err %v)", out.Reason, tc.wantReason, out.Err)
			}
			if _, _, _, _, _, _, pens := env2.rec.snapshotCounts(); len(pens) != 1 || pens[0] != tc.wantReason {
				t.Fatalf("source penalty missing/wrong: %v", pens)
			}
			if env2.tr.total() != 0 {
				t.Fatal("invalid message must not be forwarded")
			}
		})
	}
}

// TestKindLieRejectedAndPenalized 是 PLAN v26 验收②的引擎侧负例：正文装的是 cmd 的
// kick，信封却把 kind 谎报成 msg（想躲开名单校验、混进气泡流），或干脆不声明 kind。
// 三道关都拦得住，且每一道都留下差评、绝不转发：
//
//	⓪ 本机根本签不出这种原文（NewMessage 在发签前互校 kind↔body）；
//	① 入站帧在结构关（DecodeFrame）就被拒——谎报者拿到的是 malformed_frame 差评；
//	② 已解码消息（store/backfill 复验同一条规则）走到路由步，按互校拒为 unknown_name。
func TestKindLieRejectedAndPenalized(t *testing.T) {
	body, err := core.MakeBody(core.NameKick, map[string]any{"target": "00"})
	if err != nil {
		t.Fatal(err)
	}
	// lie 手工拼信封并对「谎报后的原文」签名：合法签名 + 不符的判别位。
	lie := func(t *testing.T, s core.Signer, kind string, ts int64, msgID string) core.Message {
		t.Helper()
		m := core.Message{MsgID: msgID, GroupID: testGroupID, Sender: s.Pub(),
			Alg: s.Alg(), TSms: ts, Kind: kind, Body: body}
		raw, err := core.MessageSigPayload(m)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		m.Sig = sig
		return m
	}

	t.Run("签发端拒", func(t *testing.T) {
		e := newEnv(t, true)
		s, _ := e.otherMember()
		if _, err := NewMessage(s, testGroupID, &core.Message{
			Kind: core.KindMessage, TSms: 1700000000400, Body: body}, nil); err == nil {
			t.Fatal("NewMessage 竟签出了 kind 谎报的原文")
		}
	})

	cases := []struct {
		desc   string
		kind   string
		ts     int64
		msgID  string
		reason RejectReason
	}{{"kick 伪装成 msg（入站帧）", core.KindMessage, 1700000000500, "lie-frame", ReasonMalformed},
		{"kick 不声明 kind（入站帧）", "", 1700000000501, "lie-nokind", ReasonMalformed},
		{"kick 伪装成 msg（已解码复验）", core.KindMessage, 1700000000502, "lie-ingest", ReasonUnknownName},
		{"kick 不声明 kind（已解码复验）", "", 1700000000503, "lie-ingest2", ReasonUnknownName}}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			e := newEnv(t, true)
			s, sender := e.otherMember()
			m := lie(t, s, tc.kind, tc.ts, tc.msgID)
			var out Outcome
			if tc.reason == ReasonMalformed {
				out = e.eng.Ingest(sender, frameOf(t, m))
			} else {
				out = e.eng.IngestMessage(sender, m)
			}
			if out.Accepted || out.Reason != tc.reason {
				t.Fatalf("want reject/%s, got %+v (err %v)", tc.reason, out, out.Err)
			}
			if _, _, _, _, _, _, pens := e.rec.snapshotCounts(); len(pens) != 1 || pens[0] != tc.reason {
				t.Fatalf("谎报者未差评或差评原因错: %v", pens)
			}
			if e.tr.total() != 0 {
				t.Fatal("谎报正文不得转发")
			}
		})
	}
}

// ---------- 权限判定 ----------

func TestIngestTextPermissionGates(t *testing.T) {
	e := newEnv(t, true)
	// 非成员发言 → 丢弃 + 差评
	outsider := newTestSigner()
	m := mustText(t, outsider, 1700000000000, "sneak in", "")
	out := e.eng.Ingest(outsider.pub, frameOf(t, m))
	if out.Accepted || out.Reason != ReasonNotMember {
		t.Fatalf("non-member: %+v", out)
	}
	// 成员但无 speak 权限 → 丢弃 + 差评
	muted := newTestSigner()
	e.ros.addMember(muted.pub, core.RoleMember) // 无权限位
	m2 := mustText(t, muted, 1700000000001, "muted?", "")
	out2 := e.eng.Ingest(muted.pub, frameOf(t, m2))
	if out2.Accepted || out2.Reason != ReasonNoSpeak {
		t.Fatalf("no speak: %+v", out2)
	}
	if _, _, _, _, _, _, pens := e.rec.snapshotCounts(); len(pens) != 2 {
		t.Fatalf("penalty count = %d want 2", len(pens))
	}
}

// ---------- 定向 To ----------

func TestDirectedTextOnlyDeliveredToTarget(t *testing.T) {
	e := newEnv(t, true)
	s, _ := e.otherMember()
	other := newTestSigner()
	e.ros.addMember(other.pub, core.RoleMember, core.PermSpeak)
	m := mustText(t, s, 1700000000000, "for you only", "")
	to := other.pub
	m.To = &to
	signed, err := NewMessage(s, testGroupID, &m, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := e.eng.Ingest(s.pub, frameOf(t, signed))
	if !out.Accepted || out.Delivered {
		t.Fatalf("directed-to-other must flood but not display: %+v", out)
	}
	if e.tr.total() != 3 {
		t.Fatalf("directed message not flooded: %d", e.tr.total())
	}
}

// ---------- 黑名单与定向申诉 ----------

func TestBlacklistedAndAppealChannel(t *testing.T) {
	blocked := newTestSigner()

	t.Run("plain chat from blacklisted -> reject + penalty + no flood", func(t *testing.T) {
		e := newEnv(t, true)
		e.ros.addMember(blocked.pub, core.RoleMember, core.PermSpeak)
		e.ros.blacklist(blocked.pub)
		m := mustText(t, blocked, 1700000000000, "hi?", "")
		out := e.eng.Ingest(blocked.pub, frameOf(t, m))
		if out.Accepted || out.Reason != ReasonBlacklisted {
			t.Fatalf("%+v", out)
		}
		if e.tr.total() != 0 {
			t.Fatal("blacklisted traffic must not be relayed (不收也不转发)")
		}
		if _, _, _, _, _, _, pens := e.rec.snapshotCounts(); len(pens) != 1 {
			t.Fatalf("want penalty, got %v", pens)
		}
	})

	t.Run("appeal to unban-holder self -> accepted, not flooded", func(t *testing.T) {
		e := newEnv(t, true)
		e.ros.addMember(blocked.pub, core.RoleMember)
		e.ros.blacklist(blocked.pub)
		e.ros.addMember(e.me.pub, core.RoleOwner, core.PermUnban)
		m := mustText(t, blocked, 1700000000000, "please unban me", "")
		to := e.me.pub
		m.To = &to
		signed, _ := NewMessage(blocked, testGroupID, &m, nil)
		out := e.eng.Ingest(blocked.pub, frameOf(t, signed))
		if !out.Accepted || out.Kind != KindAppeal {
			t.Fatalf("%+v", out)
		}
		if e.tr.total() != 0 {
			t.Fatal("appeal must not be flooded")
		}
		if _, _, _, appeals, _, _, _ := e.rec.snapshotCounts(); appeals != 1 {
			t.Fatal("appeal not delivered to panel")
		}
	})

	t.Run("appeal to member without unban perm -> reject", func(t *testing.T) {
		e := newEnv(t, true)
		e.ros.addMember(blocked.pub, core.RoleMember)
		e.ros.blacklist(blocked.pub)
		// 本机只是普通成员（无 unban/kick）
		e.ros.mu.Lock()
		delete(e.ros.members, e.me.pub.Key())
		e.ros.mu.Unlock()
		e.ros.addMember(e.me.pub, core.RoleMember, core.PermSpeak)
		m := mustText(t, blocked, 1700000000000, "appeal to wrong door", "")
		to := e.me.pub
		m.To = &to
		signed, _ := NewMessage(blocked, testGroupID, &m, nil)
		out := e.eng.Ingest(blocked.pub, frameOf(t, signed))
		if out.Accepted || out.Reason != ReasonBlacklisted {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("blacklisted msg directed to someone else -> reject", func(t *testing.T) {
		e := newEnv(t, true)
		e.ros.addMember(blocked.pub, core.RoleMember)
		e.ros.blacklist(blocked.pub)
		e.ros.addMember(e.me.pub, core.RoleOwner, core.PermUnban)
		m := mustText(t, blocked, 1700000000000, "sneak via another", "")
		to := pk(77)
		m.To = &to
		signed, _ := NewMessage(blocked, testGroupID, &m, nil)
		out := e.eng.Ingest(blocked.pub, frameOf(t, signed))
		if out.Accepted || out.Reason != ReasonBlacklisted {
			t.Fatalf("%+v", out)
		}
	})
}

// ---------- 名单事件同路广播、聊天流不显示 ----------

func TestRosterEventSamePathNoChat(t *testing.T) {
	e := newEnv(t, true)
	kicker := newTestSigner()
	e.ros.addMember(kicker.pub, core.RoleAdmin, core.PermKick, core.PermSpeak)
	m, err := NewMessage(kicker, testGroupID, &core.Message{
		Kind: core.KindCommand, TSms: 1700000000000, Body: []byte(`{"kick":{"pub":"aa"}}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := e.eng.Ingest(kicker.pub, frameOf(t, m))
	if !out.Accepted || out.Kind != KindRosterEvent {
		t.Fatalf("%+v", out)
	}
	chat, events, _, _, _, _, _ := e.rec.snapshotCounts()
	if chat != 0 {
		t.Fatal("roster event must not enter chat stream")
	}
	if events != 1 {
		t.Fatal("roster event not delivered to roster handler")
	}
	if e.tr.total() != 3 {
		t.Fatalf("roster event must flood same path, got %d", e.tr.total())
	}

	// 越权事件（ApplyEvent 拒绝）→ 丢弃 + 差评 + 不转发
	e2 := newEnv(t, true)
	e2.ros.mu.Lock()
	e2.ros.applyErr[core.NameKick] = fmt.Errorf("roster: %w: tier too low", core.ErrNotPermitted)
	e2.ros.mu.Unlock()
	out2 := e2.eng.Ingest(kicker.pub, frameOf(t, m))
	if out2.Accepted || out2.Reason != ReasonOverreach {
		t.Fatalf("overreach: %+v", out2)
	}
	if e2.tr.total() != 0 {
		t.Fatal("rejected event must not be relayed")
	}
	if _, _, _, _, _, _, pens := e2.rec.snapshotCounts(); len(pens) != 1 {
		t.Fatalf("overreach must penalize: %v", pens)
	}
}

// ---------- join_req 无许可中继 ----------

func TestJoinReqRelaysToOnlineCarriersOnly(t *testing.T) {
	e := newEnv(t, true)
	now := time.Unix(1700000000, 0)
	e.eng.Now = func() time.Time { return now }
	// peers: 0=在线carry, 1=离线carry, 2=在线普通
	carrier1, carrier2, plain := pk(10), pk(20), pk(30)
	e.ros.addMember(carrier1, core.RoleAdmin, core.PermCarry)
	e.ros.addMember(carrier2, core.RoleAdmin, core.PermCarry)
	e.ros.addMember(plain, core.RoleMember, core.PermSpeak)
	e.ros.setPresence(carrier1, now.UnixMilli()-1000, 60_000)      // 在线
	e.ros.setPresence(carrier2, now.UnixMilli()-3_600_000, 60_000) // 离线
	e.ros.setPresence(plain, now.UnixMilli(), 60_000)
	// 本机具 carry（newEnv 已给）→ 本地受理
	newcomer := newTestSigner()
	jr, err := NewMessage(newcomer, testGroupID, &core.Message{
		Kind: core.KindCommand, TSms: now.UnixMilli(), Body: []byte(`{"join_req":"seed-info"}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	via := carrier1
	out := e.eng.Ingest(via, frameOf(t, jr))
	if !out.Accepted || out.Kind != KindJoinReq {
		t.Fatalf("%+v", out)
	}
	if _, _, _, _, jrN, _, _ := e.rec.snapshotCounts(); jrN != 1 {
		t.Fatalf("local carry holder must accept join_req, got %d", jrN)
	}
	if got := e.tr.countTo(carrier1); got != 0 {
		t.Fatalf("must not relay back to source carrier, got %d", got)
	}
	if got := e.tr.countTo(carrier2); got != 0 {
		t.Fatalf("offline carrier must not be relayed to, got %d", got)
	}
	if got := e.tr.countTo(plain); got != 0 {
		t.Fatalf("non-carrier must not receive relay, got %d", got)
	}
	// 重复中继 → relay 去重（防风暴）
	out2 := e.eng.Ingest(plain, frameOf(t, jr))
	if !out2.Duplicate {
		t.Fatalf("second relay attempt must be suppressed: %+v", out2)
	}

	// 本机无 carry：不本地受理，但仍尽中继义务
	e3 := newEnv(t, true)
	e3.eng.Now = func() time.Time { return now }
	e3.ros.mu.Lock()
	delete(e3.ros.members, e3.me.pub.Key())
	e3.ros.mu.Unlock()
	e3.ros.addMember(e3.me.pub, core.RoleMember, core.PermSpeak)
	for _, c := range []core.PubKey{carrier1, carrier2, plain} {
		e3.ros.addMember(c, core.RoleAdmin, core.PermCarry)
	}
	e3.ros.setPresence(carrier1, now.UnixMilli()-1000, 60_000)
	e3.ros.setPresence(carrier2, now.UnixMilli()-3_600_000, 60_000)
	e3.ros.setPresence(plain, now.UnixMilli()-1000, 60_000)
	out3 := e3.eng.Ingest(via, frameOf(t, jr))
	if !out3.Accepted || out3.Delivered {
		t.Fatalf("non-carry node: accepted without local delivery expected, %+v", out3)
	}
	// via=carrier1 被排除；carrier2 离线不中继；plain 在线 carry → 恰好 1 跳
	if out3.Flooded != 1 {
		t.Fatalf("relay fanout = %d, want 1", out3.Flooded)
	}
}

// ---------- hide ----------

func TestHideRules(t *testing.T) {
	e := newEnv(t, true)
	s := newTestSigner()
	e.ros.addMember(s.pub, core.RoleMember, core.PermSpeak)
	other := newTestSigner()
	e.ros.addMember(other.pub, core.RoleMember, core.PermSpeak)

	ownMsg := mustText(t, s, 1700000000000, "embarrassing", "own-1")
	foreign := mustText(t, other, 1700000000001, "not yours", "foreign-1")
	e.rec.put(ownMsg)
	e.rec.put(foreign)

	// 1. 隐藏自己的消息 → 软删除 + flood + 不显示在聊天流
	h, _ := NewHide(s, testGroupID, 1700000000002, "own-1")
	out := e.eng.Ingest(s.pub, frameOf(t, h))
	if !out.Accepted || out.Kind != KindHide {
		t.Fatalf("own hide: %+v", out)
	}
	if _, _, hides, _, _, deleted, _ := e.rec.snapshotCounts(); len(deleted) != 1 || deleted[0] != "own-1" {
		t.Fatalf("soft delete = %v", deleted)
	} else if hides != 1 {
		t.Fatalf("hide event not recorded: %d", hides)
	}
	if e.tr.total() == 0 {
		t.Fatal("valid hide must flood")
	}

	// 2. 隐藏别人的消息（target 发送者 pubkey 不符）→ 拒绝 + 差评
	e2 := newEnv(t, true)
	e2.rec.put(foreign)
	e2.ros.addMember(s.pub, core.RoleMember, core.PermSpeak)
	h2, _ := NewHide(s, testGroupID, 1700000000003, "foreign-1")
	out2 := e2.eng.Ingest(s.pub, frameOf(t, h2))
	if out2.Accepted || out2.Reason != ReasonHideSelf {
		t.Fatalf("hide foreign: %+v", out2)
	}
	if _, _, _, _, _, _, pens := e2.rec.snapshotCounts(); len(pens) != 1 {
		t.Fatalf("want penalty %v", pens)
	}

	// 3. hide 不可被 hide
	e3 := newEnv(t, true)
	e3.rec.put(h)
	h3, _ := NewHide(s, testGroupID, 1700000000004, h.MsgID)
	out3 := e3.eng.Ingest(s.pub, frameOf(t, h3))
	if out3.Accepted || out3.Reason != ReasonHideSelf {
		t.Fatalf("hide of hide: %+v", out3)
	}

	// 4. hide 指向自身 msg_id → 结构性拒绝 + 差评
	e4 := newEnv(t, true)
	e4.ros.addMember(s.pub, core.RoleMember, core.PermSpeak)
	selfHC, _ := EncodeHideBody("self-x")
	selfHide, err := NewMessage(s, testGroupID, &core.Message{
		Kind: core.KindCommand, TSms: 1700000000006, Body: selfHC, MsgID: "self-x",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out4 := e4.eng.Ingest(s.pub, frameOf(t, selfHide))
	if out4.Accepted || out4.Reason != ReasonHideSelf {
		t.Fatalf("self-referencing hide: %+v", out4)
	}
	if _, _, _, _, _, _, pens := e4.rec.snapshotCounts(); len(pens) != 1 {
		t.Fatalf("self-referencing hide must penalize: %v", pens)
	}

	// 5. 乱序：hide 先到、目标消息后到 → 目标到达时兑现软删除
	e5 := newEnv(t, true)
	e5.ros.addMember(s.pub, core.RoleMember, core.PermSpeak)
	later := mustText(t, s, 1700000000008, "arrives late", "late-1")
	h5, _ := NewHide(s, testGroupID, 1700000000007, "late-1")
	if out := e5.eng.Ingest(s.pub, frameOf(t, h5)); !out.Accepted {
		t.Fatalf("pending hide: %+v", out)
	}
	if _, _, _, _, _, deleted, _ := e5.rec.snapshotCounts(); len(deleted) != 0 {
		t.Fatalf("must not delete before target arrives: %v", deleted)
	}
	if out := e5.eng.Ingest(s.pub, frameOf(t, later)); !out.Accepted {
		t.Fatalf("late target: %+v", out)
	}
	if _, _, _, _, _, deleted, _ := e5.rec.snapshotCounts(); len(deleted) != 1 || deleted[0] != "late-1" {
		t.Fatalf("pending hide not flushed on target arrival: %v", deleted)
	}

	// 6. 挂起的 hide：后到的目标却是别人的消息 → 不兑现（规则仍守）
	e6 := newEnv(t, true)
	e6.ros.addMember(s.pub, core.RoleMember, core.PermSpeak)
	e6.ros.addMember(other.pub, core.RoleMember, core.PermSpeak)
	h6, _ := NewHide(s, testGroupID, 1700000000009, "mismatch-1")
	if out := e6.eng.Ingest(s.pub, frameOf(t, h6)); !out.Accepted {
		t.Fatalf("%+v", out)
	}
	stranger := mustText(t, other, 1700000000010, "not yours either", "mismatch-1")
	if out := e6.eng.Ingest(other.pub, frameOf(t, stranger)); !out.Accepted {
		t.Fatalf("%+v", out)
	}
	if _, _, _, _, _, deleted, _ := e6.rec.snapshotCounts(); len(deleted) != 0 {
		t.Fatalf("hide must not delete foreign message: %v", deleted)
	}
}

// ---------- Publish ----------

func TestPublishPushesAllPeersAndSelfSuppress(t *testing.T) {
	e := newEnv(t, false)
	m := mustText(t, e.me, 1700000000000, "mine", "")
	n, err := e.eng.Publish(m)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || e.tr.total() != 3 {
		t.Fatalf("published to %d peers, want 3", n)
	}
	// 任何邻居把同一条回推 → 吞掉（本机来源抑制）
	out := e.eng.Ingest(e.peers[0], frameOf(t, m))
	if !out.Duplicate {
		t.Fatalf("echo must be suppressed: %+v", out)
	}
}

// ---------- flood 收敛仿真（4 引擎全连接，纯逻辑） ----------

// switchBoard 把 Send(to, frame) 直接路由到目标引擎的 Ingest（内存环回、无网络）。
// 来源统一标注为一个不属于任何节点的假 pubkey：收敛断言只依赖 msg_id 去重，
// 与「不回送来源」这一跳无关（各引擎逻辑独立验证于上面的用例）。
type switchBoard struct {
	mu      sync.Mutex
	engines map[string]*Engine
	dummy   core.PubKey
}

func (sb *switchBoard) Send(to core.PubKey, frame []byte) error {
	sb.mu.Lock()
	eng, ok := sb.engines[to.Key()]
	sb.mu.Unlock()
	if ok {
		eng.Ingest(sb.dummy, frame)
	}
	return nil
}

func TestFloodConvergenceFourNode(t *testing.T) {
	sigs := []*testSigner{newTestSigner(), newTestSigner(), newTestSigner(), newTestSigner()}
	sb := &switchBoard{engines: map[string]*Engine{}, dummy: pk(255)}
	delivered := make([][]string, len(sigs))
	var mu sync.Mutex
	engines := make([]*Engine, len(sigs))
	for i, s := range sigs {
		i, s := i, s
		peers := make([]core.PubKey, 0, len(sigs)-1)
		for j, o := range sigs {
			if j != i {
				peers = append(peers, o.pub)
			}
		}
		h := Handlers{Chat: func(m core.Message) {
			mu.Lock()
			delivered[i] = append(delivered[i], m.MsgID)
			mu.Unlock()
		}}
		eng := NewEngine(testGroupID, s.pub, nil, sb, fakePeers{peers}, h)
		sb.engines[s.pub.Key()] = eng
		engines[i] = eng
	}
	msg := mustText(t, sigs[0], 1700000000000, "flood converge", "")
	n, err := engines[0].Publish(msg)
	if err != nil || n != 3 {
		t.Fatalf("publish: %d %v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(sigs); i++ {
		if len(delivered[i]) != 1 {
			t.Fatalf("node %d delivered %d copies of same msg, want exactly 1 (去重/来源抑制失效)", i, len(delivered[i]))
		}
	}
	if len(delivered[0]) != 0 {
		t.Fatal("publisher must not re-deliver its own message")
	}
}

// ---------- IngestMessage 复用管线 ----------

func TestIngestMessageSamePipeline(t *testing.T) {
	e := newEnv(t, true)
	s, _ := e.otherMember()
	m := mustText(t, s, 1700000000000, "pre-decoded", "")
	out := e.eng.IngestMessage(s.pub, m)
	if !out.Accepted || out.Kind != KindChat {
		t.Fatalf("%+v", out)
	}
	// 再走帧路径 → 跨入口去重生效
	out2 := e.eng.Ingest(s.pub, frameOf(t, m))
	if !out2.Duplicate {
		t.Fatalf("cross-entry dedup failed: %+v", out2)
	}
}

// ---------- 无名单纯逻辑模式 ----------

func TestNilRosterPureLogicMode(t *testing.T) {
	e := newEnv(t, false)
	s := newTestSigner()
	m := mustText(t, s, 1700000000000, "no roster", "")
	out := e.eng.Ingest(s.pub, frameOf(t, m))
	if !out.Accepted || out.Kind != KindChat {
		t.Fatalf("%+v", out)
	}
	ev, _ := NewMessage(s, testGroupID, &core.Message{Kind: core.KindCommand, TSms: 1, Body: []byte(`{"join":"e"}`)}, nil)
	out2 := e.eng.Ingest(s.pub, frameOf(t, ev))
	if !out2.Accepted || out2.Kind != KindRosterEvent {
		t.Fatalf("%+v", out2)
	}
}

// ---------- transfer 联署提案（v17①） ----------

func proposalEnv(t *testing.T) (*env, *testSigner, *testSigner) {
	t.Helper()
	e := newEnv(t, true)
	owner := newTestSigner()
	e.ros.addMember(owner.pub, core.RoleOwner, core.PermTransfer, core.PermSpeak)
	newOwner := newTestSigner()
	e.ros.addMember(newOwner.pub, core.RoleAdmin, core.PermSpeak)
	return e, owner, newOwner
}

func makeProposal(t *testing.T, owner *testSigner, to core.PubKey, ts int64) core.Message {
	t.Helper()
	m, err := NewMessage(owner, testGroupID, &core.Message{
		Kind: core.KindCommand, TSms: ts,
		Body: []byte(`{"transfer":{"new_owner":{"alg":"ed25519","bytes":"aabb"}}}`),
		To:   &to,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTransferProposalDeliveredNotApplied(t *testing.T) {
	e, owner, no := proposalEnv(t)
	m := makeProposal(t, owner, e.me.pub, 1700000001000) // To=本机
	out := e.eng.Ingest(owner.pub, frameOf(t, m))
	if !out.Accepted || out.Kind != KindTransferProposal || !out.Delivered {
		t.Fatalf("%+v", out)
	}
	e.rec.mu.Lock()
	props, chat, events := len(e.rec.transferProps), len(e.rec.chat), len(e.rec.events)
	pens := len(e.rec.penalties)
	applied := len(e.ros.applied)
	e.rec.mu.Unlock()
	if props != 1 || chat != 0 || events != 0 {
		t.Fatalf("props=%d chat=%d events=%d", props, chat, events)
	}
	if applied != 0 {
		t.Fatal("proposal must never reach ApplyEvent")
	}
	if pens != 0 {
		t.Fatalf("legit proposal must not penalize owner: %v", pens)
	}

	// 生效事件（同 MsgID + EndorseSig）不得被提案误登记的主 dedup 吞掉
	final := m
	final.EndorseSig = []byte("endorse-by-new-owner")
	out2 := e.eng.Ingest(no.pub, frameOf(t, final))
	if out2.Duplicate || !out2.Accepted || out2.Kind != KindRosterEvent {
		t.Fatalf("endorsed event swallowed by dedup: %+v", out2)
	}
	e.ros.mu.Lock()
	applied = len(e.ros.applied)
	e.ros.mu.Unlock()
	if applied != 1 {
		t.Fatalf("endorsed transfer must be applied once, got %d", applied)
	}
}

func TestTransferProposalDirectedToOtherRelays(t *testing.T) {
	e, owner, no := proposalEnv(t)
	m := makeProposal(t, owner, no.pub, 1700000002000) // To=别人
	out := e.eng.Ingest(pk(10), frameOf(t, m))
	if !out.Accepted || out.Kind != KindTransferProposal || out.Delivered {
		t.Fatalf("%+v", out)
	}
	if out.Flooded != 2 { // 3 邻居扣除来源 pk(10)
		t.Fatalf("relay fanout=%d want 2", out.Flooded)
	}
	e.rec.mu.Lock()
	props, pens := len(e.rec.transferProps), len(e.rec.penalties)
	e.rec.mu.Unlock()
	if props != 0 || pens != 0 {
		t.Fatalf("directed-to-other: no delivery/penalty expected, props=%d pens=%d", props, pens)
	}
	// relay 匿名去重：再来一轮不重复泛洪
	out2 := e.eng.Ingest(pk(20), frameOf(t, m))
	if out2.Accepted && out2.Flooded != 0 {
		t.Fatalf("second relay must be storm-suppressed: %+v", out2)
	}
	// 转发过提案的节点，主 dedup 未被污染：同 id 生效事件正常受理
	final := m
	final.EndorseSig = []byte("e")
	out3 := e.eng.Ingest(no.pub, frameOf(t, final))
	if out3.Duplicate || !out3.Accepted {
		t.Fatalf("endorsed event after relay must not be duplicate: %+v", out3)
	}
}

func TestTransferProposalRejectsNonOwnerSigner(t *testing.T) {
	e, _, no := proposalEnv(t)
	plain := newTestSigner()
	e.ros.addMember(plain.pub, core.RoleMember, core.PermSpeak)
	m := makeProposal(t, plain, e.me.pub, 1700000003000)
	out := e.eng.Ingest(plain.pub, frameOf(t, m))
	if out.Accepted || out.Reason != ReasonOverreach {
		t.Fatalf("non-owner proposal: %+v", out)
	}
	e.rec.mu.Lock()
	props, pens := len(e.rec.transferProps), len(e.rec.penalties)
	e.rec.mu.Unlock()
	if props != 0 || pens != 1 {
		t.Fatalf("props=%d pens=%d want 0/1", props, pens)
	}
	_ = no
}

// TestEndorsedTransferFloodsToOriginalOwner 锁死 v17① 的 flood 排他规则：
// 联署生效事件的 Sender 仍是原提案者（新 owner 只对同一原文补联署），
// 新 owner 一跳广播时绝不许按 p.Equal(m.Sender) 跳过原 owner，
// 否则原 owner 永远收不到生效事件、不会让位。
func TestEndorsedTransferFloodsToOriginalOwner(t *testing.T) {
	owner := newTestSigner()
	no := newTestSigner()
	m := makeProposal(t, owner, no.pub, 1700000004000)
	m.EndorseSig = []byte("endorsed-by-new-owner")
	tr := newFakeTransport()
	engB := NewEngine(testGroupID, no.pub, nil, tr,
		fakePeers{[]core.PubKey{owner.pub}}, Handlers{})
	n, err := engB.Publish(m)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || tr.total() != 1 {
		t.Fatalf("endorsed event must reach original owner: fanout=%d sent=%d", n, tr.total())
	}
}
