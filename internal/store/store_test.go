package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dmesh/internal/core"
)

// --- 测试辅助 -------------------------------------------------------------

func mkPub(t *testing.T, tag byte) core.PubKey {
	t.Helper()
	b := make([]byte, 32)
	b[0] = tag
	for i := range b {
		b[i] = tag*31 + byte(i)
	}
	return core.PubKey{Alg: core.SigEd25519, Bytes: b}
}

// mkMsg 造一条已成形消息（不验签，只测存储索引）：body 由 name + 载荷打成标签联合，
// 载荷本身不是 JSON 时按字符串装（聊天正文即此形态）。
func mkMsg(t *testing.T, id string, sender core.PubKey, ts int64, name, payload string) core.Message {
	t.Helper()
	kind, ok := core.KindOf(name)
	if !ok {
		t.Fatalf("unknown body name %q", name)
	}
	body, err := core.MakeBody(name, json.RawMessage(payload))
	if err != nil {
		body, err = core.MakeBody(name, payload)
	}
	if err != nil {
		t.Fatal(err)
	}
	return core.Message{
		MsgID:   id,
		GroupID: [32]byte{byte(len(id)), 7},
		Sender:  sender,
		TSms:    ts,
		Kind:    kind,
		Body:    body,
		Alg:     core.SigEd25519,
		Sig:     []byte("sig-" + id),
	}
}

func openTmp(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "group")
	return dir
}

func mustOpen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- 打开 / 目录结构 -------------------------------------------------------

func TestOpenCreatesDirAndFiles(t *testing.T) {
	dir := openTmp(t)
	s := mustOpen(t, dir)
	if s.Dir() != dir {
		t.Fatalf("Dir()=%q want %q", s.Dir(), dir)
	}
	for _, name := range []string{jsonlName, dbName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s after Open: %v", name, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("double Close: %v", err)
	}
	if _, err := s.AppendMessage(mkMsg(t, "x", mkPub(t, 1), 1, core.NameText, "x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close want ErrClosed, got %v", err)
	}
}

// --- 追加 / 去重 -----------------------------------------------------------

func TestAppendDedup(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	m := mkMsg(t, "m1", mkPub(t, 1), 1000, core.NameText, "hello")

	appended, err := s.AppendMessage(m)
	if err != nil || !appended {
		t.Fatalf("first append: appended=%v err=%v", appended, err)
	}
	// 同一 msg_id 重复写（flood/回灌多源）→ 静默去重
	appended, err = s.AppendMessage(m)
	if err != nil || appended {
		t.Fatalf("dup append: appended=%v err=%v, want false/nil", appended, err)
	}
	// 不同 msg_id → 正常写入
	m2 := mkMsg(t, "m2", mkPub(t, 1), 1001, core.NameText, "again")
	if appended, err = s.AppendMessage(m2); err != nil || !appended {
		t.Fatalf("second append: appended=%v err=%v", appended, err)
	}
	if n, err := s.CountMessages(); err != nil || n != 2 {
		t.Fatalf("CountMessages=%v err=%v want 2", n, err)
	}
	// 空 msg_id 拒绝
	if _, err := s.AppendMessage(core.Message{Sender: mkPub(t, 2)}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("empty msg_id err=%v want core.ErrMalformed", err)
	}
	// JSONL 只写了两行
	raw, _ := os.ReadFile(s.jsonlPath())
	if got := strings.Count(string(raw), "\n"); got != 2 {
		t.Fatalf("jsonl lines=%d want 2 (%q)", got, raw)
	}
}

func TestHasAndGetMessage(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	sender := mkPub(t, 3)
	m := mkMsg(t, "mm", sender, 42, core.NameText, "内容")
	if _, err := s.AppendMessage(m); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HasMessage("mm"); err != nil || !ok {
		t.Fatalf("HasMessage=%v err=%v", ok, err)
	}
	if ok, err := s.HasMessage("nope"); err != nil || ok {
		t.Fatalf("HasMessage(nope)=%v err=%v", ok, err)
	}
	got, ok, err := s.GetMessage("mm")
	if err != nil || !ok {
		t.Fatalf("GetMessage ok=%v err=%v", ok, err)
	}
	if got.Sender.Key() != sender.Key() || got.TSms != 42 || string(got.Body) != `{"text":"内容"}` || got.MsgID != "mm" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, ok, _ := s.GetMessage("ghost"); ok {
		t.Fatal("ghost message found")
	}
}

// --- 查询过滤（table-driven 纯逻辑） ---------------------------------------

func TestQueryMessages(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	a, b := mkPub(t, 1), mkPub(t, 2)
	msgs := []core.Message{
		mkMsg(t, "1", a, 100, core.NameText, "t1"),
		mkMsg(t, "2", b, 200, core.NameText, "t2"),
		mkMsg(t, "3", a, 300, core.NameJoin, `{"pub":"x"}`),
		mkMsg(t, "4", b, 400, core.NameText, "t4"),
		mkMsg(t, "5", a, 500, core.NamePresence, "{}"),
	}
	for _, m := range msgs {
		if _, err := s.AppendMessage(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkHidden("2"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		q    MessageQuery
		want []string
	}{
		{"default_filters_hidden", MessageQuery{}, []string{"1", "3", "4", "5"}},
		{"types_text", MessageQuery{Names: []string{core.NameText}}, []string{"1", "4"}},
		{"exclude_events", MessageQuery{ExcludeNames: []string{core.NameJoin, core.NamePresence}}, []string{"1", "4"}},
		{"sender_a", MessageQuery{Sender: &a}, []string{"1", "3", "5"}},
		{"window", MessageQuery{SinceMS: 200, UntilMS: 400}, []string{"3", "4"}},
		{"limit", MessageQuery{Limit: 2}, []string{"1", "3"}},
		{"hidden_kept", MessageQuery{Names: []string{core.NameText}, IncludeHidden: true}, []string{"1", "2", "4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.QueryMessages(tc.q)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len=%d want %d (%v)", len(got), len(tc.want), idsOf(got))
			}
			for i := range got {
				if got[i].MsgID != tc.want[i] {
					t.Fatalf("got %v want %v", idsOf(got), tc.want)
				}
			}
		})
	}
	// AfterRowID 游标
	cur, err := s.LastRowID()
	if err != nil {
		t.Fatal(err)
	}
	m6 := mkMsg(t, "6", b, 600, core.NameText, "after cursor")
	if _, err := s.AppendMessage(m6); err != nil {
		t.Fatal(err)
	}
	got, err := s.QueryMessages(MessageQuery{AfterRowID: cur - 2})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"4", "5", "6"}
	if len(got) != len(want) {
		t.Fatalf("cursor query got %v want %v", idsOf(got), want)
	}
	for i := range got {
		if got[i].MsgID != want[i] {
			t.Fatalf("cursor query got %v want %v", idsOf(got), want)
		}
	}
}

func idsOf(ms []core.Message) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.MsgID
	}
	return out
}

// --- MaxMsgTS / AllMsgIDs ---------------------------------------------------

func TestMaxTSAndIDs(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	if v, err := s.MaxMsgTS(); err != nil || v != 0 {
		t.Fatalf("empty MaxMsgTS=%v err=%v", v, err)
	}
	if v, err := s.LastRowID(); err != nil || v != 0 {
		t.Fatalf("empty LastRowID=%v err=%v", v, err)
	}
	pub := mkPub(t, 9)
	for _, m := range []core.Message{
		mkMsg(t, "x1", pub, 300, core.NameText, ""),
		mkMsg(t, "x2", pub, 900, core.NameText, ""),
		mkMsg(t, "x3", pub, 500, core.NameText, ""),
	} {
		if _, err := s.AppendMessage(m); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := s.MaxMsgTS(); err != nil || v != 900 {
		t.Fatalf("MaxMsgTS=%v err=%v want 900", v, err)
	}
	ids, err := s.AllMsgIDs()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "x1,x2,x3" { // 插入序
		t.Fatalf("AllMsgIDs=%v want insertion order", ids)
	}
}

// --- hide 软删除 -----------------------------------------------------------

func TestHideSoftDelete(t *testing.T) {
	tests := []struct {
		name        string
		payload     string // hide 事件的载荷体（未打标签）
		wantTarget  string
		wantApplied bool
	}{
		{"raw_string", "abc", "abc", true},
		{"json_target_msg_id", `{"target_msg_id":"abc"}`, "abc", true},
		{"json_msg_id", `{"msg_id":"abc"}`, "abc", true},
		{"json_target_ids", `{"target_ids":["abc"]}`, "abc", true},
		{"empty", "", "", false},
		{"bad_json_object", `{"no_target":1}`, "", false},
		{"malformed_brace", `{not json`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := mustOpen(t, openTmp(t))
			pub := mkPub(t, 5)
			target := mkMsg(t, "abc", pub, 100, core.NameText, "secret")
			if _, err := s.AppendMessage(target); err != nil {
				t.Fatal(err)
			}
			hide := mkMsg(t, "h1", pub, 200, core.NameHide, tc.payload)
			if _, err := s.AppendMessage(hide); err != nil {
				t.Fatal(err)
			}
			vis, err := s.QueryMessages(MessageQuery{Names: []string{core.NameText}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantApplied && len(vis) != 0 {
				t.Fatalf("target still visible: %v", idsOf(vis))
			}
			if !tc.wantApplied && len(vis) != 1 {
				t.Fatalf("target unexpectedly hidden: %v", idsOf(vis))
			}
			if tc.wantApplied {
				all, err := s.QueryMessages(MessageQuery{Names: []string{core.NameText}, IncludeHidden: true})
				if err != nil || len(all) != 1 {
					t.Fatalf("soft delete must keep data: got %v err=%v", idsOf(all), err)
				}
				if all[0].MsgID != "abc" {
					t.Fatalf("wrong message hidden: %v", all[0].MsgID)
				}
			}
		})
	}
	// 乱序：hide 先到、目标消息后到 —— 标记仍生效
	t.Run("out_of_order", func(t *testing.T) {
		s := mustOpen(t, openTmp(t))
		pub := mkPub(t, 6)
		if _, err := s.AppendMessage(mkMsg(t, "h", pub, 200, core.NameHide, "later")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendMessage(mkMsg(t, "later", pub, 100, core.NameText, "x")); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.IsHidden("later"); err != nil || !ok {
			t.Fatalf("IsHidden=%v err=%v", ok, err)
		}
		vis, _ := s.QueryMessages(MessageQuery{Names: []string{core.NameText}})
		if len(vis) != 0 {
			t.Fatalf("out-of-order hide not applied: %v", idsOf(vis))
		}
	})
}

func TestMarkHiddenValidation(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	if err := s.MarkHidden(""); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("MarkHidden(\"\") err=%v want ErrMalformed", err)
	}
	if err := s.MarkHidden("q"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkHidden("q"); err != nil { // 幂等
		t.Fatal(err)
	}
	if ok, err := s.IsHidden("q"); err != nil || !ok {
		t.Fatalf("IsHidden=%v err=%v", ok, err)
	}
}

// --- JSONL 真相源 / 索引重建 ------------------------------------------------

func TestRebuildFromJSONL(t *testing.T) {
	dir := openTmp(t)
	s := mustOpen(t, dir)
	a, b := mkPub(t, 1), mkPub(t, 2)
	list := []core.Message{
		mkMsg(t, "r1", a, 10, core.NameText, "one"),
		mkMsg(t, "r2", b, 20, core.NameText, "two"),
		mkMsg(t, "r3", a, 30, core.NameText, "three"),
		mkMsg(t, "h", b, 40, core.NameHide, `{"target_msg_id":"r2"}`),
		mkMsg(t, "j", a, 50, core.NameJoin, "{}"),
	}
	for _, m := range list {
		if _, err := s.AppendMessage(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// 删掉 SQLite 索引文件 —— 真相源 JSONL 应能完整恢复
	dbPath := filepath.Join(dir, dbName)
	_ = os.Remove(dbPath)
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")

	s2 := mustOpen(t, dir)
	if n, err := s2.CountMessages(); err != nil || n != int64(len(list)) {
		t.Fatalf("rebuilt count=%v err=%v want %d", n, err, len(list))
	}
	if ok, err := s2.IsHidden("r2"); err != nil || !ok {
		t.Fatalf("hidden mark lost after rebuild: %v %v", ok, err)
	}
	m, ok, err := s2.GetMessage("r3")
	if err != nil || !ok || string(m.Body) != `{"text":"three"}` {
		t.Fatalf("rebuilt message lost: %v %v %+v", ok, err, m)
	}
	// 重建后再追加同 msg_id 仍去重
	if appended, err := s2.AppendMessage(list[0]); err != nil || appended {
		t.Fatalf("post-rebuild dedup broken: %v %v", appended, err)
	}
}

func TestTruncateCorruptTailAndSkipBadLines(t *testing.T) {
	dir := openTmp(t)
	os.MkdirAll(dir, 0o700)
	jsonlPath := filepath.Join(dir, jsonlName)
	good := core.Message{MsgID: "g1", Sender: mkPub(t, 1), TSms: 1, Kind: core.KindMessage, Body: []byte(`{"text":"ok"}`), Alg: core.SigEd25519}
	raw, err := core.CanonicalJSON(good)
	if err != nil {
		t.Fatal(err)
	}
	// 一行好数据 + 一行坏 JSON + 一行无换行尾巴（崩溃残留）
	content := string(raw) + "\n" + "NOT JSON {{{\n" + `{"msg_id":"tail"`
	if err := os.WriteFile(jsonlPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mustOpen(t, dir)
	n, err := s.CountMessages()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		got, _ := s.AllMsgIDs()
		t.Fatalf("rebuilt %d messages (%v), want only g1", n, got)
	}
	// 残缺尾行必须被截掉，之后追加不会粘连
	m2 := mkMsg(t, "g2", mkPub(t, 2), 2, core.NameText, "fresh")
	if _, err := s.AppendMessage(m2); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(jsonlPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// 追加式真相源不删除坏行（坏行只在重建时跳过），但残缺尾行已被截掉，
	// 新追加不会粘连：g1 / 坏行 / g2 共 3 行。
	if len(lines) != 3 {
		t.Fatalf("jsonl lines=%d want 3: %q", len(lines), data)
	}
	var back core.Message
	if err := json.Unmarshal([]byte(lines[2]), &back); err != nil || back.MsgID != "g2" {
		t.Fatalf("tail corrupted append: %v %v", err, lines[2])
	}
}

// --- 名单持久化 roundtrip ---------------------------------------------------

func TestMembersRoundtrip(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	p1, p2 := mkPub(t, 11), mkPub(t, 12)
	e1 := core.MemberEntry{
		Pub: p1, WG: core.WGPub{1, 2, 3}, Role: core.RoleOwner,
		Perms: []string{core.PermSpeak, core.PermKick},
		Proof: core.Proof{Raw: []byte("raw1"), Alg: core.SigEd25519, Sig: []byte("sig1")},
		TS:    100,
	}
	e2 := core.MemberEntry{Pub: p2, Role: core.RoleMember, Perms: core.AllPerms[:2], Proof: e1.Proof, TS: 200}
	for _, e := range []core.MemberEntry{e1, e2} {
		if err := s.PutMember(e); err != nil {
			t.Fatal(err)
		}
	}
	// 幂等覆盖（同 pub 第二次写入更新而非重复）
	e1b := e1
	e1b.Role = core.RoleAdmin
	e1b.TS = 300
	if err := s.PutMember(e1b); err != nil {
		t.Fatal(err)
	}
	all, err := s.Members()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("members=%d want 2", len(all))
	}
	if !all[0].Pub.Equal(p2) || !all[1].Pub.Equal(p1) { // ts 升序：e2(200) 在 e1b(300) 之前
		t.Fatalf("order wrong: %v %v", all[0].Pub, all[1].Pub)
	}
	got, ok, err := s.Member(p1)
	if err != nil || !ok || got.Role != core.RoleAdmin || got.TS != 300 {
		t.Fatalf("member p1 overwrite: ok=%v err=%v %+v", ok, err, got)
	}
	if got.WG != e1.WG || string(got.Proof.Raw) != "raw1" || len(got.Perms) != 2 {
		t.Fatalf("entry roundtrip lossy: %+v", got)
	}
	if err := s.DeleteMember(p2); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMember(p2); err != nil { // 幂等
		t.Fatal(err)
	}
	if _, ok, _ := s.Member(p2); ok {
		t.Fatal("deleted member found")
	}
}

func TestBlacklistRoundtrip(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	p := mkPub(t, 21)
	e := core.BlacklistEntry{Pub: p, Proof: core.Proof{Raw: []byte("kickraw"), Alg: core.SigEd25519, Sig: []byte("ks")}, TS: 5}
	if ok, err := s.Blacklisted(p); err != nil || ok {
		t.Fatalf("empty blacklist hit: %v %v", ok, err)
	}
	if err := s.PutBlacklist(e); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Blacklisted(p); err != nil || !ok {
		t.Fatalf("Blacklisted=%v err=%v", ok, err)
	}
	got, ok, err := s.BlacklistEntry(p)
	if err != nil || !ok || got.TS != 5 || string(got.Proof.Raw) != "kickraw" {
		t.Fatalf("entry=%+v ok=%v err=%v", got, ok, err)
	}
	all, _ := s.Blacklist()
	if len(all) != 1 {
		t.Fatalf("len=%d", len(all))
	}
	if err := s.DeleteBlacklist(p); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Blacklisted(p); ok {
		t.Fatal("still blacklisted after unban")
	}
}

func TestPresenceMaxMerge(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	p := mkPub(t, 31)
	cases := []struct {
		name    string
		in      core.PresenceEntry
		applied bool
		wantTS  int64
		wantOff int64
	}{
		{"fresh", core.PresenceEntry{Pub: p, LastMsgTS: 100, OfflineAfter: 5000}, true, 100, 5000},
		{"newer_wins", core.PresenceEntry{Pub: p, LastMsgTS: 200, OfflineAfter: 9000}, true, 200, 9000},
		{"stale_dropped", core.PresenceEntry{Pub: p, LastMsgTS: 150, OfflineAfter: 1000}, false, 200, 9000},
		{"equal_ts_applied", core.PresenceEntry{Pub: p, LastMsgTS: 200, OfflineAfter: 7000}, true, 200, 7000},
		{"default_offline_after", core.PresenceEntry{Pub: p, LastMsgTS: 300}, true, 300, core.DefaultOfflineAfterMS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applied, err := s.UpsertPresence(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if applied != tc.applied {
				t.Fatalf("applied=%v want %v", applied, tc.applied)
			}
			got, ok, err := s.PresenceFor(p)
			if err != nil || !ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if got.LastMsgTS != tc.wantTS || got.OfflineAfter != tc.wantOff {
				t.Fatalf("presence=%+v want ts=%d off=%d", got, tc.wantTS, tc.wantOff)
			}
		})
	}
	all, err := s.Presences()
	if err != nil || len(all) != 1 {
		t.Fatalf("Presences=%v err=%v", all, err)
	}
	if _, ok, _ := s.PresenceFor(mkPub(t, 99)); ok {
		t.Fatal("phantom presence")
	}
}

func TestOwnerAndGroupConfig(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	if _, ok, err := s.Owner(); err != nil || ok {
		t.Fatalf("owner before set: ok=%v err=%v", ok, err)
	}
	newOwner := mkPub(t, 41)
	if err := s.SetOwner(newOwner); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Owner()
	if err != nil || !ok || !got.Equal(newOwner) {
		t.Fatalf("owner=%v ok=%v err=%v", got, ok, err)
	}
	// transfer 覆盖
	if err := s.SetOwner(mkPub(t, 42)); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.Owner()
	if got.Equal(newOwner) {
		t.Fatal("owner not transferred")
	}

	cfg := core.GroupConfig{
		Name: "g", Version: 1, Mode: core.ModeAuto, CreatedAt: 7,
		GroupPub: mkPub(t, 43), Creator: mkPub(t, 44), CreatorWG: core.WGPub{9},
		Alg: core.SigEd25519, DefaultPerms: []string{core.PermSpeak, core.PermReceive},
		NetdiskMB: 0, CreatorSig: []byte("cs"),
	}
	id, err := s.PutGroupConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := core.GroupIDOf(cfg)
	if err != nil || id != wantID {
		t.Fatalf("group id mismatch: %v %v", id, wantID)
	}
	gotCfg, gotID, ok, err := s.GroupConfig()
	if err != nil || !ok {
		t.Fatalf("cfg ok=%v err=%v", ok, err)
	}
	if gotID != wantID || gotCfg.Name != "g" || gotCfg.Mode != core.ModeAuto ||
		!gotCfg.GroupPub.Equal(cfg.GroupPub) || !gotCfg.Creator.Equal(cfg.Creator) ||
		gotCfg.CreatorWG != cfg.CreatorWG || gotCfg.NetdiskMB != 0 ||
		string(gotCfg.CreatorSig) != "cs" || len(gotCfg.DefaultPerms) != 2 {
		t.Fatalf("cfg roundtrip lossy: %+v", gotCfg)
	}
	// RosterSnapshot 汇总
	s.MustSeedForSnapshot(t)
}

// MustSeedForSnapshot 是仅测试使用的辅助（放在这里避免污染生产 API）。
func (s *Store) MustSeedForSnapshot(t *testing.T) {
	t.Helper()
	m, banned, owner, err := s.RosterSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 || len(banned) != 0 {
		t.Fatalf("snapshot not empty: %d %d", len(m), len(banned))
	}
	if owner.IsZero() {
		t.Fatal("snapshot owner lost")
	}
}

// --- 名单持久化跨重开保留（members 不走 JSONL 重建，属 group 已验证状态）-----

func TestRosterPersistsAcrossReopen(t *testing.T) {
	dir := openTmp(t)
	s := mustOpen(t, dir)
	p := mkPub(t, 51)
	if err := s.PutMember(core.MemberEntry{Pub: p, Role: core.RoleMember, TS: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertPresence(core.PresenceEntry{Pub: p, LastMsgTS: 10, OfflineAfter: 3000}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := mustOpen(t, dir)
	if _, ok, err := s2.Member(p); err != nil || !ok {
		t.Fatalf("member lost on reopen: %v %v", ok, err)
	}
	got, ok, err := s2.PresenceFor(p)
	if err != nil || !ok || got.OfflineAfter != 3000 {
		t.Fatalf("presence lost on reopen: %+v %v %v", got, ok, err)
	}
}

// --- 并发安全 ---------------------------------------------------------------

func TestConcurrentAppend(t *testing.T) {
	s := mustOpen(t, openTmp(t))
	pub := mkPub(t, 61)
	const n = 50
	var wg sync.WaitGroup
	dupes := make(chan bool, n*2)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := mkMsg(t, string(rune('A'+i%26))+string(rune('a'+i/26)), pub, int64(i), core.NameText, "c")
			// 每个 msg_id 写两次：50 唯一 id × 2 并发
			for k := 0; k < 2; k++ {
				appended, err := s.AppendMessage(m)
				if err != nil {
					t.Errorf("append: %v", err)
					return
				}
				dupes <- appended
			}
		}(i)
	}
	wg.Wait()
	close(dupes)
	trueCount := 0
	for b := range dupes {
		if b {
			trueCount++
		}
	}
	if trueCount != n {
		t.Fatalf("concurrent dedup: %d accepted, want exactly %d", trueCount, n)
	}
	if c, err := s.CountMessages(); err != nil || c != n {
		t.Fatalf("count=%v err=%v want %d", c, err, n)
	}
}
