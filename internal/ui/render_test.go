package ui

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"dmesh/internal/core"
)

func mustPub(t *testing.T, h string) core.PubKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return core.PubKey{Alg: core.SigEd25519, Bytes: b}
}

func TestFormatAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-time.Second, "0s"},
		{9500 * time.Millisecond, "9s"},
		{59 * time.Second, "59s"},
		{61 * time.Second, "1m01s"},
		{5 * time.Minute, "5m00s"},
		{time.Hour + 2*time.Minute, "1h02m"},
		{25*time.Hour + 59*time.Minute, "1d01h"},
		{72 * time.Hour, "3d00h"},
	}
	for _, tc := range cases {
		if got := FormatAge(tc.d); got != tc.want {
			t.Errorf("FormatAge(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestShortIDAndRole(t *testing.T) {
	p := mustPub(t, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	if got := ShortID(p); got != "ed25519:aabbccdd" {
		t.Errorf("ShortID = %q", got)
	}
	if got := RoleLabel(core.RoleCreator); got != "creator" {
		t.Errorf("RoleLabel creator = %q", got)
	}
	if got := RoleLabel(core.Role("weird")); got != "weird" {
		t.Errorf("RoleLabel passthrough = %q", got)
	}
}

// fakeRoster 是最小 core.Roster 实现（纯内存，无网络）。
type fakeRoster struct {
	members  []core.MemberEntry
	banned   []core.BlacklistEntry
	owner    core.PubKey
	presence map[string]core.PresenceEntry
	perms    map[string][]string
}

func (f *fakeRoster) IsBlacklisted(p core.PubKey) bool {
	for _, b := range f.banned {
		if b.Pub.Equal(p) {
			return true
		}
	}
	return false
}

func (f *fakeRoster) Member(p core.PubKey) (core.MemberEntry, bool) {
	for _, e := range f.members {
		if e.Pub.Equal(p) {
			return e, true
		}
	}
	return core.MemberEntry{}, false
}

func (f *fakeRoster) ApplyEvent(m core.Message) error { return nil }

func (f *fakeRoster) TierOf(p core.PubKey) int {
	e, ok := f.Member(p)
	if !ok {
		return core.TierNonMember
	}
	return core.TierOfRole(e.Role)
}

func (f *fakeRoster) HasPerm(p core.PubKey, perm string) bool {
	for _, got := range f.perms[p.Key()] {
		if got == perm {
			return true
		}
	}
	return false
}

func (f *fakeRoster) Presence(p core.PubKey) core.PresenceEntry {
	return f.presence[p.Key()]
}

func (f *fakeRoster) Snapshot() ([]core.MemberEntry, []core.BlacklistEntry, core.PubKey) {
	return f.members, f.banned, f.owner
}

func TestBuildMemberRowsAndRender(t *testing.T) {
	a := mustPub(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := mustPub(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	c := mustPub(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	now := time.Unix(1700000000, 0)
	nowMs := now.UnixMilli()

	r := &fakeRoster{
		members: []core.MemberEntry{
			{Pub: a, Role: core.RoleMember, Perms: []string{"speak", "receive"}, TS: 1},
			{Pub: b, Role: core.RoleOwner, Perms: []string{"speak", "receive", "kick"}, TS: 2},
			{Pub: c, Role: core.RoleMember, Perms: []string{"speak"}, TS: 3},
		},
		owner: b,
		presence: map[string]core.PresenceEntry{
			// a: 离线（10 分钟前的活动，默认 5 分钟阈值）
			a.Key(): {Pub: a, LastMsgTS: nowMs - 10*60*1000},
			// b: 在线（12 秒前），自报 60s 阈值
			b.Key(): {Pub: b, LastMsgTS: nowMs - 12*1000, OfflineAfter: 60000},
			// c: 从未出现过（离线）
		},
	}

	rows := BuildMemberRows(r, a, now)
	if len(rows) != 3 {
		t.Fatalf("rows = %d", len(rows))
	}
	// 在线优先 → b；离线按 lastMsg 新→旧：a(10m) 比 c(0) 新
	if !rows[0].Entry.Pub.Equal(b) || !rows[0].Online {
		t.Errorf("first row = %s online=%v, want b online", ShortID(rows[0].Entry.Pub), rows[0].Online)
	}
	if !rows[1].Entry.Pub.Equal(a) {
		t.Errorf("second row = %s, want a", ShortID(rows[1].Entry.Pub))
	}
	if !rows[2].Entry.Pub.Equal(c) {
		t.Errorf("third row = %s, want c", ShortID(rows[2].Entry.Pub))
	}

	lines := RenderMemberLines(rows, now)
	if len(lines) != 3 {
		t.Fatal("line count")
	}
	if !strings.HasPrefix(lines[0], "●") || !strings.Contains(lines[0], "[owner]") || !strings.Contains(lines[0], "active 12s") {
		t.Errorf("line0 = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "○") || !strings.Contains(lines[1], "(me)") || !strings.Contains(lines[1], "offline 10m00s") {
		t.Errorf("line1 = %q", lines[1])
	}
	if !strings.Contains(lines[2], "offline (never seen)") {
		t.Errorf("line2 = %q", lines[2])
	}
	// 带色版本行数一致
	if len(RenderMemberLinesStyled(rows, now)) != 3 {
		t.Fatal("styled line count")
	}
}

func TestRenderBannedLines(t *testing.T) {
	a := mustPub(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	now := time.Unix(1700000000, 0)
	banned := []core.BlacklistEntry{{Pub: a, TS: now.Add(-time.Hour).UnixMilli(), Proof: core.Proof{Alg: core.SigEd25519}}}
	lines := RenderBannedLines(banned, now, false)
	if len(lines) != 1 || !strings.Contains(lines[0], "kicked 1h00m") || !strings.Contains(lines[0], "sig_alg=ed25519") {
		t.Fatalf("lines = %q", lines)
	}
}

func TestFormatChatLine(t *testing.T) {
	s := mustPub(t, "1111111111111111111111111111111111111111111111111111111111111111")
	d := mustPub(t, "2222222222222222222222222222222222222222222222222222222222222222")
	m := core.Message{
		Sender: s, TSms: time.Unix(1700000000, 0).UnixMilli(),
		Kind: core.KindMessage, Body: []byte(`{"text":"hi there"}`),
	}
	line := FormatChatLine(m)
	if !strings.Contains(line, "ed25519:11111111") || !strings.HasSuffix(line, "hi there") {
		t.Errorf("line = %q", line)
	}
	m.To = &d
	line = FormatChatLine(m)
	if !strings.Contains(line, "→ed25519:22222222") {
		t.Errorf("directed line = %q", line)
	}
	m.Kind = core.KindCommand
	m.Body = []byte(`{"hide":{"target_msg_id":"abc"}}`)
	if line = FormatChatLine(m); !strings.Contains(line, `(hide) {"hide":{"target_msg_id":"abc"}}`) {
		t.Errorf("non-chat line must carry the name tag + body: %q", line)
	}
}

func TestRenderNetdiskLines(t *testing.T) {
	p := mustPub(t, "3333333333333333333333333333333333333333333333333333333333333333")
	s := NetdiskStatus{
		QuotaMB: 128, TotalBytes: 3 * 128 << 20, UsedBytes: 5 << 20,
		Contributors:   []NetdiskContributor{{Pub: p, QuotaBytes: 128 << 20, ProvidedBytes: 128 << 20, Online: true}},
		OnlineWritable: 3, DegradedStripes: 1,
	}
	lines := RenderNetdiskLines(s, []NetdiskFile{{Name: "big.bin", Size: 3 << 20, Stripes: 4, Healthy: false}})
	joined := strings.Join(lines, "\n")
	// TotalBytes = 3×(128<<20) = 384MiB（<1GiB），正确单位语义即 384.0MiB。
	for _, want := range []string{"128 MB", "384.0MiB", "5.0MiB", "online-writable: 3", "degraded stripes: 1", "RAID5 degraded", "big.bin", "3.0MiB stripes=4 DEGRADED"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}

	off := RenderNetdiskLines(NetdiskStatus{QuotaMB: 0}, nil)
	joined = strings.Join(off, "\n")
	if !strings.Contains(joined, "netdisk disabled") || !strings.Contains(joined, "(empty)") {
		t.Errorf("disabled view:\n%s", joined)
	}
}

func TestFormatJoinLine(t *testing.T) {
	s := mustPub(t, "4444444444444444444444444444444444444444444444444444444444444444")
	now := time.Unix(1700000000, 0)
	req := JoinRequest{
		Msg:          core.Message{MsgID: "req-000123", Sender: s, TSms: now.Add(-30 * time.Second).UnixMilli()},
		Mode:         core.ModeVerify,
		IdentityNote: "keybase proof abc",
	}
	line := FormatJoinLine(req, now)
	for _, want := range []string{"req-000123", "mode=verify", "seed=unverified", "keybase proof", "30s ago"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %q", want, line)
		}
	}
	req.SeedOK = true
	if !strings.Contains(FormatJoinLine(req, now), "seed=OK") {
		t.Error("seed=OK missing")
	}
}
