package ui

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"dmesh/internal/core"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeApp struct {
	self  core.PubKey
	r     *fakeRoster
	sig   core.Signer
	gid   [32]byte
	calls []string
	evCh  chan Event
	joins []JoinRequest
	nd    Netdisk
}

func (f *fakeApp) record(name string) { f.calls = append(f.calls, name) }
func (f *fakeApp) has(name string) bool {
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func (f *fakeApp) Self() core.PubKey       { return f.self }
func (f *fakeApp) Roster() core.Roster     { return f.r }
func (f *fakeApp) Signer() core.Signer     { return f.sig }
func (f *fakeApp) GroupID() [32]byte       { return f.gid }
func (f *fakeApp) SendText(s string) error { f.record("SendText:" + s); return nil }
func (f *fakeApp) Hide(id string) error    { f.record("Hide:" + id); return nil }
func (f *fakeApp) Leave() error            { f.record("Leave"); return nil }
func (f *fakeApp) Kick(t core.PubKey) error {
	f.record("Kick:" + t.Key())
	return nil
}
func (f *fakeApp) Unban(t core.PubKey) error {
	f.record("Unban:" + t.Key())
	return nil
}
func (f *fakeApp) SetPerms(t core.PubKey, p []string) error {
	f.record("SetPerms:" + t.Key() + "=" + strings.Join(p, ","))
	return nil
}
func (f *fakeApp) GrantAdmin(t core.PubKey) error { f.record("GrantAdmin:" + t.Key()); return nil }
func (f *fakeApp) RevokeAdmin(t core.PubKey) error {
	f.record("RevokeAdmin:" + t.Key())
	return nil
}
func (f *fakeApp) Transfer(t core.PubKey) error { f.record("Transfer:" + t.Key()); return nil }
func (f *fakeApp) SetNetdiskMB(mb int) error    { f.record("SetNetdiskMB"); return nil }
func (f *fakeApp) SetOfflineAfter(ms int64) error {
	f.record("SetOfflineAfter")
	return nil
}
func (f *fakeApp) PendingJoins() []JoinRequest { return f.joins }
func (f *fakeApp) ApproveJoin(id string) error { f.record("ApproveJoin:" + id); return nil }
func (f *fakeApp) RejectJoin(id string) error  { f.record("RejectJoin:" + id); return nil }
func (f *fakeApp) Audit() ([]string, error) {
	f.record("Audit")
	return []string{"all sources consistent"}, nil
}
func (f *fakeApp) Netdisk() Netdisk { return f.nd }
func (f *fakeApp) NextEvent() Event {
	ev, ok := <-f.evCh
	if !ok {
		return nil
	}
	return ev
}

type fakeSigner struct{ pub core.PubKey }

func (s fakeSigner) Alg() core.SigAlg                { return s.pub.Alg }
func (s fakeSigner) Pub() core.PubKey                { return s.pub }
func (s fakeSigner) Sign(msg []byte) ([]byte, error) { return append([]byte("SIG:"), msg...), nil }

type fakeND struct{ calls []string }

func (n *fakeND) Status() (NetdiskStatus, error) {
	return NetdiskStatus{QuotaMB: 64, TotalBytes: 64 << 20, OnlineWritable: 3}, nil
}
func (n *fakeND) List() ([]NetdiskFile, error) {
	return []NetdiskFile{{Name: "a.txt", Size: 10, Stripes: 2, Healthy: true}}, nil
}
func (n *fakeND) Upload(p string) error { n.calls = append(n.calls, "Upload:"+p); return nil }
func (n *fakeND) Download(name, dest string) error {
	n.calls = append(n.calls, "Download:"+name)
	return nil
}
func (n *fakeND) Delete(name string) error { n.calls = append(n.calls, "Delete:"+name); return nil }

func keyPub(t *testing.T, fill byte) core.PubKey {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	h := hex.EncodeToString(b)
	p, err := ParsePubKey(h)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestModel(t *testing.T) (*Model, *fakeApp) {
	t.Helper()
	self := keyPub(t, 0xaa)
	other := keyPub(t, 0xbb)
	now := time.Unix(1700000000, 0)
	nowMs := now.UnixMilli()
	r := &fakeRoster{
		members: []core.MemberEntry{
			{Pub: self, Role: core.RoleMember, Perms: []string{core.PermSpeak, core.PermReceive, core.PermKick}},
			{Pub: other, Role: core.RoleAdmin, Perms: []string{core.PermSpeak, core.PermReceive}},
		},
		owner: self,
		presence: map[string]core.PresenceEntry{
			self.Key():  {Pub: self, LastMsgTS: nowMs, OfflineAfter: 60000},
			other.Key(): {Pub: other, LastMsgTS: nowMs - 600_000},
		},
		perms: map[string][]string{
			self.Key():  {core.PermSpeak, core.PermReceive, core.PermKick},
			other.Key(): {core.PermSpeak, core.PermReceive},
		},
	}
	app := &fakeApp{
		self: self,
		r:    r,
		sig:  fakeSigner{pub: self},
		evCh: make(chan Event, 8),
		nd:   &fakeND{},
	}
	m := New(app)
	m.now = func() time.Time { return now }
	m.width, m.height = 100, 30
	return m, app
}

func send(t *testing.T, m *Model, msg tea.Msg) tea.Msg {
	t.Helper()
	_, cmd := m.Update(msg)
	if cmd == nil {
		return nil
	}
	return cmd()
}

func typeText(m *Model, s string) {
	for _, r := range s {
		m.input += string(r)
	}
}

func TestModelSendTextFlow(t *testing.T) {
	m, app := newTestModel(t)
	typeText(m, "hello all")
	res := send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !app.has("SendText:hello all") {
		t.Fatalf("calls = %v", app.calls)
	}
	nm, ok := res.(noteMsg)
	if !ok || !strings.Contains(string(nm), "sent submitted") {
		t.Fatalf("cmd result = %v", res)
	}
	send(t, m, nm)
	if len(m.chat) != 2 { // 本地回显 + 系统提示
		t.Fatalf("chat = %+v", m.chat)
	}
	if !strings.Contains(m.chat[0].text, "hello all") {
		t.Errorf("echo = %q", m.chat[0].text)
	}
}

func TestModelSpeakDenied(t *testing.T) {
	m, app := newTestModel(t)
	app.r.perms[app.self.Key()] = nil // 无 speak
	typeText(m, "talk")
	send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if app.has("SendText:talk") {
		t.Fatal("sent without speak perm")
	}
	if !strings.Contains(m.status, "no speak") {
		t.Fatalf("status = %q", m.status)
	}
}

func TestModelHideMarksLine(t *testing.T) {
	m, app := newTestModel(t)
	msg := core.Message{MsgID: "m1", Sender: keyPub(t, 0xbb), TSms: 1, Type: core.TypeText, Content: []byte("secret")}
	_, cmd := m.Update(evMsg{TextEvent{Msg: msg}})
	_ = cmd
	typeText(m, "/hide m1")
	send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !app.has("Hide:m1") {
		t.Fatalf("calls = %v", app.calls)
	}
	vis := m.chatView()
	if strings.Contains(vis, "secret") {
		t.Fatalf("hidden line still visible: %q", vis)
	}
}

func TestModelInboundEvents(t *testing.T) {
	m, app := newTestModel(t)
	msg := core.Message{MsgID: "i1", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Type: core.TypeText, Content: []byte("yo")}
	_, cmd := m.Update(evMsg{TextEvent{Msg: msg}})
	if cmd == nil {
		t.Fatal("event handling must re-arm the pump")
	}
	if len(m.chat) != 1 || !strings.Contains(m.chat[0].text, "yo") {
		t.Fatalf("chat = %+v", m.chat)
	}
	m.Update(evMsg{RosterEvent{Note: "member joined"}})
	m.Update(evMsg{AppealEvent{Msg: core.Message{MsgID: "ap1", Sender: keyPub(t, 0xcc), Type: core.TypeText, Content: []byte("please unban")}}})
	if len(m.appeals) != 1 || !strings.Contains(m.status, "appeal") {
		t.Fatalf("appeals = %d status = %q", len(m.appeals), m.status)
	}
	m.Update(evMsg{JoinReqEvent{Req: JoinRequest{Msg: core.Message{MsgID: "j1", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto}}})
	if len(app.joins) != 0 {
		t.Log("join panel queue is host-owned; event copy tracked separately is fine")
	}
	// 宿主关闭：NextEvent 返回 nil → 退出
	close(app.evCh)
	res := send(t, m, evMsg{nil})
	_ = res
	if !m.quitting {
		_, cmd2 := m.Update(evMsg{nil})
		if cmd2 == nil {
			t.Fatal("nil event should trigger quit cmd")
		}
	}
}

func TestModelPanelSwitching(t *testing.T) {
	m, _ := newTestModel(t)
	send(t, m, tea.KeyMsg{Type: tea.KeyTab})
	if m.panel != PanelMembers {
		t.Fatalf("panel = %v", m.panel)
	}
	send(t, m, tea.KeyMsg{Type: tea.KeyEscape})
	if m.panel != PanelChat {
		t.Fatal("esc should return to chat")
	}
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	if m.panel != PanelJoin {
		t.Fatalf("digit switch = %v", m.panel)
	}
	// 输入非空时数字不触发切换
	m.setPanel(PanelChat)
	typeText(m, "1")
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	if m.panel != PanelChat || m.input != "12" {
		t.Fatalf("panel=%v input=%q", m.panel, m.input)
	}
}

func TestModelJoinPanelSeedGateAndApprove(t *testing.T) {
	m, app := newTestModel(t)
	req := JoinRequest{
		Msg:  core.Message{MsgID: "req-1", Sender: keyPub(t, 0xdd), TSms: 1700000000000},
		Mode: core.ModeAuto, SeedOK: false,
	}
	app.joins = []JoinRequest{req}
	m.setPanel(PanelJoin)
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if app.has("ApproveJoin:req-1") {
		t.Fatal("approved without seed verification")
	}
	if !strings.Contains(m.status, "seed") {
		t.Fatalf("status = %q", m.status)
	}
	req.SeedOK = true
	app.joins = []JoinRequest{req}
	res := send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !app.has("ApproveJoin:req-1") {
		t.Fatalf("ApproveJoin not called; calls=%v res=%v", app.calls, res)
	}
}

func TestModelAdminKickAndPermsPrompt(t *testing.T) {
	m, app := newTestModel(t)
	m.setPanel(PanelAdmin)
	m.sel = 1 // other (admin, 0xbb)
	other := keyPub(t, 0xbb)
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("K")})
	if !app.has("Kick:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	// P 打开 perms 提示，输入 csv 回车生效
	m.sel = 1
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("P")})
	if m.prompt == nil || m.prompt.action != "perms" {
		t.Fatal("perms prompt not opened")
	}
	m.prompt.value = "speak,receive,carry"
	send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !app.has("SetPerms:" + other.Key() + "=speak,receive,carry") {
		t.Fatalf("calls = %v", app.calls)
	}
	// esc 取消提示
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("P")})
	send(t, m, tea.KeyMsg{Type: tea.KeyEscape})
	if m.prompt != nil {
		t.Fatal("prompt should be cancelled")
	}
}

func TestModelAppealsUnban(t *testing.T) {
	m, app := newTestModel(t)
	sender := keyPub(t, 0xcc)
	m.Update(evMsg{AppealEvent{Msg: core.Message{MsgID: "ap", Sender: sender, Content: []byte("help")}}})
	m.setPanel(PanelAppeals)
	send(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("u")})
	if !app.has("Unban:" + sender.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
}

func TestModelChatCommandsDispatch(t *testing.T) {
	m, app := newTestModel(t)
	target := keyPub(t, 0xbb)
	cases := []struct {
		in   string
		want string
	}{
		{"/remove", "Leave"},
		{"/audit", "Audit"},
		{"/netdisk set 128", "SetNetdiskMB"},
		{"/offline-after 90000", "SetOfflineAfter"},
		{"/unban " + hexOf(target), "Unban:" + target.Key()},
		{"/grant-admin " + hexOf(target), "GrantAdmin:" + target.Key()},
		{"/revoke-admin " + hexOf(target), "RevokeAdmin:" + target.Key()},
		{"/transfer " + hexOf(target), "Transfer:" + target.Key()},
	}
	for _, tc := range cases {
		m.input = tc.in
		send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
		if !app.has(tc.want) {
			t.Errorf("%q did not trigger %s; calls=%v", tc.in, tc.want, app.calls)
		}
	}
	// /netdisk upload 走网盘门面
	m.input = "/netdisk upload /tmp/x.png"
	send(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	nd := app.nd.(*fakeND)
	if len(nd.calls) == 0 || nd.calls[0] != "Upload:/tmp/x.png" {
		t.Errorf("netdisk calls = %v", nd.calls)
	}
	// /quit 触发退出
	m.input = "/quit"
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("quit cmd missing")
	}
	m.Update(cmd()) // tea.Quit 的消息是 []*tea.exitMsg，忽略内容
	if !m.quitting {
		t.Fatal("quitting flag not set")
	}
}

func hexOf(p core.PubKey) string { return hex.EncodeToString(p.Bytes) }

func TestModelViewsSmoke(t *testing.T) {
	m, app := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m.Update(evMsg{TextEvent{Msg: core.Message{MsgID: "x", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Type: core.TypeText, Content: []byte("hello")}}})
	v := m.View()
	for _, want := range []string{"chat", "hello"} {
		if !strings.Contains(v, want) {
			t.Errorf("chat view missing %q:\n%s", want, v)
		}
	}
	app.joins = []JoinRequest{{Msg: core.Message{MsgID: "j", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto, SeedOK: true}}
	m.setPanel(PanelJoin)
	if !strings.Contains(m.View(), "seed=OK") {
		t.Error("join view missing seed state")
	}
	m.setPanel(PanelMembers)
	if !strings.Contains(m.View(), "ed25519:aaaaaa") {
		t.Errorf("members view missing member identity:\n%s", m.View())
	}
	m.setPanel(PanelNetdisk)
	if !strings.Contains(m.View(), "64 MB") {
		t.Errorf("netdisk view:\n%s", m.View())
	}
	m.setPanel(PanelAdmin)
	if !strings.Contains(m.View(), "[admin]") {
		t.Errorf("admin view:\n%s", m.View())
	}
}

func TestModelInitPump(t *testing.T) {
	m, _ := newTestModel(t)
	if m.Init() == nil {
		t.Fatal("Init should arm the event pump")
	}
	var nilApp Model
	if nilApp.Init() != nil {
		t.Fatal("no app → no pump")
	}
	nilApp.width, nilApp.height = 80, 24
	if v := nilApp.View(); v == "" {
		t.Fatal("empty view")
	}
}

func TestModelAuditResultsToChat(t *testing.T) {
	m, _ := newTestModel(t)
	m.input = "/audit"
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("audit cmd missing")
	}
	res := cmd()
	am, ok := res.(auditMsg)
	if !ok || len(am.lines) != 1 {
		t.Fatalf("audit result msg = %#v", res)
	}
	m.Update(am)
	if len(m.chat) == 0 || !strings.Contains(m.chat[len(m.chat)-1].text, "all sources consistent") {
		t.Fatalf("chat = %+v", m.chat)
	}
}
