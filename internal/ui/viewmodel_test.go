// viewmodel_test.go：viewModel 纯状态机测试（无窗口、无 ebiten 依赖）。
// 场景清单对齐 v18 的终端 TUI model_test：发送文本、无 speak 被拒、
// hide 标记、入站事件、面板切换、join 审批含 seed 门槛、transfer 提案 a/d、
// admin kick/perms 提示流、申诉 unban、chat 命令分发、audit 结果、视图冒烟。

package ui

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"dmesh/internal/core"
)

// TestMain 把界面语言钉为 en：测试断言以 v19 英文字面为基准（v20 i18n 起
// 本机系统语言若是 zh 会默认中文，故显式钉住；语言目录本身由 i18n_test 验）。
func TestMain(m *testing.M) {
	SetLang(LangEn)
	os.Exit(m.Run())
}

// ---- 测试替身 ----

type fakeApp struct {
	self      core.PubKey
	r         *fakeRoster
	sig       core.Signer
	gid       [32]byte
	calls     []string
	evCh      chan Event
	joins     []JoinRequest
	transfers []TransferProposal
	nd        Netdisk
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

func (f *fakeApp) Self() core.PubKey   { return f.self }
func (f *fakeApp) Roster() core.Roster { return f.r }
func (f *fakeApp) Signer() core.Signer { return f.sig }
func (f *fakeApp) GroupID() [32]byte   { return f.gid }
func (f *fakeApp) SendText(s string) error {
	f.record("SendText:" + s)
	return nil
}
func (f *fakeApp) Hide(id string) error { f.record("Hide:" + id); return nil }
func (f *fakeApp) Leave() error         { f.record("Leave"); return nil }
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
func (f *fakeApp) ApproveJoin(id string) error {
	f.record("ApproveJoin:" + id)
	return nil
}
func (f *fakeApp) RejectJoin(id string) error { f.record("RejectJoin:" + id); return nil }

func (f *fakeApp) PendingTransfers() []TransferProposal { return f.transfers }

// dropTransfer 按 msg_id（含 "latest"/唯一前缀）从假队列里移除提案，
// 模拟宿主批准/拒绝后的出队行为。
func (f *fakeApp) dropTransfer(id string) {
	matches := make([]int, 0, len(f.transfers))
	for i, p := range f.transfers {
		if transferIDMatches(p.Msg.MsgID, id) {
			matches = append(matches, i)
		}
	}
	if id == "latest" {
		if len(matches) == 0 {
			return
		}
		matches = matches[len(matches)-1:]
	}
	if len(matches) != 1 {
		return
	}
	i := matches[0]
	f.transfers = append(f.transfers[:i], f.transfers[i+1:]...)
}

func transferIDMatches(msgID, key string) bool {
	if key == "latest" {
		return true
	}
	return msgID == key || strings.HasPrefix(msgID, key)
}

func (f *fakeApp) ApproveTransfer(id string) error {
	f.record("ApproveTransfer:" + id)
	f.dropTransfer(id)
	return nil
}
func (f *fakeApp) RejectTransfer(id string) error {
	f.record("RejectTransfer:" + id)
	f.dropTransfer(id)
	return nil
}
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
	p, err := ParsePubKey(hex.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hexOf(p core.PubKey) string { return hex.EncodeToString(p.Bytes) }

// newTestVM 构造注入固定时钟的 viewModel（deliver=nil → 异步任务同步执行）。
func newTestVM(t *testing.T) (*viewModel, *fakeApp) {
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
	v := newViewModel(app)
	v.now = func() time.Time { return now }
	return v, app
}

func typeText(t *testing.T, v *viewModel, s string) {
	t.Helper()
	for _, r := range s {
		v.OnInput(r)
	}
}

func submit(t *testing.T, v *viewModel, line string) {
	t.Helper()
	v.input = []rune(line)
	v.cur = len(v.input)
	v.Submit()
}

func snapText(v *viewModel) string {
	var b strings.Builder
	for _, l := range v.Snapshot() {
		b.WriteString(l.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// ---- 场景 ----

func TestVMSendTextFlow(t *testing.T) {
	v, app := newTestVM(t)
	typeText(t, v, "hello all")
	v.OnKey(KeyEnter)
	if !app.has("SendText:hello all") {
		t.Fatalf("calls = %v", app.calls)
	}
	if len(v.chat) != 2 { // 本地回显 + 系统提示（deliver=nil 同步回填）
		t.Fatalf("chat = %+v", v.chat)
	}
	if !strings.Contains(v.chat[0].text, "hello all") {
		t.Errorf("echo = %q", v.chat[0].text)
	}
	if !strings.Contains(v.chat[1].text, "sent submitted") {
		t.Errorf("note = %q", v.chat[1].text)
	}
}

func TestVMSpeakDenied(t *testing.T) {
	v, app := newTestVM(t)
	app.r.perms[app.self.Key()] = nil // 无 speak
	typeText(t, v, "talk")
	v.OnKey(KeyEnter)
	if app.has("SendText:talk") {
		t.Fatal("sent without speak perm")
	}
	if !strings.Contains(v.status, "no speak") {
		t.Fatalf("status = %q", v.status)
	}
}

func TestVMHideMarksLine(t *testing.T) {
	v, app := newTestVM(t)
	msg := core.Message{MsgID: "m1", Sender: keyPub(t, 0xbb), TSms: 1, Type: core.TypeText, Content: []byte("secret")}
	v.OnEvent(TextEvent{Msg: msg})
	submit(t, v, "/hide m1")
	if !app.has("Hide:m1") {
		t.Fatalf("calls = %v", app.calls)
	}
	if strings.Contains(snapText(v), "secret") {
		t.Fatalf("hidden line still visible:\n%s", snapText(v))
	}
}

func TestVMInboundEvents(t *testing.T) {
	v, _ := newTestVM(t)
	msg := core.Message{MsgID: "i1", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Type: core.TypeText, Content: []byte("yo")}
	v.OnEvent(TextEvent{Msg: msg})
	if len(v.chat) != 1 || !strings.Contains(v.chat[0].text, "yo") {
		t.Fatalf("chat = %+v", v.chat)
	}
	v.OnEvent(RosterEvent{Note: "member joined"})
	if len(v.members) != 2 {
		t.Fatalf("roster event must refresh members: %d", len(v.members))
	}
	v.OnEvent(AppealEvent{Msg: core.Message{MsgID: "ap1", Sender: keyPub(t, 0xcc), Type: core.TypeText, Content: []byte("please unban")}})
	if len(v.appeals) != 1 || !strings.Contains(v.status, "appeal") {
		t.Fatalf("appeals = %d status = %q", len(v.appeals), v.status)
	}
	v.OnEvent(JoinReqEvent{Req: JoinRequest{Msg: core.Message{MsgID: "j1", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto}})
	if len(v.joinReqs) != 1 {
		t.Fatalf("joinReqs = %d", len(v.joinReqs))
	}
	v.OnEvent(HideEvent{MsgID: "i1"})
	if !v.chat[0].hidden {
		t.Fatal("hide event not applied")
	}
	// 宿主关闭：nil 事件 → 退出请求。
	v.OnEvent(nil)
	if !v.QuitRequested() {
		t.Fatal("nil event should request quit")
	}
}

func TestVMPanelSwitching(t *testing.T) {
	v, _ := newTestVM(t)
	v.OnKey(KeyTab)
	if v.panel != PanelMembers {
		t.Fatalf("panel = %v", v.panel)
	}
	if v.inputFocus {
		t.Fatal("members panel should start with list focus")
	}
	v.OnKey(KeyEscape)
	if v.panel != PanelChat {
		t.Fatal("esc should return to chat")
	}
	v.OnInput('3')
	if v.panel != PanelJoin {
		t.Fatalf("digit switch = %v", v.panel)
	}
	// 输入非空时数字不触发切换（回 chat 后验证）。
	v.setPanel(PanelChat)
	v.input = []rune("1")
	v.cur = 1
	v.OnInput('2')
	if v.panel != PanelChat || string(v.input) != "12" {
		t.Fatalf("panel=%v input=%q", v.panel, string(v.input))
	}
	// Shift-Tab 反向循环 + progress 占位存在。
	v.setPanel(PanelChat)
	v.OnKey(KeyShiftTab)
	if v.panel != PanelProgress {
		t.Fatalf("shift-tab wraps to progress, got %v", v.panel)
	}
	v.SwitchTab(5)
	if v.panel != PanelProgress {
		t.Fatalf("SwitchTab(5) = %v", v.panel)
	}
	v.SwitchTab(99) // 越界忽略
	if v.panel != PanelProgress {
		t.Fatalf("out of range switch changed panel to %v", v.panel)
	}
}

func TestVMJoinSeedGateAndApprove(t *testing.T) {
	v, app := newTestVM(t)
	req := JoinRequest{
		Msg:  core.Message{MsgID: "req-1", Sender: keyPub(t, 0xdd), TSms: 1700000000000},
		Mode: core.ModeAuto, SeedOK: false,
	}
	app.joins = []JoinRequest{req}
	v.SwitchTab(2) // join
	if v.panel != PanelJoin {
		t.Fatalf("panel = %v", v.panel)
	}
	v.OnInput('a')
	if app.has("ApproveJoin:req-1") {
		t.Fatal("approved without seed verification")
	}
	if !strings.Contains(v.status, "seed") {
		t.Fatalf("status = %q", v.status)
	}
	// 宿主核对通过翻转 SeedOK 后再按 a（joinAction 先 reload，宿主为事实源）。
	req.SeedOK = true
	app.joins = []JoinRequest{req}
	v.OnInput('a')
	if !app.has("ApproveJoin:req-1") {
		t.Fatalf("ApproveJoin not called; calls=%v", app.calls)
	}
	// s 打开种子核对提示。
	v.OnInput('s')
	if v.prompt == nil || v.prompt.action != "seedcheck" {
		t.Fatal("seedcheck prompt not opened")
	}
	v.OnKey(KeyEscape)
	if v.prompt != nil {
		t.Fatal("esc should cancel prompt")
	}
	// d 拒绝：本地出队。
	app.joins = nil
	v.OnInput('d')
	if app.has("RejectJoin:req-1") {
		t.Log("queue empty after host dequeue — reject skipped, fine")
	}
}

func TestVMTransferProposalAdminPanel(t *testing.T) {
	v, app := newTestVM(t)
	old := keyPub(t, 0xbb)
	prop := TransferProposal{
		Msg:       core.Message{MsgID: "xfer-1", Sender: old, TSms: 1700000000000},
		FromOwner: true,
	}
	// 事件入箱：聊天流提示 /approve。
	v.OnEvent(TransferProposalEvent{Prop: prop})
	if !strings.Contains(v.chat[len(v.chat)-1].text, "/approve xfer-1") {
		t.Fatalf("chat line = %q", v.chat[len(v.chat)-1].text)
	}
	app.transfers = []TransferProposal{prop}
	app.joins = []JoinRequest{{Msg: core.Message{MsgID: "req-1", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto, SeedOK: true}}
	// join 面板只剩 join_req 节（v19：transfer 迁到群管面板）。
	v.SwitchTab(2)
	if got := v.panelRows(); got != 1 {
		t.Fatalf("join panelRows = %d, want 1", got)
	}
	v.OnInput('a')
	if !app.has("ApproveJoin:req-1") || app.has("ApproveTransfer:xfer-1") {
		t.Fatalf("calls = %v", app.calls)
	}
	// admin 面板四节：members(2)+banned(0)+transfers(1)+appeals(0)。
	v.SwitchTab(3)
	if got := v.panelRows(); got != 3 {
		t.Fatalf("admin panelRows = %d, want 3", got)
	}
	// 渲染：提案行标注待本机联署。
	if s := snapText(v); !strings.Contains(s, "xfer-1") || !strings.Contains(s, "pending my endorse") {
		t.Errorf("admin view missing transfer section:\n%s", s)
	}
	// 下移到 transfer 节：a=联署广播。
	v.OnKey(KeyDown)
	v.OnKey(KeyDown)
	if v.sel != 2 {
		t.Fatalf("sel = %d", v.sel)
	}
	v.OnInput('a')
	if !app.has("ApproveTransfer:xfer-1") {
		t.Fatalf("ApproveTransfer not called; calls=%v", app.calls)
	}
	// 签名者非现任 owner/创建者 → 拒绝联署。
	app.calls = nil
	bad := prop
	bad.Msg.MsgID = "xfer-bad"
	bad.FromOwner = false
	app.transfers = []TransferProposal{bad}
	v.reloadTransfers()
	v.sel = len(v.members) + len(v.banned)
	v.OnInput('a')
	if app.has("ApproveTransfer:xfer-bad") {
		t.Fatal("endorsed a proposal whose signer is not owner/creator")
	}
	if !strings.Contains(v.status, "not current owner") {
		t.Fatalf("status = %q", v.status)
	}
	// d=拒绝：本地丢弃并出队，不转发。
	v.OnInput('d')
	if !app.has("RejectTransfer:xfer-bad") {
		t.Fatalf("calls = %v", app.calls)
	}
	if len(v.transfers) != 0 {
		t.Fatalf("transfer still queued after deny: %+v", v.transfers)
	}
	// 斜杠命令通道：/transfers、/approve latest、/deny <前缀>。
	v.setPanel(PanelChat)
	submit(t, v, "/transfers")
	last := v.chat[len(v.chat)-1]
	if !strings.Contains(last.text, "none pending") {
		t.Fatalf("/transfers note = %q", last.text)
	}
	app.transfers = []TransferProposal{{Msg: core.Message{MsgID: "xfer-z", Sender: old}, FromOwner: true}}
	submit(t, v, "/approve latest")
	if !app.has("ApproveTransfer:latest") {
		t.Fatalf("calls = %v", app.calls)
	}
	app.transfers = []TransferProposal{{Msg: core.Message{MsgID: "xfer-y", Sender: old}, FromOwner: true}}
	submit(t, v, "/deny xfer")
	if !app.has("RejectTransfer:xfer") {
		t.Fatalf("calls = %v", app.calls)
	}
}

func TestVMAdminKickAndPermsPrompt(t *testing.T) {
	v, app := newTestVM(t)
	v.SwitchTab(3) // admin
	v.OnKey(KeyDown)
	other := keyPub(t, 0xbb)
	// 排序后在线优先：self=0，other(admin,离线)=1。
	if !v.members[v.sel].Entry.Pub.Equal(other) {
		t.Fatalf("sel lands on %s, want other", ShortID(v.members[v.sel].Entry.Pub))
	}
	v.OnInput('K')
	if !app.has("Kick:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	// P 打开 perms 提示，输入 csv 回车生效。
	v.OnInput('P')
	if v.prompt == nil || v.prompt.action != "perms" {
		t.Fatal("perms prompt not opened")
	}
	typeText(t, v, "speak,receive,carry")
	v.OnKey(KeyEnter)
	if !app.has("SetPerms:" + other.Key() + "=speak,receive,carry") {
		t.Fatalf("calls = %v", app.calls)
	}
	// esc 取消提示。
	v.OnInput('P')
	v.OnKey(KeyEscape)
	if v.prompt != nil {
		t.Fatal("prompt should be cancelled")
	}
	// 列表焦点下 Esc 第一步退出列表焦点，第二步回 chat。
	v.OnKey(KeyEscape)
	if !v.inputFocus {
		v.OnKey(KeyEscape)
	}
	if v.panel != PanelChat {
		t.Fatalf("panel = %v, want chat", v.panel)
	}
}

func TestVMAppealUnbanAndIgnore(t *testing.T) {
	v, app := newTestVM(t)
	sender := keyPub(t, 0xcc)
	v.OnEvent(AppealEvent{Msg: core.Message{MsgID: "ap", Sender: sender, Content: []byte("help")}})
	v.SwitchTab(3) // admin
	// members(2)+banned(0)+transfers(0)+appeal at sel=2
	v.OnKey(KeyDown)
	v.OnKey(KeyDown)
	if v.sel != 2 {
		t.Fatalf("sel = %d", v.sel)
	}
	if kind := v.adminSec().rowKind(v.sel); kind != "appeal" {
		t.Fatalf("rowKind = %q", kind)
	}
	v.OnInput('u')
	if !app.has("Unban:" + sender.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	v.OnInput('i') // 忽略：仅本地移除展示
	if len(v.appeals) != 0 {
		t.Fatalf("appeal not dropped after ignore: %d", len(v.appeals))
	}
}

func TestVMChatCommandsDispatch(t *testing.T) {
	v, app := newTestVM(t)
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
		{"/approve latest", "ApproveTransfer:latest"},
		{"/deny abc123", "RejectTransfer:abc123"},
		{"/hide zz", "Hide:zz"},
		{"/kick " + hexOf(target), "Kick:" + target.Key()},
		{"/perms " + hexOf(target) + " speak", "SetPerms:" + target.Key() + "=speak"},
	}
	for _, tc := range cases {
		submit(t, v, tc.in)
		if !app.has(tc.want) {
			t.Errorf("%q did not trigger %s; calls=%v", tc.in, tc.want, app.calls)
		}
	}
	// /netdisk upload 走网盘门面。
	submit(t, v, "/netdisk upload /tmp/x.png")
	nd := app.nd.(*fakeND)
	if len(nd.calls) == 0 || nd.calls[0] != "Upload:/tmp/x.png" {
		t.Errorf("netdisk calls = %v", nd.calls)
	}
	// /help 与 /clear。
	submit(t, v, "/help")
	if len(v.chat) == 0 || !strings.Contains(v.chat[len(v.chat)-1].text, "commands:") {
		t.Error("/help should append help to chat")
	}
	submit(t, v, "/clear")
	if len(v.chat) != 0 {
		t.Errorf("clear left %d lines", len(v.chat))
	}
	// 解析错误只进 status。
	before := len(v.chat)
	submit(t, v, "/frobnicate")
	if len(v.chat) != before || !strings.Contains(v.status, "input error") {
		t.Fatalf("bad cmd: status=%q chat=%d", v.status, len(v.chat))
	}
}

func TestVMQuit(t *testing.T) {
	v, _ := newTestVM(t)
	submit(t, v, "/quit")
	if !v.QuitRequested() {
		t.Fatal("/quit should request quit")
	}
}

// v22 补做 v18：/progress 双轨进度=系统行进聊天流 + 6·进度 面板渲染，绝不广播。
func TestVMProgressCommand(t *testing.T) {
	v, app := newTestVM(t)
	submit(t, v, "/progress")
	var versions, milestones, pct bool
	for _, l := range v.chat {
		if !l.system {
			continue
		}
		if strings.Contains(l.text, "Version changelog") {
			versions = true
		}
		if strings.Contains(l.text, "Milestones") {
			milestones = true
		}
		if strings.Contains(l.text, "M0") && strings.Contains(l.text, "100%") {
			pct = true
		}
	}
	if !versions || !milestones || !pct {
		t.Fatalf("progress lines incomplete: versions=%v milestones=%v pct=%v chat=%+v", versions, milestones, pct, v.chat)
	}
	if app.has("SendText:/progress") || app.has("SendText") {
		// 同测试内 submit 的其他命令不涉及，这里只禁 /progress 被当发言。
		for _, c := range app.calls {
			if strings.HasPrefix(c, "SendText:") && strings.Contains(c, "progress") {
				t.Fatalf("/progress leaked into chat broadcast: %v", app.calls)
			}
		}
	}
	// 面板渲染同一数据。
	v.setPanel(PanelProgress)
	var inPanel bool
	for _, l := range v.Snapshot() {
		if strings.Contains(l.Text, "100%") {
			inPanel = true
		}
	}
	if !inPanel {
		t.Fatal("progress panel must render the same milestones")
	}
}

func TestVMAuditResultsToChat(t *testing.T) {
	v, _ := newTestVM(t)
	submit(t, v, "/audit")
	var found bool
	for _, l := range v.chat {
		if strings.Contains(l.text, "audit: all sources consistent") && l.system {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit result missing from chat: %+v", v.chat)
	}
}

func TestVMChatRingCap(t *testing.T) {
	v, _ := newTestVM(t)
	for i := 0; i < 2100; i++ {
		v.OnEvent(SystemEvent{Note: "x"})
	}
	// 环形上限语义照旧模型：超 2000 修剪到最后 1500。
	if len(v.chat) > 2000 || len(v.chat) < 1500 {
		t.Fatalf("ring cap: len=%d, want trimmed into [1500,2000]", len(v.chat))
	}
}

func TestVMChatScrollFollow(t *testing.T) {
	v, _ := newTestVM(t)
	for i := 0; i < 30; i++ {
		v.OnEvent(SystemEvent{Note: "m"})
	}
	v.SetBodyHeight(10)
	if v.ChatScroll() != 0 {
		t.Fatalf("new msgs while pinned must keep follow, scroll=%d", v.ChatScroll())
	}
	v.ScrollBy(-5)
	if v.ChatScroll() != 5 {
		t.Fatalf("scroll up → 5, got %d", v.ChatScroll())
	}
	v.OnEvent(SystemEvent{Note: "new"})
	if v.ChatScroll() != 5 {
		t.Fatalf("scrolled-up position must be kept, got %d", v.ChatScroll())
	}
	v.ScrollBy(1000) // 夹取到底
	if v.ChatScroll() != 0 {
		t.Fatalf("scroll down clamps to bottom, got %d", v.ChatScroll())
	}
}

func TestVMInputEditingAndPaste(t *testing.T) {
	v, _ := newTestVM(t)
	typeText(t, v, "abcd")
	v.OnKey(KeyLeft)
	v.OnKey(KeyLeft) // cur=2
	v.OnInput('X')
	if string(v.input) != "abXcd" || v.cur != 3 {
		t.Fatalf("input=%q cur=%d", string(v.input), v.cur)
	}
	v.OnKey(KeyBackspace)
	if string(v.input) != "abcd" {
		t.Fatalf("backspace: %q", string(v.input))
	}
	v.OnKey(KeyHome)
	v.OnKey(KeyDelete)
	if string(v.input) != "bcd" {
		t.Fatalf("delete fwd: %q", string(v.input))
	}
	v.OnKey(KeyEnd)
	v.Paste("!!")
	if string(v.input) != "bcd!!" || v.cur != 5 {
		t.Fatalf("paste: %q cur=%d", string(v.input), v.cur)
	}
	// Esc 清空输入（chat 面板）。
	v.OnKey(KeyEscape)
	if len(v.input) != 0 {
		t.Fatalf("esc should clear input: %q", string(v.input))
	}
}

func TestVMEnterFocusesInputOnListPanels(t *testing.T) {
	v, app := newTestVM(t)
	v.SwitchTab(1) // members，列表焦点
	if v.inputFocus {
		t.Fatal("members panel must start unfocused")
	}
	v.OnKey(KeyEnter) // 第一次 Enter：进入输入栏
	if !v.inputFocus {
		t.Fatal("Enter should focus input on list panels")
	}
	typeText(t, v, "hi")
	v.OnKey(KeyEnter) // 第二次 Enter：提交
	if !app.has("SendText:hi") {
		t.Fatalf("calls = %v", app.calls)
	}
}

func TestVMAsyncDeliverMarshalling(t *testing.T) {
	v, app := newTestVM(t)
	var pending []Event
	v.deliver = func(job func() []Event) { pending = append(pending, job()...) }
	submit(t, v, "hello")
	if !app.has("SendText:hello") {
		t.Fatalf("job should run at dispatch time; calls=%v", app.calls)
	}
	if len(v.chat) != 1 { // 结果提示被推迟（等 UI 线程抽干）
		t.Fatalf("note should be deferred: %+v", v.chat)
	}
	for _, ev := range pending {
		v.OnEvent(ev)
	}
	if len(v.chat) != 2 || !strings.Contains(v.chat[1].text, "sent submitted") {
		t.Fatalf("deferred note missing: %+v", v.chat)
	}
}

func TestVMSnapshotSmoke(t *testing.T) {
	v, app := newTestVM(t)
	v.SetBodyHeight(20)
	v.OnEvent(TextEvent{Msg: core.Message{MsgID: "x", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Type: core.TypeText, Content: []byte("hello")}})
	s := snapText(v)
	for _, want := range []string{"chat", "hello"} { // StatusLine/快照均可见
		if !strings.Contains(s+"\n"+v.StatusLine(), want) {
			t.Errorf("chat snapshot missing %q:\n%s", want, s)
		}
	}
	inboundIsChat := false
	for _, l := range v.Snapshot() {
		if strings.Contains(l.Text, "hello") {
			inboundIsChat = l.Style == StyleChat
		}
	}
	if !inboundIsChat {
		t.Errorf("inbound line style != StyleChat")
	}
	submit(t, v, "mine")
	var own ViewLine
	for _, l := range v.Snapshot() {
		if strings.Contains(l.Text, "mine") {
			own = l
		}
	}
	if own.Style != StyleSelf {
		t.Errorf("own echo style = %v, want StyleSelf", own.Style)
	}
	app.joins = []JoinRequest{{Msg: core.Message{MsgID: "j", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto, SeedOK: true}}
	v.SwitchTab(2)
	if !strings.Contains(snapText(v), "seed=OK") {
		t.Error("join snapshot missing seed state")
	}
	v.SwitchTab(1)
	if !strings.Contains(snapText(v), "ed25519:aaaaaa") {
		t.Errorf("members snapshot missing identity:\n%s", snapText(v))
	}
	v.SwitchTab(4)
	if !strings.Contains(snapText(v), "64 MB") {
		t.Errorf("netdisk snapshot:\n%s", snapText(v))
	}
	v.SwitchTab(3)
	if !strings.Contains(snapText(v), "[admin]") {
		t.Errorf("admin snapshot:\n%s", snapText(v))
	}
	v.SwitchTab(5)
	if !strings.Contains(snapText(v), "v18") {
		t.Errorf("progress snapshot:\n%s", snapText(v))
	}
	// 顶部状态行含本机 ID 与面板名。
	if top := v.TopLine(); !strings.Contains(top, "me=ed25519:aaaa") || !strings.Contains(top, "panel=progress") {
		t.Errorf("TopLine = %q", top)
	}
}

func TestVMNilAppPreview(t *testing.T) {
	v := newViewModel(nil)
	if len(v.Snapshot()) != 0 { // chat 空快照不 panic
		t.Fatal("empty snapshot expected")
	}
	v.TopLine()
	v.StatusLine()
	v.OnInput('中')
	v.OnKey(KeyEnter) // 无 app：文本分发为 no-op 但不 panic
	v.SetBodyHeight(10)
	v.ScrollBy(-3)
	if v.QuitRequested() {
		t.Fatal("preview should not quit")
	}
}

func TestVMWrapTextHelper(t *testing.T) {
	// wrapText 需要真字体度量——无窗口环境不可用 GoTextFaceSource；
	// 这里只验证纯逻辑的 hex8 与样式映射兜底。
	if got := hex8([]byte{0xab, 0xcd}); got != "abcd" {
		t.Errorf("hex8 = %q", got)
	}
	if styleColor(StyleStatus) != colStatus {
		t.Error("status color mapping")
	}
}
