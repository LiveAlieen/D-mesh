// viewmodel_test.go：viewModel 纯状态机测试（无窗口、无 ebiten 依赖）。
// v25 起场景一律走控件路径：按钮/右键菜单/对话框 → ui.App 门面方法。
// 场景清单：发送文本、无 speak 被拒、斜杠永不解析、hide 标记、入站事件、
// 面板切换与数字键不抢面板、浮层（菜单/五型对话框/模态屏蔽/校验）、
// join 审批含 seed 门槛、transfer 联署与拒绝、成员除名/权限/任命/移交、
// 黑名单解禁、申诉、网盘上传/下载/删除/配额、audit 回 chat、视图冒烟。

package ui

import (
	"encoding/hex"
	"fmt"
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

// SendTextID 实现 TextIDAck（v25）：发送成功后回报稳定 msg_id，
// 让单测能覆盖「自己刚发的那条随即可隐藏」。
func (f *fakeApp) SendTextID(s string) (string, error) {
	f.record("SendText:" + s)
	return "echo-1", nil
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

// ---- v25 GUI 路径助手：一律走「选行 → 菜单/按钮 → 表单」，不再打字下命令 ----

// rowOf 返回当前面板里首行含 substr 的可选行序号（ClickRow 用，从 0 计）。
func rowOf(t *testing.T, v *viewModel, substr string) int {
	t.Helper()
	for _, l := range v.Snapshot() {
		if l.Row > 0 && strings.Contains(l.Text, substr) {
			return l.Row - 1
		}
	}
	t.Fatalf("no selectable row containing %q in:\n%s", substr, snapText(v))
	return 0
}

func actionIDs(as []Action) []ActionID {
	out := make([]ActionID, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

// pickRowAction 复现右键链路：右键命中行→弹菜单→点其中一项。
func pickRowAction(t *testing.T, v *viewModel, row int, id ActionID) {
	t.Helper()
	v.ClickRow(row, true)
	for i, a := range v.Menu() {
		if a.ID == id {
			v.PickMenu(i)
			return
		}
	}
	t.Fatalf("row %d menu lacks action %q (menu=%v)", row, id, actionIDs(v.Menu()))
}

// hasAction 断言某排按钮里存在该动作（顶栏/面板动作条的可见性检查）。
func hasAction(t *testing.T, as []Action, id ActionID) Action {
	t.Helper()
	for _, a := range as {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("actions %v missing %q", actionIDs(as), id)
	return Action{}
}

// mustDialog 取回当前浮层（没有就直接判失败）。
func mustDialog(t *testing.T, v *viewModel) *dialog {
	t.Helper()
	if v.dlg == nil {
		t.Fatal("no dialog open")
	}
	return v.dlg
}

// typeInto 往焦点浮层里打字（OnInput 会自行路由到对话框）。
func typeInto(t *testing.T, v *viewModel, s string) {
	t.Helper()
	for _, r := range s {
		v.OnInput(r)
	}
}

// checkPerms 在 perms 勾选表单里把指定 Key 勾上（原本未勾才翻，勾了别翻回去）。
func checkPerms(t *testing.T, v *viewModel, keys ...string) {
	t.Helper()
	d := mustDialog(t, v)
	for _, k := range keys {
		for i, it := range d.items {
			if it.Key != k {
				continue
			}
			if !it.Checked {
				v.DialogClickItem(i)
			}
		}
	}
}

// dialogKeyIndex 返回 choice 表单里指定 Key 的行号。
func dialogKeyIndex(t *testing.T, v *viewModel, key string) int {
	t.Helper()
	d := mustDialog(t, v)
	for i, it := range d.items {
		if it.Key == key {
			return i
		}
	}
	t.Fatalf("dialog items missing %q", key)
	return 0
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
	if v.chat[0].msgID != "echo-1" {
		t.Errorf("宿主回报的 msg_id 未回填到回显行: %+v", v.chat[0])
	}
}

// v25：自己刚发的那条在宿主回报 msg_id 后，右键菜单里就有「隐藏本条」，
// 确认后走 Hide(<id>)；他人的消息永远不给隐藏项（协议上无权限）。
func TestVMSelfMessageHideableAfterAck(t *testing.T) {
	v, app := newTestVM(t)
	typeText(t, v, "hide me")
	v.RunAction(ActSend)
	pickRowAction(t, v, 0, ActHide)
	v.DialogAccept()
	if !app.has("Hide:echo-1") {
		t.Fatalf("calls = %v", app.calls)
	}
	if strings.Contains(snapText(v), "hide me") {
		t.Fatalf("hidden line still visible:\n%s", snapText(v))
	}
	// 他人消息：只有复制。
	other := keyPub(t, 0xbb)
	v.OnEvent(TextEvent{Msg: core.Message{MsgID: "m-other", Sender: other, TSms: 1700000000000,
		Kind: core.KindMessage, Body: []byte(`{"text":"from other"}`)}})
	vis := 0
	for _, l := range v.chat {
		if l.hidden {
			continue
		}
		if l.msgID == "m-other" {
			break
		}
		vis++
	}
	v.ClickRow(vis, true)
	if ids := fmt.Sprint(actionIDs(v.Menu())); strings.Contains(ids, string(ActHide)) ||
		!strings.Contains(ids, string(ActCopy)) {
		t.Fatalf("inbound row actions = %s, want copy only", ids)
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
	msg := core.Message{MsgID: "m1", Sender: app.self, TSms: 1700000000000, Kind: core.KindMessage, Body: []byte(`{"text":"secret"}`)}
	v.OnEvent(TextEvent{Msg: msg})
	pickRowAction(t, v, rowOf(t, v, "secret"), ActHide) // 自己的气泡右键=隐藏（先确认）
	if mustDialog(t, v).kind != dlgConfirm {
		t.Fatal("hide should ask for confirmation")
	}
	v.DialogAccept()
	if !app.has("Hide:m1") {
		t.Fatalf("calls = %v", app.calls)
	}
	if strings.Contains(snapText(v), "secret") {
		t.Fatalf("hidden line still visible:\n%s", snapText(v))
	}
}

// v25：GUI 输入框永不解析斜杠——整行按正文发出去（斜杠命令只在无头 stdin 活着）。
func TestVMSlashIsPlainTextInGUI(t *testing.T) {
	v, app := newTestVM(t)
	submit(t, v, "/kick deadbeef")
	if !app.has("SendText:/kick deadbeef") {
		t.Fatalf("GUI must send slashes as chat text; calls=%v", app.calls)
	}
	if app.has("Kick") || strings.HasPrefix(strings.Join(app.calls, "|"), "Kick") {
		t.Fatalf("slash command executed inside GUI: %v", app.calls)
	}
}

// v25：右键菜单在场时 Esc 只收菜单，不动面板与输入。
func TestVMMenuOverlayEsc(t *testing.T) {
	v, app := newTestVM(t)
	v.OnEvent(TextEvent{Msg: core.Message{MsgID: "c1", Sender: app.self, TSms: 1700000000000, Kind: core.KindMessage, Body: []byte(`{"text":"hi"}`)}})
	row := rowOf(t, v, "hi")
	v.ClickRow(row, true)
	if v.Menu() == nil {
		t.Fatal("right click should open the row menu")
	}
	v.OnKey(KeyEscape)
	if v.Menu() != nil {
		t.Fatal("esc should close the menu")
	}
	if v.panel != PanelChat || app.has("Hide:c1") {
		t.Fatalf("esc leaked into panel/action: %v %v", v.panel, app.calls)
	}
	v.ClickRow(row, false) // 左键只选中，不弹菜单
	if v.Menu() != nil {
		t.Fatal("left click must not open a menu")
	}
	if v.SelectedRow() != row {
		t.Fatalf("sel = %d, want %d", v.SelectedRow(), row)
	}
}

func TestVMInboundEvents(t *testing.T) {
	v, _ := newTestVM(t)
	msg := core.Message{MsgID: "i1", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Kind: core.KindMessage, Body: []byte(`{"text":"yo"}`)}
	v.OnEvent(TextEvent{Msg: msg})
	if len(v.chat) != 1 || !strings.Contains(v.chat[0].text, "yo") {
		t.Fatalf("chat = %+v", v.chat)
	}
	v.OnEvent(RosterEvent{Note: "member joined"})
	if len(v.members) != 2 {
		t.Fatalf("roster event must refresh members: %d", len(v.members))
	}
	v.OnEvent(AppealEvent{Msg: core.Message{MsgID: "ap1", Sender: keyPub(t, 0xcc), Kind: core.KindMessage, Body: []byte(`{"text":"please unban"}`)}})
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
	v.OnKey(KeyEscape)
	if v.panel != PanelChat {
		t.Fatal("esc should return to chat")
	}
	// v25：数字键不再抢去切面板——它只是个字符，进聊天输入框。
	v.OnInput('3')
	if v.panel != PanelChat || string(v.input) != "3" {
		t.Fatalf("digit stole the panel switch: panel=%v input=%q", v.panel, string(v.input))
	}
	v.OnKey(KeyEscape) // esc 第一步清空输入
	if len(v.input) != 0 {
		t.Fatalf("esc should clear input: %q", string(v.input))
	}
	v.OnInput('2')
	v.setPanel(PanelChat)
	if v.panel != PanelChat {
		t.Fatalf("panel = %v", v.panel)
	}
	// Shift-Tab 反向循环 + progress 面板存在。
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
	// 标签页序号与 SwitchTab 一致（点标签=切面板的唯一入口）。
	if labels := TabLabels(); len(labels) != int(panelCount) || !strings.HasPrefix(labels[0], "1·") {
		t.Fatalf("TabLabels = %v", labels)
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
	pickRowAction(t, v, 0, ActJoinApprove)
	if app.has("ApproveJoin:req-1") {
		t.Fatal("approved without seed verification")
	}
	if !strings.Contains(v.status, "seed") {
		t.Fatalf("status = %q", v.status)
	}
	// 宿主核对通过翻转 SeedOK 后再点「批准入群」（approveJoin 先 reload，宿主为事实源）。
	req.SeedOK = true
	app.joins = []JoinRequest{req}
	pickRowAction(t, v, 0, ActJoinApprove)
	if !app.has("ApproveJoin:req-1") {
		t.Fatalf("ApproveJoin not called; calls=%v", app.calls)
	}
	// 未注入原生选择框 → 「核对种子」回退成手输路径文本框。
	v.ClickRow(0, false)
	v.RunAction(ActSeedCheck)
	d := mustDialog(t, v)
	if d.kind != dlgText {
		t.Fatalf("seed check should fall back to a path form, got %v", d.kind)
	}
	typeInto(t, v, "no-such-seed.json")
	v.DialogAccept()
	if !strings.Contains(snapText(v)+"\n"+lastChat(v), "seedcheck") {
		t.Fatalf("seedcheck note missing: %+v", v.chat)
	}
	// 注入选择框后不再弹表单，直接把路径交给执行。
	var pickedTitle, pickedPath string
	v.pickFile = func(title string, onPath func(string)) {
		pickedTitle, pickedPath = title, "C:/seeds/g.json"
		onPath(pickedPath)
	}
	v.RunAction(ActSeedCheck)
	if pickedTitle == "" || v.dlg != nil {
		t.Fatalf("native picker should replace the form (title=%q dlg=%v)", pickedTitle, v.dlg)
	}
	// d=拒绝：走菜单项，宿主出队后不再报错。
	pickRowAction(t, v, 0, ActJoinReject)
	if !app.has("RejectJoin:req-1") {
		t.Fatalf("calls = %v", app.calls)
	}
}

func lastChat(v *viewModel) string {
	if len(v.chat) == 0 {
		return ""
	}
	return v.chat[len(v.chat)-1].text
}

func TestVMTransferProposalAdminPanel(t *testing.T) {
	v, app := newTestVM(t)
	old := keyPub(t, 0xbb)
	prop := TransferProposal{
		Msg:       core.Message{MsgID: "xfer-1", Sender: old, TSms: 1700000000000},
		FromOwner: true,
	}
	// 事件入箱：聊天流指向群管面板的右键菜单。
	v.OnEvent(TransferProposalEvent{Prop: prop})
	if note := lastChat(v); !strings.Contains(note, "xfer-1") || !strings.Contains(note, "admin panel") {
		t.Fatalf("chat line = %q", note)
	}
	app.transfers = []TransferProposal{prop}
	app.joins = []JoinRequest{{Msg: core.Message{MsgID: "req-1", Sender: keyPub(t, 0xdd)}, Mode: core.ModeAuto, SeedOK: true}}
	// join 面板只剩 join_req 节（v19：transfer 迁到群管面板）。
	v.SwitchTab(2)
	if got := v.panelRows(); got != 1 {
		t.Fatalf("join panelRows = %d, want 1", got)
	}
	pickRowAction(t, v, 0, ActJoinApprove)
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
	// 选中 transfer 行 → 右键「联署提案」。
	row := rowOf(t, v, "xfer-1")
	if kind := v.adminSec().rowKind(row); kind != "transfer" {
		t.Fatalf("rowKind = %q", kind)
	}
	pickRowAction(t, v, row, ActXferApprove)
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
	badRow := rowOf(t, v, "xfer-bad")
	pickRowAction(t, v, badRow, ActXferApprove)
	if app.has("ApproveTransfer:xfer-bad") {
		t.Fatal("endorsed a proposal whose signer is not owner/creator")
	}
	if !strings.Contains(v.status, "not current owner") {
		t.Fatalf("status = %q", v.status)
	}
	// 「拒绝提案」：本地丢弃并出队，不转发。
	pickRowAction(t, v, badRow, ActXferDeny)
	if !app.has("RejectTransfer:xfer-bad") {
		t.Fatalf("calls = %v", app.calls)
	}
	if len(v.transfers) != 0 {
		t.Fatalf("transfer still queued after deny: %+v", v.transfers)
	}
}

func TestVMAdminKickAndPermsDialogs(t *testing.T) {
	v, app := newTestVM(t)
	v.SwitchTab(3) // admin
	other := keyPub(t, 0xbb)
	// 排序后在线优先：self=0，other(admin,离线)=1。
	v.OnKey(KeyDown)
	if !v.members[v.sel].Entry.Pub.Equal(other) {
		t.Fatalf("sel lands on %s, want other", ShortID(v.members[v.sel].Entry.Pub))
	}
	// 除名是破坏性动作：菜单点击后先弹确认，取消不产生任何出站。
	pickRowAction(t, v, v.sel, ActKick)
	d := mustDialog(t, v)
	if d.kind != dlgConfirm || !strings.Contains(d.note, "blacklist") {
		t.Fatalf("kick confirm = %+v", d)
	}
	v.DialogCancel()
	if app.has("Kick:" + other.Key()) {
		t.Fatalf("cancelled confirm still fired: %v", app.calls)
	}
	pickRowAction(t, v, v.sel, ActKick)
	v.DialogAccept()
	if !app.has("Kick:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	// 权限勾选表单：原本 speak+receive，勾上 carry 后提交。
	pickRowAction(t, v, v.sel, ActPerms)
	d = mustDialog(t, v)
	if d.kind != dlgChecks || len(d.items) != len(core.AllPerms) {
		t.Fatalf("perms form = %+v", d)
	}
	checkPerms(t, v, core.PermCarry)
	v.DialogAccept()
	if !app.has("SetPerms:" + other.Key() + "=speak,receive,carry") {
		t.Fatalf("calls = %v", app.calls)
	}
	// 一项都不勾 = 拒绝提交并提示。
	pickRowAction(t, v, v.sel, ActPerms)
	d = mustDialog(t, v)
	for i, it := range d.items { // 取消全部勾选
		if it.Checked {
			v.DialogClickItem(i)
		}
	}
	v.DialogAccept()
	if !strings.Contains(v.status, "at least one permission") {
		t.Fatalf("status = %q", v.status)
	}
	// esc 关最上层浮层，不切面板。
	pickRowAction(t, v, v.sel, ActPerms)
	v.OnKey(KeyEscape)
	if v.dlg != nil {
		t.Fatal("esc should close the dialog")
	}
	if v.panel != PanelAdmin {
		t.Fatalf("panel = %v", v.panel)
	}
	// 群管面板没有文本载体：编辑键无事可做，Esc 第二步才回聊天。
	v.OnKey(KeyEnter)
	v.OnKey(KeyEscape)
	if v.panel != PanelChat {
		t.Fatalf("panel = %v, want chat", v.panel)
	}
}

// 顶栏与面板动作条的按钮可见性：不适用项置灰而非隐藏。
func TestVMActionBarsExposeEverything(t *testing.T) {
	v, _ := newTestVM(t)
	for _, id := range []ActionID{ActHelp, ActAudit, ActSettings, ActLeave, ActQuit} {
		hasAction(t, v.ToolbarActions(), id)
	}
	send := hasAction(t, v.PanelActions(), ActSend)
	if send.Enabled {
		t.Fatal("send must be greyed out with an empty input")
	}
	typeInto(t, v, "hi")
	if !hasAction(t, v.PanelActions(), ActSend).Enabled {
		t.Fatal("send must enable once the input has text")
	}
	v.SwitchTab(1) // members 恒有首行被选中；空列表面板才见置灰
	if a := hasAction(t, v.PanelActions(), ActKick); !a.Enabled {
		t.Fatal("kick should be enabled while a member row is selected")
	}
	v.SwitchTab(2) // join：队列为空 → 审批动作置灰摆着而非消失
	if hasAction(t, v.PanelActions(), ActJoinApprove).Enabled {
		t.Fatal("approve must be greyed out with an empty queue")
	}
	if a := hasAction(t, v.PanelActions(), ActRefresh); !a.Enabled {
		t.Fatal("refresh must always be clickable")
	}
	v.SwitchTab(5) // progress 面板没有动作条
	if len(v.PanelActions()) != 0 {
		t.Fatalf("progress actions = %v", actionIDs(v.PanelActions()))
	}
}

func TestVMAppealUnbanAndIgnore(t *testing.T) {
	v, app := newTestVM(t)
	sender := keyPub(t, 0xcc)
	v.OnEvent(AppealEvent{Msg: core.Message{MsgID: "ap", Sender: sender, Kind: core.KindMessage, Body: []byte(`{"text":"help"}`)}})
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
	pickRowAction(t, v, v.sel, ActAppealUnban)
	if !app.has("Unban:" + sender.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	pickRowAction(t, v, v.sel, ActAppealIgnore) // 忽略：仅本地移除展示
	if len(v.appeals) != 0 {
		t.Fatalf("appeal not dropped after ignore: %d", len(v.appeals))
	}
}

// v25：原先 24 条斜杠命令各归一个控件。本测试按旧命令清单逐条走 GUI 路径，
// 断言落到同一批 ui.App 门面方法上（协议层与门面零改动的证据）。
func TestVMActionsCoverFormerCommands(t *testing.T) {
	v, app := newTestVM(t)
	nd := app.nd.(*fakeND)

	// /remove → 顶栏「退群」（破坏性：先确认）
	v.RunAction(ActLeave)
	if mustDialog(t, v).kind != dlgConfirm {
		t.Fatal("leave should ask for confirmation")
	}
	v.DialogAccept()
	if !app.has("Leave") {
		t.Fatalf("calls = %v", app.calls)
	}

	// /offline-after 90000 → 数字表单
	v.RunAction(ActOfflineTune)
	if mustDialog(t, v).kind != dlgNumber {
		t.Fatal("offline threshold should be a number form")
	}
	typeInto(t, v, "90000")
	v.DialogAccept()
	if !app.has("SetOfflineAfter") {
		t.Fatalf("calls = %v", app.calls)
	}
	// 非数字输入：拦住并提示，不出站。
	app.calls = nil
	v.RunAction(ActOfflineTune)
	typeInto(t, v, "abc")
	v.DialogAccept()
	if app.has("SetOfflineAfter") || !strings.Contains(v.status, "enter a number") {
		t.Fatalf("number validation failed: calls=%v status=%q", app.calls, v.status)
	}

	// /grant-admin /revoke-admin /transfer → 成员行右键菜单
	v.SwitchTab(1)
	other := keyPub(t, 0xbb)
	row := rowOf(t, v, "bbbbbb")
	if !v.members[row].Entry.Pub.Equal(other) {
		t.Fatalf("row %d is not the target member", row)
	}
	pickRowAction(t, v, row, ActGrant)
	if !app.has("GrantAdmin:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	pickRowAction(t, v, row, ActRevoke)
	if !app.has("RevokeAdmin:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	pickRowAction(t, v, row, ActTransfer)
	if mustDialog(t, v).kind != dlgConfirm {
		t.Fatal("transfer should ask for confirmation")
	}
	v.DialogAccept()
	if !app.has("Transfer:" + other.Key()) {
		t.Fatalf("calls = %v", app.calls)
	}
	// 复制公钥走注入的剪贴板桩。
	var clip string
	v.copyText = func(s string) { clip = s }
	pickRowAction(t, v, row, ActCopyPub)
	if clip != other.String() || !strings.Contains(v.status, "clipboard") {
		t.Fatalf("clip=%q status=%q", clip, v.status)
	}

	// /unban → 黑名单行右键菜单
	app.r.banned = []core.BlacklistEntry{{Pub: keyPub(t, 0xcc), TS: 1700000000000}}
	v.setPanel(PanelAdmin)
	v.refreshRoster()
	pickRowAction(t, v, len(v.members), ActUnban)
	if !app.has("Unban:" + keyPub(t, 0xcc).Key()) {
		t.Fatalf("calls = %v", app.calls)
	}

	// /netdisk upload <路径> → 「上传文件」按钮（原生选择框桩）
	v.SwitchTab(4)
	var pickTitle string
	v.pickFile = func(title string, onPath func(string)) {
		pickTitle = title
		onPath("C:/pics/x.png")
	}
	v.RunAction(ActNDUpload)
	if pickTitle == "" || len(nd.calls) == 0 || nd.calls[0] != "Upload:C:/pics/x.png" {
		t.Fatalf("upload via picker: title=%q calls=%v", pickTitle, nd.calls)
	}
	// 下载 / 删除（确认）→ 文件行右键
	fileRow := rowOf(t, v, "a.txt")
	pickRowAction(t, v, fileRow, ActNDDownload)
	if !strings.Contains(strings.Join(nd.calls, "|"), "Download:a.txt") {
		t.Fatalf("nd calls = %v", nd.calls)
	}
	pickRowAction(t, v, fileRow, ActNDDelete)
	if mustDialog(t, v).kind != dlgConfirm {
		t.Fatal("delete should ask for confirmation")
	}
	v.DialogAccept()
	if !strings.Contains(strings.Join(nd.calls, "|"), "Delete:a.txt") {
		t.Fatalf("nd calls = %v", nd.calls)
	}
	// /netdisk set 128 → 配额数字表单（预填当前值，改完提交）
	v.RunAction(ActNDQuota)
	d := mustDialog(t, v)
	if val, _ := d.DialogValue(); val != "64" {
		t.Fatalf("quota form should prefill 64, got %q", val)
	}
	v.OnKey(KeyBackspace)
	v.OnKey(KeyBackspace)
	typeInto(t, v, "128")
	v.DialogAccept()
	if !app.has("SetNetdiskMB") {
		t.Fatalf("calls = %v", app.calls)
	}
	// 越界配额：拦住。
	v.RunAction(ActNDQuota)
	v.OnKey(KeyBackspace)
	v.OnKey(KeyBackspace)
	v.OnKey(KeyBackspace)
	typeInto(t, v, "9999")
	v.DialogAccept()
	if strings.Contains(v.status, "submitted") {
		t.Fatalf("out-of-range quota accepted: status=%q", v.status)
	}

	// /help → 「帮助」按钮（系统行进聊天流，绝不出站）
	v.setPanel(PanelChat)
	app.calls = nil
	v.RunAction(ActHelp)
	if !strings.Contains(lastChat(v), "UI tour") || app.has("SendText") {
		t.Fatalf("help: last=%q calls=%v", lastChat(v), app.calls)
	}
	// /clear → 「清屏」（确认）
	v.RunAction(ActClear)
	v.DialogAccept()
	if len(v.chat) != 0 {
		t.Fatalf("clear left %d lines", len(v.chat))
	}
}

func TestVMQuit(t *testing.T) {
	v, _ := newTestVM(t)
	v.RunAction(ActQuit)
	if !v.QuitRequested() {
		t.Fatal("the quit button should request quit")
	}
}

// 对话框五型：确认/文本/数字/单选/多选各自的键盘与校验行为。
func TestVMDialogKinds(t *testing.T) {
	v, app := newTestVM(t)

	// choice：主题单选
	defer SetTheme(string(GetTheme()))
	SetTheme(string(ThemeLight))
	v.RunAction(ActTheme)
	d := mustDialog(t, v)
	if d.kind != dlgChoice {
		t.Fatalf("theme should be a single-choice form, got %v", d.kind)
	}
	v.DialogClickItem(dialogKeyIndex(t, v, string(ThemeDark)))
	v.DialogAccept()
	if GetTheme() != ThemeDark {
		t.Fatalf("theme = %q", GetTheme())
	}
	// 未知值走 exec 的校验分支：只提示不切换
	v.exec(ActTheme, actionCtx{theme: "neon"})
	if GetTheme() != ThemeDark || !strings.Contains(v.status, "neon") {
		t.Fatalf("bad theme: theme=%q status=%q", GetTheme(), v.status)
	}

	// checks：权限多选（空勾选须拒绝提交）
	v.SwitchTab(1)
	pickRowAction(t, v, rowOf(t, v, "bbbbbb"), ActPerms)
	d = mustDialog(t, v)
	if d.kind != dlgChecks {
		t.Fatalf("perms should be a checklist form, got %v", d.kind)
	}
	v.DialogCancel()
	if v.dlg != nil {
		t.Fatal("cancel should close the form")
	}

	// 模态：浮层在场时其他动作一律不吃（清屏没执行、表单仍是数字型）
	v.RunAction(ActOfflineTune)
	v.RunAction(ActClear)
	if len(v.chat) != 0 || mustDialog(t, v).kind != dlgNumber {
		t.Fatal("a modal form must block other actions")
	}
	v.DialogCancel()

	// text：未注入选择框时「核对种子」回退手输路径
	v.setPanel(PanelChat)
	before := len(v.chat)
	v.RunAction(ActSeedCheck)
	d = mustDialog(t, v)
	if d.kind != dlgText {
		t.Fatalf("seed check fallback should be a text form, got %v", d.kind)
	}
	v.DialogCancel()
	if len(v.chat) != before {
		t.Fatal("cancelled path form must not append chat lines")
	}
	if !strings.Contains(v.status, "cancel") {
		t.Fatalf("status = %q", v.status)
	}
	_ = app
}

// v25：进度不再是命令，只有 6·进度 面板一轨；且永不广播。
func TestVMProgressPanel(t *testing.T) {
	v, app := newTestVM(t)
	v.setPanel(PanelProgress)
	var versions, milestones, pct bool
	for _, l := range v.Snapshot() {
		if strings.Contains(l.Text, "Version changelog") {
			versions = true
		}
		if strings.Contains(l.Text, "Milestones") {
			milestones = true
		}
		if strings.Contains(l.Text, "M0") && strings.Contains(l.Text, "100%") {
			pct = true
		}
	}
	if !versions || !milestones || !pct {
		t.Fatalf("progress panel incomplete: versions=%v milestones=%v pct=%v\n%s", versions, milestones, pct, snapText(v))
	}
	for _, c := range app.calls {
		if strings.HasPrefix(c, "SendText") {
			t.Fatalf("progress leaked into chat broadcast: %v", app.calls)
		}
	}
	// 进度面板是只读展示：没有动作条，也没有可选行。
	if len(v.PanelActions()) != 0 {
		t.Fatalf("progress actions = %v", actionIDs(v.PanelActions()))
	}
	for _, l := range v.Snapshot() {
		if l.Row != 0 {
			t.Fatalf("progress rows must not be selectable: %+v", l)
		}
	}
}

func TestVMAuditResultsToChat(t *testing.T) {
	v, _ := newTestVM(t)
	v.RunAction(ActAudit)
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
	v.OnEvent(TextEvent{Msg: core.Message{MsgID: "x", Sender: keyPub(t, 0xbb), TSms: 1700000000000, Kind: core.KindMessage, Body: []byte(`{"text":"hello"}`)}})
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
	if styleColor(StyleStatus) != Pal().Status {
		t.Error("status color mapping")
	}
}
