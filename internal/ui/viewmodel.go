// viewmodel.go：GUI 的纯状态机（v19）。
//
// 本文件不 import ebiten：OnInput/OnKey/Submit/SwitchTab/ScrollBy/OnEvent/
// Tick/Snapshot/ClickRow/RunAction 全部是可无窗口单测的方法。ebiten 壳
// （game.go）只负责把键盘/鼠标/滚轮事件翻译成这些调用，并按 Snapshot() 的
// ViewLine 绘制。
//
// v25 起 GUI 内不再有「打字下命令」这条路径：所有操作经 actions.go 的按钮/
// 右键菜单/对话框进来，输入框只承载聊天正文；ParseCommand 只服务无头 stdin。
// 行为规格仍移植自 v16-v18 的终端 TUI 模型（面板切换、chat 环形上限、
// join seed 门槛、transfer 联署、申诉通道、audit 回 chat 等）。

package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"dmesh/internal/core"
)

// ---- 面板 ----

// Panel 是当前活动面板。
type Panel int

const (
	PanelChat Panel = iota
	PanelMembers
	PanelJoin
	PanelAdmin
	PanelNetdisk
	PanelProgress
	panelCount
)

func (p Panel) label() string {
	if p >= 0 && int(p) < len(panelKeys) {
		return Tr("panel." + panelKeys[p])
	}
	return "?"
}

// panelKeys 与 Panel 枚举一一对应（i18n 键后缀与 tab 循环顺序，v20）。
var panelKeys = [panelCount]string{"chat", "members", "join", "admin", "netdisk", "progress"}

// ---- 视图行（viewModel → game 的绘制指令，不含任何框架类型）----

// LineStyle 是视图行的语义样式，game.go 把它映射成色板与对齐方式。
type LineStyle int

const (
	StyleChat    LineStyle = iota // 他人聊天（左侧、冷色）
	StyleSelf                     // 自己发的聊天（右侧、暖色）
	StyleSystem                   // 系统提示行（· 前缀，暗色）
	StyleHeader                   // 面板小节标题
	StyleDim                      // 次要文字
	StyleOnline                   // 在线/核对通过
	StyleOffline                  // 离线
	StyleBad                      // 黑名单/未核实签名
	StyleOwner                    // owner/creator 行
	StyleAdmin                    // admin 行
	StyleStatus                   // 底部状态行
)

// ViewLine 是一行待绘制文本。Selected 标记列表选中行（高亮底色）。
// Meta/Body 为 v20 聊天气泡加分项：Meta=发送者+时间小字行，Body=气泡正文；
// 两者为空时渲染层回退整行 Text（旧行为，测试断言仍以 Text 为准）。
// Avatar 为 v23 加分项：发送者 ShortID（头像色块取色/字母与连发分组用），
// 非聊天行为空。
// Row 为 v25 加分项：鼠标命中行 → 选中行的映射序号，从 1 起（0=标题/提示/系统
// 行等不可选行，恰是零值，故旧构造点无需改动）；game 命中后回传 ClickRow(Row-1)。
type ViewLine struct {
	Text     string
	Meta     string
	Body     string
	Avatar   string
	Style    LineStyle
	Selected bool
	Row      int
}

// ---- 按键（特殊键枚举；可打印字符走 OnInput）----

// Key 是特殊功能键。
type Key int

const (
	KeyNone Key = iota
	KeyEnter
	KeyEscape
	KeyBackspace
	KeyDelete
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyUp
	KeyDown
	KeyPgUp
	KeyPgDn
	KeyTab
	KeyShiftTab
)

// ---- 内部数据结构（语义照旧模型）----

// chatLine 是聊天流一行（支持 hide 软删除不显示）。
type chatLine struct {
	text   string
	msgID  string
	hidden bool
	system bool
	sender core.PubKey // 入站/出站发送者（StyleSelf 判定用）
	meta   string      // v20：气泡上方小字行（时间 · 发送者）
	body   string      // v20：气泡正文（不含发送者前缀）
	seq    int64       // v25：本机回显的本地序号，宿主回报 msg_id 后据此回填
}

// chatIDEvent 是包内事件（不经宿主通道）：异步出站成功后把真实 msg_id 回填到
// 对应回显行（seq 匹配），使「隐藏本条」对自己刚发的消息也可用。
type chatIDEvent struct {
	seq   int64
	msgID string
}

func (chatIDEvent) isUIEvent() {}

// ---- viewModel ----

// viewModel 是 GUI 根状态机。now 可注入以便测试；app 允许为 nil（离线预览/单测）。
type viewModel struct {
	app    App
	panel  Panel
	chat   []chatLine
	input  []rune
	cur    int // 输入栏光标（rune 下标）
	status string

	members   []MemberRow
	banned    []core.BlacklistEntry
	joinReqs  []JoinRequest
	transfers []TransferProposal // 发给本机的待决 transfer 提案（v17①，admin 面板）
	appeals   []core.Message
	sel       int // 当前面板的选中行（序号语义见 rowKindOf）

	// v25 浮层：右键菜单与模态对话框（对话框在场时吃掉键盘输入）。
	menu     []Action
	menuSel  int
	menuOpen bool
	dlg      *dialog

	// copyText/pickFile 由 game 注入（剪贴板与原生文件选择框）；pickFile 为 nil
	// 时「选文件」类动作回退为手输路径文本框，单测里注入桩函数。
	copyText func(string)
	pickFile func(title string, onPath func(string))

	ndStatus *NetdiskStatus
	ndFiles  []NetdiskFile

	chatScroll int // chat 距底部的行数（0=贴底自动跟随）
	seqNo      int64
	bodyHeight int // 最近一次的可视行数（渲染层回填，用于滚动夹取）
	quit       bool
	now        func() time.Time

	// deliver 由 game 注入：在工作线程跑 job（读文件/审计/出站广播），产出的
	// 事件回投 UI 线程应用。nil（单测/离线预览）时同步执行，结果立即可断言。
	deliver func(job func() []Event)
}

// newViewModel 构造根状态机。
func newViewModel(app App) *viewModel {
	return &viewModel{app: app, now: time.Now}
}

func (v *viewModel) currentTime() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// QuitRequested 报告 viewModel 是否请求退出（「退出」按钮或宿主关闭）。
func (v *viewModel) QuitRequested() bool { return v.quit }

// ---- 事件处理（与旧模型 handleEvent 逐条对齐）----

// OnEvent 应用一条宿主入站事件。
func (v *viewModel) OnEvent(ev Event) {
	switch e := ev.(type) {
	case TextEvent:
		v.appendChat(chatLine{text: FormatChatLine(e.Msg), msgID: e.Msg.MsgID, sender: e.Msg.Sender,
			meta: chatMeta(e.Msg), body: chatBody(e.Msg)})
	case AppealEvent:
		v.appeals = append(v.appeals, e.Msg)
		v.setStatus(Tf("ev.appeal", ShortID(e.Msg.Sender)))
	case SystemEvent:
		v.appendChat(chatLine{text: "· " + e.Note, system: true})
	case RosterEvent:
		v.refreshRoster()
		if e.Note != "" {
			v.appendChat(chatLine{text: Tf("ev.roster", e.Note), system: true})
		}
	case JoinReqEvent:
		v.upsertJoinReq(e.Req)
		v.setStatus(Tf("ev.joinreq", ShortID(e.Req.Msg.Sender)))
	case TransferProposalEvent:
		v.upsertTransfer(e.Prop)
		v.appendChat(chatLine{text: Tf("ev.xferChat", ShortID(e.Prop.Msg.Sender), e.Prop.Msg.MsgID), system: true})
		v.setStatus(Tf("ev.xferStatus", ShortID(e.Prop.Msg.Sender)))
	case HideEvent:
		v.hideLine(e.MsgID)
	case chatIDEvent:
		v.attachChatID(e.seq, e.msgID)
	case NetdiskEvent:
		v.appendChat(chatLine{text: Tf("ev.netdisk", e.Note), system: true})
		if v.panel == PanelNetdisk {
			v.refreshNetdisk()
		}
	case nil:
		v.quit = true
	}
}

// chatMeta/chatBody 把一条消息拆成 v20 气泡的「小字头 + 正文」两部分。
func chatMeta(m core.Message) string {
	ts := msTime(m.TSms).Format("15:04:05")
	dir := ""
	if m.To != nil {
		dir = " →" + ShortID(*m.To)
	}
	return ts + " · " + ShortID(m.Sender) + dir
}

func chatBody(m core.Message) string {
	body := strings.ToValidUTF8(string(m.Content), "\uFFFD")
	if m.Type != core.TypeText {
		body = "(" + m.Type + ") " + body
	}
	return body
}

func (v *viewModel) upsertJoinReq(req JoinRequest) {
	for i, r := range v.joinReqs {
		if r.Msg.MsgID == req.Msg.MsgID {
			v.joinReqs[i] = req
			return
		}
	}
	v.joinReqs = append(v.joinReqs, req)
}

func (v *viewModel) upsertTransfer(prop TransferProposal) {
	for i, p := range v.transfers {
		if p.Msg.MsgID == prop.Msg.MsgID {
			v.transfers[i] = prop
			return
		}
	}
	v.transfers = append(v.transfers, prop)
}

func (v *viewModel) hideLine(msgID string) {
	for i := range v.chat {
		if v.chat[i].msgID == msgID {
			v.chat[i].hidden = true
		}
	}
}

func (v *viewModel) setStatus(f string, args ...any) {
	if len(args) > 0 {
		f = fmt.Sprintf(f, args...)
	}
	v.status = f
}

func (v *viewModel) appendChat(l chatLine) {
	if l.seq == 0 && !l.system && l.msgID == "" {
		v.seqNo++
		l.seq = v.seqNo
	}
	v.chat = append(v.chat, l)
	if len(v.chat) > 2000 {
		v.chat = v.chat[len(v.chat)-1500:]
	}
	// 贴底时自动跟随新消息（chatScroll=0 即锚定底部）；已上滚则保持原位。
}

// attachChatID 把宿主回报的真实 msg_id 贴到对应回显行上（找不到 seq 就忽略）。
func (v *viewModel) attachChatID(seq int64, msgID string) {
	if seq == 0 || msgID == "" {
		return
	}
	for i := range v.chat {
		if v.chat[i].seq == seq {
			v.chat[i].msgID = msgID
			return
		}
	}
}

// ---- 宿主快照 ----

func (v *viewModel) refreshRoster() {
	if v.app == nil || v.app.Roster() == nil {
		return
	}
	r := v.app.Roster()
	v.members = BuildMemberRows(r, v.app.Self(), v.currentTime())
	_, banned, _ := r.Snapshot()
	v.banned = banned
	if v.sel >= v.panelRows() {
		v.sel = 0
	}
}

// reloadJoins 同步 join_req 队列（宿主为事实源）。
func (v *viewModel) reloadJoins() {
	if v.app == nil {
		return
	}
	v.joinReqs = v.app.PendingJoins()
	if v.sel >= v.panelRows() {
		v.sel = max0(v.panelRows() - 1)
	}
}

// reloadTransfers 同步 admin 面板的 transfer 提案收件箱（宿主为事实源）。
func (v *viewModel) reloadTransfers() {
	if v.app == nil {
		return
	}
	v.transfers = v.app.PendingTransfers()
}

func (v *viewModel) refreshNetdisk() {
	if v.app == nil {
		return
	}
	nd := v.app.Netdisk()
	if nd == nil {
		v.ndStatus, v.ndFiles = nil, nil
		return
	}
	if st, err := nd.Status(); err == nil {
		v.ndStatus = &st
	} else {
		v.setStatus(Tf("ev.ndStatusErr", err))
	}
	if fs, err := nd.List(); err == nil {
		v.ndFiles = fs
	}
	if v.sel >= v.panelRows() {
		v.sel = 0
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// Tick 由 game 每个 Update 调用：刷新在场表（活跃时长滚动）与网盘/join 队列
// 的宿主侧变化。
func (v *viewModel) Tick(now time.Time) {
	v.now = func() time.Time { return now }
	switch v.panel {
	case PanelMembers, PanelAdmin:
		v.refreshRoster()
		if v.panel == PanelAdmin {
			v.reloadTransfers()
		}
	case PanelJoin:
		v.reloadJoins()
	case PanelNetdisk:
		v.refreshNetdisk()
	}
}

// ---- 面板切换 ----

// SwitchTab 切到第 i 个面板（越界忽略）。
func (v *viewModel) SwitchTab(i int) {
	if i < 0 || i >= int(panelCount) {
		return
	}
	v.setPanel(Panel(i))
}

// NextTab / PrevTab 循环切换（Tab / Shift-Tab）。
func (v *viewModel) NextTab() { v.setPanel((v.panel + 1) % panelCount) }
func (v *viewModel) PrevTab() { v.setPanel((v.panel + panelCount - 1) % panelCount) }

func (v *viewModel) setPanel(p Panel) {
	v.panel = p
	v.sel = 0
	v.menuOpen, v.menu, v.menuSel, v.dlg = false, nil, 0, nil
	switch p {
	case PanelMembers, PanelAdmin:
		v.refreshRoster()
		if p == PanelAdmin {
			v.reloadTransfers()
		}
	case PanelJoin:
		v.reloadJoins()
	case PanelNetdisk:
		v.refreshNetdisk()
	}
}

// ---- 滚动 ----

// ScrollBy 滚动 chat 流：d>0 向下（趋向底部），d<0 向上（远离底部）。
// 内部记录的是「距底部行数」，故向上滚动时偏移增大。
func (v *viewModel) ScrollBy(d int) {
	v.chatScroll = max0(v.chatScroll - d)
	if v.bodyHeight > 0 {
		v.ClampScroll(v.maxChatScroll())
	}
}

// ClampScroll 由 game 在拿到可视行数后夹取滚动位置。
func (v *viewModel) ClampScroll(maxOff int) {
	if maxOff < 0 {
		maxOff = 0
	}
	if v.chatScroll > maxOff {
		v.chatScroll = maxOff
	}
}

// maxChatScroll = 可见行总数 - 可视高度（不足一屏时为 0）。
func (v *viewModel) maxChatScroll() int {
	vis := 0
	for _, l := range v.chat {
		if !l.hidden {
			vis++
		}
	}
	if v.bodyHeight <= 0 {
		return vis
	}
	return max0(vis - v.bodyHeight)
}

// ---- 输入栏（聊天正文：光标编辑 + 字符插入 + 粘贴）----

func (v *viewModel) insertRunes(rs []rune) {
	if len(rs) == 0 {
		return
	}
	out := make([]rune, 0, len(v.input)+len(rs))
	out = append(out, v.input[:v.cur]...)
	out = append(out, rs...)
	out = append(out, v.input[v.cur:]...)
	v.input = out
	v.cur += len(rs)
}

// OnInput 注入一个可打印字符（含 IME 上屏字符）。v25：不再有「按键即动作」的
// 路径，也不再抢数字键切面板——字符一律进当前焦点的文本载体（对话框优先）。
func (v *viewModel) OnInput(r rune) {
	if r < 0x20 {
		return
	}
	if v.dlg != nil {
		v.dialogInput(r)
		return
	}
	if v.panel == PanelChat {
		v.insertRunes([]rune{r})
	}
}

// Paste 注入剪贴板内容（Ctrl+V）；换行折叠为空格（单行输入栏）。
func (v *viewModel) Paste(s string) {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s)
	if s == "" {
		return
	}
	if v.dlg != nil {
		v.dlg.insert(s)
		return
	}
	if v.panel == PanelChat {
		v.insertRunes([]rune(s))
	}
}

// OnKey 注入特殊功能键。浮层优先级：对话框 > 右键菜单 > 面板。
func (v *viewModel) OnKey(k Key) {
	if v.dlg != nil {
		v.dialogKey(k)
		return
	}
	if v.menuOpen {
		switch k {
		case KeyEscape:
			v.CloseMenu()
		case KeyUp:
			v.menuSel = max0(v.menuSel - 1)
		case KeyDown:
			v.menuSel = min(v.menuSel+1, len(v.menu)-1)
		case KeyEnter:
			v.PickMenu(v.menuSel)
		default:
			v.CloseMenu()
		}
		return
	}
	switch k {
	case KeyTab:
		v.NextTab()
		return
	case KeyShiftTab:
		v.PrevTab()
		return
	case KeyEscape:
		switch {
		case len(v.input) > 0:
			v.input, v.cur = nil, 0
		case v.panel != PanelChat:
			v.setPanel(PanelChat)
		}
		return
	case KeyUp:
		if v.panel == PanelChat {
			v.ScrollBy(-1)
		} else {
			v.moveSel(-1)
		}
		return
	case KeyDown:
		if v.panel == PanelChat {
			v.ScrollBy(1)
		} else {
			v.moveSel(1)
		}
		return
	case KeyPgUp:
		if v.panel == PanelChat {
			v.ScrollBy(-10)
		}
		return
	case KeyPgDn:
		if v.panel == PanelChat {
			v.ScrollBy(10)
		}
		return
	case KeyEnter:
		if v.panel == PanelChat {
			v.Submit()
		}
		return
	}
	if v.panel != PanelChat {
		return // 非聊天面板没有文本载体，编辑键无事可做
	}
	switch k {
	case KeyBackspace:
		if v.cur > 0 {
			v.input = append(v.input[:v.cur-1], v.input[v.cur:]...)
			v.cur--
		}
	case KeyDelete:
		if v.cur < len(v.input) {
			v.input = append(v.input[:v.cur], v.input[v.cur+1:]...)
		}
	case KeyLeft:
		if v.cur > 0 {
			v.cur--
		}
	case KeyRight:
		if v.cur < len(v.input) {
			v.cur++
		}
	case KeyHome:
		v.cur = 0
	case KeyEnd:
		v.cur = len(v.input)
	}
}

// MenuSel 返回右键菜单的键盘高亮项。
func (v *viewModel) MenuSel() int { return v.menuSel }

func (v *viewModel) moveSel(d int) {
	n := v.panelRows()
	if n == 0 {
		v.sel = 0
		return
	}
	v.sel = max0(min(v.sel+d, n-1))
}

// Submit 提交输入栏（Enter）：v25 起整行都是聊天正文，斜杠不再解析。
func (v *viewModel) Submit() {
	line := string(v.input)
	v.input, v.cur = nil, 0
	v.sendText(strings.TrimSpace(line))
}

// ---- 宿主动作的共用出口 ----

func (v *viewModel) audit() {
	if v.app == nil {
		return
	}
	app := v.app
	v.async(func() []Event {
		lines, err := app.Audit()
		if err != nil {
			return []Event{SystemEvent{Note: Tf("au.failed", err.Error())}}
		}
		evs := make([]Event, 0, len(lines))
		for _, l := range lines {
			evs = append(evs, SystemEvent{Note: Tf("au.line", l)})
		}
		return evs
	})
}

func (v *viewModel) hasPerm(perm string) bool {
	if v.app == nil || v.app.Roster() == nil {
		return true // 离线预览/单测：不拦截
	}
	return v.app.Roster().HasPerm(v.app.Self(), perm)
}

func (v *viewModel) selfPub() core.PubKey {
	if v.app == nil {
		return core.PubKey{}
	}
	return v.app.Self()
}

// fire 执行出站动作并回报结果提示（异步经 deliver，同步模式直接应用）。
func (v *viewModel) fire(desc string, job func() error) {
	if v.app == nil {
		return
	}
	v.async(func() []Event {
		if err := job(); err != nil {
			return []Event{SystemEvent{Note: Tf("act.failed", desc, err)}}
		}
		return []Event{SystemEvent{Note: Tf("act.submitted", desc)}}
	})
}

// ndFire 对网盘动作做统一的「未启用」防护。
func (v *viewModel) ndFire(fn func(Netdisk) error, desc string) {
	nd := mustND(v.app)
	if nd == nil {
		v.setStatus(Tr("st.ndUnavailable"))
		return
	}
	v.fire(desc, func() error { return fn(nd) })
}

func mustND(a App) Netdisk {
	if a == nil {
		return nil
	}
	return a.Netdisk()
}

// async 跑一段产生事件的作业；deliver 为 nil（单测）时同步执行。
func (v *viewModel) async(job func() []Event) {
	if v.deliver == nil {
		for _, ev := range job() {
			v.OnEvent(ev)
		}
		return
	}
	v.deliver(job)
}

// seedCheck 核对种子文件：重算 group_id + 验 creator_sig（有效种子只有
// 创建者能签）。对申请人递交的种子（target 非空）要求其中间身份与 target 一致
// 之外的深层核对由宿主 ApproveJoin 完成，这里给操作者呈现结论。
func (v *viewModel) seedCheck(path string, applicant core.PubKey) {
	app := v.app
	v.async(func() []Event {
		raw, err := os.ReadFile(path)
		if err != nil {
			return []Event{SystemEvent{Note: Tf("sc.err", err.Error())}}
		}
		var want [32]byte
		if app != nil {
			want = app.GroupID()
		}
		cfg, match, err := CheckSeedBytes(raw, want)
		if err != nil {
			return []Event{SystemEvent{Note: Tf("sc.rejected", err.Error())}}
		}
		if !match {
			return []Event{SystemEvent{Note: Tf("sc.wrongGroup", cfg.Name)}}
		}
		if applicant.IsZero() {
			return []Event{SystemEvent{Note: Tf("sc.ok", cfg.Name, cfg.Mode)}}
		}
		return []Event{SystemEvent{Note: Tf("sc.okReq", ShortID(applicant), cfg.Name, cfg.Mode)}}
	})
}

// outboundDraft 只是本地回显形态（真实 sig 由宿主完成）。
func (v *viewModel) outboundDraft(text string) core.Message {
	var sig core.Signer
	if v.app != nil {
		sig = v.app.Signer()
	}
	self := core.PubKey{}
	if sig != nil {
		self = sig.Pub()
	}
	return core.Message{Sender: self, TSms: v.currentTime().UnixMilli(), Type: core.TypeText, Content: []byte(text)}
}

// ---- 面板行数与行语义 ----

// panelRows 是当前面板可选行数。
func (v *viewModel) panelRows() int {
	switch v.panel {
	case PanelChat:
		return v.VisibleChat()
	case PanelMembers:
		return len(v.members)
	case PanelJoin:
		return len(v.joinReqs)
	case PanelAdmin:
		return len(v.members) + len(v.banned) + len(v.transfers) + len(v.appeals)
	case PanelNetdisk:
		return len(v.ndFiles)
	default:
		return 0
	}
}

// adminSections 给出 admin 面板的四节行区间：
// [0,m) members · [m,m+b) banned · [m+b,m+b+t) transfers · [.. ,+a) appeals。
type adminSections struct{ m, b, t, a int }

func (v *viewModel) adminSec() adminSections {
	return adminSections{m: len(v.members), b: len(v.banned), t: len(v.transfers), a: len(v.appeals)}
}

func (s adminSections) rowKind(sel int) string {
	i := sel
	switch {
	case i < 0:
		return ""
	case i < s.m:
		return "member"
	case i < s.m+s.b:
		return "banned"
	case i < s.m+s.b+s.t:
		return "transfer"
	case i < s.m+s.b+s.t+s.a:
		return "appeal"
	}
	return ""
}

// ---- 快照（Snapshot → game 绘制）----

// TopLine 是顶部状态行：本机短 ID、group_id 前 8 hex、成员/在线计数、当前面板。
func (v *viewModel) TopLine() string {
	self, gid := "?", "?"
	if v.app != nil {
		self = ShortID(v.app.Self())
		g := v.app.GroupID()
		gid = hex8(g[:])
	}
	online := 0
	for _, r := range v.members {
		if r.Online {
			online++
		}
	}
	return Tf("top.line", self, gid, len(v.members), online, len(v.banned), len(v.joinReqs), v.panel.label())
}

// TabLabels 返回顶部标签页文字（与 SwitchTab 序号一致；v20 起随语言变化）。
func TabLabels() []string {
	out := make([]string, 0, panelCount)
	for i := 0; i < int(panelCount); i++ {
		out = append(out, fmt.Sprintf("%d·%s", i+1, Panel(i).label()))
	}
	return out
}

// ActiveTab 返回当前面板序号。
func (v *viewModel) ActiveTab() int { return int(v.panel) }

// InputLine 返回聊天输入栏内容与光标；仅 chat 面板有文本载体（其余面板底部是动作条）。
func (v *viewModel) InputLine() (text string, caret int, active bool) {
	if v.panel != PanelChat {
		return "", 0, false
	}
	return "> " + string(v.input), v.cur + 2, true
}

// StatusLine 返回底部状态行。
func (v *viewModel) StatusLine() string {
	if v.status != "" {
		return v.status
	}
	return Tf("status.hint", v.panel.label())
}

// Snapshot 返回当前面板的可视行（不含 header/input/status，由 game 布局）。
func (v *viewModel) Snapshot() []ViewLine {
	switch v.panel {
	case PanelChat:
		return v.chatSnapshot()
	case PanelMembers:
		return v.membersSnapshot()
	case PanelJoin:
		return v.joinSnapshot()
	case PanelAdmin:
		return v.adminSnapshot()
	case PanelNetdisk:
		return v.netdiskSnapshot()
	case PanelProgress:
		lines := ProgressLines()
		out := make([]ViewLine, 0, len(lines))
		for _, l := range lines {
			st := StyleDim
			if !strings.HasPrefix(l, " ") {
				st = StyleHeader
			}
			out = append(out, ViewLine{Text: l, Style: st})
		}
		return out
	}
	return nil
}

// chatSnapshot 的 Row 与 chatLineAt 共用一套计数（跳过 hidden、含系统行），
// 保证「右键命中哪条气泡就选中哪条」。
func (v *viewModel) chatSnapshot() []ViewLine {
	out := make([]ViewLine, 0, len(v.chat))
	vis := 0
	for _, l := range v.chat {
		if l.hidden {
			continue
		}
		st := StyleChat
		avatar := ""
		switch {
		case l.system:
			st = StyleSystem
		case !l.sender.IsZero() && v.app != nil && l.sender.Equal(v.app.Self()):
			st = StyleSelf
		}
		if !l.sender.IsZero() {
			avatar = ShortID(l.sender)
		}
		row := 0
		if !l.system {
			row = vis + 1
		}
		out = append(out, ViewLine{Text: l.text, Meta: l.meta, Body: l.body, Avatar: avatar,
			Style: st, Selected: row > 0 && vis == v.sel, Row: row})
		vis++
	}
	return out
}

func (v *viewModel) membersSnapshot() []ViewLine {
	v.refreshRoster()
	out := []ViewLine{{Text: Tr("p.members.header"), Style: StyleHeader}}
	if len(v.members) == 0 {
		out = append(out, ViewLine{Text: Tr("p.members.empty"), Style: StyleDim})
		return out
	}
	for i, l := range RenderMemberLines(v.members, v.currentTime()) {
		out = append(out, ViewLine{Text: l, Style: memberLineStyle(v.members[i]), Selected: i == v.sel, Row: i + 1})
	}
	return out
}

func (v *viewModel) joinSnapshot() []ViewLine {
	out := []ViewLine{{Text: Tr("p.join.header"), Style: StyleHeader}}
	if len(v.joinReqs) == 0 {
		out = append(out, ViewLine{Text: Tr("p.empty"), Style: StyleDim})
		return out
	}
	for i, req := range v.joinReqs {
		st := StyleChat
		if req.SeedOK {
			st = StyleOnline
		}
		out = append(out, ViewLine{Text: FormatJoinLine(req, v.currentTime()), Style: st, Selected: i == v.sel, Row: i + 1})
	}
	out = append(out, ViewLine{Text: Tr("p.join.hint"), Style: StyleDim})
	return out
}

func (v *viewModel) adminSnapshot() []ViewLine {
	v.refreshRoster()
	v.reloadTransfers()
	sec := v.adminSec()
	out := []ViewLine{{Text: Tr("p.admin.members"), Style: StyleHeader}}
	for i, l := range RenderMemberLines(v.members, v.currentTime()) {
		out = append(out, ViewLine{Text: l, Style: memberLineStyle(v.members[i]), Selected: i == v.sel, Row: i + 1})
	}
	out = append(out, ViewLine{Text: Tr("p.admin.banned"), Style: StyleBad})
	for i, l := range RenderBannedLines(v.banned, v.currentTime(), false) {
		out = append(out, ViewLine{Text: l, Style: StyleBad, Selected: sec.m+i == v.sel, Row: sec.m + i + 1})
	}
	// transfer 联署提案节（v17①，v19 起落在群管面板）。
	out = append(out, ViewLine{Text: Tr("p.admin.xfers"), Style: StyleHeader})
	if len(v.transfers) == 0 {
		out = append(out, ViewLine{Text: Tr("p.empty"), Style: StyleDim})
	}
	for i, prop := range v.transfers {
		st := StyleBad
		if prop.FromOwner {
			st = StyleOnline
		}
		out = append(out, ViewLine{Text: FormatTransferLine(prop, v.currentTime()), Style: st, Selected: sec.m+sec.b+i == v.sel, Row: sec.m + sec.b + i + 1})
	}
	// 黑名单定向申诉节。
	out = append(out, ViewLine{Text: Tr("p.admin.appeals"), Style: StyleHeader})
	if len(v.appeals) == 0 {
		out = append(out, ViewLine{Text: Tr("p.none"), Style: StyleDim})
	}
	for i, a := range v.appeals {
		out = append(out, ViewLine{Text: FormatChatLine(a), Style: StyleChat, Selected: sec.m+sec.b+sec.t+i == v.sel, Row: sec.m + sec.b + sec.t + i + 1})
	}
	return out
}

// netdiskSnapshot 顶部是总览小字（不可选），文件列表按 sel 高亮并给出 Row，
// 使「下载/删除」作用于选中的那个文件。
func (v *viewModel) netdiskSnapshot() []ViewLine {
	v.refreshNetdisk()
	if v.ndStatus == nil {
		return []ViewLine{{Text: Tr("p.nd.off"), Style: StyleHeader}}
	}
	out := []ViewLine{{Text: Tr("p.nd.header"), Style: StyleHeader}}
	for _, l := range RenderNetdiskStatusLines(*v.ndStatus) {
		out = append(out, ViewLine{Text: l, Style: StyleChat})
	}
	out = append(out, ViewLine{Text: Tr("p.nd.files"), Style: StyleHeader})
	if len(v.ndFiles) == 0 {
		out = append(out, ViewLine{Text: Tr("p.empty"), Style: StyleDim})
		return out
	}
	for i, l := range RenderNetdiskFileLines(v.ndFiles) {
		st := StyleChat
		if strings.HasPrefix(l, "!") || strings.HasPrefix(l, "！") {
			st = StyleBad
		}
		out = append(out, ViewLine{Text: l, Style: st, Selected: i == v.sel, Row: i + 1})
	}
	return out
}

// VisibleChat 返回 chat 面板去掉 hidden 后的行数（game 计算夹取用）。
func (v *viewModel) VisibleChat() int {
	n := 0
	for _, l := range v.chat {
		if !l.hidden {
			n++
		}
	}
	return n
}

// ChatScroll 返回当前距底部的滚动偏移。
func (v *viewModel) ChatScroll() int { return v.chatScroll }

// SelectedRow 返回当前选中行序号（game 高亮与菜单定位用）。
func (v *viewModel) SelectedRow() int { return v.sel }

// SetBodyHeight 由 game 回填可视行数（夹取滚动 + 渲染窗口）。
func (v *viewModel) SetBodyHeight(h int) {
	if h < 1 {
		h = 1
	}
	v.bodyHeight = h
	v.ClampScroll(v.maxChatScroll())
}

func hex8(b []byte) string {
	const digits = "0123456789abcdef"
	n := len(b)
	if n > 4 {
		n = 4
	}
	out := make([]byte, 0, n*2)
	for _, c := range b[:n] {
		out = append(out, digits[c>>4], digits[c&0xF])
	}
	return string(out)
}
