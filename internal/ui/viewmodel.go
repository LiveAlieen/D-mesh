// viewmodel.go：GUI 的纯状态机（v19）。
//
// 本文件不 import ebiten：OnInput/OnKey/Submit/SwitchTab/ScrollBy/OnEvent/
// Tick/Snapshot 全部是可无窗口单测的方法。ebiten 壳（game.go）只负责把
// 键盘/鼠标/滚轮事件翻译成这些调用，并按 Snapshot() 的 ViewLine 绘制。
// 行为规格移植自 v16-v18 的终端 TUI 模型（面板切换、chat 环形上限、
// join seed 门槛、transfer a/d、admin 提示流、申诉 unban、audit 回 chat 等）。

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
	PanelProgress // v18 /progress 欠账占位
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
	StyleDim                      // 键位提示等次要文字
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
type ViewLine struct {
	Text     string
	Meta     string
	Body     string
	Avatar   string
	Style    LineStyle
	Selected bool
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
}

// promptState 是面板里的单行输入提示（/perms 目标、种子路径等）。
type promptState struct {
	label  string
	action string // seedcheck|perms
	target core.PubKey
	value  string
}

// ---- viewModel ----

// viewModel 是 GUI 根状态机。now 可注入以便测试；app 允许为 nil（离线预览/单测）。
type viewModel struct {
	app    App
	panel  Panel
	chat   []chatLine
	input  []rune
	cur    int // 输入栏光标（rune 下标）
	status string

	members    []MemberRow
	banned     []core.BlacklistEntry
	joinReqs   []JoinRequest
	transfers  []TransferProposal // 发给本机的待决 transfer 提案（v17①，admin 面板）
	appeals    []core.Message
	sel        int
	inputFocus bool // 非 chat 面板：false=列表焦点（动作键），true=输入栏焦点

	prompt *promptState

	ndStatus *NetdiskStatus
	ndFiles  []NetdiskFile

	chatScroll int // chat 距底部的行数（0=贴底自动跟随）
	bodyHeight int // 最近一次的可视行数（渲染层回填，用于滚动夹取）
	quit       bool
	now        func() time.Time

	// deliver 由 game 注入：在工作线程跑 job（读文件/审计/出站广播），产出的
	// 事件回投 UI 线程应用。nil（单测/离线预览）时同步执行，结果立即可断言。
	deliver func(job func() []Event)
}

// newViewModel 构造根状态机。
func newViewModel(app App) *viewModel {
	return &viewModel{app: app, now: time.Now, inputFocus: true}
}

func (v *viewModel) currentTime() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// QuitRequested 报告 viewModel 是否请求退出（/quit 或宿主关闭）。
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
		v.appendChat(chatLine{text: Tf("ev.xferChat", ShortID(e.Prop.Msg.Sender), e.Prop.Msg.MsgID, e.Prop.Msg.MsgID), system: true})
		v.setStatus(Tf("ev.xferStatus", ShortID(e.Prop.Msg.Sender)))
	case HideEvent:
		v.hideLine(e.MsgID)
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
	v.chat = append(v.chat, l)
	if len(v.chat) > 2000 {
		v.chat = v.chat[len(v.chat)-1500:]
	}
	// 贴底时自动跟随新消息（chatScroll=0 即锚定底部）； scrolled-up 保持原位。
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
	v.inputFocus = p == PanelChat
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

// FocusInput 把焦点切到输入栏（鼠标点击输入行/按 Enter 进入编辑）。
func (v *viewModel) FocusInput() {
	v.inputFocus = true
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

// ---- 输入栏（光标编辑 + 字符插入 + 粘贴）----

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

// OnInput 注入一个可打印字符（含 IME 上屏字符）。
func (v *viewModel) OnInput(r rune) {
	if r < 0x20 {
		return
	}
	if v.prompt != nil {
		v.prompt.value += string(r)
		return
	}
	if v.panel == PanelChat || v.inputFocus {
		// chat 面板且输入为空时，数字 1..6 直切面板（照旧模型）。
		if v.panel == PanelChat && len(v.input) == 0 && r >= '1' && r <= '0'+rune(panelCount) {
			v.SwitchTab(int(r - '1'))
			return
		}
		v.insertRunes([]rune{r})
		return
	}
	// 列表焦点：可打印字符即面板动作键。
	v.panelAction(string(r))
}

// Paste 注入剪贴板内容（Ctrl+V）；换行折叠为空格（单行输入栏）。
func (v *viewModel) Paste(s string) {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s)
	if s == "" {
		return
	}
	if v.prompt != nil {
		v.prompt.value += s
		return
	}
	if v.panel == PanelChat || v.inputFocus {
		v.insertRunes([]rune(s))
	}
}

// OnKey 注入特殊功能键。
func (v *viewModel) OnKey(k Key) {
	if v.prompt != nil {
		v.onPromptKey(k)
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
			if v.inputFocus {
				v.inputFocus = false
			} else {
				v.setPanel(PanelChat)
			}
		}
		return
	case KeyUp:
		if v.panel == PanelChat {
			v.ScrollBy(-1)
		} else if !v.inputFocus {
			v.moveSel(-1)
		}
		return
	case KeyDown:
		if v.panel == PanelChat {
			v.ScrollBy(1)
		} else if !v.inputFocus {
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
		if v.panel != PanelChat && !v.inputFocus {
			v.inputFocus = true // 非 chat 面板：Enter 先进入输入栏
			return
		}
		v.Submit()
		return
	}
	if v.panel != PanelChat && !v.inputFocus {
		switch k {
		case KeyLeft, KeyRight, KeyHome, KeyEnd, KeyBackspace, KeyDelete:
			return // 列表焦点下不动光标
		}
		return
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

func (v *viewModel) moveSel(d int) {
	n := v.panelRows()
	if n == 0 {
		v.sel = 0
		return
	}
	v.sel = max0(min(v.sel+d, n-1))
}

// Submit 提交输入栏（Enter）：斜杠命令走 ParseCommand 分发（与无头 stdin
// 同一语义），普通文本走 SendText。
func (v *viewModel) Submit() {
	line := string(v.input)
	v.input, v.cur = nil, 0
	if strings.TrimSpace(line) == "" {
		return
	}
	cmd, err := ParseCommand(line)
	if err != nil {
		v.setStatus(Tf("st.inputErr", err))
		return
	}
	v.dispatch(cmd)
}

// ---- 命令分发（逐条移植旧模型 dispatch）----

func (v *viewModel) dispatch(c Command) {
	if c.Kind == CmdText && !v.hasPerm(core.PermSpeak) {
		v.setStatus(Tr("st.noSpeak"))
		return
	}
	switch c.Kind {
	case CmdHelp:
		v.appendChat(chatLine{text: Tr("help.text"), system: true})
	case CmdClear:
		v.chat, v.chatScroll = nil, 0
	case CmdQuit:
		v.quit = true
	case CmdLang:
		if c.Lang == "" {
			v.setStatus(Tf("st.langNow", string(GetLang()), LangList()))
			return
		}
		if SetLang(Lang(c.Lang)) {
			v.setStatus(Tf("st.langSet", string(GetLang())))
		} else {
			v.setStatus(Tf("st.langBad", c.Lang, LangList()))
		}
	case CmdTheme:
		if c.Theme == "" {
			v.setStatus(Tf("st.themeNow", string(GetTheme()), ThemeList()))
			return
		}
		if SetTheme(c.Theme) {
			v.setStatus(Tf("st.themeSet", string(GetTheme())))
		} else {
			v.setStatus(Tf("st.themeBad", c.Theme, ThemeList()))
		}
	case CmdText:
		msg := v.outboundDraft(c.Text)
		v.appendChat(chatLine{text: FormatChatLine(msg), sender: v.selfPub(), meta: chatMeta(msg), body: chatBody(msg)})
		v.fire(Tr("act.sent"), func() error { return v.app.SendText(c.Text) })
	case CmdHide:
		v.hideLine(c.MsgID)
		v.fire(Tr("act.hide"), func() error { return v.app.Hide(c.MsgID) })
	case CmdAudit:
		v.audit()
	case CmdRemove:
		v.fire(Tr("act.leave"), func() error { return v.app.Leave() })
	case CmdKick:
		v.fire(Tr("act.kick"), func() error { return v.app.Kick(c.Target) })
	case CmdUnban:
		v.fire(Tr("act.unban"), func() error { return v.app.Unban(c.Target) })
	case CmdPerms:
		v.fire(Tr("act.perms"), func() error { return v.app.SetPerms(c.Target, c.Perms) })
	case CmdGrantAdmin:
		v.fire(Tr("act.grantAdmin"), func() error { return v.app.GrantAdmin(c.Target) })
	case CmdRevokeAdmin:
		v.fire(Tr("act.revokeAdmin"), func() error { return v.app.RevokeAdmin(c.Target) })
	case CmdTransfer:
		v.fire(Tr("act.transfer"), func() error { return v.app.Transfer(c.Target) })
	case CmdApprove:
		v.fire(Tr("act.endorsed"), func() error { return v.app.ApproveTransfer(c.MsgID) })
	case CmdDeny:
		if v.app == nil {
			return
		}
		if err := v.app.RejectTransfer(c.MsgID); err != nil {
			v.setStatus(Tf("st.denyFail", err))
			return
		}
		v.appendChat(chatLine{text: Tf("act.deniedLine", truncate(c.MsgID, 10)), system: true})
		v.reloadTransfers()
	case CmdTransfers:
		v.listTransfers()
	case CmdProgress:
		// v18/v22：双轨进度以系统行展示，绝不作为发言广播。
		for _, l := range ProgressLines() {
			v.appendChat(chatLine{text: l, system: true})
		}
		v.setStatus(Tr("st.progressShown"))
	case CmdOfflineAfter:
		v.fire(Tr("act.presence"), func() error { return v.app.SetOfflineAfter(c.Millis) })
	case CmdSeedCheck:
		v.seedCheck(c.Path, core.PubKey{})
	case CmdNetdisk, CmdNDStatus:
		v.setPanel(PanelNetdisk)
	case CmdNDUpload:
		v.ndFire(func(nd Netdisk) error { return nd.Upload(c.Path) }, Tf("act.upload", c.Path))
	case CmdNDDownload:
		v.ndFire(func(nd Netdisk) error { return nd.Download(c.Name, c.Name) }, Tf("act.download", c.Name))
	case CmdNDDelete:
		v.ndFire(func(nd Netdisk) error { return nd.Delete(c.Name) }, Tf("act.delete", c.Name))
	case CmdNDSet:
		v.fire(Tf("act.ndQuota", c.MB), func() error { return v.app.SetNetdiskMB(c.MB) })
	}
}

func (v *viewModel) listTransfers() {
	if v.app == nil {
		return
	}
	app := v.app
	v.async(func() []Event {
		props := app.PendingTransfers()
		if len(props) == 0 {
			return []Event{SystemEvent{Note: Tr("lf.none")}}
		}
		now := v.currentTime()
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n", Tf("lf.title", len(props)))
		for _, p := range props {
			b.WriteString("  " + FormatTransferLine(p, now) + "\n")
		}
		b.WriteString(Tr("lf.hint"))
		return []Event{SystemEvent{Note: strings.TrimRight(b.String(), "\n")}}
	})
}

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

// ---- 面板动作（列表焦点下的可打印键）----

// panelRows 是当前面板可选行数。
func (v *viewModel) panelRows() int {
	switch v.panel {
	case PanelMembers:
		return len(v.members)
	case PanelJoin:
		return len(v.joinReqs)
	case PanelAdmin:
		return len(v.members) + len(v.banned) + len(v.transfers) + len(v.appeals)
	default:
		return 0
	}
}

func (v *viewModel) panelAction(key string) {
	switch v.panel {
	case PanelJoin:
		v.joinAction(key)
	case PanelAdmin:
		v.adminAction(key)
	case PanelNetdisk:
		if key == "r" {
			v.refreshNetdisk()
		}
	case PanelMembers:
		// 成员面板只读展示（旧模型亦无动作）；j/k 导航由 OnKey 处理。
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

// ---- 入群面板动作（join_req 节）----

func (v *viewModel) joinAction(key string) {
	// 队列宿主所有（PendingJoins 是唯一事实源）：动作前先 reload，否则
	// 种子核对通过后（宿主把 SeedOK 翻转为 true）面板仍拿着旧的本地副本，
	// 「核对通过才准签 join」的门控会永久卡住批准。
	v.reloadJoins()
	if v.sel >= len(v.joinReqs) || v.app == nil {
		return
	}
	req := v.joinReqs[v.sel]
	switch key {
	case "a": // 核对通过后签 join 广播
		if !req.SeedOK {
			v.setStatus(Tf("st.seedGate", ShortID(req.Msg.Sender)))
			return
		}
		v.fire(Tr("act.joinSigned"), func() error { return v.app.ApproveJoin(req.Msg.MsgID) })
	case "d": // 拒绝（仅本地出队，不广播）
		if err := v.app.RejectJoin(req.Msg.MsgID); err != nil {
			v.setStatus(Tf("st.rejectFail", err))
		} else {
			v.reloadJoins()
		}
	case "s": // 核对种子文件哈希（申请人递交或线下拿到的种子路径）
		v.prompt = &promptState{label: Tr("prompt.seedPath"), action: "seedcheck", target: req.Msg.Sender}
	case "r":
		v.reloadJoins()
	}
}

// ---- 群管面板动作（members/banned/transfers/appeals 四节）----

func (v *viewModel) adminAction(key string) {
	v.refreshRoster() // 行区间随宿主快照浮动，先对齐
	v.reloadTransfers()
	if key == "r" {
		v.setPanel(PanelAdmin) // 重进即刷新
		return
	}
	sec := v.adminSec()
	kind := sec.rowKind(v.sel)
	if v.app == nil {
		return
	}
	switch {
	case key == "K" && kind == "member":
		pub := v.members[v.sel].Entry.Pub
		v.fire(Tr("act.kickEvent"), func() error { return v.app.Kick(pub) })
	case key == "U" && kind == "banned":
		pub := v.banned[v.sel-sec.m].Pub
		v.fire(Tr("act.unbanEvent"), func() error { return v.app.Unban(pub) })
	case key == "P" && kind == "member":
		pub := v.members[v.sel].Entry.Pub
		v.prompt = &promptState{label: Tf("prompt.permsFor", ShortID(pub)), action: "perms", target: pub}
	case key == "G" && kind == "member":
		pub := v.members[v.sel].Entry.Pub
		v.fire(Tr("act.grantAdminEvent"), func() error { return v.app.GrantAdmin(pub) })
	case key == "R" && kind == "member":
		pub := v.members[v.sel].Entry.Pub
		v.fire(Tr("act.revokeAdminEvent"), func() error { return v.app.RevokeAdmin(pub) })
	case key == "T" && kind == "member":
		pub := v.members[v.sel].Entry.Pub
		v.fire(Tr("act.transfer"), func() error { return v.app.Transfer(pub) })
	case key == "a" && kind == "transfer":
		v.transferAction(v.transfers[v.sel-sec.m-sec.b])
	case key == "d" && kind == "transfer":
		v.denyTransfer(v.transfers[v.sel-sec.m-sec.b])
	case key == "u" && kind == "appeal":
		msg := v.appeals[v.sel-sec.m-sec.b-sec.t]
		v.fire(Tr("act.unbanEvent"), func() error { return v.app.Unban(msg.Sender) })
	case key == "i" && kind == "appeal":
		i := v.sel - sec.m - sec.b - sec.t
		v.appeals = append(v.appeals[:i:i], v.appeals[i+1:]...)
		v.setStatus(Tr("st.appealIgnored"))
		v.moveSel(0)
	}
}

// transferAction 批准 transfer 提案（v17①）：对本机收到的同一份原文补上
// 联署（EndorseSig）并广播生效；签名者非现任 owner/创建者时拒绝联署。
func (v *viewModel) transferAction(prop TransferProposal) {
	if !prop.FromOwner {
		v.setStatus(Tr("st.notOwner"))
		return
	}
	v.fire(Tr("act.endorsed"), func() error { return v.app.ApproveTransfer(prop.Msg.MsgID) })
}

// denyTransfer 拒绝提案：宿主仅本地丢弃，绝不转发、不产生任何事件。
func (v *viewModel) denyTransfer(prop TransferProposal) {
	if err := v.app.RejectTransfer(prop.Msg.MsgID); err != nil {
		v.setStatus(Tf("st.denyFail", err))
		return
	}
	v.appendChat(chatLine{text: Tf("act.deniedLine", truncate(prop.Msg.MsgID, 10)), system: true})
	v.reloadTransfers()
}

// ---- 提示行（prompt）处理 ----

func (v *viewModel) onPromptKey(k Key) {
	p := v.prompt
	switch k {
	case KeyEnter:
		v.prompt = nil
		v.runPrompt(p)
	case KeyEscape:
		v.prompt = nil
		v.setStatus(Tr("st.cancelled"))
	case KeyBackspace:
		r := []rune(p.value)
		if len(r) > 0 {
			p.value = string(r[:len(r)-1])
		}
	}
}

func (v *viewModel) runPrompt(p *promptState) {
	val := strings.TrimSpace(p.value)
	if val == "" {
		v.setStatus(Tr("st.emptyCancelled"))
		return
	}
	switch p.action {
	case "seedcheck":
		v.seedCheck(val, p.target)
	case "perms":
		perms, err := ParsePermList(val)
		if err != nil {
			v.setStatus(Tf("st.permsErr", err))
			return
		}
		if v.app == nil {
			return
		}
		v.fire(Tr("act.permsEvent"), func() error { return v.app.SetPerms(p.target, perms) })
	}
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

// InputLine 返回输入栏内容：prompt 优先，其次 "> "+input 与光标 rune 下标。
func (v *viewModel) InputLine() (text string, caret int, active bool) {
	if v.prompt != nil {
		return v.prompt.label + ": " + v.prompt.value, len([]rune(v.prompt.label + ": " + v.prompt.value)), true
	}
	if v.panel == PanelChat || v.inputFocus {
		return "> " + string(v.input), v.cur + 2, true
	}
	return Tf("input.listFocus", "> "+string(v.input)), v.cur + 2, false
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

func (v *viewModel) chatSnapshot() []ViewLine {
	out := make([]ViewLine, 0, len(v.chat))
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
		out = append(out, ViewLine{Text: l.text, Meta: l.meta, Body: l.body, Avatar: avatar, Style: st})
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
		out = append(out, ViewLine{Text: l, Style: memberLineStyle(v.members[i]), Selected: i == v.sel})
	}
	return out
}

func (v *viewModel) joinSnapshot() []ViewLine {
	out := []ViewLine{{Text: Tr("p.join.header"), Style: StyleHeader}}
	if len(v.joinReqs) == 0 {
		out = append(out, ViewLine{Text: Tr("p.empty"), Style: StyleDim})
	}
	for i, req := range v.joinReqs {
		st := StyleChat
		if req.SeedOK {
			st = StyleOnline
		}
		out = append(out, ViewLine{Text: FormatJoinLine(req, v.currentTime()), Style: st, Selected: i == v.sel})
	}
	if len(v.joinReqs) > 0 {
		out = append(out, ViewLine{Text: Tr("p.join.hint"), Style: StyleDim})
	}
	return out
}

func (v *viewModel) adminSnapshot() []ViewLine {
	v.refreshRoster()
	v.reloadTransfers()
	sec := v.adminSec()
	out := []ViewLine{{Text: Tr("p.admin.members"), Style: StyleHeader}}
	for i, l := range RenderMemberLines(v.members, v.currentTime()) {
		out = append(out, ViewLine{Text: l, Style: memberLineStyle(v.members[i]), Selected: i == v.sel})
	}
	out = append(out, ViewLine{Text: Tr("p.admin.banned"), Style: StyleBad})
	for i, l := range RenderBannedLines(v.banned, v.currentTime(), false) {
		out = append(out, ViewLine{Text: l, Style: StyleBad, Selected: sec.m+i == v.sel})
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
		out = append(out, ViewLine{Text: FormatTransferLine(prop, v.currentTime()), Style: st, Selected: sec.m+sec.b+i == v.sel})
	}
	if len(v.transfers) > 0 {
		out = append(out, ViewLine{Text: Tr("p.admin.xferHint"), Style: StyleDim})
	}
	// 黑名单定向申诉节。
	out = append(out, ViewLine{Text: Tr("p.admin.appeals"), Style: StyleHeader})
	if len(v.appeals) == 0 {
		out = append(out, ViewLine{Text: Tr("p.none"), Style: StyleDim})
	}
	for i, a := range v.appeals {
		out = append(out, ViewLine{Text: FormatChatLine(a), Style: StyleChat, Selected: sec.m+sec.b+sec.t+i == v.sel})
	}
	return out
}

func (v *viewModel) netdiskSnapshot() []ViewLine {
	v.refreshNetdisk()
	if v.ndStatus == nil {
		return []ViewLine{
			{Text: Tr("p.nd.off"), Style: StyleHeader},
		}
	}
	out := []ViewLine{{Text: Tr("p.nd.header"), Style: StyleHeader}}
	for _, l := range RenderNetdiskLines(*v.ndStatus, v.ndFiles) {
		st := StyleChat
		if strings.HasPrefix(l, "!") || strings.HasPrefix(l, "！") {
			st = StyleBad
		}
		out = append(out, ViewLine{Text: l, Style: st})
	}
	out = append(out, ViewLine{Text: Tr("p.nd.cmds"), Style: StyleDim})
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
