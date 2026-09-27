// actions.go：v25 GUI 动作层——窗口里的所有操作都以按钮/右键菜单/对话框承载，
// 输入框只承载聊天正文（斜杠命令在 GUI 内彻底退役，ParseCommand 只服务无头 stdin）。
//
// 与 viewmodel.go 同属纯状态机：本文件不 import ebiten，鼠标命中由 game.go 翻译成
// ClickRow/PickMenu/PickDialogItem 等调用，全部可无窗口单测。

package ui

import (
	"strings"

	"dmesh/internal/core"
)

// ActionID 是 GUI 动作的稳定标识（同时是对话框提交与 i18n 键的后缀）。
type ActionID string

const (
	// 顶栏（任何面板都在）
	ActHelp     ActionID = "help"
	ActAudit    ActionID = "audit"
	ActSettings ActionID = "settings"
	ActLeave    ActionID = "leave"
	ActQuit     ActionID = "quit"

	// 设置项
	ActTheme       ActionID = "theme"
	ActLang        ActionID = "lang"
	ActOfflineTune ActionID = "offlineAfter"

	// 聊天
	ActSend  ActionID = "send"
	ActClear ActionID = "clear"
	ActHide  ActionID = "hide"
	ActCopy  ActionID = "copy"

	// 成员 / 黑名单行
	ActKick     ActionID = "kick"
	ActUnban    ActionID = "unban"
	ActPerms    ActionID = "perms"
	ActGrant    ActionID = "grantAdmin"
	ActRevoke   ActionID = "revokeAdmin"
	ActTransfer ActionID = "transfer"
	ActCopyPub  ActionID = "copyPub"

	// 入群申请行
	ActJoinApprove ActionID = "joinApprove"
	ActJoinReject  ActionID = "joinReject"
	ActSeedCheck   ActionID = "seedCheck"

	// transfer 提案行 / 黑名单申诉行
	ActXferApprove  ActionID = "xferApprove"
	ActXferDeny     ActionID = "xferDeny"
	ActAppealUnban  ActionID = "appealUnban"
	ActAppealIgnore ActionID = "appealIgnore"

	// 网盘
	ActNDUpload   ActionID = "ndUpload"
	ActNDDownload ActionID = "ndDownload"
	ActNDDelete   ActionID = "ndDelete"
	ActNDQuota    ActionID = "ndQuota"

	ActRefresh ActionID = "refresh"
)

// allActionIDs 列出全部动作 ID（v27 两侧可达性契约测试用：
// 每个动作要么 GUI 有控件、要么无头可触发，两边都够不着即测试红）。
// 加动作必须同时登记到这里，否则 const 与表漂移。
var allActionIDs = []ActionID{
	ActHelp, ActAudit, ActSettings, ActLeave, ActQuit,
	ActTheme, ActLang, ActOfflineTune,
	ActSend, ActClear, ActHide, ActCopy,
	ActKick, ActUnban, ActPerms, ActGrant, ActRevoke, ActTransfer, ActCopyPub,
	ActJoinApprove, ActJoinReject, ActSeedCheck,
	ActXferApprove, ActXferDeny, ActAppealUnban, ActAppealIgnore,
	ActNDUpload, ActNDDownload, ActNDDelete, ActNDQuota,
	ActRefresh,
}

// Action 是一个可点击的动作。Enabled=false 时置灰显示（不隐藏：让用户看得见能力面）。
type Action struct {
	ID      ActionID
	Label   string
	Enabled bool
	// Confirm 非空=点击先弹确认框（破坏性动作：除名/退群/清屏/删除/隐藏）。
	Confirm string
}

func act(id ActionID, label string) Action {
	return Action{ID: id, Label: label, Enabled: true}
}

func actOff(id ActionID, label string) Action {
	return Action{ID: id, Label: label}
}

// ---- 选中行语义 ----

// rowKindOf 返回当前选中行的语义类别（"" = 无有效选中）。
func (v *viewModel) rowKindOf() string {
	switch v.panel {
	case PanelChat:
		if _, ok := v.chatLineAt(v.sel); ok {
			return "chat"
		}
	case PanelMembers:
		if v.sel >= 0 && v.sel < len(v.members) {
			return "member"
		}
	case PanelJoin:
		if v.sel >= 0 && v.sel < len(v.joinReqs) {
			return "joinreq"
		}
	case PanelAdmin:
		return v.adminSec().rowKind(v.sel)
	case PanelNetdisk:
		if v.sel >= 0 && v.sel < len(v.ndFiles) {
			return "ndfile"
		}
	}
	return ""
}

// chatLineAt 把 chat 面板的可见行序号映射回原始行。
func (v *viewModel) chatLineAt(vis int) (chatLine, bool) {
	if vis < 0 {
		return chatLine{}, false
	}
	for _, l := range v.chat {
		if l.hidden {
			continue
		}
		if vis == 0 {
			return l, true
		}
		vis--
	}
	return chatLine{}, false
}

// selectedPub 返回当前选中行对应的公钥（成员/黑名单/申诉/申请人）。
func (v *viewModel) selectedPub() (core.PubKey, bool) {
	sec := v.adminSec()
	switch v.rowKindOf() {
	case "member":
		return v.members[v.sel].Entry.Pub, true
	case "banned":
		return v.banned[v.sel-sec.m].Pub, true
	case "appeal":
		return v.appeals[v.sel-sec.m-sec.b-sec.t].Sender, true
	case "joinreq":
		if v.panel == PanelJoin && v.sel < len(v.joinReqs) {
			return v.joinReqs[v.sel].Msg.Sender, true
		}
	}
	return core.PubKey{}, false
}

// ---- 顶栏按钮 / 面板动作条 / 右键菜单 ----

// ToolbarActions 是顶栏按钮。
func (v *viewModel) ToolbarActions() []Action {
	on := v.app != nil
	a := []Action{act(ActHelp, Tr("gui.help"))}
	if on {
		a = append(a, act(ActAudit, Tr("gui.audit")))
	}
	a = append(a, act(ActSettings, Tr("gui.settings")))
	if on {
		a = append(a, actAsk(ActLeave, Tr("gui.leave")))
	}
	return append(a, act(ActQuit, Tr("gui.quit")))
}

// PanelActions 是当前面板底部动作条。
func (v *viewModel) PanelActions() []Action {
	switch v.panel {
	case PanelChat:
		send := actOff(ActSend, Tr("gui.send"))
		if strings.TrimSpace(string(v.input)) != "" {
			send = act(ActSend, Tr("gui.send"))
		}
		return []Action{send, actAsk(ActClear, Tr("gui.clear"))}
	case PanelNetdisk:
		if mustND(v.app) == nil {
			return []Action{actOff(ActNDUpload, Tr("gui.upload")), actOff(ActNDQuota, Tr("gui.quota"))}
		}
		return append(v.rowActions(),
			act(ActNDUpload, Tr("gui.upload")),
			act(ActNDQuota, Tr("gui.quota")),
			act(ActRefresh, Tr("gui.refresh")))
	case PanelProgress:
		return nil
	}
	return append(v.rowActions(), act(ActRefresh, Tr("gui.refresh")))
}

// RowActions 是当前选中行的右键菜单项。
func (v *viewModel) RowActions() []Action { return v.rowActions() }

func (v *viewModel) rowActions() []Action {
	switch v.rowKindOf() {
	case "chat":
		l, _ := v.chatLineAt(v.sel)
		out := []Action{}
		if l.system {
			return nil
		}
		if !l.sender.IsZero() && v.app != nil && l.sender.Equal(v.app.Self()) && l.msgID != "" {
			out = append(out, actAsk(ActHide, Tr("gui.hide")))
		}
		if s := chatCopyText(l); s != "" {
			out = append(out, act(ActCopy, Tr("gui.copy")))
		}
		return out
	case "member":
		return []Action{
			actAsk(ActKick, Tr("gui.kick")),
			act(ActPerms, Tr("gui.perms")),
			act(ActGrant, Tr("gui.grantAdmin")),
			act(ActRevoke, Tr("gui.revokeAdmin")),
			actAsk(ActTransfer, Tr("gui.transfer")),
			act(ActCopyPub, Tr("gui.copyPub")),
		}
	case "banned":
		return []Action{act(ActUnban, Tr("gui.unban")), act(ActCopyPub, Tr("gui.copyPub"))}
	case "transfer":
		return []Action{act(ActXferApprove, Tr("gui.xferApprove")), act(ActXferDeny, Tr("gui.xferDeny"))}
	case "appeal":
		return []Action{act(ActAppealUnban, Tr("gui.appealUnban")), act(ActAppealIgnore, Tr("gui.appealIgnore"))}
	case "joinreq":
		return []Action{
			act(ActJoinApprove, Tr("gui.joinApprove")),
			act(ActJoinReject, Tr("gui.joinReject")),
			act(ActSeedCheck, Tr("gui.seedCheck")),
		}
	case "ndfile":
		return []Action{act(ActNDDownload, Tr("gui.download")), actAsk(ActNDDelete, Tr("gui.delete"))}
	}
	// 无有效选中：面板级动作置灰摆着（成员/群管/网盘/入群面板）。
	switch v.panel {
	case PanelMembers:
		return []Action{actOff(ActKick, Tr("gui.kick")), actOff(ActPerms, Tr("gui.perms"))}
	case PanelAdmin:
		return []Action{actOff(ActKick, Tr("gui.kick"))}
	case PanelJoin:
		return []Action{actOff(ActJoinApprove, Tr("gui.joinApprove"))}
	}
	return nil
}

func chatCopyText(l chatLine) string {
	if l.body != "" {
		return l.body
	}
	return l.text
}

// ClickRow 由 game 在鼠标命中某行时调用：左键=选中；右键=选中并弹出该行的菜单。
// row 是 ViewLine.Row-1（可选行序号，从 0 计）。
func (v *viewModel) ClickRow(row int, right bool) {
	if row < 0 {
		return
	}
	v.sel = row
	v.menuSel = 0
	v.closeMenu()
	if !right {
		return
	}
	items := v.rowActions()
	if len(items) == 0 {
		return
	}
	v.menu, v.menuOpen = items, true
}

// Menu 返回当前打开的右键菜单项（nil = 未打开）。
func (v *viewModel) Menu() []Action {
	if !v.menuOpen {
		return nil
	}
	return v.menu
}

// CloseMenu 关闭右键菜单（点空白处/Esc）。
func (v *viewModel) CloseMenu() { v.closeMenu() }

func (v *viewModel) closeMenu() { v.menuOpen, v.menu = false, nil }

// PickMenu 执行菜单里第 i 项。
func (v *viewModel) PickMenu(i int) {
	if !v.menuOpen || i < 0 || i >= len(v.menu) || !v.menu[i].Enabled {
		return
	}
	id := v.menu[i].ID
	v.closeMenu()
	v.RunAction(id)
}

// RunAction 执行一个动作：需要参数或确认的先弹对话框，其余直接落地。
// 所有出站动作复用既有 App 门面方法——协议层与 ui.App 门面零改动。
func (v *viewModel) RunAction(id ActionID) {
	if v.dlg != nil {
		return // 模态浮层期间不吃其他动作
	}
	if id == ActSettings {
		v.dlg = v.settingsDialog()
		return
	}
	c := v.currentCtx(id)
	if d := v.dialogFor(id, c); d != nil {
		v.dlg = d
		return
	}
	v.exec(id, c)
}

// ---- 动作上下文（选中行 → 参数；对话框在其上填写）----

type actionCtx struct {
	pub     core.PubKey
	msgID   string
	text    string   // v27：无头通道的聊天正文（GUI 由输入栏供给）
	path    string   // 文件选择框/手输路径的结果
	name    string   // 网盘文件名
	perms   []string // 勾选框结果
	mb      int      // 网盘配额
	ms      int64    // 离线阈值
	theme   string
	lang    string
	copyStr string // 复制到剪贴板的正文
}

func (v *viewModel) currentCtx(id ActionID) actionCtx {
	var c actionCtx
	kind := v.rowKindOf()
	if pub, ok := v.selectedPub(); ok {
		c.pub = pub
	}
	sec := v.adminSec()
	switch {
	case kind == "chat":
		if l, ok := v.chatLineAt(v.sel); ok {
			c.msgID, c.copyStr = l.msgID, chatCopyText(l)
		}
	case kind == "transfer":
		if i := v.sel - sec.m - sec.b; i >= 0 && i < len(v.transfers) {
			c.msgID = v.transfers[i].Msg.MsgID
		}
	case kind == "member" && id == ActPerms:
		if v.sel < len(v.members) {
			c.perms = append([]string(nil), v.members[v.sel].Entry.Perms...)
		}
	case kind == "ndfile":
		if v.sel < len(v.ndFiles) {
			c.name = v.ndFiles[v.sel].Name
		}
	}
	return c
}

// ---- 执行 ----

func (v *viewModel) exec(id ActionID, c actionCtx) {
	if v.app == nil {
		switch id {
		case ActHelp, ActClear, ActCopy, ActTheme, ActLang, ActQuit:
		default:
			return
		}
	}
	switch id {
	case ActHelp:
		v.appendChat(chatLine{text: Tr("help.text"), system: true})
	case ActClear:
		v.chat, v.chatScroll, v.sel = nil, 0, 0
	case ActQuit:
		v.quit = true
	case ActAudit:
		v.audit()
	case ActLeave:
		v.fire(Tr("act.leave"), func() error { return v.app.Leave() })
	case ActSend:
		// 正文优先取输入栏（GUI），无头通道没有输入栏，退到动作上下文。
		text := strings.TrimSpace(string(v.input))
		if text == "" {
			text = strings.TrimSpace(c.text)
		}
		v.sendText(text)
	case ActHide:
		if c.msgID == "" {
			return
		}
		v.hideLine(c.msgID)
		v.fire(Tr("act.hide"), func() error { return v.app.Hide(c.msgID) })
	case ActCopy:
		v.toClipboard(c.copyStr)
	case ActKick:
		v.fire(Tr("act.kickEvent"), func() error { return v.app.Kick(c.pub) })
	case ActUnban:
		v.fire(Tr("act.unbanEvent"), func() error { return v.app.Unban(c.pub) })
	case ActPerms:
		if len(c.perms) == 0 {
			return
		}
		v.fire(Tr("act.permsEvent"), func() error { return v.app.SetPerms(c.pub, c.perms) })
	case ActGrant:
		v.fire(Tr("act.grantAdminEvent"), func() error { return v.app.GrantAdmin(c.pub) })
	case ActRevoke:
		v.fire(Tr("act.revokeAdminEvent"), func() error { return v.app.RevokeAdmin(c.pub) })
	case ActTransfer:
		v.fire(Tr("act.transfer"), func() error { return v.app.Transfer(c.pub) })
	case ActCopyPub:
		if !c.pub.IsZero() {
			v.toClipboard(c.pub.String())
		}
	case ActJoinApprove:
		v.approveJoin()
	case ActJoinReject:
		v.rejectJoin()
	case ActXferApprove:
		v.endorseTransfer()
	case ActXferDeny:
		v.denyTransferID(c.msgID)
	case ActAppealUnban:
		v.fire(Tr("act.unbanEvent"), func() error { return v.app.Unban(c.pub) })
	case ActAppealIgnore:
		sec := v.adminSec()
		i := v.sel - sec.m - sec.b - sec.t
		if i < 0 || i >= len(v.appeals) {
			return
		}
		v.appeals = append(v.appeals[:i:i], v.appeals[i+1:]...)
		v.setStatus(Tr("st.appealIgnored"))
		v.sel = 0
	case ActSeedCheck:
		if c.path == "" {
			return
		}
		v.seedCheck(c.path, c.pub)
	case ActNDUpload:
		if c.path == "" {
			return
		}
		v.ndFire(func(nd Netdisk) error { return nd.Upload(c.path) }, Tf("act.upload", c.path))
	case ActNDDownload:
		if c.name == "" {
			return
		}
		// c.path 非空=显式落盘目标（无头 `/netdisk save <name> <dest>`）；
		// 空则沿用 GUI 的「按原名落到当前目录」，GUI 行为零变化。
		dest := c.path
		if dest == "" {
			dest = c.name
		}
		v.ndFire(func(nd Netdisk) error { return nd.Download(c.name, dest) }, Tf("act.download", c.name))
	case ActNDDelete:
		if c.name == "" {
			return
		}
		v.ndFire(func(nd Netdisk) error { return nd.Delete(c.name) }, Tf("act.delete", c.name))
	case ActNDQuota:
		if !core.ValidNetdiskMB(c.mb) || c.mb == 0 && v.ndStatus == nil {
			return
		}
		v.fire(Tf("act.ndQuota", c.mb), func() error { return v.app.SetNetdiskMB(c.mb) })
	case ActOfflineTune:
		if c.ms <= 0 {
			return
		}
		v.fire(Tr("act.presence"), func() error { return v.app.SetOfflineAfter(c.ms) })
	case ActTheme:
		if c.theme == "" {
			return
		}
		if SetTheme(c.theme) {
			v.setStatus(Tf("st.themeSet", string(GetTheme())))
		} else {
			v.failStatus(Tf("st.themeBad", c.theme, ThemeList()))
		}
	case ActLang:
		if c.lang == "" {
			return
		}
		if SetLang(Lang(c.lang)) {
			v.setStatus(Tf("st.langSet", string(GetLang())))
		} else {
			v.failStatus(Tf("st.langBad", c.lang, LangList()))
		}
	case ActRefresh:
		v.setPanel(v.panel) // 重进即刷新（与旧 r 键同语义）
	}
}

func (v *viewModel) approveJoin() {
	v.reloadJoins()
	if v.app == nil || v.sel >= len(v.joinReqs) {
		return
	}
	req := v.joinReqs[v.sel]
	if !req.SeedOK {
		v.failStatus(Tf("st.seedGate", ShortID(req.Msg.Sender)))
		return
	}
	v.fire(Tr("act.joinSigned"), func() error { return v.app.ApproveJoin(req.Msg.MsgID) })
}

func (v *viewModel) rejectJoin() {
	v.reloadJoins()
	if v.app == nil || v.sel >= len(v.joinReqs) {
		return
	}
	if err := v.app.RejectJoin(v.joinReqs[v.sel].Msg.MsgID); err != nil {
		v.failStatus(Tf("st.rejectFail", err))
		return
	}
	v.reloadJoins()
}

// endorseTransfer 对选中提案补本机联署并广播（v17①）。
func (v *viewModel) endorseTransfer() {
	if v.app == nil {
		return
	}
	v.reloadTransfers()
	sec := v.adminSec()
	i := v.sel - sec.m - sec.b
	if i < 0 || i >= len(v.transfers) {
		return
	}
	if !v.transfers[i].FromOwner {
		v.failStatus(Tr("st.notOwner"))
		return
	}
	v.fire(Tr("act.endorsed"), func() error { return v.app.ApproveTransfer(v.transfers[i].Msg.MsgID) })
}

func (v *viewModel) denyTransferID(msgID string) {
	if v.app == nil || msgID == "" {
		return
	}
	if err := v.app.RejectTransfer(msgID); err != nil {
		v.failStatus(Tf("st.denyFail", err))
		return
	}
	v.appendChat(chatLine{text: Tf("act.deniedLine", truncate(msgID, 10)), system: true})
	v.reloadTransfers()
}

// sendText 是聊天正文出站（v25：输入框永不解析斜杠命令，整行=正文）。
func (v *viewModel) sendText(text string) {
	if text == "" {
		return
	}
	if !v.hasPerm(core.PermSpeak) {
		v.failStatus(Tr("st.noSpeak"))
		return
	}
	v.input, v.cur, v.sel = nil, 0, 0
	msg := v.outboundDraft(text)
	v.seqNo++
	seq := v.seqNo
	v.appendChat(chatLine{text: FormatChatLine(msg), sender: v.selfPub(), meta: chatMeta(msg),
		body: chatBody(msg), seq: seq})
	desc := Tr("act.sent")
	if v.app == nil { // 离线预览：只回显，不出站
		return
	}
	v.async(func() []Event {
		if ack, ok := v.app.(TextIDAck); ok {
			id, err := ack.SendTextID(text)
			if err != nil {
				return []Event{SystemEvent{Note: v.fail(Tf("act.failed", desc, err))}}
			}
			return []Event{chatIDEvent{seq: seq, msgID: id}, SystemEvent{Note: Tf("act.submitted", desc)}}
		}
		if err := v.app.SendText(text); err != nil {
			return []Event{SystemEvent{Note: v.fail(Tf("act.failed", desc, err))}}
		}
		return []Event{SystemEvent{Note: Tf("act.submitted", desc)}}
	})
}

func (v *viewModel) toClipboard(s string) {
	if s == "" || v.copyText == nil {
		return
	}
	v.copyText(s)
	v.setStatus(Tr("st.copied"))
}
