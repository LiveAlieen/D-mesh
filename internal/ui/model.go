package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"dmesh/internal/core"

	tea "github.com/charmbracelet/bubbletea"
)

// Panel 是当前活动面板。
type Panel int

const (
	PanelChat Panel = iota
	PanelMembers
	PanelJoin
	PanelAdmin
	PanelAppeals
	PanelNetdisk
	panelCount
)

func (p Panel) label() string {
	switch p {
	case PanelChat:
		return "chat"
	case PanelMembers:
		return "members"
	case PanelJoin:
		return "join"
	case PanelAdmin:
		return "admin"
	case PanelAppeals:
		return "appeals"
	case PanelNetdisk:
		return "netdisk"
	default:
		return "?"
	}
}

// panelNames 与 Panel 枚举一一对应（tab 循环顺序）。
var panelNames = [panelCount]string{"chat", "members", "join", "admin", "appeals", "netdisk"}

// evMsg 是宿主事件在 tea 消息管道里的载体。
type evMsg struct{ ev Event }

// noteMsg 是一次动作的结果提示（由 fire/seedCheck 等 tea.Cmd 产生）。它与
// evMsg 分开，避免在 Update 里被当作宿主事件重新 arm 事件泵造成泵堆积。
type noteMsg string

// auditMsg 承载 /audit 的多行摘要结果。
type auditMsg struct{ lines []string }

// promptState 是面板里的单行输入提示（/perms 目标、网盘文件名、种子路径等）。
type promptState struct {
	label  string
	action string // seedcheck|perms|upload|download|delete
	target core.PubKey
	value  string
}

// chatLine 是聊天流一行（支持 hide 软删除不显示）。
type chatLine struct {
	text   string
	msgID  string
	hidden bool
	system bool
}

// Model 是 bubbletea 根模型。now 可注入以便测试；app 允许为 nil（离线预览/单测）。
type Model struct {
	app    App
	panel  Panel
	width  int
	height int

	chat   []chatLine
	input  string
	status string

	members   []MemberRow
	banned    []core.BlacklistEntry
	joinReqs  []JoinRequest
	transfers []TransferProposal // 发给本机的待决 transfer 提案（v17①，join 面板展示）
	appeals   []core.Message
	sel       int

	prompt *promptState

	ndStatus *NetdiskStatus
	ndFiles  []NetdiskFile

	quitting bool
	now      func() time.Time
}

// 编译期确认 *Model 实现 tea.Model。
var _ tea.Model = (*Model)(nil)

// New 构造根模型。
func New(app App) *Model {
	return &Model{app: app, now: time.Now}
}

func (m *Model) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Init 启动事件泵。
func (m *Model) Init() tea.Cmd {
	return m.waitEvents()
}

func (m *Model) waitEvents() tea.Cmd {
	if m.app == nil {
		return nil
	}
	app := m.app
	return func() tea.Msg {
		// NextEvent 返回 nil 表示宿主关闭：以 evMsg{nil} 送达，Update 据此退出。
		return evMsg{app.NextEvent()}
	}
}

// Update 是 bubbletea 主循环的状态迁移；全部副作用走 tea.Cmd，
// 渲染层可被纯逻辑测试直接驱动。
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case evMsg:
		if msg.ev == nil {
			m.quitting = true
			return m, tea.Quit
		}
		m.handleEvent(msg.ev)
		return m, m.waitEvents()
	case noteMsg:
		m.appendChat(chatLine{text: "· " + string(msg), system: true})
		return m, nil
	case auditMsg:
		for _, l := range msg.lines {
			m.appendChat(chatLine{text: "· audit: " + l, system: true})
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// ---- 事件处理 ----

func (m *Model) handleEvent(ev Event) {
	switch e := ev.(type) {
	case TextEvent:
		m.appendChat(chatLine{text: FormatChatLine(e.Msg), msgID: e.Msg.MsgID})
	case AppealEvent:
		m.appeals = append(m.appeals, e.Msg)
		m.setStatus("new appeal from " + ShortID(e.Msg.Sender) + " (appeals panel)")
	case SystemEvent:
		m.appendChat(chatLine{text: "· " + e.Note, system: true})
	case RosterEvent:
		m.refreshRoster()
		if e.Note != "" {
			m.appendChat(chatLine{text: "· roster: " + e.Note, system: true})
		}
	case JoinReqEvent:
		m.upsertJoinReq(e.Req)
		m.setStatus("new join_req from " + ShortID(e.Req.Msg.Sender) + " (join panel: tab to it)")
	case TransferProposalEvent:
		m.upsertTransfer(e.Prop)
		m.appendChat(chatLine{text: "· transfer proposal from " + ShortID(e.Prop.Msg.Sender) +
			" — join panel (a/d) or /approve " + e.Prop.Msg.MsgID + " | /deny " + e.Prop.Msg.MsgID, system: true})
		m.setStatus("transfer proposal from " + ShortID(e.Prop.Msg.Sender) + " (join panel / approve with /approve)")
	case HideEvent:
		m.hideLine(e.MsgID)
	case NetdiskEvent:
		m.appendChat(chatLine{text: "· netdisk: " + e.Note, system: true})
		if m.panel == PanelNetdisk {
			m.refreshNetdisk()
		}
	}
}

func (m *Model) upsertJoinReq(req JoinRequest) {
	for i, r := range m.joinReqs {
		if r.Msg.MsgID == req.Msg.MsgID {
			m.joinReqs[i] = req
			return
		}
	}
	m.joinReqs = append(m.joinReqs, req)
}

func (m *Model) upsertTransfer(prop TransferProposal) {
	for i, p := range m.transfers {
		if p.Msg.MsgID == prop.Msg.MsgID {
			m.transfers[i] = prop
			return
		}
	}
	m.transfers = append(m.transfers, prop)
}

// reloadTransfers 从宿主拉取最新的待决 transfer 提案列表。
func (m *Model) reloadTransfers() {
	if m.app == nil {
		return
	}
	m.transfers = m.app.PendingTransfers()
}

func (m *Model) hideLine(msgID string) {
	for i := range m.chat {
		if m.chat[i].msgID == msgID {
			m.chat[i].hidden = true
		}
	}
}

func (m *Model) setStatus(f string, args ...any) {
	if len(args) > 0 {
		f = fmt.Sprintf(f, args...)
	}
	m.status = f
}

func (m *Model) appendChat(l chatLine) {
	m.chat = append(m.chat, l)
	if len(m.chat) > 2000 {
		m.chat = m.chat[len(m.chat)-1500:]
	}
}

func (m *Model) refreshRoster() {
	if m.app == nil || m.app.Roster() == nil {
		return
	}
	r := m.app.Roster()
	m.members = BuildMemberRows(r, m.app.Self(), m.currentTime())
	_, banned, _ := r.Snapshot()
	m.banned = banned
	if m.sel >= len(m.members)+len(m.banned) {
		m.sel = 0
	}
}

// reloadJoins 同步入群面板两节队列（join_req + transfer 提案，宿主为事实源）。
func (m *Model) reloadJoins() {
	if m.app == nil {
		return
	}
	m.joinReqs = m.app.PendingJoins()
	m.transfers = m.app.PendingTransfers()
	if m.sel >= len(m.joinReqs)+len(m.transfers) {
		m.sel = max0(len(m.joinReqs) + len(m.transfers) - 1)
	}
}

func (m *Model) refreshNetdisk() {
	if m.app == nil {
		return
	}
	nd := m.app.Netdisk()
	if nd == nil {
		m.ndStatus, m.ndFiles = nil, nil
		return
	}
	if st, err := nd.Status(); err == nil {
		m.ndStatus = &st
	} else {
		m.setStatus("netdisk status: %v", err)
	}
	if fs, err := nd.List(); err == nil {
		m.ndFiles = fs
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// ---- 按键处理 ----

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// 全局退出
	if msg.Type == tea.KeyCtrlC {
		m.quitting = true
		return m, tea.Quit
	}

	if m.prompt != nil {
		return m.handlePromptKey(msg)
	}

	switch msg.Type {
	case tea.KeyTab:
		m.setPanel((m.panel + 1) % panelCount)
		return m, nil
	case tea.KeyShiftTab:
		m.setPanel((m.panel + panelCount - 1) % panelCount)
		return m, nil
	case tea.KeyEscape:
		if m.panel != PanelChat {
			m.setPanel(PanelChat)
			return m, nil
		}
		m.input = ""
		return m, nil
	case tea.KeyRunes:
		// 聊天面板且输入为空时，数字 1..6 直切面板
		if m.panel == PanelChat && m.input == "" && len(msg.Runes) == 1 {
			d := msg.Runes[0]
			if d >= '1' && d <= '0'+rune(panelCount) {
				m.setPanel(Panel(d - '1'))
				return m, nil
			}
		}
	}

	if m.panel == PanelChat {
		return m.handleChatKey(msg)
	}
	return m.handlePanelKey(msg)
}

func (m *Model) setPanel(p Panel) {
	m.panel = p
	m.sel = 0
	switch p {
	case PanelMembers, PanelAdmin:
		m.refreshRoster()
	case PanelJoin:
		m.reloadJoins()
	case PanelNetdisk:
		m.refreshNetdisk()
	}
}

func (m *Model) handleChatKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		line := m.input
		m.input = ""
		if strings.TrimSpace(line) == "" {
			return m, nil
		}
		cmd, err := ParseCommand(line)
		if err != nil {
			m.setStatus("input error: %v", err)
			return m, nil
		}
		return m.dispatch(cmd)
	case tea.KeyBackspace:
		r := []rune(m.input)
		if len(r) > 0 {
			m.input = string(r[:len(r)-1])
		}
		return m, nil
	case tea.KeyRunes:
		m.input += string(msg.Runes)
		return m, nil
	case tea.KeySpace:
		m.input += " "
		return m, nil
	default:
		return m, nil
	}
}

func (m *Model) handlePanelKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	// 导航
	switch key {
	case "up", "k":
		if m.sel > 0 {
			m.sel--
		}
		return m, nil
	case "down", "j":
		if m.sel < m.panelRows()-1 {
			m.sel++
		}
		return m, nil
	case "q":
		m.setPanel(PanelChat)
		return m, nil
	case "r":
		m.setPanel(m.panel) // 重进即刷新
		return m, nil
	}
	if m.panel == PanelChat {
		return m, nil
	}
	return m.handlePanelAction(key)
}

// panelRows 是当前面板可选行数。
func (m *Model) panelRows() int {
	switch m.panel {
	case PanelMembers:
		return len(m.members)
	case PanelAdmin:
		return len(m.members) + len(m.banned)
	case PanelJoin:
		return len(m.joinReqs) + len(m.transfers)
	case PanelAppeals:
		return len(m.appeals)
	default:
		return 0
	}
}

func (m *Model) handlePanelAction(key string) (tea.Model, tea.Cmd) {
	switch m.panel {
	case PanelMembers:
		// 成员面板只读展示；无动作
	case PanelJoin:
		return m.joinAction(key)
	case PanelAdmin:
		return m.adminAction(key)
	case PanelAppeals:
		return m.appealAction(key)
	case PanelNetdisk:
		return m.netdiskAction(key)
	}
	return m, nil
}

// ---- 入群面板动作 ----

func (m *Model) selectedJoin() (JoinRequest, bool) {
	if m.panel == PanelJoin && m.sel < len(m.joinReqs) {
		return m.joinReqs[m.sel], true
	}
	return JoinRequest{}, false
}

// selectedTransfer 返回入群面板第二行（transfer 提案节）的选中项。
func (m *Model) selectedTransfer() (TransferProposal, bool) {
	if m.panel != PanelJoin {
		return TransferProposal{}, false
	}
	i := m.sel - len(m.joinReqs)
	if i >= 0 && i < len(m.transfers) {
		return m.transfers[i], true
	}
	return TransferProposal{}, false
}

func (m *Model) joinAction(key string) (tea.Model, tea.Cmd) {
	// 队列宿主所有（PendingJoins 是唯一事实源）：动作前先 reload，否则
	// 种子核对通过后（宿主把 SeedOK 翻转为 true）面板仍拿着旧的本地副本，
	// 「核对通过才准签 join」的门控会永久卡住批准。reloadJoins 只同步
	// 副本与越界的 sel，不改宿主状态，对 d/s 同样安全。
	m.reloadJoins()
	// 面板两节：先 join_req 后 transfer 提案（v17①）。
	if prop, ok := m.selectedTransfer(); ok {
		return m.transferAction(key, prop)
	}
	req, ok := m.selectedJoin()
	if !ok {
		return m, nil
	}
	switch key {
	case "a": // 核对通过后签 join 广播
		if !req.SeedOK {
			m.setStatus("seed hash not verified for %s — press s to check the seed file first", ShortID(req.Msg.Sender))
			return m, nil
		}
		if m.app == nil {
			return m, nil
		}
		return m, m.fire(func() error { return m.app.ApproveJoin(req.Msg.MsgID) }, "join signed & broadcast")
	case "d": // 拒绝（仅本地出队，不广播）
		if m.app != nil {
			if err := m.app.RejectJoin(req.Msg.MsgID); err != nil {
				m.setStatus("reject failed: %v", err)
			} else {
				m.reloadJoins()
			}
		}
	case "s": // 核对种子文件哈希（申请人递交或线下拿到的种子路径）
		m.prompt = &promptState{label: "seed file path to verify", action: "seedcheck", target: req.Msg.Sender}
	}
	return m, nil
}

// transferAction 处理 transfer 提案节（v17①）：
//   - a：对本机收到的同一份原文补上联署（EndorseSig）并广播生效
//   - d：拒绝——宿主仅本地丢弃，绝不转发、不产生任何事件
func (m *Model) transferAction(key string, prop TransferProposal) (tea.Model, tea.Cmd) {
	if m.app == nil {
		return m, nil
	}
	switch key {
	case "a":
		if !prop.FromOwner {
			m.setStatus("proposal signer is not current owner/creator — refusing to endorse")
			return m, nil
		}
		return m, m.fire(func() error { return m.app.ApproveTransfer(prop.Msg.MsgID) },
			"transfer endorsed & broadcast")
	case "d":
		if err := m.app.RejectTransfer(prop.Msg.MsgID); err != nil {
			m.setStatus("deny failed: %v", err)
			return m, nil
		}
		m.appendChat(chatLine{text: "· transfer proposal " + truncate(prop.Msg.MsgID, 10) + " denied (dropped locally, never forwarded)", system: true})
		m.reloadJoins()
	}
	return m, nil
}

// ---- 群管面板动作 ----

// adminSel 返回选中项：先成员后黑名单，kind: member|banned。
func (m *Model) adminSel() (kind string, pub core.PubKey, ok bool) {
	if m.sel < len(m.members) {
		return "member", m.members[m.sel].Entry.Pub, true
	}
	i := m.sel - len(m.members)
	if i < len(m.banned) {
		return "banned", m.banned[i].Pub, true
	}
	return "", core.PubKey{}, false
}

func (m *Model) adminAction(key string) (tea.Model, tea.Cmd) {
	kind, pub, ok := m.adminSel()
	if !ok {
		return m, nil
	}
	if m.app == nil {
		return m, nil
	}
	switch {
	case key == "K" && kind == "member":
		return m, m.fire(func() error { return m.app.Kick(pub) }, "kick event")
	case (key == "U" || key == "u") && kind == "banned":
		return m, m.fire(func() error { return m.app.Unban(pub) }, "unban event")
	case key == "P" && kind == "member":
		m.prompt = &promptState{label: "new perms for " + ShortID(pub) + " (csv)", action: "perms", target: pub}
	case key == "G" && kind == "member":
		return m, m.fire(func() error { return m.app.GrantAdmin(pub) }, "grant_admin event")
	case key == "R" && kind == "member":
		return m, m.fire(func() error { return m.app.RevokeAdmin(pub) }, "revoke_admin event")
	case key == "T" && kind == "member":
		return m, m.fire(func() error { return m.app.Transfer(pub) }, "transfer event (needs new owner endorse)")
	}
	return m, nil
}

// ---- 申诉面板动作 ----

func (m *Model) appealAction(key string) (tea.Model, tea.Cmd) {
	if m.sel >= len(m.appeals) {
		return m, nil
	}
	msg := m.appeals[m.sel]
	switch key {
	case "u": // 接受申诉：签 unban
		if m.app == nil {
			return m, nil
		}
		return m, m.fire(func() error { return m.app.Unban(msg.Sender) }, "unban event")
	}
	return m, nil
}

// ---- 网盘面板动作 ----

func (m *Model) netdiskAction(key string) (tea.Model, tea.Cmd) {
	if m.app == nil {
		return m, nil
	}
	switch key {
	case "U":
		m.prompt = &promptState{label: "upload local path", action: "upload"}
	case "D":
		m.prompt = &promptState{label: "download file name", action: "download"}
	case "X":
		m.prompt = &promptState{label: "delete file name", action: "delete"}
	}
	return m, nil
}

// ---- 提示行（prompt）处理 ----

func (m *Model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := m.prompt
	switch msg.Type {
	case tea.KeyEnter:
		m.prompt = nil
		return m.runPrompt(p)
	case tea.KeyEscape:
		m.prompt = nil
		m.setStatus("cancelled")
		return m, nil
	case tea.KeyBackspace:
		r := []rune(p.value)
		if len(r) > 0 {
			p.value = string(r[:len(r)-1])
		}
	case tea.KeyRunes:
		p.value += string(msg.Runes)
	case tea.KeySpace:
		p.value += " "
	}
	return m, nil
}

func (m *Model) runPrompt(p *promptState) (tea.Model, tea.Cmd) {
	v := strings.TrimSpace(p.value)
	if v == "" {
		m.setStatus("empty input, cancelled")
		return m, nil
	}
	switch p.action {
	case "seedcheck":
		return m, m.seedCheckCmd(v, p.target)
	case "perms":
		perms, err := ParsePermList(v)
		if err != nil {
			m.setStatus("perms error: %v", err)
			return m, nil
		}
		return m, m.fire(func() error { return m.app.SetPerms(p.target, perms) }, "perms event")
	case "upload":
		return m, m.ndFire(func(nd Netdisk) error { return nd.Upload(v) }, "upload "+v)
	case "download":
		return m, m.ndFire(func(nd Netdisk) error { return nd.Download(v, v) }, "download "+v)
	case "delete":
		return m, m.ndFire(func(nd Netdisk) error { return nd.Delete(v) }, "delete "+v)
	}
	return m, nil
}

// mustND 返回网盘门面；未接线/关闭时返回 nil（调用方判空）。
func mustND(a App) Netdisk {
	if a == nil {
		return nil
	}
	return a.Netdisk()
}

// ndFire 对网盘动作做统一的「未启用」防护。
func (m *Model) ndFire(fn func(Netdisk) error, desc string) tea.Cmd {
	nd := mustND(m.app)
	if nd == nil {
		m.setStatus("netdisk not available (quota 0 or backend not wired)")
		return nil
	}
	return m.fire(func() error { return fn(nd) }, desc)
}

// seedCheckCmd 核对种子文件：重算 group_id + 验 creator_sig（有效种子只有
// 创建者能签）。对申请人递交的种子（target 非空）要求其中间身份与 target 一致
// 之外的深层核对由宿主 ApproveJoin 完成，这里给操作者呈现结论。
func (m *Model) seedCheckCmd(path string, applicant core.PubKey) tea.Cmd {
	return func() tea.Msg {
		raw, err := os.ReadFile(path)
		if err != nil {
			return noteMsg("seedcheck: " + err.Error())
		}
		var want [32]byte
		if m.app != nil {
			want = m.app.GroupID()
		}
		cfg, match, err := CheckSeedBytes(raw, want)
		if err != nil {
			return noteMsg("seedcheck REJECTED: " + err.Error())
		}
		if !match {
			return noteMsg("seedcheck: valid seed (" + cfg.Name + ") but NOT this group")
		}
		if applicant.IsZero() {
			return noteMsg("seedcheck OK: " + cfg.Name + " (mode=" + cfg.Mode + ")")
		}
		return noteMsg(fmt.Sprintf("seedcheck OK for req from %s: group=%s mode=%s — press a to sign join",
			ShortID(applicant), cfg.Name, cfg.Mode))
	}
}

// ---- 出站命令派发（聊天流输入）----

func (m *Model) dispatch(c Command) (tea.Model, tea.Cmd) {
	if c.Kind == CmdText && !m.hasPerm(core.PermSpeak) {
		m.setStatus("no speak permission on this group (or not a member)")
		return m, nil
	}
	switch c.Kind {
	case CmdHelp:
		m.appendChat(chatLine{text: helpText, system: true})
	case CmdClear:
		m.chat = nil
	case CmdQuit:
		m.quitting = true
		return m, tea.Quit
	case CmdText:
		m.appendChat(chatLine{text: FormatChatLine(m.outboundDraft(c.Text))})
		return m, m.fire(func() error { return m.app.SendText(c.Text) }, "sent")
	case CmdHide:
		m.hideLine(c.MsgID)
		return m, m.fire(func() error { return m.app.Hide(c.MsgID) }, "hide")
	case CmdAudit:
		return m.auditCmd()
	case CmdRemove:
		return m, m.fire(func() error { return m.app.Leave() }, "remove(leave) signed")
	case CmdKick:
		return m, m.fire(func() error { return m.app.Kick(c.Target) }, "kick")
	case CmdUnban:
		return m, m.fire(func() error { return m.app.Unban(c.Target) }, "unban")
	case CmdPerms:
		return m, m.fire(func() error { return m.app.SetPerms(c.Target, c.Perms) }, "perms")
	case CmdGrantAdmin:
		return m, m.fire(func() error { return m.app.GrantAdmin(c.Target) }, "grant_admin")
	case CmdRevokeAdmin:
		return m, m.fire(func() error { return m.app.RevokeAdmin(c.Target) }, "revoke_admin")
	case CmdTransfer:
		return m, m.fire(func() error { return m.app.Transfer(c.Target) }, "transfer")
	case CmdApprove:
		return m, m.fire(func() error { return m.app.ApproveTransfer(c.MsgID) },
			"transfer endorsed & broadcast")
	case CmdDeny:
		if m.app == nil {
			return m, nil
		}
		if err := m.app.RejectTransfer(c.MsgID); err != nil {
			m.setStatus("deny failed: %v", err)
			return m, nil
		}
		m.appendChat(chatLine{text: "· transfer proposal " + truncate(c.MsgID, 10) + " denied (dropped locally, never forwarded)", system: true})
		m.reloadJoins()
	case CmdTransfers:
		return m, m.listTransfersCmd()
	case CmdOfflineAfter:
		return m, m.fire(func() error { return m.app.SetOfflineAfter(c.Millis) }, "presence threshold update")
	case CmdSeedCheck:
		return m, m.seedCheckCmd(c.Path, core.PubKey{})
	case CmdNetdisk, CmdNDStatus:
		m.setPanel(PanelNetdisk)
	case CmdNDUpload:
		return m, m.ndFire(func(nd Netdisk) error { return nd.Upload(c.Path) }, "upload "+c.Path)
	case CmdNDDownload:
		return m, m.ndFire(func(nd Netdisk) error { return nd.Download(c.Name, c.Name) }, "download "+c.Name)
	case CmdNDDelete:
		return m, m.ndFire(func(nd Netdisk) error { return nd.Delete(c.Name) }, "delete "+c.Name)
	case CmdNDSet:
		return m, m.fire(func() error { return m.app.SetNetdiskMB(c.MB) }, fmt.Sprintf("netdisk quota -> %d MB", c.MB))
	}
	return m, nil
}

// listTransfersCmd 列出本机待决的 transfer 联署提案（/transfers）。
func (m *Model) listTransfersCmd() tea.Cmd {
	if m.app == nil {
		return nil
	}
	app := m.app
	return func() tea.Msg {
		props := app.PendingTransfers()
		if len(props) == 0 {
			return noteMsg("transfer proposals: none pending")
		}
		now := m.currentTime()
		var b strings.Builder
		fmt.Fprintf(&b, "transfer proposals (%d):\n", len(props))
		for _, p := range props {
			b.WriteString("  " + FormatTransferLine(p, now) + "\n")
		}
		b.WriteString("  /approve <msg_id|latest|唯一前缀> · /deny <same>")
		return noteMsg(strings.TrimRight(b.String(), "\n"))
	}
}

func (m *Model) auditCmd() (tea.Model, tea.Cmd) {
	if m.app == nil {
		return m, nil
	}
	return m, func() tea.Msg {
		lines, err := m.app.Audit()
		if err != nil {
			return noteMsg("audit failed: " + err.Error())
		}
		return auditMsg{lines: lines}
	}
}

func (m *Model) hasPerm(perm string) bool {
	if m.app == nil || m.app.Roster() == nil {
		return true // 离线预览/单测：不拦截
	}
	return m.app.Roster().HasPerm(m.app.Self(), perm)
}

func (m *Model) fire(fn func() error, desc string) tea.Cmd {
	if m.app == nil {
		return nil
	}
	return func() tea.Msg {
		if err := fn(); err != nil {
			return noteMsg(desc + " failed: " + err.Error())
		}
		return noteMsg(desc + " submitted")
	}
}

// outboundDraft 只是本地回显形态（真实 sig 由宿主完成）。
func (m *Model) outboundDraft(text string) core.Message {
	var sig core.Signer
	if m.app != nil {
		sig = m.app.Signer()
	}
	self := core.PubKey{}
	if sig != nil {
		self = sig.Pub()
	}
	return core.Message{Sender: self, TSms: m.currentTime().UnixMilli(), Type: core.TypeText, Content: []byte(text)}
}

// ---- 渲染 ----

func (m *Model) View() string {
	if m.quitting {
		return "bye\n"
	}
	var b strings.Builder
	b.WriteString(m.header())
	body := m.body()
	b.WriteString(body)
	b.WriteString("\n")
	if m.prompt != nil {
		b.WriteString(styleStatus.Render(m.prompt.label+": ") + m.prompt.value)
	} else if m.panel == PanelChat {
		b.WriteString("> " + m.input)
	}
	b.WriteString("\n")
	b.WriteString(styleStatus.Render(" " + strings.TrimSuffix(m.statusLine(), "\n")))
	return b.String()
}

func (m *Model) statusLine() string {
	if m.status != "" {
		return m.status
	}
	return fmt.Sprintf("tab=switch panel [%s] · 1..6 jump · ctrl+c quit · /help for commands", m.panel.label())
}

func (m *Model) header() string {
	tabs := make([]string, 0, panelCount)
	for i := Panel(0); i < panelCount; i++ {
		n := fmt.Sprintf("%d:%s", int(i)+1, panelNames[i])
		if i == m.panel {
			tabs = append(tabs, styleHeader.Render("["+n+"]"))
		} else {
			tabs = append(tabs, styleDim.Render(n))
		}
	}
	return strings.Join(tabs, " ") + "\n"
}

func (m *Model) body() string {
	switch m.panel {
	case PanelChat:
		return m.chatView()
	case PanelMembers:
		return m.membersView()
	case PanelJoin:
		return m.joinView()
	case PanelAdmin:
		return m.adminView()
	case PanelAppeals:
		return m.appealsView()
	case PanelNetdisk:
		return m.netdiskView()
	}
	return ""
}

func (m *Model) visibleHeight() int {
	h := m.height - 5 // header + input + status + margins
	if h < 3 {
		h = 3
	}
	return h
}

func (m *Model) chatView() string {
	var lines []string
	for _, l := range m.chat {
		if l.hidden {
			continue
		}
		if l.system {
			lines = append(lines, styleSystem.Render(l.text))
		} else {
			lines = append(lines, l.text)
		}
	}
	lim := m.visibleHeight()
	if len(lines) > lim {
		lines = lines[len(lines)-lim:]
	}
	return strings.Join(lines, "\n")
}

func (m *Model) membersView() string {
	m.refreshRoster()
	rows := m.members
	lines := RenderMemberLinesStyled(rows, m.currentTime())
	if len(lines) == 0 {
		lines = []string{"(no members)"}
	}
	return strings.Join(trimTo(lines, m.visibleHeight()), "\n")
}

func (m *Model) joinView() string {
	m.reloadJoins()
	var lines []string
	lines = append(lines, styleHeader.Render("join_req queue (carry holders sign join; applicant self-sigs are always invalid)"))
	if len(m.joinReqs) == 0 {
		lines = append(lines, "  (empty)")
	}
	for i, req := range m.joinReqs {
		mark := "  "
		if i == m.sel {
			mark = "> "
		}
		line := mark + FormatJoinLine(req, m.currentTime())
		if req.SeedOK {
			line = styleOnline.Render(line)
		}
		lines = append(lines, line)
	}
	if len(m.joinReqs) > 0 {
		lines = append(lines, styleDim.Render("  a=approve(sign join) d=deny s=check seed file · seed must hash-match genesis (creator-signed only)"))
	}
	// transfer 联署提案节（v17①）：定向发给本机、尚缺本机 endorse_sig 的原文。
	lines = append(lines, styleHeader.Render("transfer proposals addressed to me (a=endorse+broadcast, d=deny)"))
	if len(m.transfers) == 0 {
		lines = append(lines, "  (empty)")
	}
	for i, prop := range m.transfers {
		mark := "  "
		if len(m.joinReqs)+i == m.sel {
			mark = "> "
		}
		line := mark + FormatTransferLine(prop, m.currentTime())
		if prop.FromOwner {
			line = styleOnline.Render(line)
		} else {
			line = styleBad.Render(line)
		}
		lines = append(lines, line)
	}
	if len(m.transfers) > 0 {
		lines = append(lines, styleDim.Render("  a=endorse the exact proposal & broadcast d=drop (never forwarded) · green signer = current owner/creator"))
	}
	return strings.Join(trimTo(lines, m.visibleHeight()), "\n")
}

func (m *Model) adminView() string {
	m.refreshRoster()
	var lines []string
	lines = append(lines, styleHeader.Render("members (K=kick U=unban(banned) P=perms G=grant-admin R=revoke-admin T=transfer)"))
	for i, l := range RenderMemberLinesStyled(m.members, m.currentTime()) {
		mark := "  "
		if i == m.sel {
			mark = "> "
		}
		lines = append(lines, mark+l)
	}
	if len(m.banned) > 0 {
		lines = append(lines, styleBad.Render("blacklist (kicked — appeal channel only reaches unban-authorized members):"))
		for i, l := range RenderBannedLines(m.banned, m.currentTime(), true) {
			mark := "  "
			if len(m.members)+i == m.sel {
				mark = "> "
			}
			lines = append(lines, mark+l)
		}
	}
	return strings.Join(trimTo(lines, m.visibleHeight()), "\n")
}

func (m *Model) appealsView() string {
	var lines []string
	lines = append(lines, styleHeader.Render("directed appeals from blacklisted members (u = sign unban, ignore = silence)"))
	if len(m.appeals) == 0 {
		lines = append(lines, "  (none)")
	}
	for i, a := range m.appeals {
		mark := "  "
		if i == m.sel {
			mark = "> "
		}
		lines = append(lines, mark+FormatChatLine(a))
	}
	return strings.Join(trimTo(lines, m.visibleHeight()), "\n")
}

func (m *Model) netdiskView() string {
	m.refreshNetdisk()
	if m.ndStatus == nil {
		return "(netdisk unavailable — group quota 0 or backend not wired)"
	}
	return strings.Join(trimTo(RenderNetdiskLines(*m.ndStatus, m.ndFiles), m.visibleHeight()), "\n")
}

func trimTo(lines []string, n int) []string {
	if len(lines) > n {
		return lines[:n]
	}
	return lines
}

const helpText = `commands:
  <text>                     send chat message (speak perm required)
  /hide <msg_id>             soft-delete a message you sent (hide event)
  /audit                     on-demand multi-source consistency check
  /remove                    leave group (self-signed remove; not blacklisted)
  /kick <pub>                explicit kick event -> member removed + blacklisted
  /unban <pub>               lift a blacklist entry
  /perms <pub> <p1,p2,...>   set perms (signer must outrank target)
  /grant-admin <pub> /revoke-admin <pub> /transfer <pub>
  /transfers               list transfer endorsement proposals addressed to me
  /approve <id|latest>     endorse a transfer proposal (same bytes) + broadcast
  /deny <id|latest>        drop a transfer proposal (never forwarded)
  /offline-after <ms>        self presence threshold (v13.1)
  /seedcheck <path>          verify seed file: recompute group_id + creator_sig
  /netdisk                   open netdisk panel
  /netdisk upload <path> | download <name> | delete <name> | set <MB>
  /help /clear /quit         misc
  pub forms: ed25519:<hex> or bare <hex> (defaults ed25519)
panels: tab/shift-tab cycle; chat members join admin appeals netdisk`
