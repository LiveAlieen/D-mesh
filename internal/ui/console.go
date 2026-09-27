// console.go：v27 无头命令调试前端。
//
// 定位：GUI 里的每个动作都住在同一张动作表上（actions.go 的 ActionID + exec）。
// 无头通道不另写一份业务调用，只做三件事——把命令行参数替代「对话框/选中行」的
// 输入、按 msg_id 把选中行定位好、执行同一个 exec 并取回回显。
// 于是「GUI 能点、无头跑不了」这类两侧漂移不可能出现
// （契约测试 TestBothSidesCoverEveryAction 钉死）。
//
// GUI 铁律不破（v25）：窗口内永不解析斜杠命令，本文件只被无头 stdin 通道调用。

package ui

import (
	"errors"
	"fmt"
	"strings"

	"dmesh/internal/core"
)

// Console 是无头命令通道的执行面。它持有一个不渲染的 viewModel：
// deliver 为 nil ⇒ 所有 job 同步跑完，结果立即可取（无 goroutine、无窗口）。
type Console struct {
	vm         *viewModel
	lastStatus string // 上次已报出的状态提示（避免同一句重复刷屏）
	err        string // 本次执行里 exec 抄送来的失败提示（"" = 没报错）
}

// NewConsole 以宿主 App 构造无头控制台。errSink 只在此接线：GUI 的 viewModel
// 永不带它，因此对窗口侧行为零影响。
func NewConsole(app App) *Console {
	c := &Console{vm: newViewModel(app)}
	c.vm.errSink = func(note string) { c.err = note }
	return c
}

// Out 是一条命令的完整回报。Kind 决定宿主 stdout 的前缀（沿用 v26 之前 E2E 已
// 依赖的 "[progress] "/"[audit] "/"[theme] " 口径）；Texts 是人类可读行；
// Err 非空即该命令未生效。Data 供 --json 输出结构化视图（可为 nil）。
type Out struct {
	Line   string      `json:"line"`
	Kind   string      `json:"kind"`
	Action ActionID    `json:"action,omitempty"`
	OK     bool        `json:"ok"`
	Err    string      `json:"err,omitempty"`
	Texts  []string    `json:"texts,omitempty"`
	Quit   bool        `json:"quit,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

// prepKind 是执行前需要「定位选中行」的类别——无头没有鼠标，按 msg_id 查表。
type prepKind int

const (
	prepNone prepKind = iota
	prepJoin
	prepTransfer
)

// plan 是一条命令的落点：触发动作（action）、只读回报（report），
// 或纯查询当前状态（两者皆空，如裸 /theme、/lang）。
type plan struct {
	action ActionID
	report string
	prep   prepKind
	ctx    actionCtx
}

// planFor 是命令 → 动作/回报的无头映射表。
func planFor(cmd Command) (plan, bool) {
	switch cmd.Kind {
	case CmdText:
		return plan{action: ActSend, ctx: actionCtx{text: cmd.Text}}, true
	case CmdHelp:
		return plan{action: ActHelp}, true
	case CmdClear:
		return plan{action: ActClear}, true
	case CmdQuit:
		return plan{action: ActQuit}, true
	case CmdHide:
		return plan{action: ActHide, ctx: actionCtx{msgID: cmd.MsgID}}, true
	case CmdAudit:
		return plan{action: ActAudit}, true
	case CmdRemove:
		return plan{action: ActLeave}, true
	case CmdKick:
		return plan{action: ActKick, ctx: actionCtx{pub: cmd.Target}}, true
	case CmdUnban:
		return plan{action: ActUnban, ctx: actionCtx{pub: cmd.Target}}, true
	case CmdPerms:
		return plan{action: ActPerms, ctx: actionCtx{pub: cmd.Target, perms: cmd.Perms}}, true
	case CmdGrantAdmin:
		return plan{action: ActGrant, ctx: actionCtx{pub: cmd.Target}}, true
	case CmdRevokeAdmin:
		return plan{action: ActRevoke, ctx: actionCtx{pub: cmd.Target}}, true
	case CmdTransfer:
		return plan{action: ActTransfer, ctx: actionCtx{pub: cmd.Target}}, true
	case CmdApprove:
		return plan{action: ActXferApprove, prep: prepTransfer, ctx: actionCtx{msgID: cmd.MsgID}}, true
	case CmdDeny:
		return plan{action: ActXferDeny, prep: prepTransfer, ctx: actionCtx{msgID: cmd.MsgID}}, true
	case CmdJoinApprove:
		return plan{action: ActJoinApprove, prep: prepJoin, ctx: actionCtx{msgID: cmd.MsgID}}, true
	case CmdJoinReject:
		return plan{action: ActJoinReject, prep: prepJoin, ctx: actionCtx{msgID: cmd.MsgID}}, true
	case CmdOfflineAfter:
		return plan{action: ActOfflineTune, ctx: actionCtx{ms: cmd.Millis}}, true
	case CmdSeedCheck:
		return plan{action: ActSeedCheck, ctx: actionCtx{path: cmd.Path}}, true
	case CmdNDUpload:
		return plan{action: ActNDUpload, ctx: actionCtx{path: cmd.Path}}, true
	case CmdNDDownload:
		return plan{action: ActNDDownload, ctx: actionCtx{name: cmd.Name, path: cmd.Path}}, true
	case CmdNDDelete:
		return plan{action: ActNDDelete, ctx: actionCtx{name: cmd.Name}}, true
	case CmdNDSet:
		return plan{action: ActNDQuota, ctx: actionCtx{mb: cmd.MB}}, true
	case CmdTheme:
		if cmd.Theme == "" {
			return plan{}, true // 裸查询
		}
		return plan{action: ActTheme, ctx: actionCtx{theme: cmd.Theme}}, true
	case CmdLang:
		if cmd.Lang == "" {
			return plan{}, true
		}
		return plan{action: ActLang, ctx: actionCtx{lang: cmd.Lang}}, true
	case CmdProgress:
		return plan{report: "progress"}, true
	case CmdTransfers:
		return plan{report: "transfers"}, true
	case CmdMembers:
		return plan{report: "members"}, true
	case CmdNetdisk, CmdNDStatus:
		return plan{report: "ndstatus"}, true
	}
	return plan{}, false
}

// guiOnly 是「只在窗口里成立」的动作及理由；契约测试据此放行，新增必须写理由。
var guiOnly = map[ActionID]string{
	ActSettings:     "设置浮层本身是窗口控件；其三项内容各有独立动作（theme/lang/offlineAfter），无头均可触发",
	ActCopy:         "复制正文到系统剪贴板——无头无 GUI 剪贴板语义",
	ActCopyPub:      "复制公钥到系统剪贴板，同上",
	ActAppealUnban:  "申诉面板里的「解禁」只是队列视图入口；同一出站动作无头经 /unban <pub> 直达",
	ActAppealIgnore: "申诉队列的本机视图出队，不产生任何网络事件；无头改读队列并按 /unban 处理",
	ActRefresh:      "重画当前面板——无头每条命令都现场取数，本就无需刷新",
}

// Run 执行一行输入（非 '/' 开头 = 发言）。
func (c *Console) Run(line string) Out {
	line = strings.TrimSpace(line)
	if line == "" {
		return Out{Kind: "err", Err: "empty input"}
	}
	cmd, err := ParseCommand(line)
	if err != nil {
		return Out{Line: line, Kind: "err", Err: err.Error()}
	}
	p, ok := planFor(cmd)
	if !ok {
		return Out{Line: line, Kind: "err", Err: fmt.Sprintf("no console plan for %q", line)}
	}
	v := c.vm

	switch {
	case p.report != "":
		texts, data, rerr := c.report(p.report)
		if rerr != nil {
			return Out{Line: line, Kind: "err", Err: rerr.Error()}
		}
		return Out{Line: line, Kind: p.report, OK: true, Texts: texts, Data: data}
	case p.action == "":
		return Out{Line: line, Kind: "state", OK: true, Texts: []string{c.stateLine(cmd)}}
	}

	if verr := verifyArgs(&p); verr != nil {
		return Out{Line: line, Kind: "err", Action: p.action, Err: verr.Error()}
	}
	if perr := c.prepare(&p); perr != nil {
		return Out{Line: line, Kind: "err", Action: p.action, Err: perr.Error()}
	}

	c.err = ""
	before := len(v.chat)
	v.exec(p.action, p.ctx)
	switch p.action {
	case ActNDUpload, ActNDDownload, ActNDDelete, ActNDQuota:
		v.refreshNetdisk() // GUI 靠事件泵刷新，无头在动作后显式补一次
	}
	o := Out{Line: line, Kind: "action", Action: p.action, Texts: c.drain(before), Quit: v.quit}
	o.OK = c.err == ""
	o.Err = c.err
	switch p.action {
	case ActNDUpload, ActNDDownload, ActNDDelete, ActNDQuota:
		o.Data = v.ndStatus
	}
	return o
}

// prepare 把「选中行」摆到命令参数所指的那一条（GUI 由鼠标点选，无头按 id 定位）。
// 队列一律现拉宿主为准：无头没有事件泵，vm 里的副本不可信。
func (c *Console) prepare(p *plan) error {
	v := c.vm
	switch p.prep {
	case prepJoin:
		v.setPanel(PanelJoin)
		v.reloadJoins()
		i, err := pickID(len(v.joinReqs), p.ctx.msgID, func(i int) string { return v.joinReqs[i].Msg.MsgID })
		if err != nil {
			return fmt.Errorf("join queue: %w", err)
		}
		v.sel = i
	case prepTransfer:
		v.setPanel(PanelAdmin)
		v.reloadTransfers()
		i, err := pickID(len(v.transfers), p.ctx.msgID, func(i int) string { return v.transfers[i].Msg.MsgID })
		if err != nil {
			return fmt.Errorf("transfer inbox: %w", err)
		}
		sec := v.adminSec()
		v.sel = sec.m + sec.b + i
		p.ctx.msgID = v.transfers[i].Msg.MsgID // latest/前缀 → 具体 id，exec 只认具体 id
	}
	return nil
}

// verifyArgs 把 exec 里「静默 no-op」的缺参情形提前报出来（调试通道要说清为什么没动）。
func verifyArgs(p *plan) error {
	c := p.ctx
	switch p.action {
	case ActSend:
		if strings.TrimSpace(c.text) == "" {
			return errors.New("empty message")
		}
	case ActHide, ActXferDeny:
		if c.msgID == "" {
			return errors.New("missing msg_id")
		}
	case ActKick, ActUnban, ActGrant, ActRevoke, ActTransfer:
		if c.pub.IsZero() {
			return errors.New("missing target pubkey")
		}
	case ActPerms:
		if c.pub.IsZero() {
			return errors.New("missing target pubkey")
		}
		if len(c.perms) == 0 {
			return errors.New("missing perm list")
		}
	case ActNDUpload, ActSeedCheck:
		if c.path == "" {
			return errors.New("missing path")
		}
	case ActNDDownload, ActNDDelete:
		if c.name == "" {
			return errors.New("missing file name")
		}
	case ActNDQuota:
		if !core.ValidNetdiskMB(c.mb) {
			return fmt.Errorf("quota out of range 0..%d MB: %d", core.NetdiskMaxMB, c.mb)
		}
	case ActOfflineTune:
		if c.ms <= 0 {
			return errors.New("offline-after must be > 0 ms")
		}
	}
	return nil
}

// drain 取回本次执行新产生的可见行与状态提示。
func (c *Console) drain(before int) []string {
	v := c.vm
	if before > len(v.chat) {
		before = 0 // /clear 之类把聊天流清空了，整份取回
	}
	var out []string
	for _, l := range v.chat[before:] {
		if !l.hidden {
			out = append(out, l.text)
		}
	}
	if s := v.status; s != "" && s != c.lastStatus {
		out = append(out, s)
		c.lastStatus = s
	}
	return out
}

// stateLine 回答「现在是什么」：无参数的 /theme、/lang。
func (c *Console) stateLine(cmd Command) string {
	switch cmd.Kind {
	case CmdTheme:
		return fmt.Sprintf("%s (available: %s)", GetTheme(), ThemeList())
	case CmdLang:
		return fmt.Sprintf("%s (available: %s)", GetLang(), LangList())
	}
	return ""
}

// report 是只读回报：不产生任何出站动作。
func (c *Console) report(kind string) ([]string, interface{}, error) {
	v := c.vm
	switch kind {
	case "progress":
		return ProgressLines(), nil, nil
	case "transfers":
		v.reloadTransfers()
		out := make([]string, 0, len(v.transfers))
		for _, prop := range v.transfers {
			out = append(out, FormatTransferLine(prop, v.currentTime()))
		}
		return out, v.transfers, nil
	case "members":
		v.refreshRoster()
		out := make([]string, 0, len(v.members)+len(v.banned)+1)
		out = append(out, fmt.Sprintf("members=%d banned=%d", len(v.members), len(v.banned)))
		for _, m := range v.members {
			online, self := "off", ""
			if m.Online {
				online = "on"
			}
			if m.IsSelf {
				self = " self"
			}
			out = append(out, fmt.Sprintf("%s %s %s alg=%s%s", ShortID(m.Entry.Pub), online,
				strings.Join(m.Entry.Perms, ","), m.Entry.Pub.Alg, self))
		}
		for _, b := range v.banned {
			out = append(out, fmt.Sprintf("banned %s alg=%s", ShortID(b.Pub), b.Pub.Alg))
		}
		return out, v.members, nil
	case "ndstatus":
		v.refreshNetdisk()
		if v.ndStatus == nil {
			return nil, nil, errors.New("netdisk disabled (netdisk_mb=0)")
		}
		st := *v.ndStatus
		out := []string{fmt.Sprintf("quota_mb=%d total=%d used=%d contributors=%d online_writable=%d degraded=%d",
			st.QuotaMB, st.TotalBytes, st.UsedBytes, len(st.Contributors), st.OnlineWritable, st.DegradedStripes)}
		if st.Note != "" {
			out = append(out, "note: "+st.Note)
		}
		for _, f := range v.ndFiles {
			healthy := "unhealthy"
			if f.Healthy {
				healthy = "ok"
			}
			out = append(out, fmt.Sprintf("file %s size=%d stripes=%d %s", f.Name, f.Size, f.Stripes, healthy))
		}
		return out, st, nil
	}
	return nil, nil, fmt.Errorf("unknown report %q", kind)
}

// pickID 在 n 条目的队列里按 "latest"/空/精确/唯一前缀 定位下标。
func pickID(n int, id string, at func(int) string) (int, error) {
	if n == 0 {
		return 0, errors.New("queue empty")
	}
	if id == "" || id == "latest" {
		return n - 1, nil
	}
	for i := 0; i < n; i++ {
		if at(i) == id {
			return i, nil
		}
	}
	var hits []int
	for i := 0; i < n; i++ {
		if strings.HasPrefix(at(i), id) {
			hits = append(hits, i)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return 0, fmt.Errorf("no id %q", id)
	default:
		return 0, fmt.Errorf("ambiguous id prefix %q (%d matches)", id, len(hits))
	}
}
