// dialog.go：v25 模态浮层（对话框）状态机——把「打字下命令」换成「填表单」。
//
// 五种表单覆盖原先全部需要参数的命令：确认框（confirm）、单行文本（text）、
// 数字（number）、单选（choice）、多选勾选（checks）。浮层吃键盘输入，
// Esc 关最上层；提交一律回到 actions.go 的 exec，出站仍走 ui.App 门面。

package ui

import (
	"strconv"
	"strings"

	"dmesh/internal/core"
)

type dialogKind int

const (
	dlgConfirm dialogKind = iota
	dlgText
	dlgNumber
	dlgChoice
	dlgChecks
)

// dialogItem 是 choice/checks 表单里的一行。
type dialogItem struct {
	Label   string
	Key     string
	Checked bool
}

// dialog 是当前打开的模态表单。
type dialog struct {
	kind  dialogKind
	title string
	note  string
	value string // text/number 的编辑内容
	cur   int    // value 光标（rune 下标）
	items []dialogItem
	sel   int
	act   ActionID
	ctx   actionCtx
}

// confirmKeys 是「点击先确认」的动作集与其文案键。
var confirmKeys = map[ActionID]string{
	ActLeave:    "gui.leaveConfirm",
	ActClear:    "gui.clearConfirm",
	ActKick:     "gui.kickConfirm",
	ActTransfer: "gui.transferConfirm",
	ActNDDelete: "gui.deleteConfirm",
	ActHide:     "gui.hideConfirm",
}

func confirmText(id ActionID) string {
	if k, ok := confirmKeys[id]; ok {
		return Tr(k)
	}
	return ""
}

func actAsk(id ActionID, label string) Action {
	return Action{ID: id, Label: label, Enabled: true, Confirm: confirmText(id)}
}

func dlgOf(kind dialogKind, title string, id ActionID, c actionCtx) *dialog {
	return &dialog{kind: kind, title: title, act: id, ctx: c, cur: 0}
}

// dialogFor 返回该动作的参数/确认表单；nil = 无需参数，直接执行。
func (v *viewModel) dialogFor(id ActionID, c actionCtx) *dialog {
	if s := confirmText(id); s != "" {
		d := dlgOf(dlgConfirm, Tr("gui."+string(id)), id, c)
		d.note = s
		return d
	}
	switch id {
	case ActPerms:
		d := dlgOf(dlgChecks, Tr("dialog.permsTitle"), id, c)
		for _, p := range core.AllPerms {
			d.items = append(d.items, dialogItem{Label: Tr("perm." + p), Key: p, Checked: has(c.perms, p)})
		}
		d.note = Tr("dialog.permsNote")
		return d
	case ActTheme:
		d := dlgOf(dlgChoice, Tr("dialog.themeTitle"), id, c)
		for _, t := range SupportedThemes() {
			d.items = append(d.items, dialogItem{Label: string(t), Key: string(t), Checked: string(t) == string(GetTheme())})
		}
		d.sel = d.checked()
		return d
	case ActLang:
		d := dlgOf(dlgChoice, Tr("dialog.langTitle"), id, c)
		for _, l := range SupportedLangs() {
			d.items = append(d.items, dialogItem{Label: Tr("lang." + string(l)), Key: string(l), Checked: string(l) == string(GetLang())})
		}
		d.sel = d.checked()
		return d
	case ActOfflineTune:
		d := dlgOf(dlgNumber, Tr("dialog.offlineTitle"), id, c)
		d.note = Tr("dialog.offlineNote")
		return d
	case ActNDQuota:
		d := dlgOf(dlgNumber, Tr("dialog.quotaTitle"), id, c)
		if v.ndStatus != nil {
			d.value = strconv.Itoa(v.ndStatus.QuotaMB)
			d.cur = len([]rune(d.value))
		}
		d.note = Tf("dialog.quotaNote", core.NetdiskMinMB, core.NetdiskMaxMB)
		return d
	case ActNDUpload:
		return v.pathDialog(Tr("dialog.uploadTitle"), id, c)
	case ActSeedCheck:
		return v.pathDialog(Tr("dialog.seedTitle"), id, c)
	}
	return nil
}

// pathDialog 走原生文件选择框；宿主未注入选择能力时回退为手输路径文本框。
func (v *viewModel) pathDialog(title string, id ActionID, c actionCtx) *dialog {
	if v.pickFile != nil {
		v.pickFile(title, func(path string) {
			c.path = path
			v.exec(id, c)
		})
		return nil
	}
	d := dlgOf(dlgText, title, id, c)
	d.note = Tr("dialog.pathNote")
	return d
}

// settingsDialog 是「设置」入口：列出可切换的界面项。
func (v *viewModel) settingsDialog() *dialog {
	d := dlgOf(dlgChoice, Tr("gui.settings"), ActSettings, actionCtx{})
	d.items = []dialogItem{
		{Label: Tr("dialog.themeTitle"), Key: string(ActTheme)},
		{Label: Tr("dialog.langTitle"), Key: string(ActLang)},
		{Label: Tr("dialog.offlineTitle"), Key: string(ActOfflineTune)},
	}
	return d
}

func (d *dialog) checked() int {
	for i, it := range d.items {
		if it.Checked {
			return i
		}
	}
	return 0
}

// ---- 对外访问（game 绘制用）----

// Dialog 返回当前模态表单（nil = 未打开）。
func (v *viewModel) Dialog() *dialog { return v.dlg }

// DialogKind 是表单类型（game 据此选择绘制方式）。
func (d *dialog) Kind() dialogKind { return d.kind }

// DialogTitle/DialogNote 是标题与说明文字。
func (d *dialog) DialogTitle() string { return d.title }
func (d *dialog) DialogNote() string  { return d.note }

// DialogValue 是 text/number 的编辑内容与光标。
func (d *dialog) DialogValue() (string, int) { return d.value, d.cur }

// DialogItems 是 choice/checks 的行。
func (d *dialog) DialogItems() []dialogItem { return d.items }

// DialogSel 是键盘高亮行。
func (d *dialog) DialogSel() int { return d.sel }

// DialogEditable 报告键盘此刻该不该往表单里打字。
func (d *dialog) DialogEditable() bool {
	return d.kind == dlgText || d.kind == dlgNumber
}

// ---- 交互 ----

func (d *dialog) insert(s string) {
	if d.kind == dlgNumber {
		s = strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, s)
	}
	r := []rune(d.value)
	out := append([]rune{}, r[:d.cur]...)
	out = append(out, []rune(s)...)
	out = append(out, r[d.cur:]...)
	d.value, d.cur = string(out), d.cur+len([]rune(s))
}

// dialogInput 往表单里插入可打印字符。
func (v *viewModel) dialogInput(r rune) {
	d := v.dlg
	if d == nil || !d.DialogEditable() || r < 0x20 {
		return
	}
	d.insert(string(r))
}

// dialogKey 处理表单里的特殊键。
func (v *viewModel) dialogKey(k Key) {
	d := v.dlg
	if d == nil {
		return
	}
	switch k {
	case KeyEscape:
		v.DialogCancel()
	case KeyEnter:
		v.DialogAccept()
	case KeyBackspace:
		r := []rune(d.value)
		if d.DialogEditable() && d.cur > 0 {
			d.value = string(r[:d.cur-1]) + string(r[d.cur:])
			d.cur--
		}
	case KeyDelete:
		r := []rune(d.value)
		if d.DialogEditable() && d.cur < len(r) {
			d.value = string(r[:d.cur]) + string(r[d.cur+1:])
		}
	case KeyLeft:
		if d.cur > 0 {
			d.cur--
		}
	case KeyRight:
		if n := len([]rune(d.value)); d.cur < n {
			d.cur++
		}
	case KeyUp:
		v.DialogMove(-1)
	case KeyDown:
		v.DialogMove(1)
	}
}

// DialogMove 在 choice/checks 行与「确定/取消」按钮间移动高亮。
func (v *viewModel) DialogMove(dn int) {
	d := v.dlg
	if d == nil {
		return
	}
	n := len(d.items) + 2 // +确定/取消
	if n <= 2 {
		d.sel = max0(min(d.sel+dn, 1))
		return
	}
	d.sel = max0(min(d.sel+dn, n-1))
}

// DialogClickItem 命中第 i 行：choice 选中、checks 翻转。
func (v *viewModel) DialogClickItem(i int) {
	d := v.dlg
	if d == nil || i < 0 || i >= len(d.items) {
		return
	}
	switch d.kind {
	case dlgChecks:
		d.items[i].Checked = !d.items[i].Checked
		d.sel = i
	case dlgChoice:
		for j := range d.items {
			d.items[j].Checked = j == i
		}
		d.sel = i
	}
}

// DialogAccept 提交表单。
func (v *viewModel) DialogAccept() {
	d := v.dlg
	if d == nil {
		return
	}
	v.dlg = nil
	switch d.kind {
	case dlgText:
		d.ctx.path = strings.TrimSpace(d.value)
		d.ctx.name = strings.TrimSpace(d.value)
	case dlgNumber:
		n, err := strconv.ParseInt(strings.TrimSpace(d.value), 10, 64)
		if err != nil {
			v.setStatus(Tr("st.notNumber"))
			return
		}
		switch d.act {
		case ActNDQuota:
			mb := int(n)
			if !core.ValidNetdiskMB(mb) {
				v.setStatus(Tf("st.quotaBad", core.NetdiskMinMB, core.NetdiskMaxMB))
				return
			}
			d.ctx.mb = mb
		default:
			if n <= 0 {
				v.setStatus(Tr("st.mustPositive"))
				return
			}
			d.ctx.ms = n
		}
	case dlgChoice:
		if len(d.items) == 0 {
			return
		}
		i := d.sel
		if i < 0 || i >= len(d.items) {
			i = d.checked()
		}
		key := d.items[i].Key
		switch d.act {
		case ActTheme:
			d.ctx.theme = key
		case ActLang:
			d.ctx.lang = key
		case ActSettings:
			v.RunAction(ActionID(key))
			return
		}
	case dlgChecks:
		var perms []string
		for _, it := range d.items {
			if it.Checked {
				perms = append(perms, it.Key)
			}
		}
		if len(perms) == 0 {
			v.setStatus(Tr("st.permsEmpty"))
			return
		}
		d.ctx.perms = perms
	}
	v.exec(d.act, d.ctx)
}

// DialogCancel 放弃表单（不产生任何出站）。
func (v *viewModel) DialogCancel() {
	if v.dlg == nil {
		return
	}
	v.dlg = nil
	v.setStatus(Tr("st.cancelled"))
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
