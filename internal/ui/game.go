// game.go：Ebitengine 原生窗口壳（v19）。
//
// game 不含任何业务状态：Update 把键盘/鼠标/滚轮翻译成 viewModel 的
// OnInput/OnKey/ClickRow/RunAction/PickMenu 等调用，Draw 按 Snapshot() 的
// ViewLine 与 ToolbarActions/PanelActions/Menu/Dialog 绘制，并顺手登记每条
// 可点区域的矩形；下一次 Update 用这些矩形把点击坐标还原成动作。
//
// v25 起本文件是「控件层」：顶栏按钮、标签页、面板动作条、行命中、右键菜单、
// 模态对话框全在这里落地；业务判断仍全在纯状态机（actions/dialog/viewmodel）。
// 颜色一律取自 Pal()（v23 起禁字面量色；遮罩用调色板 token 缩 alpha 得到）。
//
// 事件泵在 Run 启动的 goroutine 里跑 app.NextEvent()，nil（宿主关闭）即关闭
// channel，Update 抽干后返回 ebiten.Termination。

package ui

import (
	"image/color"
	"math"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/hajimehoshi/ebiten/v2"
	"github.com/hajimehoshi/ebiten/v2/inpututil"
	"github.com/hajimehoshi/ebiten/v2/text/v2"
	"github.com/hajimehoshi/ebiten/v2/vector"
)

const (
	windowW, windowH = 1200, 760 // 逻辑=像素
	padX             = float32(12)
	padDlg           = float32(18) // 对话框内边距
)

// Run 启动 Ebitengine GUI。字体装载失败返回 error（绝不 panic）。
func Run(app App) error {
	src, _, err := loadFontSource()
	if err != nil {
		return err
	}
	g := newGame(app, src)
	ebiten.SetWindowTitle("D-Mesh")
	ebiten.SetWindowSize(windowW, windowH)
	ebiten.SetWindowResizingMode(ebiten.WindowResizingModeEnabled)
	return ebiten.RunGame(g)
}

// ---- 字体与色板 ----

type fontSet struct {
	body   *text.GoTextFace
	small  *text.GoTextFace
	lineH  float64 // body 行高（像素，含 v20 加宽行距）
	smallH float64 // small 行高（meta 行/状态行）
}

func newFontSet(src *text.GoTextFaceSource) *fontSet {
	body := &text.GoTextFace{Source: src, Size: 15}
	small := &text.GoTextFace{Source: src, Size: 13}
	m := body.Metrics()
	lh := (m.HAscent + m.HDescent + m.HLineGap) * 1.18
	if lh < 12 {
		lh = 18
	}
	sm := small.Metrics()
	sh := sm.HAscent + sm.HDescent + sm.HLineGap
	if sh < 10 {
		sh = 16
	}
	return &fontSet{body: body, small: small, lineH: lh, smallH: sh}
}

// styleColor 把语义样式映射到当前主题调色板 token（v23：颜色全部收敛
// theme.go，本文件零字面量色）。
func styleColor(s LineStyle) color.RGBA {
	p := Pal()
	switch s {
	case StyleSelf:
		return p.TextSelf
	case StyleSystem:
		return p.System
	case StyleHeader:
		return p.Header
	case StyleDim:
		return p.Dim
	case StyleOnline:
		return p.Online
	case StyleOffline:
		return p.Offline
	case StyleBad:
		return p.Bad
	case StyleOwner:
		return p.Owner
	case StyleAdmin:
		return p.Admin
	case StyleStatus:
		return p.Status
	default:
		return p.Text
	}
}

// scrim 把调色板 token 按系数压暗/变淡，得到模态遮罩（仍非字面量色）。
func scrim(c color.RGBA, k float64) color.RGBA {
	if k < 0 {
		k = 0
	}
	if k > 1 {
		k = 1
	}
	c.A = uint8(float64(c.A) * k)
	return c
}

// ---- game（viewModel 的壳）----

type rect struct{ x, y, w, h float32 }

func (r rect) contains(x, y float32) bool {
	return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h
}

// hitKind 是一次鼠标命中要还原成的调用类别。
type hitKind int

const (
	hitTab        hitKind = iota
	hitAction             // 顶栏/动作条按钮
	hitRow                // 面板主体行（选中/右键菜单）
	hitMenuItem           // 右键菜单项
	hitDialogItem         // 对话框 choice/checks 行
	hitDialogOK
	hitDialogCancel
)

type hit struct {
	r     rect
	kind  hitKind
	a     Action
	index int
}

type game struct {
	vm         *viewModel
	tasks      chan func()
	events     chan Event
	done       chan struct{}
	hostClosed bool
	fs         *fontSet
	w, h       int32
	hits       []hit // 上一帧 Draw 登记的命中区
	dlgBase    int   // 对话框命中区在 hits 中的起点（模态：遮罩外不可点）
	menuAt     rect  // 右键菜单弹出位置
	menuShown  bool
	inputBuf   []rune
}

func newGame(app App, src *text.GoTextFaceSource) *game {
	g := &game{
		vm:     newViewModel(app),
		tasks:  make(chan func(), 1024),
		events: make(chan Event, 512),
		done:   make(chan struct{}),
		fs:     newFontSet(src),
		w:      windowW, h: windowH,
	}
	g.vm.deliver = func(job func() []Event) {
		go func() {
			evs := job() // 工作线程：文件 IO / 审计 / 出站广播
			g.post(func() {
				for _, ev := range evs {
					g.vm.OnEvent(ev)
				}
			})
		}()
	}
	g.vm.copyText = func(s string) { _ = clipboard.WriteAll(s) }
	if nativePickerAvailable {
		// 必须在 UI 线程（持有本窗口 HWND 的那条线程）上同步弹出：先前放在
		// LockOSThread 的工作线程里跑，协程退出即销毁该线程，Windows 的鼠标捕获
		// 留在已消失的线程上——实测对话框关闭后本窗口再也收不到任何点击。
		g.vm.pickFile = func(title string, onPath func(string)) {
			path, ok, err := pickNativeFile(title)
			switch {
			case ok:
				onPath(path)
			case err != nil:
				g.vm.setStatus(Tf("dialog.pickFail", err))
			default:
				g.vm.setStatus(Tr("st.cancelled"))
			}
		}
	}
	if app != nil {
		go g.pump(app)
	}
	return g
}

// post 把一段回投 UI 线程的工作塞进任务队列；窗口已关则丢弃。
func (g *game) post(run func()) {
	select {
	case g.tasks <- run:
	case <-g.done:
	}
}

// pump 是宿主事件泵：NextEvent 返回 nil（宿主关闭）即关闭 events。
func (g *game) pump(app App) {
	for {
		ev := app.NextEvent()
		if ev == nil {
			select {
			case <-g.done:
			default:
				close(g.events)
			}
			return
		}
		select {
		case g.events <- ev:
		case <-g.done:
			return
		}
	}
}

// Layout 直接用传入尺寸（逻辑=像素）。
func (g *game) Layout(outsideWidth, outsideHeight int) (int, int) {
	g.w, g.h = int32(outsideWidth), int32(outsideHeight)
	return outsideWidth, outsideHeight
}

// Update 每 tick：抽干任务/事件 → 输入翻译 → Tick。
func (g *game) Update() error {
	g.drain()
	if g.shouldTerminate() {
		close(g.done)
		return ebiten.Termination
	}
	g.handleInput()
	g.vm.Tick(time.Now())
	return nil
}

// drain 非阻塞抽干（一次最多 64×2 条防卡帧）。
func (g *game) drain() {
	for i := 0; i < 64; i++ {
		select {
		case run := <-g.tasks:
			run()
		default:
			i = 64
		}
	}
	for i := 0; i < 64; i++ {
		select {
		case ev, ok := <-g.events:
			if !ok {
				g.hostClosed = true
				i = 64
				continue
			}
			g.vm.OnEvent(ev)
		default:
			i = 64
		}
	}
}

func (g *game) shouldTerminate() bool {
	if g.vm.QuitRequested() {
		return true
	}
	if !g.hostClosed {
		return false
	}
	// 宿主关闭：剩余事件/任务处理完再退。
	select {
	case <-g.events:
		return false
	default:
	}
	select {
	case <-g.tasks:
		return false
	default:
	}
	return true
}

// handleInput：特殊键/字符/粘贴/滚轮/鼠标 → viewModel 调用。
func (g *game) handleInput() {
	mapped := []struct {
		ek  ebiten.Key
		key Key
	}{
		{ebiten.KeyEnter, KeyEnter}, {ebiten.KeyNumpadEnter, KeyEnter},
		{ebiten.KeyEscape, KeyEscape},
		{ebiten.KeyBackspace, KeyBackspace}, {ebiten.KeyDelete, KeyDelete},
		{ebiten.KeyLeft, KeyLeft}, {ebiten.KeyRight, KeyRight},
		{ebiten.KeyHome, KeyHome}, {ebiten.KeyEnd, KeyEnd},
		{ebiten.KeyUp, KeyUp}, {ebiten.KeyDown, KeyDown},
		{ebiten.KeyPageUp, KeyPgUp}, {ebiten.KeyPageDown, KeyPgDn},
	}
	for _, m := range mapped {
		if inpututil.IsKeyJustPressed(m.ek) {
			g.vm.OnKey(m.key)
		}
	}
	if inpututil.IsKeyJustPressed(ebiten.KeyTab) {
		if ebiten.IsKeyPressed(ebiten.KeyShift) {
			g.vm.OnKey(KeyShiftTab)
		} else {
			g.vm.OnKey(KeyTab)
		}
	}
	// Ctrl+V 粘贴（剪贴板；空内容/报错静默忽略）。
	if (ebiten.IsKeyPressed(ebiten.KeyControl) || ebiten.IsKeyPressed(ebiten.KeyMeta)) &&
		inpututil.IsKeyJustPressed(ebiten.KeyV) {
		if s, err := clipboard.ReadAll(); err == nil && s != "" {
			g.vm.Paste(s)
		}
	}
	// 可打印字符（含 IME 上屏）。
	g.inputBuf = ebiten.AppendInputChars(g.inputBuf[:0])
	for _, r := range g.inputBuf {
		g.vm.OnInput(r)
	}
	// 滚轮（chat 面板）。
	_, yoff := ebiten.Wheel()
	if yoff != 0 {
		lines := int(math.Round(math.Abs(yoff)))
		if lines < 1 {
			lines = 1
		}
		if yoff > 0 {
			g.vm.ScrollBy(-lines)
		} else {
			g.vm.ScrollBy(lines)
		}
	}
	g.handleClicks()
}

// handleClicks 用上一帧登记的矩形把鼠标事件翻译成 viewModel 调用。
// 逆序扫描：后画的浮层（对话框/菜单）盖在先画的主体上，优先级更高。
func (g *game) handleClicks() {
	x, y := ebiten.CursorPosition()
	fx, fy := float32(x), float32(y)
	hits := g.hits
	if d := g.vm.Dialog(); d != nil {
		hits = hits[min(g.dlgBase, len(hits)):] // 模态：遮罩下层一律不吃点击
	}
	right := inpututil.IsMouseButtonJustPressed(ebiten.MouseButtonRight)
	left := inpututil.IsMouseButtonJustPressed(ebiten.MouseButtonLeft)
	if !right && !left {
		return
	}
	for i := len(hits) - 1; i >= 0; i-- {
		h := hits[i]
		if !h.r.contains(fx, fy) {
			continue
		}
		switch h.kind {
		case hitTab:
			g.vm.SwitchTab(h.index)
		case hitAction:
			if h.a.Enabled {
				g.vm.RunAction(h.a.ID)
			}
		case hitRow:
			g.vm.ClickRow(h.index, right)
		case hitMenuItem:
			if left {
				g.vm.PickMenu(h.index)
			}
		case hitDialogItem:
			if left {
				g.vm.DialogClickItem(h.index)
			}
		case hitDialogOK:
			if left {
				g.vm.DialogAccept()
			}
		case hitDialogCancel:
			if left {
				g.vm.DialogCancel()
			}
		}
		return
	}
	if right || g.vm.Menu() != nil {
		g.vm.CloseMenu() // 空白处：收起右键菜单
	}
}

// ---- 布局 ----

// layoutBox 是本帧各条带的纵坐标（hasInput=false 时输入框让位给动作条）。
type layoutBox struct {
	topLineY, tabY, bodyTop, barY, inputY, statusY float32
	hasInput                                       bool
}

func (g *game) layout() layoutBox {
	lh, sh := float32(g.fs.lineH), float32(g.fs.smallH)
	var l layoutBox
	l.topLineY = 10
	l.tabY = l.topLineY + sh + 6
	l.bodyTop = l.tabY + maxF(lh, g.btnH()) + 12
	l.statusY = float32(g.h) - sh - 10
	l.hasInput = g.vm.ActiveTab() == 0
	if l.hasInput {
		l.inputY = l.statusY - lh - 30
		l.barY = l.inputY - g.btnH() - 10
	} else {
		l.inputY = 0
		l.barY = l.statusY - g.btnH() - 12
	}
	return l
}

// btnH = 按钮药丸高度（顶栏、动作条、对话框按钮共用）。
func (g *game) btnH() float32 { return float32(g.fs.smallH) + 12 }

// inputBoxH = v20 输入框总高（含内边距）。
func (g *game) inputBoxH() float32 { return float32(g.fs.lineH) + 18 }

func maxF(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

// ---- Draw ----

// Draw 按 Snapshot 绘制。v25 QQ 风格布局：顶栏（群信息小字 + 右上工具按钮，
// 下一行文字标签页）→ 主体（聊天=头像+气泡流/其余=浅色列表）→ 面板动作条 →
// 圆角输入框（仅聊天）→ 底部状态带；最后叠右键菜单与模态对话框。
// 全部颜色取自 Pal()。
func (g *game) Draw(screen *ebiten.Image) {
	p := Pal()
	w, h := float32(g.w), float32(g.h)
	vector.DrawFilledRect(screen, 0, 0, w, h, p.WindowBG, false)
	g.hits = g.hits[:0]

	lh := float32(g.fs.lineH)
	L := g.layout()
	bodyBottom := L.barY - 8
	bodyRows := int((bodyBottom - L.bodyTop) / (lh + 4))
	if bodyRows < 1 {
		bodyRows = 1
	}
	g.vm.SetBodyHeight(bodyRows)

	// 顶栏带 + 聊天区底 + 底栏带。
	vector.DrawFilledRect(screen, 0, 0, w, L.bodyTop-6, p.BarBG, false)
	vector.DrawFilledRect(screen, 0, L.bodyTop-6, w, 1, p.Divider, false)
	if L.hasInput {
		vector.DrawFilledRect(screen, 0, L.bodyTop, w, bodyBottom-L.bodyTop, p.ChatBG, false)
	}
	vector.DrawFilledRect(screen, 0, L.statusY-8, w, h-L.statusY+8, p.BarBG, false)
	vector.DrawFilledRect(screen, 0, L.statusY-8, w, 1, p.Divider, false)

	// 顶栏状态行 + 标签页 + 工具按钮。
	g.drawText(screen, g.fs.small, padX+8, L.topLineY, g.vm.TopLine(), p.Dim)
	g.drawTabs(screen, L.tabY)
	g.drawActions(screen, g.vm.ToolbarActions(), L.tabY+(lh-g.btnH())/2, true)

	// 主体 + 动作条。
	g.drawBody(screen, g.vm.Snapshot(), L.bodyTop, bodyBottom, bodyRows)
	g.drawActions(screen, g.vm.PanelActions(), L.barY, false)

	// 输入框 + 状态行。
	if L.hasInput {
		txt, caret, active := g.vm.InputLine()
		g.drawInput(screen, txt, caret, active, L.inputY, w)
	}
	g.drawText(screen, g.fs.small, padX+4, L.statusY, g.vm.StatusLine(), styleColor(StyleStatus))

	// 浮层：右键菜单 + 模态对话框。
	items := g.vm.Menu()
	if items != nil && !g.menuShown {
		cx, cy := ebiten.CursorPosition()
		g.menuAt = rect{x: float32(cx), y: float32(cy)}
		g.menuShown = true
	}
	if items == nil {
		g.menuShown = false
	} else {
		g.drawMenu(screen, g.menuAt, items)
	}
	if d := g.vm.Dialog(); d != nil {
		g.dlgBase = len(g.hits)
		g.drawDialog(screen, d)
	}
}

// drawTabs 画 QQ 式文字标签页：激活项加粗深色 + accent 下划线。
func (g *game) drawTabs(screen *ebiten.Image, y float32) {
	p := Pal()
	lh := float32(g.fs.lineH)
	x := padX + 6
	active := g.vm.ActiveTab()
	for i, name := range TabLabels() {
		tw := float32(text.Advance(name, g.fs.body))
		pad := float32(10)
		if i == active {
			g.drawTextB(screen, g.fs.body, x+pad, y, name, p.TabActive)
			drawRoundRect(screen, x+pad, y+lh+1, tw-2, 2.5, 1.2, p.Accent)
		} else {
			g.drawText(screen, g.fs.body, x+pad, y, name, p.Dim)
		}
		r := rect{x: x, y: y - 4, w: tw + 2*pad, h: lh + 8}
		g.hits = append(g.hits, hit{r: r, kind: hitTab, index: i})
		x += tw + 2*pad + 10
	}
}

// drawActions 画一排按钮并登记命中区。rightAligned=true 时从窗口右边缘向左排。
// 不可用动作置灰显示而非隐藏（能力面可见）。
func (g *game) drawActions(screen *ebiten.Image, acts []Action, y float32, rightAligned bool) {
	if len(acts) == 0 {
		return
	}
	p := Pal()
	hh := g.btnH()
	w := float32(g.w)
	gap := float32(8)
	widths := make([]float32, len(acts))
	total := float32(-gap)
	for i, a := range acts {
		widths[i] = float32(text.Advance(a.Label, g.fs.small)) + 24
		total += widths[i] + gap
	}
	x := padX + 6
	if rightAligned {
		x = w - padX - 6 - total
	}
	if x < padX {
		x = padX
	}
	for i, a := range acts {
		cw := widths[i]
		bg, fg := p.CardBG, p.Text
		if !a.Enabled {
			bg, fg = p.RowAlt, p.Dim
		} else if a.Confirm != "" {
			fg = p.Bad
		}
		r := rect{x: x, y: y, w: cw, h: hh}
		drawRoundRect(screen, r.x, r.y, r.w, r.h, hh/2, p.Border)
		drawRoundRect(screen, r.x+1, r.y+1, r.w-2, r.h-2, (hh-2)/2, bg)
		lw := float32(text.Advance(a.Label, g.fs.small))
		g.drawText(screen, g.fs.small, x+(cw-lw)/2, y+(hh-float32(g.fs.smallH))/2, a.Label, fg)
		g.hits = append(g.hits, hit{r: r, kind: hitAction, a: a})
		x += cw + gap
	}
}

// drawBody 绘制面板主体。chat 面板：头像色块 + 左右气泡流 + 居中系统行；
// 其余面板：浅色列表（斑马纹 + 选中行 accent 竖条）。
// 带 Row 的行同时登记命中区（左键选中、右键弹菜单）。
func (g *game) drawBody(screen *ebiten.Image, lines []ViewLine, top, bottom float32, rows int) {
	lh := float32(g.fs.lineH)
	w := float32(g.w)
	if g.vm.ActiveTab() == 0 { // chat
		g.drawChat(screen, lines, top, bottom, w, rows)
		return
	}
	p := Pal()
	y := top
	pitch := lh + 4
	for zi, l := range lines {
		if y+lh > bottom {
			return
		}
		if l.Selected {
			drawRoundRect(screen, padX, y-2, w-2*padX, pitch-1, 5, p.SelBG)
			drawRoundRect(screen, padX+3, y+2, 3, lh-5, 1.5, p.Accent)
		} else if zi%2 == 1 {
			vector.DrawFilledRect(screen, padX, y-2, w-2*padX, pitch-1, p.RowAlt, false)
		}
		c := styleColor(l.Style)
		tx := padX + 14
		frags := wrapText(l.Text, g.fs.body, float64(w-2*padX-24))
		for fi, f := range frags {
			if y+lh > bottom {
				return
			}
			if l.Row > 0 {
				g.hits = append(g.hits, hit{r: rect{x: padX, y: y - 2, w: w - 2*padX, h: pitch},
					kind: hitRow, index: l.Row - 1})
			}
			if l.Style == StyleHeader && fi == 0 {
				g.drawTextB(screen, g.fs.body, tx, y, f, c)
			} else {
				g.drawText(screen, g.fs.body, tx, y, f, c)
			}
			y += pitch
		}
	}
}

const (
	avatarSz    = float32(36) // 头像色块边长
	avatarGap   = float32(10) // 头像与气泡间距
	groupWindow = 5 * 60      // 连发分组窗口（秒）：同人同时段隐头像与 meta
)

// drawChat 绘制 QQ 风格聊天流：他人=左头像+白气泡（尾巴朝左），
// 自身=右头像+绿气泡（尾巴朝右），系统/标题行=居中灰小字。
// 同一发送者连续消息在 groupWindow 内不重复头像与名·时间行。
func (g *game) drawChat(screen *ebiten.Image, lines []ViewLine, top, bottom, w float32, rows int) {
	vis := lines
	off := g.vm.ChatScroll()
	end := len(vis) - off
	if end > len(vis) {
		end = len(vis)
	}
	start := end - rows
	if start < 0 {
		start = 0
	}
	y := top
	var prevAv string
	var prevT time.Time
	var prevSelf bool
	havePrev := false
	for _, l := range vis[start:end] {
		if y > bottom {
			return
		}
		switch l.Style {
		case StyleChat, StyleSelf:
			if l.Body == "" && l.Meta == "" { // 无气泡元数据的旧行：按系统行画
				y = g.drawCentered(screen, l.Text, y, bottom, w)
				havePrev = false
				continue
			}
			y, prevAv, prevT, prevSelf, havePrev = g.drawBubble(screen, l, y, bottom, w,
				prevAv, prevT, prevSelf, havePrev)
		default:
			y = g.drawCentered(screen, l.Text, y, bottom, w)
			havePrev = false
		}
	}
}

// drawCentered 画一条系统小字行（QQ 时间/系统提示样式）：短行居中，
// 超过半宽的长行（如 progress 面板输出）退回左对齐，返回下一 y。
func (g *game) drawCentered(screen *ebiten.Image, s string, y, bottom, w float32) float32 {
	p := Pal()
	frags := wrapText(s, g.fs.small, float64(w-2*padX-20))
	for _, f := range frags {
		if y+float32(g.fs.smallH) > bottom {
			return y
		}
		fw := float32(text.Advance(f, g.fs.small))
		x := (w - fw) / 2
		if fw > w*0.55 {
			x = padX + 4
		}
		g.drawText(screen, g.fs.small, x, y, f, p.System)
		y += float32(g.fs.smallH) + 2
	}
	y += 4
	return y
}

// drawBubble 画一条 QQ 式消息（头像色块 + 名·时间 meta + 带尾巴圆角气泡），
// 返回下一 y 与分组状态（prev* 用于隐藏重复头像）。
func (g *game) drawBubble(screen *ebiten.Image, l ViewLine, y, bottom, w float32,
	prevAv string, prevT time.Time, prevSelf, havePrev bool) (float32, string, time.Time, bool, bool) {
	p := Pal()
	lh := float32(g.fs.lineH)
	startY := y
	self := l.Style == StyleSelf
	body := l.Body
	if body == "" {
		body = l.Text
	}
	avatar := l.Avatar
	if avatar == "" {
		avatar = l.Meta // 退而求其次：meta 串本身足够稳定取色
	}
	grouped := havePrev && self == prevSelf && avatar == prevAv &&
		!metaClock(l.Meta).IsZero() && !prevT.IsZero() &&
		metaClock(l.Meta).Sub(prevT).Seconds() <= groupWindow
	// 头像边长 + 间距占用的最大文本宽。
	maxTextW := w - 2*padX - 2*avatarSz - 2*avatarGap - 24
	if maxTextW < 120 {
		maxTextW = 120
	}
	if !grouped {
		if l.Meta != "" {
			if y+float32(g.fs.smallH) > bottom {
				return y, avatar, metaClock(l.Meta), self, true
			}
			mw := float32(text.Advance(l.Meta, g.fs.small))
			mx := padX + avatarSz + avatarGap + 4
			if self {
				mx = w - padX - avatarSz - avatarGap - 4 - mw
			}
			g.drawText(screen, g.fs.small, mx, y, l.Meta, p.Meta)
			y += float32(g.fs.smallH) + 2
		}
	}
	frags := wrapText(body, g.fs.body, float64(maxTextW))
	tw := float32(0)
	for _, f := range frags {
		if a := float32(text.Advance(f, g.fs.body)); a > tw {
			tw = a
		}
	}
	boxW := tw + 22
	boxH := float32(len(frags))*lh + 10
	tail := float32(6) // 尾巴宽
	bx := padX + avatarSz + avatarGap + tail
	if self {
		bx = w - padX - avatarSz - avatarGap - tail - boxW
	}
	rowH := boxH
	if !grouped {
		if rowH < avatarSz {
			rowH = avatarSz
		}
	}
	if y+rowH > bottom+lh {
		return y, avatar, metaClock(l.Meta), self, true
	}
	bubbleBG := p.BubbleOther
	textC := p.Text
	if self {
		bubbleBG = p.BubbleSelf
		textC = p.TextSelf
	}
	if l.Selected { // v25：右键命中即选中，整条消息行给选中底色
		drawRoundRect(screen, padX, startY-3, w-2*padX, y-startY+boxH+8, 7, p.SelBG)
	}
	// 头像色块（分组续行时与首条对齐：仍画头像，QQ 连发即如此）。
	if !grouped {
		ax := padX
		if self {
			ax = w - padX - avatarSz
		}
		ay := y
		drawRoundRect(screen, ax, ay, avatarSz, avatarSz, 6, avatarColor(avatar, p))
		init := avatarInitials(avatar)
		iw := float32(text.Advance(init, g.fs.small))
		g.drawTextB(screen, g.fs.small, ax+(avatarSz-iw)/2, ay+avatarSz/2-float32(g.fs.smallH)/2,
			init, p.CardBG)
	}
	// 气泡尾巴（小三角指向头像）。
	if self {
		tx := bx + boxW
		drawTriangle(screen, tx-1, y+10, tx-1, y+10+tail, tx+tail-2, y+10+tail/2, bubbleBG)
	} else {
		tx := bx
		drawTriangle(screen, tx+1, y+10, tx+1, y+10+tail, tx-tail+2, y+10+tail/2, bubbleBG)
	}
	drawRoundRect(screen, bx, y, boxW, boxH, 7, bubbleBG)
	for _, f := range frags {
		g.drawText(screen, g.fs.body, bx+11, y+5, f, textC)
		y += lh
	}
	if l.Row > 0 {
		g.hits = append(g.hits, hit{r: rect{x: padX, y: startY - 3, w: w - 2*padX, h: y + 7 - startY},
			kind: hitRow, index: l.Row - 1})
	}
	return y + 10, avatar, metaClock(l.Meta), self, true
}

// metaClock 从 Meta 前缀 "15:04:05" 解析当日时刻（分组用）；失败返回零值。
func metaClock(meta string) time.Time {
	if len(meta) < 8 {
		return time.Time{}
	}
	t, err := time.Parse("15:04:05", meta[:8])
	if err != nil {
		return time.Time{}
	}
	return t
}

func (g *game) drawInput(screen *ebiten.Image, txt string, caret int, active bool, y, w float32) {
	p := Pal()
	lh := float32(g.fs.lineH)
	boxW := w - 2*(padX-6)
	drawRoundRect(screen, padX-6, y, boxW, g.inputBoxH(), 9, p.Border) // 1px 描边
	drawRoundRect(screen, padX-5, y+1, boxW-2, g.inputBoxH()-2, 8, p.CardBG)
	ty := y + 9
	tx := padX + 8
	if txt == "> " { // 空输入：占位提示
		g.drawText(screen, g.fs.body, tx, ty, Tr("input.placeholder"), p.Dim)
		if active {
			vector.DrawFilledRect(screen, tx+1, ty+2, 2, lh-8, p.Caret, false)
		}
		return
	}
	frags := wrapText(txt, g.fs.body, float64(w-2*padX-24))
	last := frags[len(frags)-1]
	g.drawText(screen, g.fs.body, tx, ty, last, p.Text)
	if active && time.Now().UnixMilli()%1060 < 530 { // 光标 530ms 闪烁
		g.drawCaret(screen, tx, ty+3, last, caret, p.Caret)
	}
}

// drawCaret 在单行文本的第 caret 个 rune 处画竖线光标。
func (g *game) drawCaret(screen *ebiten.Image, x, y float32, s string, caret int, c color.RGBA) {
	r := []rune(s)
	if caret > len(r) {
		caret = len(r)
	}
	cx := x + float32(text.Advance(string(r[:caret]), g.fs.body))
	vector.DrawFilledRect(screen, cx+1, y, 2, float32(g.fs.lineH)-10, c, false)
}

// ---- 浮层：右键菜单 ----

func (g *game) drawMenu(screen *ebiten.Image, pos rect, items []Action) {
	p := Pal()
	lh := float32(g.fs.lineH)
	rowH := lh + 8
	cw := float32(160)
	for _, it := range items {
		if a := float32(text.Advance(it.Label, g.fs.body)) + 30; a > cw {
			cw = a
		}
	}
	th := float32(len(items))*rowH + 8
	x, y := pos.x+2, pos.y+2
	if x+cw > float32(g.w)-padX {
		x = float32(g.w) - padX - cw
	}
	if y+th > float32(g.h)-4 {
		y = float32(g.h) - 4 - th
	}
	if x < padX {
		x = padX
	}
	if y < 4 {
		y = 4
	}
	drawRoundRect(screen, x-1, y-1, cw+2, th+2, 8, p.Border)
	drawRoundRect(screen, x, y, cw, th, 7, p.CardBG)
	for i, it := range items {
		ry := y + 4 + float32(i)*rowH
		r := rect{x: x + 4, y: ry, w: cw - 8, h: rowH - 3}
		if i == g.vm.MenuSel() && it.Enabled {
			drawRoundRect(screen, r.x, r.y, r.w, r.h, 5, p.SelBG)
		}
		fg := p.Text
		if !it.Enabled {
			fg = p.Dim
		} else if it.Confirm != "" {
			fg = p.Bad
		}
		g.drawText(screen, g.fs.body, x+14, ry+3, it.Label, fg)
		g.hits = append(g.hits, hit{r: r, kind: hitMenuItem, a: it, index: i})
	}
}

// ---- 浮层：模态对话框 ----

// dialogBox 是对话框的一次排版结果（高度先量后画，两趟共用）。
type dialogBox struct {
	x, y, w, h float32
	noteLines  []string
	itemPitch  float32
	bodyTop    float32
}

func (g *game) drawDialog(screen *ebiten.Image, d *dialog) {
	p := Pal()
	lh, sh := float32(g.fs.lineH), float32(g.fs.smallH)
	w, h := float32(g.w), float32(g.h)
	vector.DrawFilledRect(screen, 0, 0, w, h, scrim(p.WindowBG, 0.55), false)

	inner := minF(w-2*40, 540) - 2*padDlg
	box := dialogBox{w: inner + 2*padDlg, itemPitch: lh + 6}
	box.noteLines = wrapText(d.DialogNote(), g.fs.small, float64(inner))
	box.h = padDlg + lh + 8 + float32(len(box.noteLines))*(sh+2) + 4
	if d.DialogEditable() {
		box.h += lh + 18
	}
	if n := len(d.DialogItems()); n > 0 {
		box.h += float32(n)*box.itemPitch + 4
	}
	box.h += g.btnH() + padDlg
	box.x, box.y = (w-box.w)/2, (h-box.h)/2

	drawRoundRect(screen, box.x-1, box.y-1, box.w+2, box.h+2, 10, p.Border)
	drawRoundRect(screen, box.x, box.y, box.w, box.h, 9, p.CardBG)

	y := box.y + padDlg
	g.drawTextB(screen, g.fs.body, box.x+padDlg, y, d.DialogTitle(), p.Header)
	y += lh + 8
	for _, n := range box.noteLines {
		g.drawText(screen, g.fs.small, box.x+padDlg, y, n, p.Meta)
		y += sh + 2
	}
	y += 4

	if d.DialogEditable() {
		fh := lh + 10
		fy := y
		drawRoundRect(screen, box.x+padDlg, fy, inner, fh, 6, p.Border)
		drawRoundRect(screen, box.x+padDlg+1, fy+1, inner-2, fh-2, 5, p.WindowBG)
		val, cur := d.DialogValue()
		g.drawText(screen, g.fs.body, box.x+padDlg+9, fy+5, val, p.Text)
		if time.Now().UnixMilli()%1060 < 530 {
			g.drawCaret(screen, box.x+padDlg+9, fy+8, val, cur, p.Caret)
		}
		y = fy + fh + 8
	}

	items := d.DialogItems()
	for i, it := range items {
		ry := y + float32(i)*box.itemPitch
		r := rect{x: box.x + padDlg, y: ry, w: inner, h: box.itemPitch - 3}
		if i == d.DialogSel() {
			drawRoundRect(screen, r.x-4, r.y, r.w+8, r.h, 5, p.SelBG)
		}
		markX := r.x + 4
		switch d.Kind() {
		case dlgChecks:
			drawRoundRect(screen, markX, ry+3, lh-6, lh-6, 3, p.Border)
			if it.Checked {
				drawRoundRect(screen, markX+3, ry+6, lh-12, lh-12, 2, p.Accent)
			}
		case dlgChoice:
			dia := lh - 6
			vector.DrawFilledCircle(screen, markX+dia/2, ry+3+dia/2, dia/2, p.Border, true)
			vector.DrawFilledCircle(screen, markX+dia/2, ry+3+dia/2, dia/2-2, p.CardBG, true)
			if it.Checked {
				vector.DrawFilledCircle(screen, markX+dia/2, ry+3+dia/2, dia/2-5, p.Accent, true)
			}
		}
		fg := p.Text
		if it.Checked && d.Kind() == dlgChoice {
			fg = p.TabActive
		}
		g.drawText(screen, g.fs.body, markX+lh+2, ry+2, it.Label, fg)
		g.hits = append(g.hits, hit{r: r, kind: hitDialogItem, index: i})
	}
	if len(items) > 0 {
		y += float32(len(items))*box.itemPitch + 4
	}

	g.drawDialogButtons(screen, box, y, inner)
}

// drawDialogButtons 画对话框底部的「取消/确定」（确定贴右边缘，accent 底）。
func (g *game) drawDialogButtons(screen *ebiten.Image, box dialogBox, y, inner float32) {
	p := Pal()
	hh := g.btnH()
	x := box.x + padDlg + inner
	for i, pair := range []struct {
		label string
		kind  hitKind
	}{
		{Tr("dialog.ok"), hitDialogOK},
		{Tr("dialog.cancel"), hitDialogCancel},
	} {
		cw := float32(text.Advance(pair.label, g.fs.small)) + 28
		x -= cw
		if i > 0 {
			x -= 8
		}
		r := rect{x: x, y: y, w: cw, h: hh}
		bg, fg := p.Border, p.Text
		if pair.kind == hitDialogOK {
			bg, fg = p.Accent, p.CardBG
		}
		drawRoundRect(screen, r.x, r.y, r.w, r.h, hh/2, bg)
		if pair.kind != hitDialogOK {
			drawRoundRect(screen, r.x+1, r.y+1, r.w-2, r.h-2, (hh-2)/2, p.CardBG)
		}
		lw := float32(text.Advance(pair.label, g.fs.small))
		g.drawText(screen, g.fs.small, r.x+(cw-lw)/2, r.y+(hh-float32(g.fs.smallH))/2, pair.label, fg)
		g.hits = append(g.hits, hit{r: r, kind: pair.kind})
	}
}

func minF(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func (g *game) drawText(screen *ebiten.Image, face text.Face, x, y float32, s string, c color.Color) {
	if s == "" {
		return
	}
	op := &text.DrawOptions{}
	op.GeoM.Translate(float64(x), float64(y))
	op.ColorScale.ScaleWithColor(c)
	text.Draw(screen, s, face, op)
}

// drawTextB 伪加粗：同串以 +0.6px 偏移重绘一次（标题/激活标签用）。
func (g *game) drawTextB(screen *ebiten.Image, face text.Face, x, y float32, s string, c color.Color) {
	g.drawText(screen, face, x, y, s, c)
	g.drawText(screen, face, x+0.6, y, s, c)
}

// drawRoundRect 圆角矩形：两条正交内接矩形 + 四角圆盘（aa 平滑）。
func drawRoundRect(dst *ebiten.Image, x, y, w, h, r float32, c color.RGBA) {
	if r*2 > h {
		r = h / 2
	}
	if r*2 > w {
		r = w / 2
	}
	vector.DrawFilledRect(dst, x, y+r, w, h-2*r, c, true)
	vector.DrawFilledRect(dst, x+r, y, w-2*r, h, c, true)
	vector.DrawFilledCircle(dst, x+r, y+r, r, c, true)
	vector.DrawFilledCircle(dst, x+w-r, y+r, r, c, true)
	vector.DrawFilledCircle(dst, x+r, y+h-r, r, c, true)
	vector.DrawFilledCircle(dst, x+w-r, y+h-r, r, c, true)
}

// drawTriangle 实心三角（v23 气泡尾巴）：ebiten v2.10 的 vector 无三角
// 快捷 API，走 Path+FillPath。
func drawTriangle(dst *ebiten.Image, x0, y0, x1, y1, x2, y2 float32, c color.RGBA) {
	var path vector.Path
	path.MoveTo(x0, y0)
	path.LineTo(x1, y1)
	path.LineTo(x2, y2)
	path.Close()
	op := &vector.DrawPathOptions{}
	op.ColorScale.ScaleWithColor(c)
	vector.FillPath(dst, &path, nil, op)
}

// ---- CJK 换行 ----

// wrapText 按「每个汉字可断、拉丁按空格/标点」把一行折进 maxW 宽度。
// 先按 \n 分段；每段再软折。
func wrapText(s string, face text.Face, maxW float64) []string {
	if maxW <= 0 {
		maxW = 100
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		out = append(out, wrapPara(para, face, maxW)...)
	}
	return out
}

func wrapPara(s string, face text.Face, maxW float64) []string {
	if s == "" || text.Advance(s, face) <= maxW {
		return []string{s}
	}
	var out []string
	var cur []rune
	var curW float64
	breakAt := -1 // cur[:breakAt] 可成行
	for _, r := range s {
		rw := text.Advance(string(r), face)
		if curW+rw > maxW && len(cur) > 0 {
			if breakAt > 0 {
				out = append(out, strings.TrimRight(string(cur[:breakAt]), " "))
				rest := append([]rune{}, cur[breakAt:]...)
				cur, breakAt = rest, -1
				curW = text.Advance(string(cur), face)
			} else {
				out = append(out, string(cur))
				cur, breakAt = cur[:0], -1
				curW = 0
			}
		}
		cur = append(cur, r)
		curW += rw
		if r == ' ' || isCJK(r) {
			breakAt = len(cur)
		}
	}
	if len(cur) > 0 {
		out = append(out, strings.TrimRight(string(cur), " "))
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// isCJK 粗判中日韩统一表意/假名/全角区段（这些字符每个都可断行）。
func isCJK(r rune) bool {
	return (r >= 0x2E80 && r <= 0x9FFF) ||
		(r >= 0xAC00 && r <= 0xD7AF) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0x20000 && r <= 0x2FA1F) ||
		(r >= 0x3000 && r <= 0x303F)
}
