// game.go：Ebitengine 原生窗口壳（v19）。
//
// game 不含任何业务状态：Update 把键盘/鼠标/滚轮翻译成 viewModel 的
// OnInput/OnKey/Submit/SwitchTab/ScrollBy 调用，Draw 按 viewModel 的
// Snapshot()/TopLine()/InputLine()/StatusLine() 绘制。事件泵在 Run 启动的
// goroutine 里跑 app.NextEvent()，nil（宿主关闭）即关闭 channel，Update
// 抽干后返回 ebiten.Termination。

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
	body  *text.GoTextFace
	small *text.GoTextFace
	lineH float64 // body 行高（像素）
}

func newFontSet(src *text.GoTextFaceSource) *fontSet {
	body := &text.GoTextFace{Source: src, Size: 15}
	small := &text.GoTextFace{Source: src, Size: 13}
	m := body.Metrics()
	lh := m.HAscent + m.HDescent + m.HLineGap
	if lh < 12 {
		lh = 18
	}
	return &fontSet{body: body, small: small, lineH: lh}
}

var (
	colBG          = color.RGBA{16, 18, 22, 255}
	colDivider     = color.RGBA{52, 58, 74, 255}
	colChat        = color.RGBA{220, 224, 232, 255}
	colSelf        = color.RGBA{255, 196, 120, 255}
	colSystem      = color.RGBA{140, 146, 160, 255}
	colHeader      = color.RGBA{96, 165, 250, 255}
	colDim         = color.RGBA{120, 125, 138, 255}
	colOnline      = color.RGBA{102, 217, 145, 255}
	colOffline     = color.RGBA{130, 134, 145, 255}
	colBad         = color.RGBA{244, 102, 102, 255}
	colOwner       = color.RGBA{120, 230, 120, 255}
	colAdmin       = color.RGBA{230, 140, 230, 255}
	colStatus      = color.RGBA{250, 200, 90, 255}
	colSelBG       = color.RGBA{40, 48, 66, 255}
	colBubbleSelf  = color.RGBA{52, 44, 30, 255}
	colBubbleOther = color.RGBA{28, 32, 42, 255}
	colCaret       = color.RGBA{250, 250, 250, 255}
	colTabActive   = color.RGBA{255, 255, 255, 255}
)

func styleColor(s LineStyle) color.RGBA {
	switch s {
	case StyleSelf:
		return colSelf
	case StyleSystem:
		return colSystem
	case StyleHeader:
		return colHeader
	case StyleDim:
		return colDim
	case StyleOnline:
		return colOnline
	case StyleOffline:
		return colOffline
	case StyleBad:
		return colBad
	case StyleOwner:
		return colOwner
	case StyleAdmin:
		return colAdmin
	case StyleStatus:
		return colStatus
	default:
		return colChat
	}
}

// ---- game（viewModel 的壳）----

type rect struct{ x, y, w, h float32 }

type game struct {
	vm         *viewModel
	tasks      chan func()
	events     chan Event
	done       chan struct{}
	hostClosed bool
	fs         *fontSet
	w, h       int32
	tabRects   []rect
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
			run := func() {
				for _, ev := range evs {
					g.vm.OnEvent(ev)
				}
			}
			select {
			case g.tasks <- run:
			case <-g.done: // 窗口已关：丢弃回报即可
			}
		}()
	}
	if app != nil {
		go g.pump(app)
	}
	return g
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

func (g *game) handleClicks() {
	if !inpututil.IsMouseButtonJustPressed(ebiten.MouseButtonLeft) {
		return
	}
	x, y := ebiten.CursorPosition()
	for i, r := range g.tabRects {
		if float32(x) >= r.x && float32(x) < r.x+r.w && float32(y) >= r.y && float32(y) < r.y+r.h {
			g.vm.SwitchTab(i)
			return
		}
	}
	// 点击输入栏行 → 聚焦输入。
	_, inputY, _ := g.layout()
	if float32(y) >= inputY && float32(y) < inputY+float32(g.fs.lineH) {
		g.vm.FocusInput()
	}
}

// ---- Draw ----

// Draw 按 Snapshot 绘制。布局：顶栏 1 行 + 标签页 1 行 + 分隔线 + 主体 +
// 输入栏 + 状态行。
func (g *game) Draw(screen *ebiten.Image) {
	w, h := float32(g.w), float32(g.h)
	vector.DrawFilledRect(screen, 0, 0, w, h, colBG, false)

	lh := float32(g.fs.lineH)
	bodyTop, inputY, statusY := g.layout()
	bodyRows := int((inputY - bodyTop) / lh)
	if bodyRows < 1 {
		bodyRows = 1
	}
	g.vm.SetBodyHeight(bodyRows)

	// 顶栏 + 标签页。
	g.drawText(screen, g.fs.small, padX, 6, g.vm.TopLine(), colDim)
	g.drawTabs(screen, bodyTop-lh-6)

	// 主体。
	lines := g.vm.Snapshot()
	g.drawBody(screen, lines, bodyTop, inputY-lh*0.4, bodyRows)

	// 输入栏 + 状态行。
	txt, caret, active := g.vm.InputLine()
	g.drawInput(screen, txt, caret, active, inputY, w)
	g.drawText(screen, g.fs.small, padX, statusY, g.vm.StatusLine(), styleColor(StyleStatus))
}

// layout 返回主体起始 y、输入栏 y、状态行 y。
func (g *game) layout() (bodyTop, inputY, statusY float32) {
	lh := float32(g.fs.lineH)
	bodyTop = 6 + float32(g.fs.small.Metrics().HAscent+g.fs.small.Metrics().HDescent+g.fs.small.Metrics().HLineGap) + lh + 8
	statusY = float32(g.h) - lh - 4
	inputY = statusY - lh - 2
	return
}

func (g *game) drawTabs(screen *ebiten.Image, y float32) {
	lh := float32(g.fs.lineH)
	g.tabRects = g.tabRects[:0]
	x := padX
	active := g.vm.ActiveTab()
	labels := TabLabels()
	for i, name := range labels {
		tw := float32(text.Advance(name, g.fs.body))
		c := colDim
		if i == active {
			c = colTabActive
			vector.DrawFilledRect(screen, x-4, y-2, tw+8, lh+2, colSelBG, true)
		}
		g.drawText(screen, g.fs.body, x, y, name, c)
		g.tabRects = append(g.tabRects, rect{x: x - 4, y: y - 2, w: tw + 12, h: lh + 4})
		x += tw + 16
	}
	lw := float32(g.w) - 2*padX
	vector.DrawFilledRect(screen, padX, y+lh+3, lw, 1, colDivider, false)
}

// drawBody 绘制面板主体。chat 面板：气泡 + 底部锚定滚动 + CJK 换行；
// 其余面板：逐行左对齐。
func (g *game) drawBody(screen *ebiten.Image, lines []ViewLine, top, bottom float32, rows int) {
	lh := float32(g.fs.lineH)
	w := float32(g.w)
	if g.vm.ActiveTab() == 0 { // chat
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
		for _, l := range vis[start:end] {
			frags := wrapText(l.Text, g.fs.body, float64(w-2*padX-56))
			bubble := colBubbleOther
			if l.Style == StyleSelf {
				bubble = colBubbleSelf
			}
			if l.Style == StyleChat || l.Style == StyleSelf {
				bw := float32(text.Advance(frags[len(frags)-1], g.fs.body))
				bx := padX
				if l.Style == StyleSelf {
					bx = w - padX - bw - 8
				}
				for _, f := range frags {
					if y+lh > bottom {
						return
					}
					fw := float32(text.Advance(f, g.fs.body))
					rx := bx - 6
					if l.Style == StyleSelf {
						rx = w - padX - fw - 14
					}
					vector.DrawFilledRect(screen, rx, y+1, fw+12, lh-1, bubble, false)
					g.drawText(screen, g.fs.body, bx, y, f, styleColor(l.Style))
					y += lh
				}
			} else {
				for _, f := range frags {
					if y+lh > bottom {
						return
					}
					g.drawText(screen, g.fs.body, padX, y, f, styleColor(l.Style))
					y += lh
				}
			}
		}
		return
	}
	y := top
	for _, l := range lines {
		if y+lh > bottom {
			return
		}
		if l.Selected {
			vector.DrawFilledRect(screen, padX-6, y-1, w-2*(padX-6), lh, colSelBG, true)
		}
		frags := wrapText(l.Text, g.fs.body, float64(w-2*padX))
		for _, f := range frags {
			if y+lh > bottom {
				return
			}
			mark := "   "
			if l.Selected {
				mark = " > "
			}
			g.drawText(screen, g.fs.body, padX, y, mark+f, styleColor(l.Style))
			y += lh
		}
	}
}

func (g *game) drawInput(screen *ebiten.Image, txt string, caret int, active bool, y, w float32) {
	lh := float32(g.fs.lineH)
	inputRowY := y + 2
	vector.DrawFilledRect(screen, 0, inputRowY-2, w, lh+4, color.RGBA{22, 25, 31, 255}, false)
	vector.DrawFilledRect(screen, 0, inputRowY-2, w, 1, colDivider, false)
	frags := wrapText(txt, g.fs.body, float64(w-2*padX))
	last := frags[len(frags)-1]
	g.drawText(screen, g.fs.body, padX, inputRowY, last, colChat)
	if active {
		r := []rune(last)
		if caret >= len(r) {
			caret = len(r)
		}
		cx := padX + float32(text.Advance(string(r[:caret]), g.fs.body))
		vector.DrawFilledRect(screen, cx+1, inputRowY+2, 2, lh-6, colCaret, false)
	}
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
