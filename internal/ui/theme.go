// theme.go：v23 深浅双主题调色板，v24 起主题文件化（仿 v21 语言文件）。
// 所有渲染颜色收敛到这里的 palette，game.go 及后续渲染层禁止出现字面量色。
// 调色板不再写死在 Go 代码：内置主题= internal/ui/themes/<name>.json 经
// go:embed 内嵌（单构建铁律不破）；运行期可叠加外置目录
// <data-dir>/themes/*.json——新文件=新主题、同名文件=按 token 覆盖
// （LoadThemeDir，与 LoadLangDir 同接线点）。token 键=palette 字段小驼峰、
// 色值 #RGB/#RRGGBB/#RRGGBBAA、avatar=色值数组（不足 8 位补底）、未知键忽略
// 保持前向兼容；新建主题以 light 为底合并，允许只写差异 token。
// 默认 light（QQ 浅色风），/theme <name> 运行期即时切换（仅 UI 线程/启动期
// 调用，纪律同 curLang），选择持久化到 <data-dir>/ui_prefs.json
// （LoadThemePref 启动恢复，SetThemeSaver 由宿主接线；
// headless 不读主题偏好、但加载 themes 目录）。

package ui

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"image/color"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ThemeName 是主题标识（/theme 参数、ui_prefs.json 字段值共用）。
type ThemeName string

const (
	ThemeLight ThemeName = "light"
	ThemeDark  ThemeName = "dark"
)

// palette 是渲染层用到的全部颜色 token（一套主题一份，来自主题文件）。
type palette struct {
	WindowBG    color.RGBA // 窗口/面板底
	ChatBG      color.RGBA // 聊天区底（QQ 浅灰蓝）
	BarBG       color.RGBA // 顶/底状态带
	CardBG      color.RGBA // 输入框/卡片
	Border      color.RGBA // 描边
	Divider     color.RGBA // 分割线
	Accent      color.RGBA // 强调色（下划线/选中竖条）
	SelBG       color.RGBA // 列表选中行底
	RowAlt      color.RGBA // 斑马纹
	Text        color.RGBA // 聊天/正文默认字色
	TextSelf    color.RGBA // 自身气泡字色
	Meta        color.RGBA // 气泡上方 名·时间 小字
	System      color.RGBA // 系统行（居中灰字）
	Header      color.RGBA // 面板小节标题
	Dim         color.RGBA // 次要提示
	Online      color.RGBA
	Offline     color.RGBA
	Bad         color.RGBA
	Owner       color.RGBA
	Admin       color.RGBA
	Status      color.RGBA // 底部状态行
	BubbleSelf  color.RGBA // 自身气泡（QQ 绿）
	BubbleOther color.RGBA // 他人气泡（白/深卡）
	Caret       color.RGBA
	TabActive   color.RGBA    // 激活标签字色
	Avatar      [8]color.RGBA // 头像色块循环表（QQ 彩色系）
}

// tokenSetters 把主题 JSON 的小驼峰键映射到 palette 字段。
var tokenSetters = map[string]func(*palette, color.RGBA){
	"windowBG":    func(p *palette, c color.RGBA) { p.WindowBG = c },
	"chatBG":      func(p *palette, c color.RGBA) { p.ChatBG = c },
	"barBG":       func(p *palette, c color.RGBA) { p.BarBG = c },
	"cardBG":      func(p *palette, c color.RGBA) { p.CardBG = c },
	"border":      func(p *palette, c color.RGBA) { p.Border = c },
	"divider":     func(p *palette, c color.RGBA) { p.Divider = c },
	"accent":      func(p *palette, c color.RGBA) { p.Accent = c },
	"selBG":       func(p *palette, c color.RGBA) { p.SelBG = c },
	"rowAlt":      func(p *palette, c color.RGBA) { p.RowAlt = c },
	"text":        func(p *palette, c color.RGBA) { p.Text = c },
	"textSelf":    func(p *palette, c color.RGBA) { p.TextSelf = c },
	"meta":        func(p *palette, c color.RGBA) { p.Meta = c },
	"system":      func(p *palette, c color.RGBA) { p.System = c },
	"header":      func(p *palette, c color.RGBA) { p.Header = c },
	"dim":         func(p *palette, c color.RGBA) { p.Dim = c },
	"online":      func(p *palette, c color.RGBA) { p.Online = c },
	"offline":     func(p *palette, c color.RGBA) { p.Offline = c },
	"bad":         func(p *palette, c color.RGBA) { p.Bad = c },
	"owner":       func(p *palette, c color.RGBA) { p.Owner = c },
	"admin":       func(p *palette, c color.RGBA) { p.Admin = c },
	"status":      func(p *palette, c color.RGBA) { p.Status = c },
	"bubbleSelf":  func(p *palette, c color.RGBA) { p.BubbleSelf = c },
	"bubbleOther": func(p *palette, c color.RGBA) { p.BubbleOther = c },
	"caret":       func(p *palette, c color.RGBA) { p.Caret = c },
	"tabActive":   func(p *palette, c color.RGBA) { p.TabActive = c },
}

//go:embed themes/*.json
var embeddedThemes embed.FS

// palettes 是内置 + 外置主题文件合并后的调色板表。
var palettes = map[ThemeName]palette{}

func init() {
	entries, err := fs.ReadDir(embeddedThemes, "themes")
	if err != nil {
		panic("themes: embedded themes unreadable: " + err.Error())
	}
	for _, e := range entries {
		b, err := embeddedThemes.ReadFile("themes/" + e.Name())
		if err != nil {
			panic("themes: embedded " + e.Name() + ": " + err.Error())
		}
		// 内置文件随二进制分发，解析失败=打包错误，直接 panic。
		if err := mergeTheme(b, strings.TrimSuffix(e.Name(), ".json")); err != nil {
			panic("themes: embedded " + e.Name() + ": " + err.Error())
		}
	}
	if _, ok := palettes[ThemeLight]; !ok {
		panic("themes: embedded light.json missing")
	}
}

var (
	curThemeName = ThemeLight // v23 默认浅色
	themeSaver   func(name ThemeName)
)

// parseHexColor 接受 #RGB / #RRGGBB / #RRGGBBAA（大小写不限）。
func parseHexColor(s string) (color.RGBA, error) {
	bad := func() (color.RGBA, error) {
		return color.RGBA{}, fmt.Errorf("bad color %q (want #RGB/#RRGGBB/#RRGGBBAA)", s)
	}
	if len(s) == 0 || s[0] != '#' {
		return bad()
	}
	digits := s[1:]
	out := color.RGBA{A: 255}
	switch len(digits) {
	case 3:
		digits = string([]byte{digits[0], digits[0], digits[1], digits[1], digits[2], digits[2]})
	case 6:
	case 8:
		a, err := hexByte(digits[6:8])
		if err != nil {
			return bad()
		}
		out.A = a
		digits = digits[:6]
	default:
		return bad()
	}
	for i := 0; i < 3; i++ {
		v, err := hexByte(digits[i*2 : i*2+2])
		if err != nil {
			return bad()
		}
		switch i {
		case 0:
			out.R = v
		case 1:
			out.G = v
		case 2:
			out.B = v
		}
	}
	return out, nil
}

func hexByte(s string) (byte, error) {
	var v uint8
	for _, c := range []byte(s) {
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + c - '0'
		case c >= 'a' && c <= 'f':
			v = v*16 + c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = v*16 + c - 'A' + 10
		default:
			return 0, fmt.Errorf("bad hex digit %q in %q", c, s)
		}
	}
	return v, nil
}

// mergeTheme 把一份主题 JSON 合并进 palettes：同名=按 token 覆盖，
// 新名=以 light 为底新建（若有）。未知键忽略（前向兼容），avatar 为
// 色值数组、不足 8 位保留底色。仅限启动/测试阶段调用。
func mergeTheme(data []byte, name string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("theme %q: %w", name, err)
	}
	t := ThemeName(strings.ToLower(strings.TrimSpace(name)))
	if t == "" {
		return errors.New("theme: empty name")
	}
	p, ok := palettes[t]
	if !ok {
		if base, has := palettes[ThemeLight]; has {
			p = base
		}
	}
	for k, raw := range m {
		if k == "avatar" {
			var hs []string
			if err := json.Unmarshal(raw, &hs); err != nil {
				return fmt.Errorf("theme %q: avatar: %w", t, err)
			}
			for i, h := range hs {
				if i >= len(p.Avatar) {
					break
				}
				c, err := parseHexColor(h)
				if err != nil {
					return fmt.Errorf("theme %q: avatar: %w", t, err)
				}
				p.Avatar[i] = c
			}
			continue
		}
		set, known := tokenSetters[k]
		if !known {
			continue // 未知 token：忽略而非报错，新版本文件对旧版本二进制仍可用
		}
		var h string
		if err := json.Unmarshal(raw, &h); err != nil {
			return fmt.Errorf("theme %q: %s: %w", t, k, err)
		}
		c, err := parseHexColor(h)
		if err != nil {
			return fmt.Errorf("theme %q: %s: %w", t, k, err)
		}
		set(&p, c)
	}
	palettes[t] = p
	return nil
}

// LoadThemeDir 把外置主题目录叠加进内置主题（v24）：目录下 <name>.json，
// 新文件=新主题、同名文件=按 token 覆盖。目录不存在视为无外置主题，
// 返回 nil；单个文件非法只跳过该文件，错误聚合返回、不影响其余加载。
// 仅限启动阶段（UI 打开前）调用。
func LoadThemeDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("themes dir: %w", err)
	}
	var bad []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		base := strings.TrimSuffix(name, ".json")
		if base == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if err := mergeTheme(b, base); err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("skipped %d bad theme file(s) in %s: %s", len(bad), dir, strings.Join(bad, "; "))
	}
	return nil
}

// Pal 返回当前主题调色板（game 绘制帧内读取；切换只在 UI 线程发生）。
func Pal() palette { return palettes[curThemeName] }

// GetTheme 返回当前主题名。
func GetTheme() ThemeName { return curThemeName }

// SetTheme 切换主题；未知名字返回 false 且不改状态。成功后调用已接线的
// saver 持久化（saver 由宿主注入，可能做小文件 IO——仅 UI 线程调用）。
func SetTheme(name string) bool {
	t := ThemeName(strings.ToLower(strings.TrimSpace(name)))
	if _, ok := palettes[t]; !ok {
		return false
	}
	curThemeName = t
	if themeSaver != nil {
		themeSaver(t)
	}
	return true
}

// SupportedThemes 返回全部已加载主题名（升序，稳定）。
func SupportedThemes() []ThemeName {
	out := make([]ThemeName, 0, len(palettes))
	for t := range palettes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ThemeList 返回可切换主题名（错误提示用，升序稳定）。
func ThemeList() string {
	parts := make([]string, 0, len(palettes))
	for _, t := range SupportedThemes() {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ", ")
}

// SetThemeSaver 由宿主接线持久化回调（GUI 启动时挂，headless 不挂）。
func SetThemeSaver(save func(name ThemeName)) { themeSaver = save }

// uiPrefsPath 是主题持久化文件（<data-dir>/ui_prefs.json）。
func uiPrefsPath(dataDir string) string { return filepath.Join(dataDir, "ui_prefs.json") }

// LoadThemePref 从 <data-dir>/ui_prefs.json 恢复主题；文件缺失/损坏=静默
// 保持默认 light（首启无配置是常态，不是错误）。
func LoadThemePref(dataDir string) {
	b, err := os.ReadFile(uiPrefsPath(dataDir))
	if err != nil {
		return
	}
	var p struct {
		Theme string `json:"theme"`
	}
	if json.Unmarshal(b, &p) != nil {
		return
	}
	t := ThemeName(strings.ToLower(strings.TrimSpace(p.Theme)))
	if _, ok := palettes[t]; ok {
		curThemeName = t
	}
}

// SaveThemePref 写主题偏好文件（saver 接线的实现，宿主传 dataDir）。
func SaveThemePref(dataDir string, name ThemeName) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(map[string]string{"theme": string(name)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(uiPrefsPath(dataDir), b, 0o644)
}

// avatarColor 按发送者标识稳定取色（同一人跨主题恒同位）。
func avatarColor(id string, p palette) color.RGBA {
	h := fnv.New32a()
	h.Write([]byte(id))
	return p.Avatar[int(h.Sum32())%len(p.Avatar)]
}

// avatarInitials 取头像字母：ShortID 去 alg 前缀后的前两位大写。
func avatarInitials(id string) string {
	s := id
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	r := []rune(strings.ToUpper(s))
	if len(r) > 2 {
		r = r[:2]
	}
	return string(r)
}
