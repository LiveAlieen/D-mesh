// theme.go：v23 深浅双主题调色板。所有渲染颜色收敛到这里的 palette，
// game.go 及后续渲染层禁止出现字面量色。默认 light（QQ 浅色风），
// /theme light|dark 运行期即时切换（仅 UI 线程/启动期调用，纪律同 curLang），
// 选择持久化到 <data-dir>/ui_prefs.json（LoadThemePref 启动恢复，
// SetThemeSaver 由宿主接线；headless 不读主题、不装 saver）。

package ui

import (
	"encoding/json"
	"hash/fnv"
	"image/color"
	"os"
	"path/filepath"
	"strings"
)

// ThemeName 是主题标识（/theme 参数、ui_prefs.json 字段值共用）。
type ThemeName string

const (
	ThemeLight ThemeName = "light"
	ThemeDark  ThemeName = "dark"
)

// palette 是渲染层用到的全部颜色 token（一套主题一份）。
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

var palettes = map[ThemeName]palette{
	ThemeLight: {
		WindowBG:    color.RGBA{245, 247, 250, 255},
		ChatBG:      color.RGBA{237, 240, 245, 255},
		BarBG:       color.RGBA{248, 249, 251, 255},
		CardBG:      color.RGBA{255, 255, 255, 255},
		Border:      color.RGBA{217, 222, 228, 255},
		Divider:     color.RGBA{228, 232, 237, 255},
		Accent:      color.RGBA{18, 183, 245, 255},
		SelBG:       color.RGBA{222, 234, 248, 255},
		RowAlt:      color.RGBA{242, 244, 248, 255},
		Text:        color.RGBA{48, 50, 54, 255},
		TextSelf:    color.RGBA{32, 52, 28, 255},
		Meta:        color.RGBA{150, 156, 164, 255},
		System:      color.RGBA{144, 151, 158, 255},
		Header:      color.RGBA{31, 98, 168, 255},
		Dim:         color.RGBA{152, 160, 168, 255},
		Online:      color.RGBA{64, 168, 96, 255},
		Offline:     color.RGBA{176, 182, 188, 255},
		Bad:         color.RGBA{214, 78, 78, 255},
		Owner:       color.RGBA{196, 132, 26, 255},
		Admin:       color.RGBA{146, 84, 222, 255},
		Status:      color.RGBA{140, 100, 20, 255},
		BubbleSelf:  color.RGBA{149, 236, 105, 255},
		BubbleOther: color.RGBA{255, 255, 255, 255},
		Caret:       color.RGBA{48, 50, 54, 255},
		TabActive:   color.RGBA{38, 42, 48, 255},
		Avatar: [8]color.RGBA{
			{255, 150, 130, 255}, {255, 196, 100, 255}, {150, 210, 120, 255}, {110, 200, 220, 255},
			{140, 160, 240, 255}, {200, 140, 230, 255}, {250, 160, 200, 255}, {130, 190, 170, 255},
		},
	},
	ThemeDark: {
		WindowBG:    color.RGBA{30, 34, 39, 255},
		ChatBG:      color.RGBA{23, 26, 30, 255},
		BarBG:       color.RGBA{35, 39, 45, 255},
		CardBG:      color.RGBA{42, 47, 54, 255},
		Border:      color.RGBA{58, 64, 72, 255},
		Divider:     color.RGBA{48, 54, 61, 255},
		Accent:      color.RGBA{51, 169, 223, 255},
		SelBG:       color.RGBA{47, 59, 76, 255},
		RowAlt:      color.RGBA{27, 30, 34, 255},
		Text:        color.RGBA{221, 227, 234, 255},
		TextSelf:    color.RGBA{232, 242, 226, 255},
		Meta:        color.RGBA{138, 146, 155, 255},
		System:      color.RGBA{124, 133, 142, 255},
		Header:      color.RGBA{111, 179, 232, 255},
		Dim:         color.RGBA{129, 138, 147, 255},
		Online:      color.RGBA{108, 207, 124, 255},
		Offline:     color.RGBA{106, 112, 118, 255},
		Bad:         color.RGBA{224, 108, 117, 255},
		Owner:       color.RGBA{123, 216, 143, 255},
		Admin:       color.RGBA{199, 146, 234, 255},
		Status:      color.RGBA{229, 192, 123, 255},
		BubbleSelf:  color.RGBA{74, 122, 66, 255},
		BubbleOther: color.RGBA{42, 47, 54, 255},
		Caret:       color.RGBA{232, 234, 237, 255},
		TabActive:   color.RGBA{240, 243, 246, 255},
		Avatar: [8]color.RGBA{
			{196, 112, 98, 255}, {198, 156, 82, 255}, {118, 168, 96, 255}, {88, 158, 172, 255},
			{108, 126, 198, 255}, {158, 110, 186, 255}, {196, 118, 152, 255}, {108, 156, 140, 255},
		},
	},
}

var (
	curThemeName = ThemeLight // v23 默认浅色
	themeSaver   func(name ThemeName)
)

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

// ThemeList 返回可切换主题名（错误提示用，稳定顺序）。
func ThemeList() string { return string(ThemeLight) + ", " + string(ThemeDark) }

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
