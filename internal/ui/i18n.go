// i18n.go：GUI 用户可见文案的多语言目录（v20；v21 起词条落文件）。
//
// 词条存于 JSON 语言文件：内置语言在 internal/ui/langs/<code>.json，
// 编译期 go:embed 内嵌（单构建铁律不破，分发自带中英）；运行期可叠加
// 外置目录 <data-dir>/langs/*.json——新文件=新语言、同名文件=按键覆盖
// 内置词条，加语言不改代码不重编译（v21）。
//
// en 为源语言：缺键回退链 当前语言 → en → 键名原样。
// 全部取串走 Tr/Tf：命令名（/kick…）与协议 token（sig_alg、perm 名、
// pubkey hex、mode、seed=OK 之类的结构位）不翻译——它们是协议面而非
// UI 文案；消息正文永远原样显示。
//
// 语言选择：初始语言固定 zh（v22，用户裁定「默认语言为中文」；zh 文件缺失
// 的极端情况回退 en），/lang <code> 运行期切换即时生效（每帧绘制都现取目录）。

package ui

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Lang 是界面语言代码。v21 起语言集合由语言文件驱动，不限于内置 en/zh。
type Lang string

const (
	LangEn Lang = "en"
	LangZh Lang = "zh"
)

// SupportedLangs 返回当前已加载的全部语言（内置+外置），按代码排序。
func SupportedLangs() []Lang {
	out := make([]Lang, 0, len(catalogs))
	for l := range catalogs {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LangList 把已加载语言拼成展示串（"en, zh, ja"），供提示文案用。
func LangList() string {
	langs := SupportedLangs()
	parts := make([]string, len(langs))
	for i, l := range langs {
		parts[i] = string(l)
	}
	return strings.Join(parts, ", ")
}

// curLang 初值在 init() 里定为 zh（v22 默认中文）；此处占位保证零值安全。
var curLang = LangEn

// SetLang 切换界面语言；未加载的语言返回 false 且不变。
// 仅限启动/UI 事件循环线程调用（与 curLang 读写方一致）。
func SetLang(l Lang) bool {
	if _, ok := catalogs[l]; !ok {
		return false
	}
	curLang = l
	return true
}

// GetLang 返回当前界面语言。
func GetLang() Lang { return curLang }

// Tr 按当前语言取模板串；当前语言缺键回退 en，再缺则原样返回键。
func Tr(key string) string {
	if m, ok := catalogs[curLang][key]; ok {
		return m
	}
	if m, ok := catalogs[LangEn][key]; ok {
		return m
	}
	return key
}

// Tf 按当前语言取模板并格式化。
func Tf(key string, args ...any) string {
	if len(args) == 0 {
		return Tr(key)
	}
	return fmt.Sprintf(Tr(key), args...)
}

//go:embed langs/*.json
var embeddedLangs embed.FS

// catalogs 内置 + 外置语言文件合并后的词条表：语言 → 键 → 模板串。
var catalogs = map[Lang]map[string]string{}

func init() {
	entries, err := fs.ReadDir(embeddedLangs, "langs")
	if err != nil {
		panic("i18n: embedded langs unreadable: " + err.Error())
	}
	for _, e := range entries {
		b, err := embeddedLangs.ReadFile("langs/" + e.Name())
		if err != nil {
			panic("i18n: embedded " + e.Name() + ": " + err.Error())
		}
		// 内置文件随二进制分发，解析失败=打包错误，直接 panic。
		if err := mergeCatalog(b, strings.TrimSuffix(e.Name(), ".json")); err != nil {
			panic("i18n: embedded " + e.Name() + ": " + err.Error())
		}
	}
	if _, ok := catalogs[LangEn]; !ok {
		catalogs[LangEn] = map[string]string{} // Tr 回退链要求 en 恒存在
	}
	// v22：默认语言固定中文（不再按系统 locale 检测）；zh 缺失回退 en。
	if _, ok := catalogs[LangZh]; ok {
		curLang = LangZh
	}
}

// LoadLangDir 把外置语言目录叠加进内置目录（v21）：目录下 <code>.json，
// 新文件=新语言、同名文件=按键覆盖内置词条。目录不存在视为无外置语言，
// 返回 nil；单个文件非法只跳过该文件，错误聚合返回、不影响其余加载。
// 仅限启动阶段（UI 打开前）调用。
func LoadLangDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("langs dir: %w", err)
	}
	var bad []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		code := strings.TrimSuffix(name, ".json")
		if code == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if err := mergeCatalog(b, code); err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("skipped %d bad lang file(s) in %s: %s", len(bad), dir, strings.Join(bad, "; "))
	}
	return nil
}

func mergeCatalog(data []byte, code string) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("lang %q: %w", code, err)
	}
	l := Lang(code)
	if catalogs[l] == nil {
		catalogs[l] = map[string]string{}
	}
	for k, v := range m {
		catalogs[l][k] = v
	}
	return nil
}
