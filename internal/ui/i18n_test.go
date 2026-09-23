// i18n_test.go：多语言目录（v20）与语言文件化（v21）的完整性、加载与切换行为。

package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogKeySetsMatch(t *testing.T) {
	en, zh := catalogs[LangEn], catalogs[LangZh]
	if len(en) == 0 || len(zh) == 0 {
		t.Fatal("embedded catalogs must be non-empty")
	}
	for k := range en {
		if _, ok := zh[k]; !ok {
			t.Errorf("zh catalog missing key %q", k)
		}
	}
	for k := range zh {
		if _, ok := en[k]; !ok {
			t.Errorf("en catalog missing key %q", k)
		}
	}
}

func TestTrFallback(t *testing.T) {
	defer SetLang(GetLang())
	SetLang(LangZh)
	if got := Tr("panel.chat"); got != "聊天" {
		t.Fatalf("zh panel.chat = %q", got)
	}
	// 当前语言缺键 → 回退 en；两边都缺 → 原样返回键。
	if got := Tr("p.members.header"); got != "成员 — 在线/离线/最后活跃（v13.1，本面板只读）" {
		t.Fatalf("zh members header = %q", got)
	}
	if got := Tr("no.such.key.ever"); got != "no.such.key.ever" {
		t.Fatalf("unknown key = %q", got)
	}
	SetLang(LangEn)
	if got := Tr("panel.chat"); got != "chat" {
		t.Fatalf("en panel.chat = %q", got)
	}
}

func TestSetLangRejectsUnknown(t *testing.T) {
	defer SetLang(GetLang())
	before := GetLang()
	if SetLang(Lang("fr")) {
		t.Fatal("SetLang(fr) should return false")
	}
	if GetLang() != before {
		t.Fatalf("unknown SetLang changed language to %q", GetLang())
	}
	if !SetLang(LangEn) || !SetLang(LangZh) {
		t.Fatal("supported langs must be accepted")
	}
}

func TestLangCommandDispatch(t *testing.T) {
	defer SetLang(GetLang())
	v := newViewModel(nil)
	v.dispatch(Command{Kind: CmdLang, Lang: "zh"})
	if GetLang() != LangZh {
		t.Fatalf("after /lang zh, lang=%q", GetLang())
	}
	if !strings.Contains(v.status, "zh") && !strings.Contains(v.status, "语言") {
		t.Fatalf("status not localized feedback: %q", v.status)
	}
	v.dispatch(Command{Kind: CmdLang, Lang: "en"})
	if GetLang() != LangEn {
		t.Fatalf("after /lang en, lang=%q", GetLang())
	}
	v.dispatch(Command{Kind: CmdLang, Lang: "de"})
	if GetLang() != LangEn {
		t.Fatalf("bad lang must not switch: %q", GetLang())
	}
	if !strings.Contains(v.status, "de") {
		t.Fatalf("bad lang status: %q", v.status)
	}
	c, err := ParseCommand("/lang zh")
	if err != nil || c.Kind != CmdLang || c.Lang != "zh" {
		t.Fatalf("ParseCommand(/lang zh) = %+v, %v", c, err)
	}
	if c, err := ParseCommand("/lang"); err != nil || c.Kind != CmdLang || c.Lang != "" {
		t.Fatalf("ParseCommand(/lang) = %+v, %v", c, err)
	}
}

// ---- v21：语言文件化 ----

func TestLoadLangDirAddsAndOverrides(t *testing.T) {
	defer SetLang(GetLang())
	const code = "qq" // 测试专用语言代码，避免与真实语言冲突
	defer delete(catalogs, Lang(code))
	zhBackup, had := catalogs[LangZh]["panel.chat"]
	defer func() {
		if had {
			catalogs[LangZh]["panel.chat"] = zhBackup
		} else {
			delete(catalogs[LangZh], "panel.chat")
		}
	}()

	dir := t.TempDir()
	// 新语言：只给两个键，其余键走 en 回退链。
	writeLang(t, dir, code+".json", map[string]string{
		"panel.chat": "チャット",
		"role.owner": "オーナー",
	})
	// 同名覆盖：给 zh 追加/覆盖一个键。
	writeLang(t, dir, "zh.json", map[string]string{"panel.chat": "聊天(覆盖)"})
	// 非法文件：跳过且聚合报错，不影响其他文件。
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := LoadLangDir(dir)
	if err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("bad file must be reported: %v", err)
	}
	if catalogs[Lang(code)]["panel.chat"] != "チャット" {
		t.Fatalf("new language not loaded: %v", catalogs[Lang(code)])
	}
	if catalogs[LangZh]["panel.chat"] != "聊天(覆盖)" {
		t.Fatalf("override not applied: %q", catalogs[LangZh]["panel.chat"])
	}
	if !SetLang(Lang(code)) {
		t.Fatal("loaded language must be switchable")
	}
	if got := Tr("panel.chat"); got != "チャット" {
		t.Fatalf("Tr after switch = %q", got)
	}
	if got := Tr("panel.members"); got != "members" { // 缺键 → en 回退
		t.Fatalf("fallback to en = %q", got)
	}
	// 语言集合动态可见 + /lang 错误提示列出可选项。
	found := false
	for _, l := range SupportedLangs() {
		if l == Lang(code) {
			found = true
		}
	}
	if !found {
		t.Fatalf("SupportedLangs missing %q: %v", code, SupportedLangs())
	}
	// 目录不存在 = 静默无操作。
	if err := LoadLangDir(filepath.Join(dir, "nope")); err != nil {
		t.Fatalf("missing dir must be no-op: %v", err)
	}
}

func writeLang(t *testing.T, dir, name string, m map[string]string) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
