// i18n_test.go：v20 多语言目录的完整性与切换行为。

package ui

import (
	"strings"
	"testing"
)

func TestCatalogKeySetsMatch(t *testing.T) {
	for k := range catalogEn {
		if _, ok := catalogZh[k]; !ok {
			t.Errorf("zh catalog missing key %q", k)
		}
	}
	for k := range catalogZh {
		if _, ok := catalogEn[k]; !ok {
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
