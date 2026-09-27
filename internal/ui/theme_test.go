// theme_test.go：v23 主题切换、持久化往返与头像取色。

package ui

import (
	"image/color"
	"os"
	"path/filepath"
	"testing"
)

func TestSetThemeValidates(t *testing.T) {
	defer SetTheme(string(GetTheme()))
	if GetTheme() != ThemeLight {
		t.Fatalf("default theme = %q, want light", GetTheme())
	}
	if !SetTheme("dark") || GetTheme() != ThemeDark {
		t.Fatal("SetTheme(dark) failed")
	}
	if !SetTheme(" LIGHT ") || GetTheme() != ThemeLight {
		t.Fatal("SetTheme should trim+lowercase")
	}
	if SetTheme("neon") || GetTheme() != ThemeLight {
		t.Fatal("unknown theme must not switch")
	}
	if ThemeList() == "" {
		t.Fatal("ThemeList must list options")
	}
}

func TestThemeSaverFires(t *testing.T) {
	defer SetThemeSaver(nil)
	defer SetTheme(string(GetTheme()))
	var got ThemeName
	SetThemeSaver(func(name ThemeName) { got = name })
	if !SetTheme("dark") || got != ThemeDark {
		t.Fatalf("saver got %q", got)
	}
	SetTheme("neon")
	if got != ThemeDark {
		t.Fatalf("failed switch must not fire saver: %q", got)
	}
}

func TestThemePrefRoundTrip(t *testing.T) {
	defer SetTheme(string(GetTheme()))
	dir := t.TempDir()
	// 缺文件=保持默认，不报错。
	SetTheme(string(ThemeLight))
	LoadThemePref(dir)
	if GetTheme() != ThemeLight {
		t.Fatalf("missing prefs changed theme: %q", GetTheme())
	}
	if err := SaveThemePref(dir, ThemeDark); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "ui_prefs.json")); err != nil || !contains(string(b), "dark") {
		t.Fatalf("prefs file: %s %v", b, err)
	}
	SetTheme(string(ThemeLight))
	LoadThemePref(dir)
	if GetTheme() != ThemeDark {
		t.Fatalf("LoadThemePref did not restore: %q", GetTheme())
	}
	// 损坏 JSON 静默忽略。
	os.WriteFile(filepath.Join(dir, "ui_prefs.json"), []byte("{oops"), 0o644)
	SetTheme(string(ThemeLight))
	LoadThemePref(dir)
	if GetTheme() != ThemeLight {
		t.Fatalf("corrupt prefs must be ignored: %q", GetTheme())
	}
}

func TestAvatarColorStableAndInitials(t *testing.T) {
	p := palettes[ThemeLight]
	if avatarColor("ed25519:aabb", p) != avatarColor("ed25519:aabb", p) {
		t.Fatal("same sender must map to same color")
	}
	if avatarInitials("ed25519:aabbccdd") != "AA" {
		t.Fatalf("initials = %q", avatarInitials("ed25519:aabbccdd"))
	}
	if avatarInitials("ff") != "FF" {
		t.Fatalf("short initials = %q", avatarInitials("ff"))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestParseHexColor(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want color.RGBA
	}{
		{"#fff", color.RGBA{255, 255, 255, 255}},
		{"#95EC69", color.RGBA{149, 236, 105, 255}},
		{"#00000080", color.RGBA{0, 0, 0, 128}},
	} {
		got, err := parseHexColor(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseHexColor(%q) = %v, %v", tc.in, got, err)
		}
	}
	for _, bad := range []string{"fff", "#", "#gg0000", "#12345", ""} {
		if _, err := parseHexColor(bad); err == nil {
			t.Errorf("parseHexColor(%q) must fail", bad)
		}
	}
}

// v24：内置主题文件必须与 v23 Go 字面量逐一等价（渲染零漂移）——抽查代表性 token。
func TestEmbeddedThemesMatchV23Literals(t *testing.T) {
	l := palettes[ThemeLight]
	d := palettes[ThemeDark]
	checks := []struct {
		name string
		got  color.RGBA
		want color.RGBA
	}{
		{"light.chatBG", l.ChatBG, color.RGBA{237, 240, 245, 255}},
		{"light.accent", l.Accent, color.RGBA{18, 183, 245, 255}},
		{"light.bubbleSelf", l.BubbleSelf, color.RGBA{149, 236, 105, 255}},
		{"light.status", l.Status, color.RGBA{140, 100, 20, 255}},
		{"light.avatar0", l.Avatar[0], color.RGBA{255, 150, 130, 255}},
		{"dark.windowBG", d.WindowBG, color.RGBA{30, 34, 39, 255}},
		{"dark.bubbleSelf", d.BubbleSelf, color.RGBA{74, 122, 66, 255}},
		{"dark.avatar7", d.Avatar[7], color.RGBA{108, 156, 140, 255}},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadThemeDirOverlayAndNew(t *testing.T) {
	defer SetTheme(string(GetTheme()))
	dir := t.TempDir()
	// 目录不存在=无外置主题，返回 nil。
	if err := LoadThemeDir(filepath.Join(dir, "nope")); err != nil {
		t.Fatalf("missing dir must be nil: %v", err)
	}
	// 新主题（小写文件名 extTest 落为 exttest）：以 light 为底只覆盖 bubbleSelf。
	if err := os.WriteFile(filepath.Join(dir, "extTest.json"),
		[]byte(`{"bubbleSelf":"#FF00FF","unknownToken":"#000000","avatar":["#010203"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// 同名文件=按 token 覆盖内置 light。
	if err := os.WriteFile(filepath.Join(dir, "light.json"),
		[]byte(`{"header":"#123456"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// 非法文件只跳过自身，错误聚合返回，不影响其余。
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{oops"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := LoadThemeDir(dir)
	if err == nil || !contains(err.Error(), "broken.json") {
		t.Fatalf("bad file must aggregate: %v", err)
	}
	if !SetTheme("exttest") {
		t.Fatal("external theme must be switchable")
	}
	if p := Pal(); p.BubbleSelf != (color.RGBA{255, 0, 255, 255}) || p.Avatar[0] != (color.RGBA{1, 2, 3, 255}) ||
		p.ChatBG != palettes[ThemeLight].ChatBG {
		t.Fatalf("ext theme merge wrong: %+v", p)
	}
	if palettes[ThemeLight].Header != (color.RGBA{0x12, 0x34, 0x56, 255}) {
		t.Fatal("same-name overlay must replace built-in token")
	}
	if !contains(ThemeList(), "exttest") {
		t.Fatalf("ThemeList must include external theme: %s", ThemeList())
	}
	SetTheme(string(ThemeLight))
}
