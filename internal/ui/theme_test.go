// theme_test.go：v23 主题切换、持久化往返与头像取色。

package ui

import (
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
