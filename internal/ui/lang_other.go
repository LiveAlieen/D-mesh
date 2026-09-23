//go:build !windows

package ui

import "os"

// detectSystemLang 在非 Windows 上读 LC_ALL/LANG 环境变量，"zh" 前缀 → zh。
func detectSystemLang() Lang {
	for _, key := range []string{"LC_ALL", "LANG"} {
		if v := os.Getenv(key); v != "" {
			if len(v) >= 2 && v[:2] == "zh" {
				return LangZh
			}
			return LangEn
		}
	}
	return LangEn
}
