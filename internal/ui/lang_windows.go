//go:build windows

package ui

import "syscall"

// detectSystemLang 按 Windows 显示语言选界面语言：
// kernel32!GetUserDefaultUILanguage 的 PRIMARYLANGID==0x04（中文）→ zh，
// 其余回退 en。纯 syscall，无 cgo。
func detectSystemLang() Lang {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetUserDefaultUILanguage")
	langID, _, _ := proc.Call()
	if uintptr(uint16(langID)&0x3FF) == 0x04 { // PRIMARYLANGID == LANG_CHINESE
		return LangZh
	}
	return LangEn
}
