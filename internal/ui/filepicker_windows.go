// filepicker_windows.go：v25 原生「打开文件」对话框（Windows 路径）。
//
// 纯 syscall 打 comdlg32!GetOpenFileNameW——无 cgo、零新增依赖，守单构建铁律。
// 由 game 在 UI 线程上同步调用（对话框自带消息泵，弹窗期间主循环让位给模态框）。

//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
	procGetActiveWindow  = user32.NewProc("GetActiveWindow")
)

// ofn 是 OPENFILENAMEW 的完整布局（Unicode 版）。
type ofn struct {
	Size              uint32
	Inst              syscall.Handle
	HwndOwner         syscall.Handle
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	nShowState        uint16
	cbReserved        uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
}

const (
	ofnFileMustExist = 0x00000008
	ofnPathMustExist = 0x00000800
	ofnHideReadOnly  = 0x00000004

	// 用户点了「取消」时 GetOpenFileNameW 返回 0，错误码为 ERROR_CANCELLED。
	errCancelled = syscall.Errno(1223)
)

const nativePickerAvailable = true

// pickNativeFile 弹出系统「打开」对话框。ok=false 且 err==nil 表示用户取消。
// 调用方须在持有本窗口 HWND 的 UI 线程上同步调用（game.pickFile 里直接调，
// 协程换线程会让对话框关闭后鼠标捕获失效）。
func pickNativeFile(title string) (path string, ok bool, err error) {
	buf := make([]uint16, 4096)
	filter, ferr := utf16Filter(Tr("dialog.filterAll"), "*.*")
	if ferr != nil {
		return "", false, ferr
	}
	ttl, terr := syscall.UTF16PtrFromString(title)
	if terr != nil {
		return "", false, terr
	}
	var o ofn
	o.Size = uint32(unsafe.Sizeof(o))
	o.HwndOwner = activeWindow()
	o.LpstrFilter = filter
	o.LpstrFile = &buf[0]
	o.NMaxFile = uint32(len(buf))
	o.LpstrTitle = ttl
	o.Flags = ofnFileMustExist | ofnPathMustExist | ofnHideReadOnly

	r, _, werr := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&o)))
	if r == 0 {
		if werr == errCancelled {
			return "", false, nil
		}
		return "", false, werr
	}
	return utf16First(buf), true, nil
}

// utf16Filter 拼「显示名\0模式\0\0」的双空结尾过滤器串（UTF16PtrFromString
// 拒绝内嵌 NUL，故逐段编码后手工串接）。
func utf16Filter(display, pattern string) (*uint16, error) {
	a, err := syscall.UTF16FromString(display)
	if err != nil {
		return nil, err
	}
	b, err := syscall.UTF16FromString(pattern)
	if err != nil {
		return nil, err
	}
	joined := append(a, b...)
	joined = append(joined, 0) // 结尾多一个空串
	return &joined[0], nil
}

func utf16First(buf []uint16) string {
	for i, u := range buf {
		if u == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

// activeWindow 取当前活动窗口作对话框父窗口（拿不到就 0，对话框仍可用）。
func activeWindow() syscall.Handle {
	h, _, _ := procGetActiveWindow.Call()
	return syscall.Handle(h)
}
