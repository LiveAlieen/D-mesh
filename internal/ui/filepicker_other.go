// filepicker_other.go：非 Windows 平台没有内置原生选择框实现，
// 「上传/核对种子」按钮自动回退为手输路径文本框（功能不缺失）。

//go:build !windows

package ui

import "errors"

const nativePickerAvailable = false

func pickNativeFile(string) (string, bool, error) {
	return "", false, errors.New("native file picker not supported on this platform")
}
