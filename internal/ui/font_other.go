//go:build !windows

// font_other.go：非 Windows 平台的字体装载回退——直接用内嵌
// gofont/goregular（仅拉丁；本项目发布目标为 Windows，此文件只保证可编译）。

package ui

import (
	"bytes"
	"fmt"

	"github.com/hajimehoshi/ebiten/v2/text/v2"
	"golang.org/x/image/font/gofont/goregular"
)

// loadFontSource 返回内嵌拉丁字体源。
func loadFontSource() (*text.GoTextFaceSource, string, error) {
	src, err := text.NewGoTextFaceSource(bytes.NewReader(goregular.TTF))
	if err != nil {
		return nil, "", fmt.Errorf("embedded gofont fallback failed: %w", err)
	}
	return src, "gofont/goregular (latin only)", nil
}
