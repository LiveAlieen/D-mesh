//go:build windows

// font_windows.go：v19 中文渲染的字体装载（Windows 路径）。
// 依次尝试系统字体 msyh.ttc（微软雅黑集合，取 [0]）→ Deng.ttf → simhei.ttf，
// 全部失败回退内嵌 gofont/goregular（仅拉丁）。不向仓库提交任何字体文件，
// 一切运行期 os.ReadFile 整读后 bytes.NewReader 交给 GoTextFaceSource。

package ui

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hajimehoshi/ebiten/v2/text/v2"
	"golang.org/x/image/font/gofont/goregular"
)

// loadFontSource 返回首个可用的字体源与其来源名。
func loadFontSource() (*text.GoTextFaceSource, string, error) {
	var errs []byte
	try := func(desc string, f func() (*text.GoTextFaceSource, error)) *text.GoTextFaceSource {
		src, err := f()
		if err != nil {
			errs = append(errs, (desc + ": " + err.Error() + "\n")...)
			return nil
		}
		return src
	}
	if src := try(`C:\Windows\Fonts\msyh.ttc`, func() (*text.GoTextFaceSource, error) {
		raw, err := os.ReadFile(`C:\Windows\Fonts\msyh.ttc`)
		if err != nil {
			return nil, err
		}
		srcs, err := text.NewGoTextFaceSourcesFromCollection(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if len(srcs) == 0 {
			return nil, fmt.Errorf("empty font collection")
		}
		return srcs[0], nil
	}); src != nil {
		return src, "msyh.ttc", nil
	}
	for _, p := range []string{`C:\Windows\Fonts\Deng.ttf`, `C:\Windows\Fonts\simhei.ttf`} {
		path := p
		if src := try(path, func() (*text.GoTextFaceSource, error) {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			return text.NewGoTextFaceSource(bytes.NewReader(raw))
		}); src != nil {
			return src, path, nil
		}
	}
	src, err := text.NewGoTextFaceSource(bytes.NewReader(goregular.TTF))
	if err != nil {
		return nil, "", fmt.Errorf("embedded gofont fallback failed: %v (system fonts: %s)", err, bytes.TrimSpace(errs))
	}
	return src, "gofont/goregular (latin only)", nil
}
