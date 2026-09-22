package store

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxLineBytes 限制单行 JSONL 的最大长度（消息 content 上限由协议层管，
// 这里只防御性地把控重建时的内存峰值）。
const maxLineBytes = 8 << 20 // 8 MiB

// truncateTail 删除文件末尾没有换行符的残缺行（崩溃时半截写入）。
func truncateTail(path string) error {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1)
	off := st.Size() - 1
	if _, err := f.ReadAt(buf, off); err != nil {
		return fmt.Errorf("store: read jsonl tail: %w", err)
	}
	if buf[0] == '\n' {
		return nil
	}
	// 从尾部向前找最后一个换行
	for off > 0 {
		if _, err := f.ReadAt(buf, off-1); err != nil {
			return fmt.Errorf("store: read jsonl tail: %w", err)
		}
		if buf[0] == '\n' {
			break
		}
		off--
	}
	if off == 0 && buf[0] != '\n' {
		// 整个文件都没有换行 = 一条残缺记录，清空
		return f.Truncate(0)
	}
	return f.Truncate(off)
}

// scanLines 逐行读取 JSONL；skip 为 true 的行（空行/解析失败）被计数跳过。
// fn 返回错误则中止。
func scanLines(path string, fn func(raw []byte) error) (skipped int, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) > 0 {
				if len(trimmed) > maxLineBytes {
					skipped++
				} else if err := fn(trimmed); err != nil {
					return skipped, err
				}
			}
		}
		if readErr == io.EOF {
			return skipped, nil
		}
		if readErr != nil {
			return skipped, readErr
		}
	}
}

// jsonlPath 内部小工具。
func (s *Store) jsonlPath() string { return filepath.Join(s.dir, jsonlName) }
