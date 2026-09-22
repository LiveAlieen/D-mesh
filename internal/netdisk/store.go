package netdisk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// BlockStore 是「一个成员本地的定额目录」抽象：落盘本成员承载的块并守住配额。
// MemStore 供测试与内存模式；DirStore 是生产用的本地定额目录实现。
type BlockStore interface {
	// Put 存一块（按 FileID/Stripe/Pos 定位，重复 Put 覆盖）。超配额返回 ErrQuotaFull。
	Put(b *Block) error
	// Get 取块；不存在返回包装 ErrNotFound 的错误。
	Get(fileID string, stripe, pos int) (*Block, error)
	// List 列出某文件在本成员盘上的全部块（下载/重平衡收集用）。
	List(fileID string) ([]*Block, error)
	// Delete 删块；不存在视为成功。
	Delete(fileID string, stripe, pos int) error
	// Usage 返回已占用字节（按块数据长度计）。
	Usage() int64
	// Quota 返回本目录配额字节上限。
	Quota() int64
}

func blockKey(fileID string, stripe, pos int) string {
	return fmt.Sprintf("%s/%09d/%03d", fileID, stripe, pos)
}

// MemStore 是内存块存储（测试与临时缓存用），并发安全。
type MemStore struct {
	mu     sync.Mutex
	quota  int64
	usage  int64
	blocks map[string]*Block
}

// NewMemStore 建一个配额为 quotaBytes 的内存定额目录。
func NewMemStore(quotaBytes int64) *MemStore {
	return &MemStore{quota: quotaBytes, blocks: map[string]*Block{}}
}

// Put 存块（深拷贝，防调用方事后改数据）。
func (s *MemStore) Put(b *Block) error {
	if b == nil || len(b.Data) == 0 {
		return ErrBadBlock
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := blockKey(b.FileID, b.Stripe, b.Pos)
	delta := int64(len(b.Data))
	if old, ok := s.blocks[k]; ok {
		delta -= int64(len(old.Data))
	}
	if s.quota > 0 && s.usage+delta > s.quota {
		return fmt.Errorf("%w: need %d more of %d", ErrQuotaFull, delta, s.quota)
	}
	cp := *b
	cp.Data = append([]byte(nil), b.Data...)
	s.blocks[k] = &cp
	s.usage += delta
	return nil
}

// Get 取块（返回拷贝）。
func (s *MemStore) Get(fileID string, stripe, pos int) (*Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blocks[blockKey(fileID, stripe, pos)]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%d/%d", ErrNotFound, fileID, stripe, pos)
	}
	cp := *b
	cp.Data = append([]byte(nil), b.Data...)
	return &cp, nil
}

// List 列出文件全部块（按 key 升序，确定性）。
func (s *MemStore) List(fileID string) ([]*Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Block
	for k, b := range s.blocks {
		if strings.HasPrefix(k, fileID+"/") {
			cp := *b
			cp.Data = append([]byte(nil), b.Data...)
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stripe != out[j].Stripe {
			return out[i].Stripe < out[j].Stripe
		}
		return out[i].Pos < out[j].Pos
	})
	return out, nil
}

// Delete 删块。
func (s *MemStore) Delete(fileID string, stripe, pos int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := blockKey(fileID, stripe, pos)
	if b, ok := s.blocks[k]; ok {
		s.usage -= int64(len(b.Data))
		delete(s.blocks, k)
	}
	return nil
}

// Usage 返回已占字节。
func (s *MemStore) Usage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

// Quota 返回配额上限。
func (s *MemStore) Quota() int64 { return s.quota }

// DirStore 是本地定额目录实现（~/.dmesh/groups/<group_id>/netdisk_quota/ 语义）：
// 一块一个 JSON 文件（Block 完整序列化），配额按磁盘字节数计。
// 文件名只含 hex fileID 与数字坐标，不做路径拼接注入。
type DirStore struct {
	mu    sync.Mutex
	root  string
	quota int64
	usage int64
}

// OpenDirStore 打开（或创建）定额目录并盘点当前占用。quotaBytes<=0 视为 unlimited。
func OpenDirStore(root string, quotaBytes int64) (*DirStore, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: empty quota dir", ErrBadParams)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("netdisk: mkdir quota dir: %w", err)
	}
	s := &DirStore{root: root, quota: quotaBytes}
	// 盘点：累计全部 *.blk 的文件大小。
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".blk") {
			s.usage += info.Size()
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("netdisk: audit quota dir: %w", err)
	}
	return s, nil
}

func (s *DirStore) pathFor(fileID string, stripe, pos int) (string, error) {
	if !safeFileID(fileID) {
		return "", fmt.Errorf("%w: unsafe file_id %q", ErrBadParams, fileID)
	}
	dir := filepath.Join(s.root, fileID)
	return filepath.Join(dir, fmt.Sprintf("%09d_%03d.blk", stripe, pos)), nil
}

// safeFileID 只允许 MakeFileID 产出的 hex 串（含 '-'/'_' 亦放行以兼容外部 id）。
func safeFileID(id string) bool {
	if id == "" || len(id) > 128 || filepath.Base(id) != id {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Put 序列化块写入磁盘（原子：先 .tmp 再 rename），超配额拒绝。
func (s *DirStore) Put(b *Block) error {
	if b == nil || len(b.Data) == 0 {
		return ErrBadBlock
	}
	p, err := s.pathFor(b.FileID, b.Stripe, b.Pos)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("netdisk: marshal block: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldSize int64
	if fi, err := os.Stat(p); err == nil {
		oldSize = fi.Size()
	}
	if s.quota > 0 && s.usage-oldSize+int64(len(raw)) > s.quota {
		return fmt.Errorf("%w: dir %s holds %d/%d", ErrQuotaFull, s.root, s.usage, s.quota)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("netdisk: mkdir: %w", err)
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("netdisk: write block: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("netdisk: rename block: %w", err)
	}
	s.usage += int64(len(raw)) - oldSize
	return nil
}

// Get 读一块并反序列化。
func (s *DirStore) Get(fileID string, stripe, pos int) (*Block, error) {
	p, err := s.pathFor(fileID, stripe, pos)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s/%d/%d", ErrNotFound, fileID, stripe, pos)
		}
		return nil, fmt.Errorf("netdisk: read block: %w", err)
	}
	var b Block
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: corrupt block file %s: %v", ErrBadBlock, p, err)
	}
	return &b, nil
}

// List 列出文件全部块。
func (s *DirStore) List(fileID string) ([]*Block, error) {
	if !safeFileID(fileID) {
		return nil, fmt.Errorf("%w: unsafe file_id %q", ErrBadParams, fileID)
	}
	dir := filepath.Join(s.root, fileID)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("netdisk: list: %w", err)
	}
	var out []*Block
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".blk") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var b Block
		if json.Unmarshal(raw, &b) == nil {
			out = append(out, &b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stripe != out[j].Stripe {
			return out[i].Stripe < out[j].Stripe
		}
		return out[i].Pos < out[j].Pos
	})
	return out, nil
}

// Delete 删一块。
func (s *DirStore) Delete(fileID string, stripe, pos int) error {
	p, err := s.pathFor(fileID, stripe, pos)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("netdisk: stat for delete: %w", err)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("netdisk: remove block: %w", err)
	}
	s.usage -= fi.Size()
	return nil
}

// Usage 返回磁盘占用字节。
func (s *DirStore) Usage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

// Quota 返回目录配额上限（<=0 为 unlimited）。
func (s *DirStore) Quota() int64 { return s.quota }

var (
	_ BlockStore = (*MemStore)(nil)
	_ BlockStore = (*DirStore)(nil)
)
