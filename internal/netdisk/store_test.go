package netdisk

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMemStoreQuota(t *testing.T) {
	s := NewMemStore(2*16 + 8) // 只放得下两块 16B + 8B 余量
	b1 := &Block{FileID: "f", Stripe: 0, Pos: 0, Data: randBytes(16)}
	b2 := &Block{FileID: "f", Stripe: 0, Pos: 1, Data: randBytes(16)}
	b3 := &Block{FileID: "f", Stripe: 0, Pos: 2, Data: randBytes(16)}
	mustOK(t, s.Put(b1))
	mustOK(t, s.Put(b2))
	if err := s.Put(b3); !errors.Is(err, ErrQuotaFull) {
		t.Fatalf("want ErrQuotaFull, got %v", err)
	}
	// 覆盖写不重复计费。
	mustOK(t, s.Put(b1))
	if s.Usage() != 32 {
		t.Fatalf("usage=%d want 32", s.Usage())
	}
	// 删一块后可再放。
	mustOK(t, s.Delete("f", 0, 0))
	mustOK(t, s.Put(b3))
	// Get 返回的是拷贝：改它不影响库存。
	got, err := s.Get("f", 0, 2)
	mustOK(t, err)
	got.Data[0] ^= 0xff
	again, err := s.Get("f", 0, 2)
	mustOK(t, err)
	if again.Data[0] == got.Data[0] {
		t.Fatal("store must hand out copies")
	}
	if _, err := s.Get("f", 9, 9); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing block must be ErrNotFound")
	}
	bs, err := s.List("f")
	mustOK(t, err)
	if len(bs) != 2 || bs[0].Pos > bs[1].Pos { // b1 已删：剩 pos1、pos2
		t.Fatalf("list: %d %+v", len(bs), bs)
	}
	// Delete 幂等。
	mustOK(t, s.Delete("f", 42, 42))
}

func TestDirStoreRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "netdisk_quota")
	s, err := OpenDirStore(root, 1<<20)
	mustOK(t, err)
	gid := [32]byte{5, 6}
	up := newSigner(t, "d")
	blocks := []*Block{
		{FileID: "abc123", GroupID: gid, Stripe: 0, Pos: 0, Data: randBytes(32)},
		{FileID: "abc123", GroupID: gid, Stripe: 0, Pos: 1, Data: randBytes(32)},
		{FileID: "abc123", GroupID: gid, Stripe: 7, Pos: 2, Data: randBytes(32)},
		{FileID: "other", GroupID: gid, Stripe: 0, Pos: 0, Data: randBytes(32)},
	}
	for _, b := range blocks {
		mustOK(t, SignBlock(up, b, 1))
		mustOK(t, s.Put(b))
	}
	// 重开目录：占用盘点与块内容都还在（重启进程后的定额目录语义）。
	s2, err := OpenDirStore(root, 1<<20)
	mustOK(t, err)
	if s2.Usage() != s.Usage() {
		t.Fatalf("usage after reopen %d vs %d", s2.Usage(), s.Usage())
	}
	for _, b := range blocks {
		got, err := s2.Get(b.FileID, b.Stripe, b.Pos)
		mustOK(t, err)
		if !bytes.Equal(got.Data, b.Data) || got.Proof.Alg != b.Proof.Alg {
			t.Fatalf("roundtrip mismatch (%s %d %d)", b.FileID, b.Stripe, b.Pos)
		}
		mustOK(t, CheckBlock(got, gid))
	}
	ls, err := s2.List("abc123")
	mustOK(t, err)
	if len(ls) != 3 {
		t.Fatalf("list %d", len(ls))
	}
	mustOK(t, s2.Delete("abc123", 0, 0))
	if _, err := s2.Get("abc123", 0, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted block still there")
	}
	if s2.Usage() >= s.Usage() {
		t.Fatal("usage did not drop after delete")
	}
}

func TestDirStoreQuotaAndSafety(t *testing.T) {
	root := filepath.Join(t.TempDir(), "q")
	s, err := OpenDirStore(root, 0) // unlimited，先量一块的真实占用
	mustOK(t, err)
	b1 := &Block{FileID: "aa", Stripe: 0, Pos: 0, Data: randBytes(32)}
	mustOK(t, s.Put(b1))
	full, err := OpenDirStore(root, s.Usage()) // 恰好已被占满的配额
	mustOK(t, err)
	b2 := *b1
	b2.Pos = 1
	b2.Data = randBytes(32)
	if err := full.Put(&b2); !errors.Is(err, ErrQuotaFull) {
		t.Fatalf("want ErrQuotaFull, got %v", err)
	}
	// 路径注入：fileID 含分隔符必须拒绝而不是写到别处。
	bad := &Block{FileID: "../../evil", Stripe: 0, Pos: 0, Data: []byte{1}}
	if err := s.Put(bad); !errors.Is(err, ErrBadParams) {
		t.Fatalf("path traversal want ErrBadParams, got %v", err)
	}
	if _, err := s.Get("..\\..\\evil", 0, 0); err == nil {
		t.Fatal("traversal get must fail")
	}
	// 目录里不应出现逃逸文件。
	entries, _ := os.ReadDir(filepath.Dir(root))
	for _, e := range entries {
		if e.Name() == "evil" {
			t.Fatal("escaped quota dir!")
		}
	}
}
