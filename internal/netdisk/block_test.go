package netdisk

import (
	"crypto/sha256"
	"errors"
	"testing"

	"dmesh/internal/core"
)

func TestSignCheckBlockRoundTrip(t *testing.T) {
	gid := [32]byte{9, 8, 7}
	up := newSigner(t, "uploader")
	b := &Block{FileID: "f1", GroupID: gid, Stripe: 2, Pos: 0, Data: randBytes(16)}
	mustOK(t, SignBlock(up, b, 111))
	if b.Kind != KindParity {
		t.Fatalf("pos 0 must be parity, got %q", b.Kind)
	}
	if b.ContentHash != sha256.Sum256(b.Data) {
		t.Fatal("content hash not set")
	}
	if !b.Publisher.Equal(up.Pub()) {
		t.Fatal("publisher")
	}
	mustOK(t, CheckBlock(b, gid))
	// 数据被改一个字节 → 哈希不符。
	bad := *b
	bad.Data = append([]byte(nil), b.Data...)
	bad.Data[3] ^= 1
	if err := CheckBlock(&bad, gid); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered data want ErrHashMismatch, got %v", err)
	}
	// 元数据被改（换条号）→ proof 原文不再匹配。
	bad2 := *b
	bad2.Stripe = 5
	if err := CheckBlock(&bad2, gid); !errors.Is(err, ErrBadBlock) {
		t.Fatalf("tampered stripe want ErrBadBlock, got %v", err)
	}
	// 换个群 → 拒。
	if err := CheckBlock(b, [32]byte{1}); !errors.Is(err, ErrBadBlock) {
		t.Fatalf("wrong group want ErrBadBlock, got %v", err)
	}
	// 未注册 alg → ErrUnknownAlg（经 VerifyProof 传播），绝不误信。
	forged := *b
	forged.Proof = core.Proof{Raw: append([]byte(nil), b.Proof.Raw...), Alg: core.SigAlg("sm2"), Sig: append([]byte(nil), b.Proof.Sig...)}
	err := CheckBlock(&forged, gid)
	if !errors.Is(err, core.ErrUnknownAlg) {
		t.Fatalf("unknown alg must be rejected with ErrUnknownAlg, got %v", err)
	}
	// Host 不在签名原文里：换落盘成员（重平衡搬移）proof 仍有效。
	moved := *b
	moved.Host = newSigner(t, "whoever").Pub()
	mustOK(t, CheckBlock(&moved, gid))
}

func TestCheckBlockAgainstManifest(t *testing.T) {
	mf := &Manifest{FileID: "f", K: 2, Stripes: 2}
	mf.BlockHashes = make([][32]byte, 2*3)
	ok := &Block{Stripe: 1, Pos: 2, ContentHash: sha256.Sum256([]byte("x"))}
	mf.BlockHashes[1*3+2] = ok.ContentHash
	mustOK(t, CheckBlockAgainstManifest(mf, ok))
	bad := *ok
	bad.ContentHash = sha256.Sum256([]byte("y"))
	if err := CheckBlockAgainstManifest(mf, &bad); !errors.Is(err, ErrHashMismatch) {
		t.Fatal(err)
	}
	out := &Block{Stripe: 9, Pos: 0}
	if err := CheckBlockAgainstManifest(mf, out); !errors.Is(err, ErrBadBlock) {
		t.Fatal(err)
	}
	// 清单没带逐块哈希 → 跳过交叉比对（底线是块自身验签+自洽哈希）。
	if err := CheckBlockAgainstManifest(&Manifest{K: 2, Stripes: 2}, ok); err != nil {
		t.Fatal(err)
	}
}

func TestManifestSignCheck(t *testing.T) {
	gid := [32]byte{2, 3}
	up := newSigner(t, "u")
	content := randBytes(50)
	hosts := pubs(up, newSigner(t, "v"), newSigner(t, "w"), newSigner(t, "x"))
	mf, err := NewManifest(gid, "doc.bin", content, 16, 3, hosts, 777)
	mustOK(t, err)
	mustOK(t, SignManifest(up, mf))
	mustOK(t, CheckManifest(mf, gid))
	// 篡改 BlockHashes（换掉一块锚）→ 原文不匹配。
	tam := *mf
	tam.BlockHashes = append([][32]byte(nil), mf.BlockHashes...)
	tam.BlockHashes[0] = [32]byte{}
	if err := CheckManifest(&tam, gid); !errors.Is(err, ErrBadManifest) {
		t.Fatalf("tampered hashes want ErrBadManifest, got %v", err)
	}
	// 条带数与尺寸不符 → 拒。
	tam2 := *mf
	tam2.Stripes = 99
	if err := CheckManifest(&tam2, gid); !errors.Is(err, ErrBadManifest) {
		t.Fatalf("bad stripes want ErrBadManifest, got %v", err)
	}
	// 别人重签同名文件也必须验不过伪造 proof：换 proof.raw 即拒。
	tam3 := *mf
	tam3.Proof.Raw = append([]byte("x"), mf.Proof.Raw...)
	if err := CheckManifest(&tam3, gid); !errors.Is(err, ErrBadManifest) {
		t.Fatalf("bad proof raw want ErrBadManifest, got %v", err)
	}
	// FileID 必须由内容派生（防 id 与内容脱钩）。
	if mf.FileID != MakeFileID(gid, mf.ContentHash, "doc.bin", 777) {
		t.Fatal("file id not content-derived")
	}
}
