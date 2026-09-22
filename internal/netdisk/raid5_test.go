package netdisk

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"dmesh/internal/core"
)

// TestEncodeReconstructRoundTrip 是任务要求的硬覆盖：
// 切条 → XOR 校验 → 任意单块丢失（数据或校验）→ 异或重建 → 与原内容逐字节一致。
func TestEncodeReconstructRoundTrip(t *testing.T) {
	blockSizes := []int{1, 7, 16}
	ks := []int{1, 2, 3, 5}
	sizes := []int{1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 160, 301}
	for _, bs := range blockSizes {
		for _, k := range ks {
			for _, n := range sizes {
				content := randBytes(n)
				stripes, err := EncodeToStripes(content, bs, k)
				if err != nil {
					t.Fatalf("Encode(bs=%d k=%d n=%d): %v", bs, k, n, err)
				}
				// 重组（无损）基线：截断零填充后必须等于原文。
				if got := concatData(stripes, k); !bytes.Equal(got[:n], content) {
					t.Fatalf("plain reassembly mismatch bs=%d k=%d n=%d", bs, k, n)
				}
				// 每条带恰好丢一块（含校验块）都能重建回原字节。
				for s, blocks := range stripes {
					for miss := 0; miss < len(blocks); miss++ {
						scr := append([][]byte(nil), blocks...)
						orig := scr[miss]
						scr[miss] = nil
						pos, rec, err := ReconstructStripe(scr)
						if err != nil {
							t.Fatalf("reconstruct bs=%d k=%d n=%d stripe=%d miss=%d: %v", bs, k, n, s, miss, err)
						}
						if pos != miss {
							t.Fatalf("reconstruct returned pos %d want %d", pos, miss)
						}
						if !bytes.Equal(rec, orig) {
							t.Fatalf("recovered bytes differ bs=%d k=%d n=%d stripe=%d miss=%d", bs, k, n, s, miss)
						}
						// 重建块放回去 → 全文按条带重拼接必须逐字节等于原文。
						scr[miss] = rec
						rebuilt := make([][][]byte, len(stripes))
						copy(rebuilt, stripes)
						rebuilt[s] = scr
						if got := concatData(rebuilt, k); !bytes.Equal(got[:n], content) {
							t.Fatalf("round-trip content mismatch bs=%d k=%d n=%d stripe=%d miss=%d", bs, k, n, s, miss)
						}
					}
					// 同条丢 2 块 → 明确拒绝（RAID5 只容单块）。
					if len(blocks) >= 3 {
						scr := append([][]byte(nil), blocks...)
						scr[0], scr[1] = nil, nil
						if _, _, err := ReconstructStripe(scr); !errors.Is(err, ErrTooManyMissing) {
							t.Fatalf("2-missing want ErrTooManyMissing, got %v", err)
						}
					}
				}
			}
		}
	}
}

// concatData 把条带的 k 个数据块按序拼接（pos 1..k）。
func concatData(stripes [][]([]byte), k int) []byte {
	var out []byte
	for _, blocks := range stripes {
		for j := 0; j < k; j++ {
			out = append(out, blocks[ParityPos+j+1]...)
		}
	}
	return out
}

func TestEncodeParityIsXorOfData(t *testing.T) {
	content := randBytes(3*16 + 5)
	stripes, err := EncodeToStripes(content, 16, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(stripes) != 2 {
		t.Fatalf("stripes=%d want 2", len(stripes))
	}
	for s, blocks := range stripes {
		want := make([]byte, 16)
		for j := 0; j < 3; j++ {
			for i := range want {
				want[i] ^= blocks[j+1][i]
			}
		}
		if !bytes.Equal(blocks[0], want) {
			t.Fatalf("stripe %d parity != xor(data)", s)
		}
	}
	// 空内容 → 0 条带。
	if got, err := EncodeToStripes(nil, 16, 3); err != nil || got != nil {
		t.Fatalf("empty content: %v %v", got, err)
	}
	// 非法参数。
	if _, err := EncodeToStripes([]byte{1}, 0, 3); !errors.Is(err, ErrBadParams) {
		t.Fatal("blockSize=0 must fail")
	}
	if _, err := EncodeToStripes([]byte{1}, 16, 0); !errors.Is(err, ErrBadParams) {
		t.Fatal("k=0 must fail")
	}
}

func TestReconstructStripeRejectsMalformed(t *testing.T) {
	if _, _, err := ReconstructStripe([][]byte{{1, 2}, {1}}); err == nil {
		t.Fatal("no-missing must fail")
	}
	if _, _, err := ReconstructStripe([][]byte{nil, {1, 2}, {1}}); !errors.Is(err, ErrBadBlock) {
		t.Fatalf("ragged lengths want ErrBadBlock, got %v", err)
	}
	if _, _, err := ReconstructStripe([][]byte{nil, {}}); !errors.Is(err, ErrBadBlock) {
		t.Fatalf("empty present block want ErrBadBlock, got %v", err)
	}
}

func TestLayoutPlacement(t *testing.T) {
	ids := make([]string, 6)
	var signers []*tsigner
	for i := range ids {
		ids[i] = fmt.Sprintf("h%d", i)
		signers = append(signers, newSigner(t, ids[i]))
	}
	hosts := pubs(signers...)
	lay, err := NewLayout(hosts, 0) // k=0 → n-1 经典 RAID5
	if err != nil {
		t.Fatal(err)
	}
	if lay.N() != 6 || lay.K != 5 {
		t.Fatalf("n=%d k=%d", lay.N(), lay.K)
	}
	// 校验块轮转：第 i 条校验落 (i mod n) 号成员（按升序编号）。
	for i := 0; i < 12; i++ {
		wantIdx := i % lay.N()
		got, err := lay.HostFor(i, ParityPos)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(lay.Hosts[wantIdx]) {
			t.Fatalf("stripe %d parity on %s want %s", i, got, lay.Hosts[wantIdx])
		}
	}
	// 同一条带内 K+1 个槽位互不同成员（成员不重复承载）。
	for i := 0; i < 12; i++ {
		seen := map[string]int{}
		for p := 0; p <= lay.K; p++ {
			h, err := lay.HostFor(i, p)
			if err != nil {
				t.Fatal(err)
			}
			if prev, dup := seen[h.Key()]; dup {
				t.Fatalf("stripe %d pos %d and %d on same host", i, prev, p)
			}
			seen[h.Key()] = p
		}
	}
	// 越界槽位/条号拒绝。
	if _, err := lay.HostFor(-1, 0); !errors.Is(err, ErrBadParams) {
		t.Fatal("negative stripe")
	}
	if _, err := lay.HostFor(0, lay.K+1); !errors.Is(err, ErrBadParams) {
		t.Fatal("pos out of range")
	}
	// 布局输入乱序 → 输出仍按 Key() 升序（确定性，全端一致）。
	shuffled := []core.PubKey{hosts[3], hosts[0], hosts[5], hosts[1], hosts[4], hosts[2], hosts[0]}
	lay2, err := NewLayout(shuffled, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(joinKeys(lay2.Hosts), joinKeys(lay.Hosts)) {
		t.Fatal("hosts not sorted+deduped deterministically")
	}
	if lay2.K != 2 {
		t.Fatal("explicit k must be honored")
	}
	// n<3 或 k+1>n 拒绝。
	if _, err := NewLayout(hosts[:2], 0); !errors.Is(err, ErrNotEnoughHosts) {
		t.Fatalf("2 hosts want ErrNotEnoughHosts, got %v", err)
	}
	if _, err := NewLayout(hosts[:3], 3); !errors.Is(err, ErrBadParams) {
		t.Fatalf("k+1>n want ErrBadParams, got %v", err)
	}
}

func joinKeys(ps []core.PubKey) []byte {
	var b bytes.Buffer
	for _, p := range ps {
		b.WriteString(p.Key())
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestEncodeStripesManifestHashConsistency(t *testing.T) {
	// NewManifest 的逐块哈希必须与 EncodeToStripes 的块一致。
	s := newSigner(t, "creator")
	hosts := pubs(s, newSigner(t, "b"), newSigner(t, "c"), newSigner(t, "d"))
	content := randBytes(70)
	mf, err := NewManifest([32]byte{1}, "f.bin", content, 16, 3, hosts, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if mf.Strides()*mf.Stripes != len(mf.BlockHashes) {
		t.Fatalf("block hashes %d want %d", len(mf.BlockHashes), mf.Strides()*mf.Stripes)
	}
	stripes, err := EncodeToStripes(content, mf.BlockSize, mf.K)
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for _, blocks := range stripes {
		for _, b := range blocks {
			if got := sha256.Sum256(b); got != mf.BlockHashes[i] {
				t.Fatalf("hash mismatch at %d", i)
			}
			i++
		}
	}
	if mf.Size != int64(len(content)) || mf.Stripes != len(stripes) {
		t.Fatal("manifest size/stripes")
	}
	// 空文件拒绝。
	if _, err := NewManifest([32]byte{1}, "e", nil, 16, 3, hosts, 1); !errors.Is(err, ErrBadManifest) {
		t.Fatalf("empty file want ErrBadManifest got %v", err)
	}
}
