package netdisk

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// setupGroup 建一个 n 成员的全内存网盘群。返回群 id、网络、成员 manager。
func setupGroup(t *testing.T, n int, quota int64, blockSize int) ([32]byte, *simNet, []*tsigner, []*Manager) {
	t.Helper()
	gid := sha256.Sum256([]byte("dmesh-netdisk-test-group"))
	net := newSimNet(t)
	var signers []*tsigner
	var mgrs []*Manager
	for i := 0; i < n; i++ {
		s := newSigner(t, string(rune('a'+i)))
		h := net.add(s, quota)
		signers = append(signers, s)
		mgrs = append(mgrs, newMgr(t, gid, s, net, h.store))
	}
	return gid, net, signers, mgrs
}

func setAllHosts(t *testing.T, mgrs []*Manager, signers []*tsigner, quota int64, except ...int) {
	t.Helper()
	infos := hostsInfo(quota, signers...)
	for i := range except {
		infos[except[i]].QuotaBytes = 0 // 模拟：该成员未出配额/已退
	}
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
}

// TestUploadDownloadRoundTrip 端到端：上传→各源布局正确→另一成员多源下载。
func TestUploadDownloadRoundTrip(t *testing.T) {
	_, net, signers, mgrs := setupGroup(t, 4, 1<<20, 16)
	setAllHosts(t, mgrs, signers, 1<<20)
	content := randBytes(100)
	mf, err := mgrs[0].Upload("hello.bin", content)
	mustOK(t, err)
	// 每块都落在轮转布局指向的成员盘上。
	lay := Layout{Hosts: mf.Hosts, K: mf.K}
	total := 0
	for s := 0; s < mf.Stripes; s++ {
		for p := 0; p < mf.Strides(); p++ {
			host, err := lay.HostFor(s, p)
			mustOK(t, err)
			h := net.hosts[host.Key()]
			b, err := h.store.Get(mf.FileID, s, p)
			if err != nil {
				t.Fatalf("block (%d,%d) missing on %s: %v", s, p, host, err)
			}
			mustOK(t, CheckBlockAgainstManifest(mf, b))
			total++
		}
	}
	if want := mf.Stripes * mf.Strides(); total != want {
		t.Fatalf("placed %d blocks, want %d", total, want)
	}
	// 第 3 号成员（也出了配额）下载。
	got, err := mgrs[3].Download(mf)
	mustOK(t, err)
	if string(got) != string(content) {
		t.Fatal("downloaded content mismatch")
	}
}

// TestSingleMemberLossReconstruct 任务核心场景：任一单成员离线（其块全部拿不到）
// → 其余成员仍能异或重建读出完整原文；同条双缺则明确报 ErrTooManyMissing。
func TestSingleMemberLossReconstruct(t *testing.T) {
	_, net, signers, mgrs := setupGroup(t, 4, 1<<20, 16)
	setAllHosts(t, mgrs, signers, 1<<20)
	content := randBytes(97)
	mf, err := mgrs[0].Upload("x.bin", content)
	mustOK(t, err)
	// 每个成员轮流离线一次，其余成员都要能读回原文。
	for i, s := range signers {
		net.hosts[s.Pub().Key()].online = false
		for j, m := range mgrs {
			if i == j {
				continue
			}
			got, err := m.Download(mf)
			if err != nil {
				t.Fatalf("host %d offline, reader %d: %v", i, j, err)
			}
			if string(got) != string(content) {
				t.Fatalf("host %d offline, reader %d: content mismatch", i, j)
			}
		}
		net.hosts[s.Pub().Key()].online = true
	}
	// 同一条带的两个不同槽位分属哪两个成员——找到后同时离线其中一条带的两源：
	// 用直接删块模拟「双块同损」（PLAN 已知限制 8：不可恢复，必须报错）。
	b0, err := net.hosts[mf.Hosts[0].Key()].store.Get(mf.FileID, 0, 0)
	mustOK(t, err)
	_ = b0
	mustOK(t, net.hosts[mf.Hosts[0].Key()].store.Delete(mf.FileID, 0, 0))
	// 校验块（pos0）没了 → 单缺仍可恢复（数据块齐）。
	got, err := mgrs[1].Download(mf)
	mustOK(t, err)
	if string(got) != string(content) {
		t.Fatal("parity loss: content mismatch")
	}
	// 再删同条一个数据块 → 双缺，必须拒绝而非返回错数据。
	lay := Layout{Hosts: mf.Hosts, K: mf.K}
	h2, err := lay.HostFor(0, 1)
	mustOK(t, err)
	mustOK(t, net.hosts[h2.Key()].store.Delete(mf.FileID, 0, 1))
	if _, err := mgrs[1].Download(mf); !errors.Is(err, ErrTooManyMissing) {
		t.Fatalf("double loss want ErrTooManyMissing, got %v", err)
	}
}

// TestReadOnlyWithoutQuota 验证「仅出配额成员可写、无配额只读」。
func TestReadOnlyWithoutQuota(t *testing.T) {
	_, net, signers, mgrs := setupGroup(t, 4, 1<<20, 16)
	// 成员 3 不出配额。
	infos := hostsInfo(1<<20, signers...)
	infos[3].QuotaBytes = 0
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
	content := randBytes(60)
	mf, err := mgrs[0].Upload("a.bin", content)
	mustOK(t, err)
	// 无配额成员写入被拒（ErrNotWritable），下载照读。
	if _, err := mgrs[3].Upload("nope.bin", content); !errors.Is(err, ErrNotWritable) {
		t.Fatalf("want ErrNotWritable, got %v", err)
	}
	if err := mgrs[3].CanWrite(10); !errors.Is(err, ErrNotWritable) {
		t.Fatalf("CanWrite want ErrNotWritable, got %v", err)
	}
	got, err := mgrs[3].Download(mf)
	mustOK(t, err)
	if string(got) != string(content) {
		t.Fatal("read-only member download mismatch")
	}
	// 无配额成员的本地盘没被落任何块。
	h := net.hosts[signers[3].Pub().Key()]
	if bs, _ := h.store.List(mf.FileID); len(bs) != 0 {
		t.Fatal("blocks must not be placed on non-quota member")
	}
	// 配额成员数 <3：组不成 RAID5，禁写。
	infos2 := hostsInfo(1<<20, signers[0], signers[1])
	infos2 = append(infos2, HostInfo{Pub: signers[2].Pub(), QuotaBytes: 0}, HostInfo{Pub: signers[3].Pub(), QuotaBytes: 0})
	if err := mgrs[0].SetHosts(infos2); !errors.Is(err, ErrNotEnoughHosts) {
		t.Fatalf("want ErrNotEnoughHosts, got %v", err)
	}
	if _, err := mgrs[0].Upload("b.bin", content); !errors.Is(err, ErrNotEnoughHosts) {
		t.Fatalf("upload with <3 hosts want ErrNotEnoughHosts, got %v", err)
	}
	// 读取仍按 Manifest 写入时布局工作。
	if _, err := mgrs[0].Download(mf); err != nil {
		t.Fatalf("read must still work with <3 quota hosts: %v", err)
	}
}

// TestQuotaFull 验证配额硬上限：出配额成员的定额目录塞满即拒。
func TestQuotaFull(t *testing.T) {
	_, _, signers, mgrs := setupGroup(t, 3, 64, 16)
	setAllHosts(t, mgrs, signers, 64)
	// 每个成员每文件承载 K+1=3 槽中的 stripes*1 块（k=2）；传一个明显超容量的文件。
	big := randBytes(3000)
	// CanWrite 粗估先拦（也可能推到成员盘时 ErrQuotaFull）——两者都是配额拒绝。
	if _, err := mgrs[0].Upload("big.bin", big); err == nil {
		t.Fatal("oversize upload must fail on quota")
	} else if !errors.Is(err, ErrQuotaFull) {
		t.Fatalf("want ErrQuotaFull chain, got %v", err)
	}
	// 小文件仍可传。
	mf, err := mgrs[0].Upload("s.bin", randBytes(48))
	mustOK(t, err)
	if _, err := mgrs[1].Download(mf); err != nil {
		t.Fatal(err)
	}
}

// TestDegradedFreeze 验证降级冻结开关（重平衡前暂停新写入）。
func TestDegradedFreeze(t *testing.T) {
	_, _, signers, mgrs := setupGroup(t, 3, 1<<20, 16)
	setAllHosts(t, mgrs, signers, 1<<20)
	mgrs[0].SetWriteFrozen(true)
	if _, err := mgrs[0].Upload("f.bin", randBytes(10)); !errors.Is(err, ErrDegradedFrozen) {
		t.Fatalf("want ErrDegradedFrozen, got %v", err)
	}
	mgrs[0].SetWriteFrozen(false)
	if _, err := mgrs[0].Upload("f.bin", randBytes(10)); err != nil {
		t.Fatal(err)
	}
}
