package netdisk

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"dmesh/internal/core"
)

func TestNetdiskConfigEvent(t *testing.T) {
	gid := sha256.Sum256([]byte("cfg"))
	owner := newSigner(t, "owner")

	// 合法值 0/1/256 全部可签发并复验。
	for _, mb := range []int{0, 1, 256} {
		msg, err := MakeNetdiskEvent(owner, gid, mb, 1000)
		mustOK(t, err)
		if msg.Type != core.TypeNetdisk {
			t.Fatal("type")
		}
		raw, err := core.MessageSigPayload(msg)
		mustOK(t, err)
		if err := core.Verify(msg.Sender, raw, msg.Sig); err != nil {
			t.Fatalf("mb=%d event signature invalid: %v", mb, err)
		}
		got, err := ValidateNetdiskContent(msg.Content)
		mustOK(t, err)
		if got != mb {
			t.Fatalf("roundtrip %d != %d", got, mb)
		}
	}
	// 越界值直接拒绝（签发与验证两侧都拦）。
	for _, mb := range []int{-1, 257, 1024} {
		if _, err := MakeNetdiskEvent(owner, gid, mb, 1); !errors.Is(err, ErrBadQuotaMB) {
			t.Fatalf("mb=%d must be rejected at signing, got %v", mb, err)
		}
		content, _ := json.Marshal(map[string]any{"mb": mb})
		if _, err := ValidateNetdiskContent(content); !errors.Is(err, ErrBadQuotaMB) {
			t.Fatalf("mb=%d must be rejected at validation, got %v", mb, err)
		}
	}
	// 非 canonical / 夹带多余字段 / 畸形 JSON 全部拒绝。
	if _, err := ValidateNetdiskContent([]byte(`{ "mb" : 5 }`)); !errors.Is(err, ErrBadQuotaMB) {
		t.Fatalf("non-canonical content must be rejected, got %v", err)
	}
	if _, err := ValidateNetdiskContent([]byte(`{"kind":"netdisk_config","mb":5}`)); !errors.Is(err, ErrBadQuotaMB) {
		t.Fatalf("extra field must be rejected, got %v", err)
	}
	if _, err := ValidateNetdiskContent([]byte(`not json`)); !errors.Is(err, ErrBadQuotaMB) {
		t.Fatalf("garbage must be rejected, got %v", err)
	}
}

func TestManifestMessageRoundTrip(t *testing.T) {
	gid, _, signers, mgrs := setupGroup(t, 3, 1<<20, 16)
	setAllHosts(t, mgrs, signers, 1<<20)
	mf, err := mgrs[0].Upload("msg.bin", randBytes(40))
	mustOK(t, err)
	msg, err := mgrs[0].ManifestMessage(mf)
	mustOK(t, err)
	if msg.Type != core.TypeHide || msg.GroupID != gid {
		t.Fatal("message envelope wrong")
	}
	got, sender, err := ManifestFromMessage(msg, gid)
	mustOK(t, err)
	if !sender.Equal(signers[0].Pub()) || !got.Creator.Equal(signers[0].Pub()) {
		t.Fatal("sender/creator lost")
	}
	if got.FileID != mf.FileID || got.ContentHash != mf.ContentHash {
		t.Fatal("manifest fields lost in transit")
	}
	// 换群拒收。
	if _, _, err := ManifestFromMessage(msg, [32]byte{1, 2}); err == nil {
		t.Fatal("other group must reject")
	}
	// 篡改内容 → 验签/复验必失败。
	bad := msg
	bad.Content = append([]byte(nil), msg.Content...)
	bad.Content[len(bad.Content)/2] ^= 0x01
	if _, _, err := ManifestFromMessage(bad, gid); err == nil {
		t.Fatal("tampered message must fail")
	}
	// 解出的清单可直接下载。
	content2, err := mgrs[2].Download(got)
	mustOK(t, err)
	if len(content2) == 0 {
		t.Fatal("empty download")
	}
}

func TestCrossSourceCorruptRejected(t *testing.T) {
	// 多源交叉验哈希：作恶源交出被改的块 → 丢弃 + 差评，好源/重建兜底。
	gid := sha256.Sum256([]byte("xsrc"))
	net := newSimNet(t)
	var signers []*tsigner
	var mgrs []*Manager
	for i := 0; i < 4; i++ {
		s := newSigner(t, string(rune('a'+i)))
		h := net.add(s, 1<<20)
		signers = append(signers, s)
		mgrs = append(mgrs, newMgr(t, gid, s, net, h.store))
	}
	infos := hostsInfo(1<<20, signers...)
	for _, m := range mgrs {
		mustOK(t, m.SetHosts(infos))
	}
	content := randBytes(70)
	mf, err := mgrs[0].Upload("c.bin", content)
	mustOK(t, err)
	// 全员变坏源。
	for _, h := range net.hosts {
		h.bad = true
	}
	var suspects int
	mgrs[1].suspect = func(core.PubKey, error) { suspects++ }
	if _, err := mgrs[1].Download(mf); err == nil {
		t.Fatal("all-corrupt sources must fail download, not return garbage")
	}
	if suspects == 0 {
		t.Fatal("bad sources must trigger OnSuspect (差评)")
	}
	// 恢复一个好源 → 交叉验证后仍能读出正确内容（坏源被逐块筛掉）。
	for _, h := range net.hosts {
		h.bad = false
	}
	got, err := mgrs[1].Download(mf)
	mustOK(t, err)
	if string(got) != string(content) {
		t.Fatal("content mismatch after mixed sources")
	}
}
