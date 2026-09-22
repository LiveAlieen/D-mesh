package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"dmesh/internal/core"
)

// 用假算法 "uitest" 测试种子核对纯逻辑路径：不依赖 ed25519 真实密钥，
// 验签器只是 payload→固定 sig 的查表。测试结束注销，不污染全局注册表。
const testAlg core.SigAlg = "uitest"

// fakeSig 是假算法的签名规则：sig 同时绑定签名者公钥与原文 payload
// （真实签名算法的本质性质——改动原文任何字段，sig 必须随之不同，篡改
// 检测才成立；只绑公钥不绑 payload 的"签名"无法防伪签，核对逻辑再正确
// 也检测不出字段篡改）。
func fakeSig(pub core.PubKey, payload []byte) string {
	h := sha256.Sum256(payload)
	return "SIG:" + hex.EncodeToString(pub.Bytes) + ":" + hex.EncodeToString(h[:])
}

func withFakeVerifier(t *testing.T) {
	t.Helper()
	core.Register(testAlg, func(pub core.PubKey, msg, sig []byte) bool {
		return string(sig) == fakeSig(pub, msg)
	})
	t.Cleanup(func() { core.Register(testAlg, nil) })
}

func testCreatorPub() core.PubKey {
	b, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	return core.PubKey{Alg: testAlg, Bytes: b}
}

func testGroupPub() core.PubKey {
	b, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	return core.PubKey{Alg: testAlg, Bytes: b}
}

func signWithFake(cfg *core.GroupConfig) error {
	payload, err := core.GroupConfigSigPayload(*cfg)
	if err != nil {
		return err
	}
	cfg.CreatorSig = []byte(fakeSig(cfg.Creator, payload))
	return nil
}

func TestVerifySeedConfigValid(t *testing.T) {
	withFakeVerifier(t)
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto, CreatedAt: 42,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
		DefaultPerms: []string{core.PermSpeak, core.PermReceive}, NetdiskMB: 0,
	}
	if err := signWithFake(&cfg); err != nil {
		t.Fatal(err)
	}
	gid, err := VerifySeedConfig(cfg)
	if err != nil {
		t.Fatalf("valid seed rejected: %v", err)
	}
	want, _ := core.GroupIDOf(cfg)
	if gid != want {
		t.Errorf("gid mismatch")
	}
}

func TestVerifySeedConfigTampered(t *testing.T) {
	withFakeVerifier(t)
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeVerify, CreatedAt: 42,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
		DefaultPerms: []string{core.PermSpeak}, NetdiskMB: 16,
	}
	_ = signWithFake(&cfg)
	cfg2 := cfg
	cfg2.Name = "evil" // 篡改字段：payload 变了但 sig 还是旧创建者的（伪造失败）
	cfg2.CreatorSig = append([]byte(nil), cfg.CreatorSig...)
	if _, err := VerifySeedConfig(cfg2); err == nil {
		t.Fatal("tampered seed accepted")
	}
	bad := cfg
	bad.CreatorSig = []byte("SIG:deadbeef")
	if _, err := VerifySeedConfig(bad); err == nil {
		t.Fatal("bad signature accepted")
	}
}

func TestVerifySeedUnknownAlgRejected(t *testing.T) {
	// 不注册 uitest：未知 sig_alg 一律拒绝（v16），且错误可判定为 ErrUnknownAlg。
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
	}
	_ = signWithFake(&cfg)
	_, err := VerifySeedConfig(cfg)
	if !core.IsUnknownAlg(err) {
		t.Fatalf("err = %v, want ErrUnknownAlg chain", err)
	}
}

func TestParseSeedAndCheckBytes(t *testing.T) {
	withFakeVerifier(t)
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto, CreatedAt: 7,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
		DefaultPerms: []string{core.PermSpeak, core.PermReceive}, NetdiskMB: 32,
	}
	_ = signWithFake(&cfg)
	raw, err := json.Marshal(cfg) // WGPub 走 core 的 base64 MarshalJSON
	if err != nil {
		t.Fatal(err)
	}
	want, err := VerifySeedConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	got, match, err := CheckSeedBytes(raw, want)
	if err != nil || !match {
		t.Fatalf("roundtrip failed: match=%v err=%v", match, err)
	}
	if got.Name != "g1" || got.NetdiskMB != 32 || got.Mode != core.ModeAuto {
		t.Fatalf("parsed cfg = %+v", got)
	}
	// 有效种子但属于别的群
	if _, match, err := CheckSeedBytes(raw, [32]byte{9}); err != nil || match {
		t.Fatalf("expected valid-but-other-group, match=%v err=%v", match, err)
	}
}

func TestParseSeedValidation(t *testing.T) {
	base := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
	}
	mk := func(mut func(*core.GroupConfig)) []byte {
		c := base
		mut(&c)
		b, _ := json.Marshal(c)
		return b
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not json", []byte("{")},
		{"no name", mk(func(c *core.GroupConfig) { c.Name = "" })},
		{"bad mode", mk(func(c *core.GroupConfig) { c.Mode = "yolo" })},
		{"no group pub", mk(func(c *core.GroupConfig) { c.GroupPub = core.PubKey{} })},
		{"netdisk over max", mk(func(c *core.GroupConfig) { c.NetdiskMB = 1024 })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSeed(tc.raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := ParseSeed([]byte("[]")); err == nil {
		t.Fatal("expected error for array input")
	}
}

func TestVerifySeedErrorMessageMentionsCreator(t *testing.T) {
	withFakeVerifier(t)
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto,
		GroupPub: testGroupPub(), Creator: testCreatorPub(), Alg: testAlg,
	}
	cfg.CreatorSig = []byte("garbage")
	_, err := VerifySeedConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "creator_sig") {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, core.ErrInvalidSig) {
		t.Fatalf("err chain should be ErrInvalidSig: %v", err)
	}
}
