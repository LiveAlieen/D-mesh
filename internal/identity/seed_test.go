package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"dmesh/internal/core"
)

func mustIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustSeed(t *testing.T, p SeedParams) (core.GroupConfig, [32]byte, *Identity) {
	t.Helper()
	creator := mustIdentity(t)
	cfg, _, id, err := NewSeed(creator, creator.WGPub(), p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, id, creator
}

func TestNewSeedVerifyRoundTrip(t *testing.T) {
	cfg, id, _ := mustSeed(t, SeedParams{
		Name: "首发群", Mode: core.ModeVerify, NetdiskMB: 64,
		DefaultPerms: []string{core.PermSpeak, core.PermReceive, core.PermCarry},
		CreatedAt:    1732000000000,
	})
	got, err := VerifyGroupConfig(cfg)
	if err != nil {
		t.Fatalf("fresh seed must verify: %v", err)
	}
	if got != id {
		t.Fatalf("group_id mismatch: %x vs %x", got, id)
	}
	if cfg.Alg != core.SigEd25519 || cfg.Version != 1 {
		t.Fatalf("defaults not applied: alg=%v version=%d", cfg.Alg, cfg.Version)
	}
	// group_id 必须等于 sha256(签名原文)——锚与签名域同源。
	payload, err := core.GroupConfigSigPayload(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(payload) != id {
		t.Fatal("group_id != sha256(payload)")
	}
}

func TestSeedFileRoundTripViaDisk(t *testing.T) {
	cfg, id, _ := mustSeed(t, SeedParams{Name: "g", Mode: core.ModeAuto})
	path := filepath.Join(t.TempDir(), "group.json")
	if err := SaveGroupConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := VerifySeedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("group_id after disk roundtrip: %x, want %x", got, id)
	}
}

func TestGroupKeysAreUniquePerGroup(t *testing.T) {
	creator := mustIdentity(t)
	_, id1, _ := mustSeed(t, SeedParams{Name: "same"})
	_, id2, _ := mustSeed(t, SeedParams{Name: "same"})
	if id1 == id2 {
		t.Fatal("two NewSeed calls must yield distinct group_id (fresh group key each time)")
	}
	// 同一创建者跨群复用身份密钥：creator 相同也应产生不同群。
	a, _, _, err := NewSeed(creator, creator.WGPub(), SeedParams{Name: "x", CreatedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := NewSeed(creator, creator.WGPub(), SeedParams{Name: "x", CreatedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	ida, _ := core.GroupIDOf(a)
	idb, _ := core.GroupIDOf(b)
	if ida == idb {
		t.Fatal("group_id must depend on freshly generated group key, not only on params")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	good, _, _ := mustSeed(t, SeedParams{Name: "g", Mode: core.ModeAuto, CreatedAt: 9})
	cases := []struct {
		name    string
		tamper  func(*core.GroupConfig)
		wantErr error
	}{
		{"name changed", func(c *core.GroupConfig) { c.Name = "evil" }, core.ErrInvalidSig},
		{"netdisk changed", func(c *core.GroupConfig) { c.NetdiskMB = 255 }, core.ErrInvalidSig},
		{"mode changed", func(c *core.GroupConfig) { c.Mode = core.ModeVerify }, core.ErrInvalidSig},
		{"group_pub swapped", func(c *core.GroupConfig) {
			k, _ := NewGroupKey()
			c.GroupPub = k.Pub()
		}, core.ErrInvalidSig},
		{"creator swapped", func(c *core.GroupConfig) {
			k, _ := NewKeyPair()
			c.Creator = k.Pub()
		}, core.ErrInvalidSig},
		{"sig truncated", func(c *core.GroupConfig) { c.CreatorSig = c.CreatorSig[:len(c.CreatorSig)-1] }, core.ErrInvalidSig},
		{"sig removed", func(c *core.GroupConfig) { c.CreatorSig = nil }, core.ErrMalformed},
		{"unknown config alg", func(c *core.GroupConfig) { c.Alg = "sm2" }, core.ErrUnknownAlg},
		{"unknown creator alg", func(c *core.GroupConfig) {
			c.Creator = core.PubKey{Alg: "sm9", Bytes: c.Creator.Bytes}
		}, core.ErrUnknownAlg},
		{"alg mismatch creator vs config", func(c *core.GroupConfig) {
			c.Alg = core.SigEd25519
			c.Creator = core.PubKey{Alg: "ed448", Bytes: c.Creator.Bytes}
		}, core.ErrUnknownAlg},
		{"bad mode value", func(c *core.GroupConfig) { c.Mode = "open" }, core.ErrMalformed},
		{"netdisk out of range", func(c *core.GroupConfig) { c.NetdiskMB = 257 }, core.ErrMalformed},
		{"negative netdisk", func(c *core.GroupConfig) { c.NetdiskMB = -1 }, core.ErrMalformed},
		{"unknown default perm", func(c *core.GroupConfig) { c.DefaultPerms = []string{"fly"} }, core.ErrMalformed},
		{"zero creator wg", func(c *core.GroupConfig) { c.CreatorWG = core.WGPub{} }, core.ErrMalformed},
		{"empty name", func(c *core.GroupConfig) { c.Name = "" }, core.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good // struct copy (slices shared but tamper replaces or leaves them)
			tc.tamper(&cfg)
			_, err := VerifyGroupConfig(cfg)
			if err == nil {
				t.Fatal("tampered seed accepted")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want chain %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewSeedRejectsBadParams(t *testing.T) {
	creator := mustIdentity(t)
	if _, _, _, err := NewSeed(creator, creator.WGPub(), SeedParams{Name: "", Mode: core.ModeAuto}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("empty name: %v", err)
	}
	if _, _, _, err := NewSeed(creator, creator.WGPub(), SeedParams{Name: "n", Mode: "yolo"}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("bad mode: %v", err)
	}
	if _, _, _, err := NewSeed(creator, core.WGPub{}, SeedParams{Name: "n"}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("zero creator wg: %v", err)
	}
	if _, _, _, err := NewSeed(nil, creator.WGPub(), SeedParams{Name: "n"}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("nil signer: %v", err)
	}
}

func TestSignGroupConfigRequiresMatchingCreator(t *testing.T) {
	creator := mustIdentity(t)
	other, _ := NewKeyPair()
	cfg := core.GroupConfig{
		Name: "g", Version: 1, Mode: core.ModeAuto, CreatedAt: 5,
		Creator: other.Pub(), Alg: core.SigEd25519,
		DefaultPerms: []string{core.PermSpeak},
	}
	if _, _, err := SignGroupConfig(cfg, creator); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("must refuse signing for a different creator pubkey: %v", err)
	}
	cfg.Creator = creator.Pub()
	k, _ := NewGroupKey()
	cfg.GroupPub = k.Pub()
	cfg.CreatorWG = creator.WGPub()
	signed, id, err := SignGroupConfig(cfg, creator)
	if err != nil {
		t.Fatal(err)
	}
	if id == ([32]byte{}) {
		t.Fatal("zero group id")
	}
	if _, err := VerifyGroupConfig(signed); err != nil {
		t.Fatalf("manually signed config must verify: %v", err)
	}
}

func TestGroupIDEqualsHexSelfCheck(t *testing.T) {
	cfg, id, _ := mustSeed(t, SeedParams{Name: "hex"})
	got, err := VerifyGroupConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(id[:]) {
		t.Fatal("hex rendering unstable")
	}
}
