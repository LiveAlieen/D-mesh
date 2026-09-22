package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"dmesh/internal/core"
)

func TestEd25519RegisteredOnInit(t *testing.T) {
	if !core.AlgRegistered(core.SigEd25519) {
		t.Fatal("identity init must register ed25519 verifier in core")
	}
	found := false
	for _, a := range core.RegisteredAlgs() {
		if a == core.SigEd25519 {
			found = true
		}
	}
	if !found {
		t.Fatalf("RegisteredAlgs() = %v, want contains ed25519", core.RegisteredAlgs())
	}
}

func TestSignVerifyTable(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello 世界")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig length %d, want %d", len(sig), ed25519.SignatureSize)
	}
	cases := []struct {
		name    string
		pub     core.PubKey
		msg     []byte
		sig     []byte
		wantErr error
	}{
		{"valid", kp.Pub(), msg, sig, nil},
		{"tampered msg", kp.Pub(), []byte("hello 世界!"), sig, core.ErrInvalidSig},
		{"extended sig", kp.Pub(), msg, append(append([]byte{}, sig...), 0), core.ErrInvalidSig},
		{"short pub", core.PubKey{Alg: core.SigEd25519, Bytes: kp.Pub().Bytes[:10]}, msg, sig, core.ErrInvalidSig},
		{"foreign alg tag", core.PubKey{Alg: "ed448", Bytes: kp.Pub().Bytes}, msg, sig, core.ErrUnknownAlg},
		{"empty sig", kp.Pub(), msg, nil, core.ErrInvalidSig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := core.Verify(tc.pub, tc.msg, tc.sig)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifierRejectsForeignAlgTag(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := kp.Sign([]byte("x"))
	if Ed25519Verifier(core.PubKey{Alg: "sm2", Bytes: kp.Pub().Bytes}, []byte("x"), sig) {
		t.Fatal("ed25519 verifier must refuse pubs not tagged ed25519")
	}
}

func TestKeyPairFromSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, ed25519.SeedSize)
	a, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Pub().Equal(b.Pub()) {
		t.Fatal("same seed must derive same pubkey")
	}
	if !bytes.Equal(a.Seed(), seed) {
		t.Fatal("Seed() roundtrip broken")
	}
	if _, err := NewKeyPairFromSeed([]byte{1, 2, 3}); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("bad seed err = %v, want ErrMalformed", err)
	}
}

func TestIdentityWGPubDerived(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.WGPub().IsZero() {
		t.Fatal("wg pub must not be zero")
	}
	priv := id.WGPrivate()
	wgPub := id.WGPub()
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, wgPub[:]) {
		t.Fatal("wg pub not derived from wg priv")
	}
	// 确定性构造：同输入同输出。
	fixed := [32]byte{1}
	x, err := NewIdentityFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize), fixed)
	if err != nil {
		t.Fatal(err)
	}
	y, err := NewIdentityFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize), fixed)
	if err != nil {
		t.Fatal(err)
	}
	if !x.Pub().Equal(y.Pub()) || x.WGPub() != y.WGPub() {
		t.Fatal("NewIdentityFromSeed not deterministic")
	}
}

func TestIdentitySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "identity.json")
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(path, id); err != nil {
		t.Fatal(err)
	}
	got, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Pub().Equal(id.Pub()) || got.WGPub() != id.WGPub() {
		t.Fatal("roundtrip changed keys")
	}
	if got.WGPrivate() != id.WGPrivate() {
		t.Fatal("wg priv roundtrip mismatch")
	}
	sig, err := got.Sign([]byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Verify(id.Pub(), []byte("m"), sig); err != nil {
		t.Fatalf("reloaded key cannot sign for old pubkey: %v", err)
	}
	// LoadOrCreate 复用已有文件。
	again, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Pub().Equal(id.Pub()) {
		t.Fatal("LoadOrCreateIdentity regenerated instead of reusing")
	}
	// 不存在时自动创建。
	p2 := filepath.Join(dir, "fresh.json")
	if _, err := LoadOrCreateIdentity(p2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Fatal("LoadOrCreateIdentity did not save new key")
	}
}

func TestLoadIdentityRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	id, _ := NewIdentity()
	other, _ := NewIdentity()
	path := filepath.Join(dir, "id.json")
	if err := SaveIdentity(path, id); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(b []byte) []byte
	}{
		{"garbage", func([]byte) []byte { return []byte("{not json") }},
		{"pub/priv mismatch", func(b []byte) []byte {
			return bytes.Replace(b,
				[]byte(hex.EncodeToString(id.Pub().Bytes)),
				[]byte(hex.EncodeToString(other.Pub().Bytes)), 1)
		}},
		{"unknown sig_alg", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"sig_alg": "ed25519"`), []byte(`"sig_alg": "sm2"`), 1)
		}},
		{"bad wg_pub length", func(b []byte) []byte {
			return bytes.Replace(b, []byte(b64Of(id.WGPub())), []byte("abcd"), 1)
		}},
		{"wg_priv/wg_pub mismatch", func(b []byte) []byte {
			return bytes.Replace(b, []byte(b64Of(id.WGPub())), []byte(b64Of(other.WGPub())), 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(append([]byte(nil), base...))
			if bytes.Equal(bad, base) {
				t.Skip("mutation had no effect (pattern not found)")
			}
			p := filepath.Join(dir, "bad-"+strings.ReplaceAll(tc.name, "/", "_")+".json")
			if err := os.WriteFile(p, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadIdentity(p); err == nil {
				t.Fatalf("LoadIdentity accepted corrupt file (%s)", tc.name)
			} else if !errors.Is(err, core.ErrMalformed) && !errors.Is(err, core.ErrUnknownAlg) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestSaveLoadKeyPair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groupkey.json")
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyPair(path, kp); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKeyPair(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Pub().Equal(kp.Pub()) {
		t.Fatal("keypair roundtrip mismatch")
	}
}

func b64Of(w core.WGPub) string {
	return base64.StdEncoding.EncodeToString(w[:])
}
