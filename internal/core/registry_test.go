package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

// fakeVerifier 是个只用于测试的「算法」：sig 必须等于 "OK"+msg。
func fakeVerifier(pub PubKey, msg, sig []byte) bool {
	return bytes.Equal(sig, append([]byte("OK"), msg...))
}

func TestVerifyUnknownAlgRejected(t *testing.T) {
	if err := Verify(PubKey{Alg: SigAlg("sm2"), Bytes: []byte{1}}, []byte("m"), []byte("s")); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("unknown alg must be rejected with ErrUnknownAlg, got %v", err)
	}
	// 未注册时绝不误信：即使 sig 看起来「正确」也拒绝。
	if err := Verify(PubKey{Alg: SigEd25519, Bytes: []byte{1}}, nil, nil); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("ed25519 not registered yet: want ErrUnknownAlg, got %v", err)
	}
}

func TestRegisterDispatchAndReject(t *testing.T) {
	const alg = SigAlg("test-mac")
	Register(alg, fakeVerifier)
	t.Cleanup(func() { Register(alg, nil) })

	if !AlgRegistered(alg) {
		t.Fatal("AlgRegistered false after Register")
	}
	if _, ok := VerifierOf(alg); !ok {
		t.Fatal("VerifierOf missing after Register")
	}
	found := false
	for _, a := range RegisteredAlgs() {
		if a == alg {
			found = true
		}
	}
	if !found {
		t.Fatalf("RegisteredAlgs missing %q: %v", alg, RegisteredAlgs())
	}

	msg := []byte("payload")
	pub := PubKey{Alg: alg, Bytes: []byte("k")}
	if err := Verify(pub, msg, append([]byte("OK"), msg...)); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}
	if err := Verify(pub, msg, []byte("nope")); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("bad sig: want ErrInvalidSig, got %v", err)
	}
	// 原文被改一个字节即验签失败。
	if err := Verify(pub, []byte("payloaX"), append([]byte("OK"), msg...)); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("tampered msg: want ErrInvalidSig, got %v", err)
	}
	// 空签名 / 空公钥不当成验签通过。
	if err := Verify(pub, msg, nil); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("empty sig: want ErrInvalidSig, got %v", err)
	}
	// Register(alg, nil) 即注销 -> 回到未知算法。
	Register(alg, nil)
	if err := Verify(pub, msg, append([]byte("OK"), msg...)); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("after unregister: want ErrUnknownAlg, got %v", err)
	}
}

// TestVerifyWithRealEd25519 演示 identity 包应当做的注册方式，并确认可插拔链路通。
func TestVerifyWithRealEd25519(t *testing.T) {
	Register(SigEd25519, func(pub PubKey, msg, sig []byte) bool {
		if len(pub.Bytes) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
	})
	t.Cleanup(func() { Register(SigEd25519, nil) })

	_, priv, err := ed25519.GenerateKey(strings.NewReader("dmesh-core-test-seed-0000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	pub := PubKey{Alg: SigEd25519, Bytes: []byte(priv.Public().(ed25519.PublicKey))}
	msg, _ := CanonicalJSON(map[string]any{"b": 2, "a": 1})
	sig := ed25519.Sign(priv, msg)
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("real ed25519 verify failed: %v", err)
	}
	sig[0] ^= 0xff
	if err := Verify(pub, msg, sig); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("tampered ed25519 sig: want ErrInvalidSig, got %v", err)
	}
	// 同字节但 alg 标为未注册算法 -> 拒。
	if err := Verify(PubKey{Alg: SigAlg("ed448"), Bytes: pub.Bytes}, msg, sig); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("want ErrUnknownAlg, got %v", err)
	}
}

func TestTierOrdering(t *testing.T) {
	if !(TierOfRole(RoleCreator) > TierOfRole(RoleOwner) &&
		TierOfRole(RoleOwner) > TierOfRole(RoleAdmin) &&
		TierOfRole(RoleAdmin) > TierOfRole(RoleMember)) {
		t.Fatal("creator>owner>admin>member required")
	}
	if TierOfRole(Role("bogus")) != TierNonMember || TierOfRole(Role("")) != TierNonMember {
		t.Fatal("unknown role must be TierNonMember(-1)")
	}
	if TierNonMember != -1 {
		t.Fatalf("TierNonMember = %d, want -1", TierNonMember)
	}
	if got := RoleOfTier(TierOfRole(RoleAdmin)); got != RoleAdmin {
		t.Fatalf("RoleOfTier roundtrip: %q", got)
	}
	if got := RoleOfTier(99); got != "" {
		t.Fatalf("RoleOfTier(99) = %q, want empty", got)
	}
}

func TestPubKeyHelpers(t *testing.T) {
	a := PubKey{Alg: SigEd25519, Bytes: []byte{1, 2, 3}}
	b := PubKey{Alg: SigEd25519, Bytes: []byte{1, 2, 3}}
	c := PubKey{Alg: SigAlg("sm2"), Bytes: []byte{1, 2, 3}}
	d := PubKey{Alg: SigEd25519, Bytes: []byte{1, 2}}
	if !a.Equal(b) || a.Equal(c) || a.Equal(d) {
		t.Fatal("Equal must compare alg + bytes")
	}
	if a.Key() != b.Key() || a.String() != "ed25519:010203" {
		t.Fatalf("Key/String: %q %q", a.Key(), a.String())
	}
	if (PubKey{}).IsZero() == false || a.IsZero() {
		t.Fatal("IsZero wrong")
	}
	seen := map[string]bool{a.Key(): true, b.Key(): true}
	if len(seen) != 1 {
		t.Fatal("PubKey.Key must be usable as dedup map key")
	}
}

func TestPresenceOnlineRule(t *testing.T) {
	p := PresenceEntry{LastMsgTS: 1000, OfflineAfter: 500}
	if !p.Online(1400) {
		t.Fatal("within offline_after must be online")
	}
	if p.Online(1500) {
		t.Fatal("elapsed >= offline_after must be offline")
	}
	// 未自报阈值时用默认值。
	d := PresenceEntry{LastMsgTS: 0}
	if !d.Online(DefaultOfflineAfterMS-1) || d.Online(DefaultOfflineAfterMS) {
		t.Fatal("default offline_after not applied")
	}
}

func TestValidNetdiskMB(t *testing.T) {
	for _, mb := range []int{0, 1, 256} {
		if !ValidNetdiskMB(mb) {
			t.Fatalf("%d must be valid", mb)
		}
	}
	for _, mb := range []int{-1, 257, 1024} {
		if ValidNetdiskMB(mb) {
			t.Fatalf("%d must be rejected", mb)
		}
	}
}
