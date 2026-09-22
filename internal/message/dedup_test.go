package message

import (
	"fmt"
	"testing"
	"time"

	"dmesh/internal/core"
)

func pk(i byte) core.PubKey {
	return core.PubKey{Alg: core.SigEd25519, Bytes: []byte{i, i + 1, i + 2}}
}

func TestDeduperObserveTable(t *testing.T) {
	clock := &fixedClock{t: time.Unix(1700000000, 0)}
	d := NewDeduper(time.Minute, 0, clock.Now)
	srcA, srcB := pk(1), pk(2)

	cases := []struct {
		name string
		run  func() DedupResult
		want DedupResult
	}{
		{"first sight from A", func() DedupResult { return d.Observe("m1", srcA) }, DedupFresh},
		{"same src repeat -> suppressed (来源抑制)", func() DedupResult { return d.Observe("m1", srcA) }, DedupSameSource},
		{"other src -> suppressed (去重)", func() DedupResult { return d.Observe("m1", srcB) }, DedupOtherSource},
		{"new id fresh", func() DedupResult { return d.Observe("m2", srcB) }, DedupFresh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run(); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}

	// TTL 过期后重新可见
	clock.Advance(2 * time.Minute)
	if got := d.Observe("m1", srcA); got != DedupFresh {
		t.Fatalf("after TTL want Fresh, got %v", got)
	}
	// 未过期部分：m2 记录在 advance 前写入、TTL 1 分钟，也已过期
	if got := d.Observe("m2", srcB); got != DedupFresh {
		t.Fatalf("m2 after TTL want Fresh, got %v", got)
	}
}

func TestDeduperAnonAndForgetAndContains(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	d := NewDeduper(time.Hour, 0, clock.Now)
	if d.ObserveAnon("j1") != DedupFresh {
		t.Fatal("first anon observe should be fresh")
	}
	if d.ObserveAnon("j1") != DedupOtherSource {
		t.Fatal("second anon observe should be suppressed")
	}
	if !d.Contains("j1") {
		t.Fatal("Contains should be true")
	}
	if d.Contains("nope") {
		t.Fatal("Contains false positive")
	}
	d.Forget("j1")
	if d.Contains("j1") {
		t.Fatal("Forget failed")
	}
	if d.ObserveAnon("j1") != DedupFresh {
		t.Fatal("after Forget should be fresh again")
	}
	// Contains 不得写入记录
	if d.Observe("x", pk(9)) != DedupFresh {
		t.Fatal("Observe x fresh expected")
	}
	if d.Observe("y", pk(9)) != DedupFresh {
		t.Fatal("y fresh")
	}
	if d.Contains("y") != true {
		t.Fatal("y contained")
	}
}

func TestDeduperCapEvicts(t *testing.T) {
	clock := &fixedClock{t: time.Unix(0, 0)}
	d := NewDeduper(time.Hour, 100, clock.Now)
	for i := 0; i < 1000; i++ {
		d.Observe(fmt.Sprintf("id-%d", i), pk(byte(i%250)))
	}
	if d.Len() > 100 {
		t.Fatalf("cap not enforced: %d", d.Len())
	}
}

func TestDedupDefaultTTL(t *testing.T) {
	d := NewDeduper(0, 0, nil)
	if d.ttl != DefaultDedupTTL {
		t.Fatalf("default ttl = %v, want %v", d.ttl, DefaultDedupTTL)
	}
}
