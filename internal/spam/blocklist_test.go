package spam

import (
	"encoding/json"
	"testing"

	"dmesh/internal/core"
)

func pubOf(b byte) core.PubKey {
	return core.PubKey{Alg: core.SigEd25519, Bytes: []byte{b, b + 1, b + 2}}
}

func TestBlocklistAddBlockExpireRemove(t *testing.T) {
	clk := newFakeClock(1000)
	b := NewBlocklist(clk.now)

	b.Add(pubOf(1), "flooding", 500) // 500ms 后过期
	b.Add(pubOf(2), "harassment", 0) // 永久
	b.Add(pubOf(3), "", 1000)        // 1000ms 后过期

	tests := []struct {
		name    string
		advance int64
		pub     core.PubKey
		want    bool
	}{
		{"short block active at +499", 499, pubOf(1), true},
		{"permanent block active at +499", 0, pubOf(2), true},
		{"short block expired at +500", 1, pubOf(1), false},
		{"unknown pub never blocked", 0, pubOf(9), false},
		{"zero pub never blocked", 0, core.PubKey{}, false},
		{"permanent still active much later", 100_000, pubOf(2), true},
		{"mid block long expired by now", 500, pubOf(3), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk.advance(tc.advance)
			if got := b.Blocked(tc.pub); got != tc.want {
				t.Fatalf("Blocked(%v) = %v, want %v", tc.pub, got, tc.want)
			}
		})
	}

	if !b.Remove(pubOf(2)) {
		t.Fatalf("Remove permanent entry = false, want true")
	}
	if b.Remove(pubOf(2)) {
		t.Fatalf("double Remove = true, want false")
	}
	if b.Blocked(pubOf(2)) {
		t.Fatalf("still blocked after Remove")
	}
}

func TestBlocklistAddOverwrites(t *testing.T) {
	clk := newFakeClock(0)
	b := NewBlocklist(clk.now)
	b.Add(pubOf(4), "temp", 100)
	b.Add(pubOf(4), "renewed with longer duration", 10_000)
	clk.advance(500)
	if !b.Blocked(pubOf(4)) {
		t.Fatalf("re-Add should overwrite old (shorter) entry")
	}
	e, ok := b.Lookup(pubOf(4))
	if !ok || e.Reason != "renewed with longer duration" {
		t.Fatalf("Lookup = %+v,%v, want updated reason", e, ok)
	}
}

func TestBlocklistListSortedAndDeterministic(t *testing.T) {
	clk := newFakeClock(100)
	b := NewBlocklist(clk.now)
	b.Add(pubOf(7), "late", 0)
	clk.advance(50)
	b.Add(pubOf(3), "earlier-but-higher-key", 0)
	b.Add(pubOf(8), "same-time-as-3", 0)
	clk.advance(50)
	b.Add(pubOf(1), "short-lived", 10) // 立即过期，不应出现
	clk.advance(20)

	list := b.List()
	if len(list) != 3 {
		t.Fatalf("List len = %d, want 3 (expired excluded): %+v", len(list), list)
	}
	// AddedMS 升序：7(100) < 3(150) == 8(150)；同时间按 key 字典序
	if list[0].Pub.Key() != pubOf(7).Key() {
		t.Fatalf("first = %s, want pubOf(7)", list[0].Pub)
	}
	if list[1].Pub.Key() > list[2].Pub.Key() {
		t.Fatalf("tie-break by key failed: %s before %s", list[1].Pub, list[2].Pub)
	}
	if b.Size() != 3 {
		t.Fatalf("Size = %d, want 3", b.Size())
	}
}

func TestBlocklistPersistenceRoundtrip(t *testing.T) {
	clk := newFakeClock(1000)
	b := NewBlocklist(clk.now)
	b.Add(pubOf(5), "spam", 0)
	b.Add(pubOf(6), "temp", 10_000)
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// 时钟前进后加载：过期条目应被识别为不屏蔽
	clk2 := newFakeClock(20_000)
	b2, err := LoadBlocklist(data, clk2.now)
	if err != nil {
		t.Fatalf("LoadBlocklist: %v", err)
	}
	if !b2.Blocked(pubOf(5)) {
		t.Fatalf("permanent entry lost after roundtrip")
	}
	if b2.Blocked(pubOf(6)) {
		t.Fatalf("expired entry still blocks after roundtrip")
	}
	if e, ok := b2.Lookup(pubOf(5)); !ok || e.Reason != "spam" {
		t.Fatalf("reason lost: %+v", e)
	}

	if _, err := LoadBlocklist([]byte("garbage"), nil); err == nil {
		t.Fatalf("LoadBlocklist(garbage) = nil error, want error")
	}
	if _, err := LoadBlocklist([]byte(`{"version":99}`), nil); err == nil {
		t.Fatalf("LoadBlocklist(bad version) = nil error, want error")
	}
	if _, err := LoadBlocklist([]byte(`{"version":1,"entries":[{"pub":{"sig_alg":"","pub":null}}]}`), nil); err == nil {
		t.Fatalf("LoadBlocklist(zero pub) = nil error, want error")
	}
}
