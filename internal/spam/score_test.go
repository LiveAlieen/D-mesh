package spam

import (
	"sync"
	"testing"

	"dmesh/internal/core"
)

func TestScorePenalizeAndRewardBasics(t *testing.T) {
	clk := newFakeClock(0)
	tr := NewScoreTracker(DefaultScoreConfig(), clk.now)

	tests := []struct {
		name string
		op   func() int
		want int
	}{
		{"initial default", func() int { return tr.Score("a") }, 50},
		{"bad signature -25", func() int { return tr.Penalize("a", EvBadSignature) }, 25},
		{"unknown alg only -5 (v16: 不等于伪签)", func() int { return tr.Penalize("a", EvUnknownAlg) }, 20},
		{"spam -10", func() int { return tr.Penalize("a", EvSpam) }, 10},
		{"floor at Min", func() int { return tr.Penalize("a", EvBadSignature) }, 0},
		{"reward +8 valid roster", func() int { return tr.Reward("a", EvValidRoster) }, 8},
		{"reward ceiling at Max", func() int {
			v := 0
			for i := 0; i < 30; i++ {
				v = tr.Reward("b", EvValidRoster)
			}
			return v
		}, 100},
		{"unknown penalty event treated as spam", func() int { return tr.Penalize("c", ScoreEvent("bogus")) }, 40},
		{"unknown reward event ignored", func() int { return tr.Reward("d", ScoreEvent("bogus")) }, 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.op(); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestScoreRepeatViolationEscalation(t *testing.T) {
	tr := NewScoreTracker(DefaultScoreConfig(), newFakeClock(0).now)
	// 先来 3 次违规（spam）把 violations 计到 3，再来第 4 次重复违规：
	// 罚分 = 10 * min(4, RepeatCap=5) = 40。
	for i := 0; i < 3; i++ {
		tr.Penalize("x", EvSpam)
	}
	before := tr.Score("x") // 50 - 30 = 20
	tr.Penalize("x", EvRepeatViolation)
	after := tr.Score("x")
	if before != 20 {
		t.Fatalf("before = %d, want 20", before)
	}
	// 第 4 次违规罚 -10*4 = -40，20-40 压穿到 Min=0：反复违规快速出局
	if after != 0 {
		t.Fatalf("after = %d, want 0 (20-40 clamped to Min)", after)
	}
	if tr.Violations("x") != 4 {
		t.Fatalf("violations = %d, want 4", tr.Violations("x"))
	}
	if !tr.ShouldDrop("x") {
		t.Fatalf("ShouldDrop = false after repeat-violation avalanche")
	}
}

func TestScoreRepeatCapMultiplier(t *testing.T) {
	cfg := ScoreConfig{
		Initial: 200, Min: 0, Max: 300,
		GoodThreshold: 250, DropThreshold: 50,
		DecayIntervalMS: 600_000, RepeatCap: 2,
	}
	tr := NewScoreTracker(cfg, newFakeClock(0).now)
	// unknown_alg 不计违规（v16：只是本地未注册算法，不升级成坏行为记录）
	for i := 0; i < 5; i++ {
		tr.Penalize("y", EvUnknownAlg)
	}
	if tr.Violations("y") != 0 {
		t.Fatalf("unknown_alg must not count as violation, got %d", tr.Violations("y"))
	}
	for i := 0; i < 5; i++ { // viol=5，超出 RepeatCap=2
		tr.Penalize("y", EvSpam) // 固定 -10，不放大
	}
	if got := tr.Score("y"); got != 125 { // 200 - 25(unknown) - 50(spam)
		t.Fatalf("after 5 unknown-alg + 5 spam = %d, want 125", got)
	}
	tr.Penalize("y", EvRepeatViolation) // mult = min(6, 2) = 2 → -20（未封顶会 -60）
	if got := tr.Score("y"); got != 105 {
		t.Fatalf("repeat violation with capped multiplier: got %d, want 105", got)
	}
}

func TestScoreThresholds(t *testing.T) {
	tr := NewScoreTracker(DefaultScoreConfig(), newFakeClock(0).now)
	if tr.GoodSource("n") {
		t.Fatalf("fresh key (50) should not be GoodSource (>=65)")
	}
	tr.Reward("n", EvValidRoster) // 58
	tr.Reward("n", EvValidRoster) // 66
	if !tr.GoodSource("n") {
		t.Fatalf("score %d should be GoodSource", tr.Score("n"))
	}
	tr.Penalize("n", EvBadSignature) // 41
	if tr.GoodSource("n") {
		t.Fatalf("41 should not be GoodSource")
	}
	if tr.ShouldDrop("n") {
		t.Fatalf("41 should not be dropped yet (threshold 20)")
	}
	tr.Penalize("n", EvBadSignature) // 16
	if !tr.ShouldDrop("n") {
		t.Fatalf("16 should be droppable source")
	}
}

func TestScoreDecayTowardInitial(t *testing.T) {
	clk := newFakeClock(0)
	cfg := DefaultScoreConfig() // DecayInterval 10min，每周期回移 1 分、violation-1
	tr := NewScoreTracker(cfg, clk.now)
	tr.Penalize("d", EvBadSignature) // 25, viol=1
	if tr.Score("d") != 25 {
		t.Fatalf("after penalty = %d, want 25", tr.Score("d"))
	}
	clk.advance(10*60*1000 - 1)
	if tr.Score("d") != 25 {
		t.Fatalf("decay must not start before one interval")
	}
	clk.advance(1) // 满一个周期 → 26, viol=0
	if got := tr.Score("d"); got != 26 {
		t.Fatalf("after 1 interval = %d, want 26", got)
	}
	if tr.Violations("d") != 0 {
		t.Fatalf("violations should decay to 0, got %d", tr.Violations("d"))
	}
	clk.advance(10 * 60 * 1000 * 30) // 远超回到 Initial 所需
	if got := tr.Score("d"); got != cfg.Initial {
		t.Fatalf("long idle score = %d, want decay back to initial %d", got, cfg.Initial)
	}
	// 好评侧同样向 Initial 回移（从上方降）
	tr.Reward("u", EvValidRoster) // 58
	clk.advance(10 * 60 * 1000 * 2)
	if got := tr.Score("u"); got != 56 {
		t.Fatalf("rewarded score decay = %d, want 56", got)
	}
	// 新事件重置衰减锚点
	tr.Penalize("u", EvSpam) // 46, lastEvent=now
	clk.advance(10*60*1000 + 5000)
	if got := tr.Score("u"); got != 47 {
		t.Fatalf("after fresh event + 1.5 interval = %d, want 47", got)
	}
}

func TestScoreSnapshotOrdering(t *testing.T) {
	clk := newFakeClock(0)
	tr := NewScoreTracker(DefaultScoreConfig(), clk.now)
	tr.Penalize("bad1", EvBadSignature) // 25
	tr.Penalize("bad2", EvBadSignature) // 25
	tr.Penalize("bad2", EvBadSignature) // 0（第 2 次仍 -25 → clamp 0）
	tr.Reward("good", EvValidRoster)    // 58
	tr.Penalize("unknown-late", EvSpam) // 40
	snap := tr.Snapshot()
	if len(snap) != 4 {
		t.Fatalf("snapshot len = %d, want 4", len(snap))
	}
	// 分数升序；同分按 key 字典序：bad2(0) < bad1(25) < unknown-late(40) < good(58)
	want := []string{"bad2", "bad1", "unknown-late", "good"}
	for i, w := range want {
		if snap[i].Key != w {
			t.Fatalf("snapshot[%d] = %s (%d), want %s", i, snap[i].Key, snap[i].Score, w)
		}
	}
	if snap[0].Violations != 2 {
		t.Fatalf("bad2 violations = %d, want 2", snap[0].Violations)
	}
}

func TestScorePubHelpersAndConcurrency(t *testing.T) {
	tr := NewScoreTracker(DefaultScoreConfig(), newFakeClock(0).now)
	p := core.PubKey{Alg: core.SigEd25519, Bytes: []byte{1, 2, 3}}
	if got := tr.ScorePub(p); got != 50 {
		t.Fatalf("ScorePub = %d, want 50", got)
	}
	tr.PenalizePub(p, EvBadSignature)
	if got := tr.Score(p.Key()); got != 25 {
		t.Fatalf("after PenalizePub = %d, want 25", got)
	}
	tr.RewardPub(p, EvTimelyData)
	if got := tr.ScorePub(p); got != 28 {
		t.Fatalf("after RewardPub = %d, want 28", got)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				tr.Penalize("hot", EvSpam)
				tr.Reward("hot2", EvValidRoster)
				tr.Score("hot")
				tr.Snapshot()
			}
		}(i)
	}
	wg.Wait()
}
