package group

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"dmesh/internal/core"
)

func TestMain(m *testing.M) {
	RegisterEd25519Verifier()
	if !core.AlgRegistered(core.SigEd25519) {
		panic("ed25519 verifier not registered")
	}
	m.Run()
}

// --- 测试夹具 ---------------------------------------------------------------

func mkSigner(t *testing.T, b byte) *Ed25519Signer {
	t.Helper()
	s, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mkWG(b byte) core.WGPub {
	var w core.WGPub
	w[0] = b
	return w
}

type env struct {
	t     *testing.T
	r     *Roster
	cfg   core.GroupConfig
	gid   [32]byte
	creat *Ed25519Signer // 创建者（初始群主）
	now   int64          // 注入时钟的固定 now（毫秒）
}

func newEnv(t *testing.T, opt Options) *env {
	t.Helper()
	creat := mkSigner(t, 1)
	gpub := mkSigner(t, 99)
	cfg := core.GroupConfig{
		Name: "g1", Version: 1, Mode: core.ModeAuto, CreatedAt: 1_000,
		GroupPub: gpub.Pub(), Creator: creat.Pub(), CreatorWG: mkWG(1),
		Alg:          core.SigEd25519,
		DefaultPerms: []string{core.PermSpeak, core.PermReceive},
	}
	payload, err := core.GroupConfigSigPayload(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CreatorSig, err = creat.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := core.GroupIDOf(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, opt)
	now := time.Now().UnixMilli() - 60_000 // 留出未来事件余量
	r.SetClock(func() time.Time { return time.UnixMilli(now) })
	return &env{t: t, r: r, cfg: cfg, gid: gid, creat: creat, now: now}
}

// ev 构造并签名一个事件。
func (e *env) ev(s core.Signer, typ string, content any, ts int64) core.Message {
	e.t.Helper()
	c, err := EncodeEventContent(content)
	if err != nil {
		e.t.Fatal(err)
	}
	m := core.Message{Type: typ, TSms: ts, Content: c}
	if err := SignEvent(&m, s, e.gid); err != nil {
		e.t.Fatal(err)
	}
	return m
}

// mustApply 应用事件并强制排空乱序缓存（正向路径）。
func (e *env) mustApply(m core.Message) {
	e.t.Helper()
	if err := e.r.ApplyEvent(m); err != nil {
		e.t.Fatalf("ApplyEvent(%s): %v", m.Type, err)
	}
	_, failed := e.r.FlushAll()
	for _, f := range failed {
		if f.MsgID == m.MsgID {
			e.t.Fatalf("event %s failed on flush", m.Type)
		}
	}
}

// applyNoFlush 应用事件但不排空乱序缓存（用于验证 hold 行为）。
func (e *env) applyNoFlush(m core.Message) {
	e.t.Helper()
	if err := e.r.ApplyEvent(m); err != nil {
		e.t.Fatalf("ApplyEvent(%s): %v", m.Type, err)
	}
}

// wantErr 断言 ApplyEvent 返回指定契约错误。
func (e *env) wantErr(m core.Message, want error) {
	e.t.Helper()
	err := e.r.ApplyEvent(m)
	if err == nil {
		e.t.Fatalf("event %s: want %v, got nil", m.Type, want)
	}
	if !errors.Is(err, want) {
		e.t.Fatalf("event %s: want error %v, got %v", m.Type, want, err)
	}
}

func (e *env) joinAs(carrier core.Signer, target core.PubKey, ts int64, wg core.WGPub, perms ...string) core.Message {
	if len(perms) == 0 {
		perms = e.cfg.DefaultPerms
	}
	return e.ev(carrier, core.TypeJoin, eventJoin{Pub: target, WG: wg, Perms: perms}, ts)
}

// bootstrapAdmin：拉入 name 密钥成员 → 升为管理 → 追加敏感权限位。
// 返回签名者与下一个可用 ts。
func (e *env) bootstrapAdmin(name byte, ts int64, extra ...string) (*Ed25519Signer, int64) {
	e.t.Helper()
	admin := mkSigner(e.t, name)
	e.mustApply(e.joinAs(e.creat, admin.Pub(), ts, mkWG(name)))
	e.mustApply(e.ev(e.creat, core.TypeGrantAdmin, eventTarget{Target: admin.Pub()}, ts+1))
	if len(extra) > 0 {
		e.mustApply(e.ev(e.creat, core.TypePerms, eventPerms{Target: admin.Pub(),
			Perms: unique(append(append([]string{}, e.cfg.DefaultPerms...), extra...))}, ts+2))
	}
	return admin, ts + 3
}

func (e *env) memberPerms(p core.PubKey) []string {
	m, ok := e.r.Member(p)
	if !ok {
		e.t.Fatalf("member %s missing", p)
	}
	return m.Perms
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// snapshotBan 测试辅助：查黑名单条目。
func (r *Roster) snapshotBan(p core.PubKey) (core.BlacklistEntry, bool) {
	_, banned, _ := r.Snapshot()
	for _, b := range banned {
		if b.Pub.Equal(p) {
			return b, true
		}
	}
	return core.BlacklistEntry{}, false
}

// --- 创世与创建者 -----------------------------------------------------------

func TestGenesisCreatorPermanentTop(t *testing.T) {
	e := newEnv(t, Options{})
	if e.r.MemberCount() != 1 {
		t.Fatalf("member count = %d, want 1", e.r.MemberCount())
	}
	m, ok := e.r.Member(e.cfg.Creator)
	if !ok || m.Role != core.RoleCreator {
		t.Fatalf("creator entry = %+v, ok=%v", m, ok)
	}
	if got := e.r.TierOf(e.cfg.Creator); got != core.TierCreator {
		t.Fatalf("creator tier = %d", got)
	}
	if !e.r.Owner().Equal(e.cfg.Creator) {
		t.Fatal("owner pointer should be creator")
	}
	for _, p := range []string{core.PermCarry, core.PermKick, core.PermUnban, core.PermGrantAdmin, core.PermTransfer, core.PermNetdisk, core.PermSpeak} {
		if !e.r.HasPerm(e.cfg.Creator, p) {
			t.Fatalf("creator should hold %s", p)
		}
	}
	var stranger core.PubKey
	if got := e.r.TierOf(stranger); got != core.TierNonMember {
		t.Fatalf("stranger tier = %d", got)
	}
	ts := e.now
	// 创建者不可被 remove / perms / kick（永久最高）。
	e.wantErr(e.ev(e.creat, core.TypeRemove, eventTarget{Target: e.cfg.Creator}, ts), core.ErrNotPermitted)
	e.wantErr(e.ev(e.creat, core.TypePerms, eventPerms{Target: e.cfg.Creator, Perms: []string{core.PermSpeak}}, ts), core.ErrNotPermitted)
	other := mkSigner(t, 77) // 非成员冒名签事件 → 伪签前验不过 sender；用群内另一事件源测 kick 层级
	_ = other
	e.wantErr(e.ev(e.creat, core.TypeKick, eventTarget{Target: mkSigner(t, 77).Pub()}, ts), core.ErrMalformed) // 目标非成员
}

// --- join -------------------------------------------------------------------

func TestJoinFlows(t *testing.T) {
	t.Run("creatorCarriesNewMember", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		e.mustApply(e.joinAs(e.creat, alice.Pub(), e.now-50_000, mkWG(10)))
		m, ok := e.r.Member(alice.Pub())
		if !ok || m.Role != core.RoleMember {
			t.Fatalf("alice not joined: %+v", m)
		}
		if e.r.TierOf(alice.Pub()) != core.TierMember {
			t.Fatal("alice should be member tier")
		}
		if err := verifyMemberProof(m); err != nil {
			t.Fatalf("join proof invalid: %v", err)
		}
	})
	t.Run("adminWithCarryCanJoin", func(t *testing.T) {
		e := newEnv(t, Options{})
		admin, ts := e.bootstrapAdmin(20, e.now-50_000, core.PermCarry)
		if !e.r.HasPerm(admin.Pub(), core.PermCarry) {
			t.Fatal("admin should have carry")
		}
		bob := mkSigner(t, 21)
		e.mustApply(e.joinAs(admin, bob.Pub(), ts, mkWG(21)))
		if _, ok := e.r.Member(bob.Pub()); !ok {
			t.Fatal("bob should be member")
		}
	})
	t.Run("selfSignedJoinAlwaysInvalid", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		// 未入群者自签 join → 「签名者须为成员」拦下。
		e.wantErr(e.joinAs(alice, alice.Pub(), e.now, mkWG(10)), core.ErrNotPermitted)
		// 具 carry 的创建者自签自己 → 「新人自签无效」拦下。
		e.wantErr(e.joinAs(e.creat, e.creat.Pub(), e.now, mkWG(1)), core.ErrNotPermitted)
	})
	t.Run("nonCarryMemberJoinRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		e.mustApply(e.joinAs(e.creat, alice.Pub(), e.now-50_000, mkWG(10)))
		carol := mkSigner(t, 11)
		e.wantErr(e.joinAs(alice, carol.Pub(), e.now, mkWG(11)), core.ErrNotPermitted)
	})
	t.Run("tierGatedPermViaJoinRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		dave := mkSigner(t, 12)
		e.wantErr(e.joinAs(e.creat, dave.Pub(), e.now, mkWG(12), core.PermSpeak, core.PermCarry), core.ErrNotPermitted)
	})
	t.Run("badPermListRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		frank := mkSigner(t, 13)
		e.wantErr(e.joinAs(e.creat, frank.Pub(), e.now, mkWG(13), "bogus"), core.ErrMalformed)
	})
	t.Run("blacklistedTargetRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		ts := e.now - 50_000
		e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))
		e.mustApply(e.ev(e.creat, core.TypeKick, eventTarget{Target: alice.Pub()}, ts+1))
		e.wantErr(e.joinAs(e.creat, alice.Pub(), ts+2, mkWG(10)), core.ErrNotPermitted)
	})
	t.Run("alreadyMemberRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		ts := e.now - 50_000
		e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))
		e.wantErr(e.joinAs(e.creat, alice.Pub(), ts+1, mkWG(10)), core.ErrMalformed)
	})
	t.Run("zeroWGRejected", func(t *testing.T) {
		e := newEnv(t, Options{})
		alice := mkSigner(t, 10)
		e.wantErr(e.joinAs(e.creat, alice.Pub(), e.now, core.WGPub{}), core.ErrMalformed)
	})
}

// --- remove（退群）与 kick（除名）分离 ----------------------------------------

func TestRemoveIsSelfOnlyAndNeverEscalates(t *testing.T) {
	e := newEnv(t, Options{})
	alice := mkSigner(t, 10)
	bob := mkSigner(t, 11)
	ts := e.now - 50_000
	e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))
	e.mustApply(e.joinAs(e.creat, bob.Pub(), ts+1, mkWG(11)))

	// 他人代签 remove：无效，且绝不进黑名单（不升级为除名）。
	e.wantErr(e.ev(bob, core.TypeRemove, eventTarget{Target: alice.Pub()}, ts+2), core.ErrNotPermitted)
	if e.r.IsBlacklisted(alice.Pub()) {
		t.Fatal("proxy remove must not blacklist")
	}
	if _, ok := e.r.Member(alice.Pub()); !ok {
		t.Fatal("alice should still be member")
	}
	// 具 kick 权限者代签 remove：同样只算无效（v15 不再看签名者定效果）。
	_, _ = e.bootstrapAdmin(20, ts+2)
	e.wantErr(e.ev(mkSigner(t, 20), core.TypeRemove, eventTarget{Target: alice.Pub()}, ts+3), core.ErrNotPermitted)
	if e.r.IsBlacklisted(alice.Pub()) {
		t.Fatal("admin proxy remove must not blacklist")
	}
	// 本人自签 remove：退群，不进黑名单。
	e.mustApply(e.ev(alice, core.TypeRemove, eventTarget{Target: alice.Pub()}, ts+4))
	if _, ok := e.r.Member(alice.Pub()); ok {
		t.Fatal("alice should have left")
	}
	if e.r.IsBlacklisted(alice.Pub()) {
		t.Fatal("remove must not blacklist")
	}
	// 退群后可被重新拉入。
	e.mustApply(e.joinAs(e.creat, alice.Pub(), ts+5, mkWG(10)))
	if _, ok := e.r.Member(alice.Pub()); !ok {
		t.Fatal("alice should rejoin")
	}
}

func TestKickUnbanFlows(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	admin, ts := e.bootstrapAdmin(20, base, core.PermKick)
	alice := mkSigner(t, 10)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))

	// 无 kick 权限的成员不能除人。
	e.wantErr(e.ev(alice, core.TypeKick, eventTarget{Target: admin.Pub()}, ts+1), core.ErrNotPermitted)
	// 管理（具 kick）除名成员：删白名单 + 进黑名单。
	e.mustApply(e.ev(admin, core.TypeKick, eventTarget{Target: alice.Pub()}, ts+2))
	if !e.r.IsBlacklisted(alice.Pub()) {
		t.Fatal("kicked member must be blacklisted")
	}
	if _, ok := e.r.Member(alice.Pub()); ok {
		t.Fatal("kicked member must leave whitelist")
	}
	ban, ok := e.r.snapshotBan(alice.Pub())
	if !ok {
		t.Fatal("blacklist entry missing")
	}
	if err := verifyBlacklistProof(ban); err != nil {
		t.Fatalf("ban proof: %v", err)
	}
	// 被除名者任何事件一律无效（黑名单优先）。
	e.wantErr(e.ev(alice, core.TypeUnban, eventTarget{Target: alice.Pub()}, ts+3), core.ErrNotPermitted)
	// unban（kick 权限位=具解禁权限）恢复。
	e.mustApply(e.ev(admin, core.TypeUnban, eventTarget{Target: alice.Pub()}, ts+4))
	if e.r.IsBlacklisted(alice.Pub()) {
		t.Fatal("should be unbanned")
	}
	// unban 目标不在黑名单 → 无效事件。
	e.wantErr(e.ev(admin, core.TypeUnban, eventTarget{Target: alice.Pub()}, ts+5), core.ErrMalformed)
	// unban 后可重新被拉入。
	e.mustApply(e.joinAs(e.creat, alice.Pub(), ts+6, mkWG(10)))
	// kick 自己 → 无效（离开请用 remove）。
	e.wantErr(e.ev(admin, core.TypeKick, eventTarget{Target: admin.Pub()}, ts+7), core.ErrNotPermitted)
	// 管理 kick 管理（同级）→ 无效。
	admin2, ts2 := e.bootstrapAdmin(30, ts+8, core.PermKick)
	e.wantErr(e.ev(admin2, core.TypeKick, eventTarget{Target: admin.Pub()}, ts2), core.ErrNotPermitted)
	// 管理不可除名创建者/群主。
	e.wantErr(e.ev(admin, core.TypeKick, eventTarget{Target: e.cfg.Creator}, ts2+1), core.ErrNotPermitted)
}

// --- 层级权限矩阵 ------------------------------------------------------------

func TestHierarchyMatrix(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	admin, ts := e.bootstrapAdmin(20, base)
	mallory := mkSigner(t, 40)
	other := mkSigner(t, 41)
	e.mustApply(e.joinAs(e.creat, mallory.Pub(), ts, mkWG(40)))
	e.mustApply(e.joinAs(e.creat, other.Pub(), ts+1, mkWG(41)))

	t.Run("adminOverMemberOK", func(t *testing.T) {
		e.mustApply(e.ev(admin, core.TypePerms, eventPerms{Target: mallory.Pub(),
			Perms: []string{core.PermSpeak}}, ts+2))
		if got := e.memberPerms(mallory.Pub()); len(got) != 1 || got[0] != core.PermSpeak {
			t.Fatalf("perms = %v", got)
		}
	})
	t.Run("adminOverAdminRejected", func(t *testing.T) {
		e.wantErr(e.ev(admin, core.TypePerms, eventPerms{Target: admin.Pub(),
			Perms: []string{core.PermSpeak}}, ts+3), core.ErrNotPermitted)
	})
	t.Run("memberSigningAnyAdminEventRejected", func(t *testing.T) {
		e.wantErr(e.ev(mallory, core.TypePerms, eventPerms{Target: other.Pub(),
			Perms: []string{core.PermSpeak}}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeGrantAdmin, eventTarget{Target: other.Pub()}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeRevokeAdmin, eventTarget{Target: admin.Pub()}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeTransfer, eventTransfer{NewOwner: other.Pub()}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeNetdisk, eventNetdisk{MB: 10}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeKick, eventTarget{Target: other.Pub()}, ts+4), core.ErrNotPermitted)
		e.wantErr(e.ev(mallory, core.TypeUnban, eventTarget{Target: other.Pub()}, ts+4), core.ErrNotPermitted)
	})
	t.Run("adminCannotGrantAdminOrCarry", func(t *testing.T) {
		e.wantErr(e.ev(admin, core.TypeGrantAdmin, eventTarget{Target: mallory.Pub()}, ts+5), core.ErrNotPermitted)
		e.wantErr(e.ev(admin, core.TypePerms, eventPerms{Target: mallory.Pub(),
			Perms: []string{core.PermSpeak, core.PermCarry}}, ts+5), core.ErrNotPermitted)
	})
	t.Run("ownerGrantsTierGatedToAdmin", func(t *testing.T) {
		e.mustApply(e.ev(e.creat, core.TypePerms, eventPerms{Target: admin.Pub(),
			Perms: []string{core.PermSpeak, core.PermReceive, core.PermCarry}}, ts+6))
		if !e.r.HasPerm(admin.Pub(), core.PermCarry) {
			t.Fatal("admin should have carry")
		}
	})
	t.Run("grantAndRevokeAdmin", func(t *testing.T) {
		e.mustApply(e.ev(e.creat, core.TypeGrantAdmin, eventTarget{Target: mallory.Pub()}, ts+7))
		if e.r.TierOf(mallory.Pub()) != core.TierAdmin {
			t.Fatal("mallory should be admin")
		}
		e.wantErr(e.ev(e.creat, core.TypeGrantAdmin, eventTarget{Target: mallory.Pub()}, ts+8), core.ErrMalformed)
		e.mustApply(e.ev(e.creat, core.TypeRevokeAdmin, eventTarget{Target: mallory.Pub()}, ts+9))
		if e.r.TierOf(mallory.Pub()) != core.TierMember {
			t.Fatal("mallory revoked should be member")
		}
		e.wantErr(e.ev(e.creat, core.TypeRevokeAdmin, eventTarget{Target: mallory.Pub()}, ts+10), core.ErrMalformed)
	})
	t.Run("badPermNamesRejected", func(t *testing.T) {
		e.wantErr(e.ev(e.creat, core.TypePerms, eventPerms{Target: mallory.Pub(),
			Perms: []string{"fly"}}, ts+11), core.ErrMalformed)
		e.wantErr(e.ev(e.creat, core.TypePerms, eventPerms{Target: mallory.Pub(),
			Perms: nil}, ts+11), core.ErrMalformed)
		e.wantErr(e.ev(e.creat, core.TypePerms, eventPerms{Target: mallory.Pub(),
			Perms: []string{core.PermSpeak, core.PermSpeak}}, ts+11), core.ErrMalformed)
	})
}

// --- transfer ----------------------------------------------------------------

func TestTransferWithEndorsement(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	admin, ts := e.bootstrapAdmin(20, base, core.PermTransfer, core.PermKick, core.PermUnban, core.PermNetdisk)
	carol := mkSigner(t, 45)

	t.Run("noEndorsementRejected", func(t *testing.T) {
		e.wantErr(e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts), core.ErrNotPermitted)
	})
	t.Run("wrongEndorserRejected", func(t *testing.T) {
		m := e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts+1)
		if err := EndorseEvent(&m, mkSigner(t, 41)); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m, core.ErrInvalidSig)
	})
	t.Run("memberSignedTransferRejected", func(t *testing.T) {
		e.mustApply(e.joinAs(e.creat, carol.Pub(), ts+2, mkWG(45)))
		m := e.ev(carol, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts+3)
		if err := EndorseEvent(&m, admin); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m, core.ErrNotPermitted)
	})
	t.Run("validTransfer", func(t *testing.T) {
		m := e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts+4)
		if err := EndorseEvent(&m, admin); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m)
		if !e.r.Owner().Equal(admin.Pub()) {
			t.Fatal("owner pointer should move")
		}
		if e.r.TierOf(admin.Pub()) != core.TierOwner {
			t.Fatal("admin should be owner tier")
		}
		if e.r.TierOf(e.cfg.Creator) != core.TierCreator {
			t.Fatal("creator stays top tier")
		}
	})
	t.Run("transferToSelfRejected", func(t *testing.T) {
		m := e.ev(admin, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts+5)
		if err := EndorseEvent(&m, admin); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("chainTransferDemotesOldOwner", func(t *testing.T) {
		e.mustApply(e.ev(admin, core.TypePerms, eventPerms{Target: carol.Pub(),
			Perms: []string{core.PermSpeak, core.PermReceive, core.PermTransfer}}, ts+6))
		m := e.ev(admin, core.TypeTransfer, eventTransfer{NewOwner: carol.Pub()}, ts+7)
		if err := EndorseEvent(&m, carol); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m)
		if !e.r.Owner().Equal(carol.Pub()) {
			t.Fatal("owner should be carol")
		}
		if e.r.TierOf(admin.Pub()) != core.TierAdmin {
			t.Fatalf("old owner demoted: tier=%d", e.r.TierOf(admin.Pub()))
		}
	})
	t.Run("creatorCanKickOwnerAndPointerFallsBack", func(t *testing.T) {
		e.mustApply(e.ev(e.creat, core.TypeKick, eventTarget{Target: carol.Pub()}, ts+8))
		if !e.r.IsBlacklisted(carol.Pub()) {
			t.Fatal("owner carol should be kicked")
		}
		if !e.r.Owner().Equal(e.cfg.Creator) {
			t.Fatal("owner pointer should fall back to creator")
		}
	})
}

// evTo 构造带 to 的名单事件（v17①：唯一允许 to 非空的是 transfer）。
func (e *env) evTo(s core.Signer, to *core.PubKey, typ string, content any, ts int64) core.Message {
	e.t.Helper()
	c, err := EncodeEventContent(content)
	if err != nil {
		e.t.Fatal(err)
	}
	m := core.Message{Type: typ, TSms: ts, Content: c, To: to}
	if err := SignEvent(&m, s, e.gid); err != nil {
		e.t.Fatal(err)
	}
	return m
}

func TestTransferDirectedAndSelfClaim(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 40_000
	admin, ts := e.bootstrapAdmin(20, base, core.PermTransfer)
	carol := mkSigner(t, 45)

	t.Run("directedEndorsedTransferAdopted", func(t *testing.T) {
		// 提案定向（to=新 owner）→ 联署后的生效原文仍含 to → 广播采纳。
		m := e.evTo(e.creat, ptrOf(admin.Pub()), core.TypeTransfer,
			eventTransfer{NewOwner: admin.Pub()}, ts)
		if err := EndorseEvent(&m, admin); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m)
		if !e.r.Owner().Equal(admin.Pub()) {
			t.Fatal("owner pointer should move via directed transfer")
		}
	})
	t.Run("directedToMismatchRejected", func(t *testing.T) {
		e.mustApply(e.joinAs(e.creat, carol.Pub(), ts+1, mkWG(45)))
		m := e.evTo(e.creat, ptrOf(carol.Pub()), core.TypeTransfer,
			eventTransfer{NewOwner: admin.Pub()}, ts+2)
		if err := EndorseEvent(&m, admin); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("nonTransferDirectedRejected", func(t *testing.T) {
		dave := mkSigner(t, 46)
		m := e.evTo(e.creat, ptrOf(dave.Pub()), core.TypeJoin,
			eventJoin{Pub: dave.Pub(), WG: mkWG(46), Perms: e.cfg.DefaultPerms}, ts+3)
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("creatorSelfClaimReclaimsOwnership", func(t *testing.T) {
		// 自领快捷路径（v17 C.4）：创建者签原文 + 自联署一步生效。
		m := e.evTo(e.creat, ptrOf(e.cfg.Creator), core.TypeTransfer,
			eventTransfer{NewOwner: e.cfg.Creator}, ts+4)
		if err := EndorseEvent(&m, e.creat); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m)
		if !e.r.Owner().Equal(e.cfg.Creator) {
			t.Fatal("creator self-claim should move pointer back")
		}
		if got := e.r.TierOf(admin.Pub()); got != core.TierAdmin {
			t.Fatalf("prev owner demoted by creator-signed reclaim: tier=%d", got)
		}
	})
	t.Run("transferToCurrentOwnerRejected", func(t *testing.T) {
		m := e.ev(e.creat, core.TypeTransfer, eventTransfer{NewOwner: e.cfg.Creator}, ts+5)
		if err := EndorseEvent(&m, e.creat); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m, core.ErrMalformed) // 已是 owner：无操作移交无效
	})
	t.Run("nonCreatorSelfClaimRejected", func(t *testing.T) {
		// 先把群主位交给 admin，再让 admin 自领自签：非创建者无效。
		m1 := e.evTo(e.creat, ptrOf(admin.Pub()), core.TypeTransfer,
			eventTransfer{NewOwner: admin.Pub()}, ts+6)
		if err := EndorseEvent(&m1, admin); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m1)
		m2 := e.ev(admin, core.TypeTransfer, eventTransfer{NewOwner: admin.Pub()}, ts+7)
		if err := EndorseEvent(&m2, admin); err != nil {
			t.Fatal(err)
		}
		e.wantErr(m2, core.ErrMalformed)
	})
}

func ptrOf(p core.PubKey) *core.PubKey { return &p }
