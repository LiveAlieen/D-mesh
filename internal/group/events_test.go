package group

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"dmesh/internal/core"
)

// --- presence -----------------------------------------------------------------

func TestPresenceSelfOnlyMaxMerge(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	bob := mkSigner(t, 11)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
	e.mustApply(e.joinAs(e.creat, bob.Pub(), base+1, mkWG(11)))

	p := func(s core.Signer, last, after int64) core.Message {
		return e.ev(s, core.TypePresence, eventPresence{Pub: s.Pub(), LastMsgTS: last, OfflineAfter: after}, last)
	}
	// 本人自签推进。
	e.mustApply(p(alice, base+10, 60_000))
	got := e.r.Presence(alice.Pub())
	if got.LastMsgTS != base+10 || got.OfflineAfter != 60_000 {
		t.Fatalf("presence = %+v", got)
	}
	if !got.Online(base+10+59_999) || got.Online(base+10+60_000) {
		t.Fatal("Online boundary wrong")
	}
	// 旧值不覆盖新值（max 合并，静默幂等）。
	e.mustApply(p(alice, base+5, 90_000))
	if got := e.r.Presence(alice.Pub()); got.LastMsgTS != base+10 || got.OfflineAfter != 60_000 {
		t.Fatalf("stale presence overwrote: %+v", got)
	}
	// 同 ts 窗口内可更新阈值。
	e.mustApply(e.ev(alice, core.TypePresence, eventPresence{Pub: alice.Pub(), LastMsgTS: base + 10, OfflineAfter: 45_000}, base+12))
	if got := e.r.Presence(alice.Pub()); got.OfflineAfter != 45_000 {
		t.Fatalf("offline_after not refreshed: %+v", got)
	}
	// 代签/代报一律丢弃。
	proxy := e.ev(bob, core.TypePresence, eventPresence{Pub: alice.Pub(), LastMsgTS: base + 999, OfflineAfter: 1}, base+999)
	e.wantErr(proxy, core.ErrNotPermitted)
	if got := e.r.Presence(alice.Pub()); got.LastMsgTS == base+999 {
		t.Fatal("proxy presence applied!")
	}
	// 自相矛盾：last_msg_ts 晚于消息自身 ts。
	e.wantErr(e.ev(alice, core.TypePresence, eventPresence{Pub: alice.Pub(), LastMsgTS: base + 500, OfflineAfter: 0}, base+100), core.ErrMalformed)
	// 负值拒绝。
	e.wantErr(e.ev(alice, core.TypePresence, eventPresence{Pub: alice.Pub(), LastMsgTS: base, OfflineAfter: -1}, base+101), core.ErrMalformed)
	// 非成员 presence → 拒。
	stranger := mkSigner(t, 55)
	e.wantErr(e.ev(stranger, core.TypePresence, eventPresence{Pub: stranger.Pub(), LastMsgTS: base, OfflineAfter: 0}, base+102), core.ErrNotPermitted)
	// presence 不占白名单。
	if _, ok := e.r.Member(bob.Pub()); !ok {
		t.Fatal("bob still member (sanity)")
	}
	if e.r.MemberCount() != 3 { // creator + alice + bob
		t.Fatalf("member count = %d", e.r.MemberCount())
	}
}

// --- netdisk -------------------------------------------------------------------

func TestNetdiskBoundsAndAuthority(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))

	tcs := []struct {
		name    string
		signer  core.Signer
		mb      int
		wantErr error
		wantMB  int
	}{
		{"creatorSet64", e.creat, 64, nil, 64},
		{"ownerSetMax256", e.creat, 256, nil, 256},
		{"ownerSet0", e.creat, 0, nil, 0},
		{"memberSignedRejected", alice, 10, core.ErrNotPermitted, 0},
		{"outOfRangeHighRejected", e.creat, 257, core.ErrMalformed, 0},
		{"outOfRangeNegativeRejected", e.creat, -1, core.ErrMalformed, 0},
	}
	mb := 0
	for i, tc := range tcs {
		m := e.ev(tc.signer, core.TypeNetdisk, eventNetdisk{MB: tc.mb}, base+int64(i)+1)
		if tc.wantErr != nil {
			e.wantErr(m, tc.wantErr)
			continue
		}
		e.mustApply(m)
		mb = tc.wantMB
		if got := e.r.NetdiskMB(); got != mb {
			t.Fatalf("%s: NetdiskMB = %d, want %d", tc.name, got, mb)
		}
		if cfg, ok := e.r.Config(); !ok || cfg.NetdiskMB != mb {
			t.Fatalf("%s: cfg.NetdiskMB = %d", tc.name, cfg.NetdiskMB)
		}
	}
	// 群主把 netdisk 位授给成员（须群主层级+本人持有）后，成员仍不可签 netdisk。
	e.mustApply(e.ev(e.creat, core.TypePerms, eventPerms{Target: alice.Pub(),
		Perms: []string{core.PermSpeak, core.PermReceive, core.PermNetdisk}}, base+20))
	e.wantErr(e.ev(alice, core.TypeNetdisk, eventNetdisk{MB: 5}, base+21), core.ErrNotPermitted)
}

// --- join_req 收件箱 ------------------------------------------------------------

func TestJoinReqInbox(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	newcomer := mkSigner(t, 60)
	req := e.ev(newcomer, core.TypeJoinReq, eventJoinReq{Pub: newcomer.Pub(), WG: mkWG(60), Ref: "abc"}, base)
	e.mustApply(req)
	if e.r.MemberCount() != 1 {
		t.Fatal("join_req must not change whitelist")
	}
	qs := e.r.PollJoinReqs()
	if len(qs) != 1 || qs[0].MsgID != req.MsgID {
		t.Fatalf("inbox = %+v", qs)
	}
	if len(e.r.PollJoinReqs()) != 0 {
		t.Fatal("inbox should drain")
	}
	// 同一申请人重复申请只留最新。
	e.mustApply(e.ev(newcomer, core.TypeJoinReq, eventJoinReq{Pub: newcomer.Pub(), WG: mkWG(60)}, base+1))
	e.mustApply(e.ev(newcomer, core.TypeJoinReq, eventJoinReq{Pub: newcomer.Pub(), WG: mkWG(61)}, base+2))
	qs = e.r.PollJoinReqs()
	if len(qs) != 1 || qs[0].TSms != base+2 {
		t.Fatalf("dedup inbox = %+v", qs)
	}
	// 成员发 join_req → 拒。
	alice := mkSigner(t, 10)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), base+3, mkWG(10)))
	e.wantErr(e.ev(alice, core.TypeJoinReq, eventJoinReq{Pub: alice.Pub(), WG: mkWG(10)}, base+4), core.ErrNotPermitted)
	// 代报（content.pub != sender）→ 拒。
	e.wantErr(e.ev(alice, core.TypeJoinReq, eventJoinReq{Pub: newcomer.Pub(), WG: mkWG(62)}, base+5), core.ErrMalformed)
	// 缺 wg_pub → 拒。
	e.wantErr(e.ev(alice, core.TypeJoinReq, eventJoinReq{Pub: alice.Pub()}, base+6), core.ErrMalformed)
	// 被拉黑者的 join_req → 拒（黑名单优先）。
	e.mustApply(e.ev(e.creat, core.TypeKick, eventTarget{Target: alice.Pub()}, base+7))
	e.wantErr(e.ev(alice, core.TypeJoinReq, eventJoinReq{Pub: alice.Pub(), WG: mkWG(10)}, base+8), core.ErrNotPermitted)
}

// --- 签名/算法（v16 可插拔） ------------------------------------------------------

func TestSignatureAndAlgRules(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	good := e.joinAs(e.creat, alice.Pub(), base, mkWG(10))

	t.Run("tamperedSig", func(t *testing.T) {
		m := good
		m.Sig = append([]byte(nil), m.Sig...)
		m.Sig[0] ^= 0xFF
		e.wantErr(m, core.ErrInvalidSig)
	})
	t.Run("tamperedContent", func(t *testing.T) {
		m := good
		m.Content = append([]byte(nil), m.Content...)
		m.Content[0] ^= 0x20
		e.wantErr(m, core.ErrInvalidSig)
	})
	t.Run("wrongGroup", func(t *testing.T) {
		m := good
		m.GroupID = sha256.Sum256([]byte("other group"))
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("directedMessageNotEvent", func(t *testing.T) {
		m := e.ev(e.creat, core.TypeNetdisk, eventNetdisk{MB: 1}, base+1)
		to := alice.Pub()
		m.To = &to
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("chatTypesRejected", func(t *testing.T) {
		m := e.ev(alice, core.TypeText, "hi", base+1)
		e.wantErr(m, core.ErrMalformed)
		m2 := e.ev(alice, core.TypeHide, "x", base+1)
		e.wantErr(m2, core.ErrMalformed)
		m3 := e.ev(alice, "bogus_type", "x", base+1)
		e.wantErr(m3, core.ErrMalformed)
	})
	t.Run("emptyMsgID", func(t *testing.T) {
		m := good
		m.MsgID = ""
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("algMismatchSender", func(t *testing.T) {
		m := good
		m.Alg = "sm2" // 与 sender.alg 不符 → 串用降级，判结构非法
		e.wantErr(m, core.ErrMalformed)
	})
	t.Run("unknownAlgRejected", func(t *testing.T) {
		fake := &algSigner{alg: "sm2-not-registered", pub: []byte("fake-pub")}
		m := core.Message{Type: core.TypeNetdisk, TSms: base + 1}
		if err := SignEvent(&m, fake, e.gid); err != nil {
			t.Fatal(err)
		}
		err := e.r.ApplyEvent(m)
		if !core.IsUnknownAlg(err) {
			t.Fatalf("want ErrUnknownAlg, got %v", err)
		}
		if !errors.Is(err, core.ErrUnknownAlg) {
			t.Fatalf("errors.Is failed: %v", err)
		}
	})
	t.Run("crossAlgCoexistence", func(t *testing.T) {
		// 注册临时算法 x-test → 不同算法密钥共存于同一群、同一名单（v16）。
		core.Register("x-test", func(pub core.PubKey, msg, sig []byte) bool {
			return pub.Alg == "x-test" && bytes.Equal(sig, append([]byte("x:"), pub.Bytes...))
		})
		defer core.Register("x-test", nil)
		dave := &algSigner{alg: "x-test", pub: []byte("dave")}
		creator := e.creat // ed25519 拉人者
		e.mustApply(e.ev(creator, core.TypeJoin, eventJoin{Pub: dave.Pub(), WG: mkWG(70),
			Perms: e.cfg.DefaultPerms}, base+2))
		if e.r.TierOf(dave.Pub()) != core.TierMember {
			t.Fatal("x-test member should be in whitelist")
		}
		// x-test 成员自签 presence 走新算法验签。
		m := core.Message{Type: core.TypePresence, TSms: base + 3,
			Content: mustEnc(e.t, eventPresence{Pub: dave.Pub(), LastMsgTS: base + 3})}
		if err := SignEvent(&m, dave, e.gid); err != nil {
			t.Fatal(err)
		}
		e.mustApply(m)
		if got := e.r.Presence(dave.Pub()); got.LastMsgTS != base+3 {
			t.Fatalf("cross-alg presence = %+v", got)
		}
		// 群主用 ed25519 改 x-test 成员权限：跨算法信任成立。
		e.mustApply(e.ev(creator, core.TypePerms, eventPerms{Target: dave.Pub(),
			Perms: []string{core.PermReceive}}, base+4))
		if got := e.memberPerms(dave.Pub()); len(got) != 1 || got[0] != core.PermReceive {
			t.Fatalf("perms = %v", got)
		}
	})
}

type algSigner struct {
	alg core.SigAlg
	pub []byte
}

func (a *algSigner) Alg() core.SigAlg { return a.alg }
func (a *algSigner) Pub() core.PubKey {
	return core.PubKey{Alg: a.alg, Bytes: append([]byte(nil), a.pub...)}
}
func (a *algSigner) Sign(msg []byte) ([]byte, error) {
	return append([]byte("x:"), a.pub...), nil
}

func mustEnc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := EncodeEventContent(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- 幂等 / 时间窗 / 乱序 --------------------------------------------------------

func TestIdempotentApply(t *testing.T) {
	e := newEnv(t, Options{})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	join := e.joinAs(e.creat, alice.Pub(), base, mkWG(10))
	e.mustApply(join)
	e.mustApply(join) // 同 msg_id 重复：静默幂等
	if e.r.MemberCount() != 2 {
		t.Fatalf("member count = %d", e.r.MemberCount())
	}
	kick := e.ev(e.creat, core.TypeKick, eventTarget{Target: alice.Pub()}, base+1)
	e.mustApply(kick)
	e.mustApply(kick)
	if n, _, _ := e.r.Snapshot(); len(n) != 1 {
		t.Fatalf("whitelist = %d entries", len(n))
	}
}

func TestTimeWindowRejects(t *testing.T) {
	e := newEnv(t, Options{LowWaterGraceMS: 1000, MaxClockSkewMS: 500})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
	// 未来超限。
	e.wantErr(e.ev(e.creat, core.TypeNetdisk, eventNetdisk{MB: 1}, e.now+501), core.ErrMalformed)
	// 远古重放（低于低水位-宽限）。
	e.wantErr(e.ev(e.creat, core.TypeNetdisk, eventNetdisk{MB: 1}, base-1001), core.ErrMalformed)
	// 未来但在偏差内 → 允许（进入乱序缓存或直接应用）。
	e.mustApply(e.ev(e.creat, core.TypeNetdisk, eventNetdisk{MB: 2}, e.now+400))
	if e.r.NetdiskMB() != 2 {
		t.Fatal("within-skew future event must apply")
	}
}

func TestOutOfOrderHoldAndReapplyInTSOrder(t *testing.T) {
	// 重排窗口开大：高 ts 事件必须等水位衔接。
	e := newEnv(t, Options{ReorderWindowMS: 60_000})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	e.applyNoFlush(e.joinAs(e.creat, alice.Pub(), base, mkWG(10))) // 建立水位 base

	// 两个 perms 事件：t1（[speak]）与 t2（[receive]），若按 t2→t1 立即应用，
	// 最终权限将是 [speak]；正确行为是按 ts 升序应用 → 最终 [receive]。
	p1 := e.ev(e.creat, core.TypePerms, eventPerms{Target: alice.Pub(), Perms: []string{core.PermSpeak}}, base+10)
	p2 := e.ev(e.creat, core.TypePerms, eventPerms{Target: alice.Pub(), Perms: []string{core.PermReceive}}, base+20)

	e.applyNoFlush(p2) // 迟到的高位事件 → 进缓存（尚未生效）
	if got := e.memberPerms(alice.Pub()); len(got) != 2 {
		t.Fatalf("held event must not mutate state yet: %v", got)
	}
	if e.r.PendingCount() != 1 {
		t.Fatalf("pending = %d", e.r.PendingCount())
	}
	e.applyNoFlush(p1) // ts=base+10 > watermark=base → 也进缓存
	if e.r.PendingCount() != 2 {
		t.Fatalf("pending = %d, want 2", e.r.PendingCount())
	}
	// 窗口未到不排出。
	applied, failed := e.r.FlushPending()
	if applied != 0 || len(failed) != 0 {
		t.Fatalf("premature drain: applied=%d failed=%d", applied, len(failed))
	}
	// 时钟越过重排窗口 → 按 ts 升序衔接应用：先 p1 后 p2 → 终态 [receive]。
	e.r.SetClock(func() time.Time { return time.UnixMilli(e.now + 61_000) })
	applied, failed = e.r.FlushPending()
	if applied != 2 || len(failed) != 0 {
		t.Fatalf("drain: applied=%d failed=%d", applied, len(failed))
	}
	if got := e.memberPerms(alice.Pub()); len(got) != 1 || got[0] != core.PermReceive {
		t.Fatalf("final perms = %v, want [receive] (ts order)", got)
	}
}

func TestOutOfOrderLateWithinWatermark(t *testing.T) {
	// 默认小窗口：低于水位但仍在宽限内的迟到事件按当前状态直接应用。
	e := newEnv(t, Options{})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	e.mustApply(e.joinAs(e.creat, alice.Pub(), base+100, mkWG(10))) // watermark=base+100
	late := e.ev(e.creat, core.TypePerms, eventPerms{Target: alice.Pub(), Perms: []string{core.PermSpeak}}, base+50)
	e.mustApply(late) // ts <= watermark → 立即应用（不入缓存）
	if e.r.PendingCount() != 0 {
		t.Fatal("late event should not be held")
	}
	if got := e.memberPerms(alice.Pub()); len(got) != 1 {
		t.Fatalf("late event not applied: %v", got)
	}
}

// TestV16PermissionSemanticsMatrix 逐条（表驱动）覆盖 PLAN v15/v16 的权限/签名语义
// 正/负例，每条都在独立 env 里用本地生成的 ed25519 密钥对真实事件原文签名，
// 完整走 SignEvent → core.Verify 验签路径，并隔离出「拒绝原因」到底是权限位、
// 层级还是自签规则（配套 post 断言校验被拒后名单状态不被错误改动，例如代签
// remove 绝不升级为除名）。既有单测多把层级与权限两条件叠在同一条事件上，
// 本表把「层级够但无对应权限位」「有权限位但层级同级」等组合拆开验证。
func TestV16PermissionSemanticsMatrix(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T) (*env, core.Message, core.PubKey) // 返回 env、已签名事件、供 post 检查的目标 pub
		wantErr error                                                // nil 表示应成功应用（正例）
		post    func(t *testing.T, e *env, victim core.PubKey)
	}{
		// --- perms：签名者层级须严格高于目标 ---
		{
			name: "permsSameTierRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				a, ts := e.bootstrapAdmin(20, e.now-50_000)
				b, tsb := e.bootstrapAdmin(30, ts)
				return e, e.ev(a, core.TypePerms, eventPerms{Target: b.Pub(), Perms: []string{core.PermSpeak}}, tsb+1), b.Pub()
			},
			wantErr: core.ErrNotPermitted,
		},
		{
			name: "permsLowerTierSignerRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				m := mkSigner(t, 10)
				o := mkSigner(t, 11)
				e.mustApply(e.joinAs(e.creat, m.Pub(), base, mkWG(10)))
				e.mustApply(e.joinAs(e.creat, o.Pub(), base+1, mkWG(11)))
				return e, e.ev(m, core.TypePerms, eventPerms{Target: o.Pub(), Perms: []string{core.PermSpeak}}, base+2), o.Pub()
			},
			wantErr: core.ErrNotPermitted,
		},
		// --- join：只认 carry 权限者；新人自签一律无效 ---
		{
			name: "joinNonCarryRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				alice := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10))) // 普通成员，无 carry
				stranger := mkSigner(t, 44)
				return e, e.joinAs(alice, stranger.Pub(), base+1, mkWG(44)), stranger.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if _, ok := e.r.Member(victim); ok {
					t.Fatal("non-carry join must not add member")
				}
			},
		},
		{
			name: "joinSelfSignedRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				// 拉人者自身（持 carry 的创建者）自签 join 自己：仍属「新人自签」，一律无效。
				return e, e.joinAs(e.creat, e.creat.Pub(), e.now-50_000, mkWG(1)), e.creat.Pub()
			},
			wantErr: core.ErrNotPermitted,
		},
		// --- remove 仅本人自签 = 退群；代签无效且绝不升级为除名 ---
		{
			name: "removeSelfIsLeaveNotBan",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				alice := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
				return e, e.ev(alice, core.TypeRemove, eventTarget{Target: alice.Pub()}, base+1), alice.Pub()
			},
			wantErr: nil,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if _, ok := e.r.Member(victim); ok {
					t.Fatal("self remove should delete whitelist entry")
				}
				if e.r.IsBlacklisted(victim) {
					t.Fatal("self remove must NOT blacklist")
				}
			},
		},
		{
			name: "proxyRemoveByKickHolderNeverEscalates",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				admin, ts := e.bootstrapAdmin(20, base, core.PermKick) // 具 kick 权限者代签 remove
				alice := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))
				return e, e.ev(admin, core.TypeRemove, eventTarget{Target: alice.Pub()}, ts+1), alice.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if _, ok := e.r.Member(victim); !ok {
					t.Fatal("proxy remove must leave whitelist untouched")
				}
				if e.r.IsBlacklisted(victim) {
					t.Fatal("proxy remove must NEVER escalate to kick/blacklist")
				}
			},
		},
		// --- kick：须具 kick 权限位（与层级分别隔离验证）---
		{
			name: "kickSufficientTierNoPermRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				admin, ts := e.bootstrapAdmin(20, base) // 管理，但无 kick 位
				alice := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), ts, mkWG(10)))
				return e, e.ev(admin, core.TypeKick, eventTarget{Target: alice.Pub()}, ts+1), alice.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if e.r.IsBlacklisted(victim) {
					t.Fatal("kick rejected without perm must not blacklist")
				}
			},
		},
		{
			name: "kickHasPermButSameTierRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				a, ts := e.bootstrapAdmin(20, base, core.PermKick)
				b, tsb := e.bootstrapAdmin(30, ts, core.PermKick) // 同为管理（层级相同）
				return e, e.ev(a, core.TypeKick, eventTarget{Target: b.Pub()}, tsb+1), b.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if e.r.IsBlacklisted(victim) {
					t.Fatal("same-tier kick must not blacklist")
				}
			},
		},
		// --- unban：须具解禁权限（unban 或 kick 位）---
		{
			name: "unbanNoPermRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				x := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, x.Pub(), base, mkWG(10)))
				e.mustApply(e.ev(e.creat, core.TypeKick, eventTarget{Target: x.Pub()}, base+1)) // x 进黑名单
				alice := mkSigner(t, 11)                                                        // 普通成员，无 unban/kick 位
				e.mustApply(e.joinAs(e.creat, alice.Pub(), base+2, mkWG(11)))
				return e, e.ev(alice, core.TypeUnban, eventTarget{Target: x.Pub()}, base+3), x.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if !e.r.IsBlacklisted(victim) {
					t.Fatal("unban by non-permitted signer must keep blacklist entry")
				}
			},
		},
		// --- presence：仅本人自签推进，代签一律丢弃 ---
		{
			name: "presenceProxyRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				alice := mkSigner(t, 10)
				bob := mkSigner(t, 11)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
				e.mustApply(e.joinAs(e.creat, bob.Pub(), base+1, mkWG(11)))
				// bob 代报 alice 的在场：pub != sender。
				return e, e.ev(bob, core.TypePresence, eventPresence{Pub: alice.Pub(), LastMsgTS: base + 10, OfflineAfter: 60_000}, base+10), alice.Pub()
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, victim core.PubKey) {
				if got := e.r.Presence(victim); got.LastMsgTS != 0 {
					t.Fatalf("proxy presence must be dropped, got %+v", got)
				}
			},
		},
		// --- netdisk：0~256 越界直接拒 + 仅群主/创建者可签 ---
		{
			name: "netdiskOutOfRangeRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				return e, e.ev(e.creat, core.TypeNetdisk, eventNetdisk{MB: 300}, e.now-50_000), core.PubKey{}
			},
			wantErr: core.ErrMalformed,
			post: func(t *testing.T, e *env, _ core.PubKey) {
				if e.r.NetdiskMB() != 0 {
					t.Fatalf("out-of-range netdisk must not change quota, got %d", e.r.NetdiskMB())
				}
			},
		},
		{
			name: "netdiskInRangeButMemberRejected",
			build: func(t *testing.T) (*env, core.Message, core.PubKey) {
				e := newEnv(t, Options{})
				base := e.now - 50_000
				alice := mkSigner(t, 10)
				e.mustApply(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
				// 取值在合法区间内，但签名者层级不足 → 拒（隔离「越权」与「越界」）。
				return e, e.ev(alice, core.TypeNetdisk, eventNetdisk{MB: 5}, base+1), core.PubKey{}
			},
			wantErr: core.ErrNotPermitted,
			post: func(t *testing.T, e *env, _ core.PubKey) {
				if e.r.NetdiskMB() != 0 {
					t.Fatalf("member-signed netdisk must not change quota, got %d", e.r.NetdiskMB())
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e, m, victim := tc.build(t)
			if tc.wantErr == nil {
				e.mustApply(m)
			} else {
				e.wantErr(m, tc.wantErr)
			}
			if tc.post != nil {
				tc.post(t, e, victim)
			}
		})
	}
}

func TestPendingCapacityEvictsOldest(t *testing.T) {
	e := newEnv(t, Options{ReorderWindowMS: 60_000, MaxPendingEvents: 2})
	base := e.now - 50_000
	alice := mkSigner(t, 10)
	bob := mkSigner(t, 11)
	carol := mkSigner(t, 12)
	dave := mkSigner(t, 13)
	e.applyNoFlush(e.joinAs(e.creat, alice.Pub(), base, mkWG(10)))
	// 三个高位 join 事件，容量 2：ts 最小的 bob 被逐出（可再 flood 送达）。
	e.applyNoFlush(e.joinAs(e.creat, bob.Pub(), base+10, mkWG(11)))
	e.applyNoFlush(e.joinAs(e.creat, carol.Pub(), base+20, mkWG(12)))
	e.applyNoFlush(e.joinAs(e.creat, dave.Pub(), base+30, mkWG(13)))
	if e.r.PendingCount() != 2 {
		t.Fatalf("pending = %d", e.r.PendingCount())
	}
	applied, failed := e.r.FlushAll()
	if applied != 2 || len(failed) != 0 {
		t.Fatalf("applied=%d failed=%d", applied, len(failed))
	}
	if _, ok := e.r.Member(bob.Pub()); ok {
		t.Fatal("evicted join must not have applied")
	}
	if _, ok := e.r.Member(carol.Pub()); !ok {
		t.Fatal("carol should be member")
	}
}
