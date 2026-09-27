package group

import (
	"bytes"
	"testing"

	"dmesh/internal/core"
	"dmesh/internal/netdisk"
)

// 本文件是 PLAN v26 验收③「跨包字节契约制度化」。
//
// 每一行的载荷都写成 map[string]any 并把线上键名逐字抄在这里，**绝不复用本包的
// event* 结构体**：契约的权威是线上键名，不是某个包里的字段名。v25 查出的事故
// ——网盘配额自 v14 起在全网从未生效——正是生产端与解码端各写一份结构、字段名
// 漂移而两边都不报错。注册表里新增名字却在本表缺行即测试失败，等于「每加一个
// 名字自动补一份契约」。

// signBody 把 wire 载荷签成事件：kind 一律查注册表得出，测试里不写字面量。
func signBody(t *testing.T, e *env, s core.Signer, name string, payload any, ts int64) core.Message {
	t.Helper()
	kind, ok := core.KindOf(name)
	if !ok {
		t.Fatalf("body name %q not registered", name)
	}
	m := core.Message{Kind: kind, Body: mustBody(t, name, payload), TSms: ts}
	if err := SignEvent(&m, s, e.gid); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRegistryWireContract(t *testing.T) {
	rows := map[string]func(t *testing.T, e *env){
		// 聊天正文/撤回/清单都不是名单事件：群层须按名字拒收（判序在验签之后）。
		core.NameText: func(t *testing.T, e *env) {
			wire := mustBody(t, core.NameText, "hello")
			if prod, err := core.TextBody("hello"); err != nil || !bytes.Equal(wire, prod) {
				t.Fatalf("text 正文与 core.TextBody 生产端不一致: %s vs %s", wire, prod)
			}
			e.wantErr(signBody(t, e, e.creat, core.NameText, "hello", e.now-50_000), core.ErrMalformed)
		},
		core.NameHide: func(t *testing.T, e *env) {
			e.wantErr(signBody(t, e, e.creat, core.NameHide,
				map[string]any{"target_msg_id": "deadbeef"}, e.now-50_000), core.ErrMalformed)
		},
		// 清单走消息层/netdisk 层（ext/manifest 回环见 netdisk TestManifestMessageRoundTrip）；
		// 群层只负责把它挡在名单之外。
		core.NameManifest: func(t *testing.T, e *env) {
			e.wantErr(signBody(t, e, e.creat, core.NameManifest,
				map[string]any{"name": "f.bin"}, e.now-50_000), core.ErrMalformed)
		},
		core.NameJoinReq: func(t *testing.T, e *env) {
			newbie := mkSigner(t, 60)
			e.mustApply(signBody(t, e, newbie, core.NameJoinReq,
				map[string]any{"pub": newbie.Pub(), "wg_pub": mkWG(60), "ref": "seedhash"}, e.now-50_000))
			qs := e.r.PollJoinReqs()
			if len(qs) != 1 || !qs[0].Sender.Equal(newbie.Pub()) {
				t.Fatalf("join_req 收件箱 = %+v", qs)
			}
			if e.r.MemberCount() != 1 {
				t.Fatal("join_req 不该改白名单")
			}
		},
		core.NameJoin: func(t *testing.T, e *env) {
			alice := mkSigner(t, 10)
			e.mustApply(signBody(t, e, e.creat, core.NameJoin,
				map[string]any{"pub": alice.Pub(), "wg_pub": mkWG(10), "perms": e.cfg.DefaultPerms}, e.now-50_000))
			if _, ok := e.r.Member(alice.Pub()); !ok {
				t.Fatal("join 未生效：新人没进白名单")
			}
			if got := e.memberPerms(alice.Pub()); len(got) != len(e.cfg.DefaultPerms) {
				t.Fatalf("join perms = %v", got)
			}
		},
		core.NameRemove: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, alice, core.NameRemove,
				map[string]any{"target": alice.Pub()}, e.now-40_000))
			if _, ok := e.r.Member(alice.Pub()); ok {
				t.Fatal("remove 未生效：仍在白名单")
			}
			if e.r.IsBlacklisted(alice.Pub()) {
				t.Fatal("本人自签 remove = 退群，不该拉黑")
			}
		},
		core.NameKick: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, e.creat, core.NameKick,
				map[string]any{"target": alice.Pub()}, e.now-40_000))
			if !e.r.IsBlacklisted(alice.Pub()) {
				t.Fatal("kick 未生效：没进黑名单")
			}
		},
		core.NameUnban: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, e.creat, core.NameKick,
				map[string]any{"target": alice.Pub()}, e.now-40_000))
			e.mustApply(signBody(t, e, e.creat, core.NameUnban,
				map[string]any{"target": alice.Pub()}, e.now-30_000))
			if e.r.IsBlacklisted(alice.Pub()) {
				t.Fatal("unban 未生效：黑名单仍在")
			}
		},
		core.NamePerms: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, e.creat, core.NamePerms,
				map[string]any{"target": alice.Pub(),
					"perms": []string{core.PermSpeak, core.PermReceive, core.PermCarry}}, e.now-40_000))
			if !e.r.HasPerm(alice.Pub(), core.PermCarry) {
				t.Fatalf("perms 未生效: %v", e.memberPerms(alice.Pub()))
			}
		},
		core.NameGrantAdmin: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, e.creat, core.NameGrantAdmin,
				map[string]any{"target": alice.Pub()}, e.now-40_000))
			if e.r.TierOf(alice.Pub()) != core.TierAdmin {
				t.Fatalf("grant_admin 未生效: tier=%d", e.r.TierOf(alice.Pub()))
			}
		},
		core.NameRevokeAdmin: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			e.mustApply(signBody(t, e, e.creat, core.NameGrantAdmin,
				map[string]any{"target": alice.Pub()}, e.now-40_000))
			e.mustApply(signBody(t, e, e.creat, core.NameRevokeAdmin,
				map[string]any{"target": alice.Pub()}, e.now-30_000))
			if e.r.TierOf(alice.Pub()) != core.TierMember {
				t.Fatalf("revoke_admin 未生效: tier=%d", e.r.TierOf(alice.Pub()))
			}
		},
		core.NameTransfer: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			m := signBody(t, e, e.creat, core.NameTransfer,
				map[string]any{"new_owner": alice.Pub()}, e.now-40_000)
			if err := EndorseEvent(&m, alice); err != nil {
				t.Fatal(err)
			}
			e.mustApply(m)
			if !e.r.Owner().Equal(alice.Pub()) {
				t.Fatalf("transfer 未生效: owner=%s", e.r.Owner())
			}
		},
		core.NamePresence: func(t *testing.T, e *env) {
			alice := joinViaWire(t, e)
			ts := e.now - 40_000
			e.mustApply(signBody(t, e, alice, core.NamePresence,
				map[string]any{"pub": alice.Pub(), "last_msg_ts": ts, "offline_after": 60_000}, ts))
			got := e.r.Presence(alice.Pub())
			if got.LastMsgTS != ts || got.OfflineAfter != 60_000 {
				t.Fatalf("presence 未生效: %+v", got)
			}
		},
		// netdisk 行必须用**生产端**（internal/netdisk）的正文：那才是「网盘配额」这条
		// 曾经静默失效的跨包契约。同时断言生产端字节与本表键名逐字节一致。
		core.NameNetdisk: func(t *testing.T, e *env) {
			wire := mustBody(t, core.NameNetdisk, map[string]any{"mb": 32})
			prod, err := netdisk.NetdiskEventBody(32)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, prod) {
				t.Fatalf("netdisk 生产端与本表键名漂移:\n netdisk: %s\n contract: %s", prod, wire)
			}
			m := core.Message{Kind: core.KindCommand, Body: prod, TSms: e.now - 40_000}
			if err := SignEvent(&m, e.creat, e.gid); err != nil {
				t.Fatal(err)
			}
			e.mustApply(m)
			if got := e.r.NetdiskMB(); got != 32 {
				t.Fatalf("netdisk 未生效: MB=%d", got)
			}
		},
	}

	names := core.Names()
	for _, name := range names {
		run, ok := rows[name]
		if !ok {
			t.Fatalf("注册表名字 %q 在契约表里没有行：加一个名字必须补一条「签发→严格解码→断言生效」", name)
		}
		t.Run(name, func(t *testing.T) {
			run(t, newEnv(t, Options{}))
		})
	}
	if len(rows) > len(names) {
		t.Fatalf("契约表有 %d 行、注册表只有 %d 个名字：有行对应的名字已从注册表消失", len(rows), len(names))
	}
}

// joinViaWire 用 wire 键名把 alice 拉进群（各行的公共前置），返回她的签名者。
func joinViaWire(t *testing.T, e *env) *Ed25519Signer {
	t.Helper()
	alice := mkSigner(t, 10)
	e.mustApply(signBody(t, e, e.creat, core.NameJoin,
		map[string]any{"pub": alice.Pub(), "wg_pub": mkWG(10), "perms": e.cfg.DefaultPerms}, e.now-50_000))
	return alice
}

// sameShapeNames 是载荷完全同形（都只带 {"target":…}）的五条命令：v26 把 type 字段
// 拿掉之后，它们的语义差别只剩 body 的唯一键。本测试钉住「判别位必须住在 body 里」
// 这个设计前提——若退回按 payload 形状推断，这五条在数学上无法区分。
func TestSameShapeCommandsDistinguishable(t *testing.T) {
	sameShape := []string{core.NameRemove, core.NameKick, core.NameUnban,
		core.NameGrantAdmin, core.NameRevokeAdmin}
	e := newEnv(t, Options{})
	victim := mkSigner(t, 77)

	bodies := make(map[string][]byte, len(sameShape))
	msgIDs := make(map[string]string, len(sameShape))
	for _, name := range sameShape {
		body := mustBody(t, name, map[string]any{"target": victim.Pub()})
		bodies[name] = body
		var c eventTarget
		if err := core.BodyPayload(body, name, &c); err != nil {
			t.Fatalf("%s: 严格解码失败: %v", name, err)
		}
		if !c.Target.Equal(victim.Pub()) {
			t.Fatalf("%s: target 解错: %s", name, c.Target)
		}
		kind, ok := core.KindOf(name)
		if !ok {
			t.Fatalf("%s 未注册", name)
		}
		m := core.Message{Kind: kind, Body: body, TSms: e.now - 10_000}
		if err := SignEvent(&m, e.creat, e.gid); err != nil {
			t.Fatal(err)
		}
		if prev, dup := msgIDs[m.MsgID]; dup {
			t.Fatalf("%s 与 %s 的 msg_id 撞车（%s）：判别位没进原文，去重会误并", prev, name, m.MsgID)
		}
		msgIDs[m.MsgID] = name
	}

	for _, a := range sameShape {
		for _, b := range sameShape {
			if a == b {
				continue
			}
			var c eventTarget
			if err := core.BodyPayload(bodies[a], b, &c); err == nil {
				t.Fatalf("%s 的正文被当成 %s 解成功了：名字与载荷没互校", a, b)
			}
		}
	}
	if len(msgIDs) != len(sameShape) {
		t.Fatalf("同形命令的 msg_id 去重后只剩 %d 个", len(msgIDs))
	}

	// 同形不同名 ⇒ 效果互异：五条各按自己的语义改名单。
	t.Run("effectsDiffer", func(t *testing.T) {
		scenarios := map[string]func(t *testing.T, e *env, alice *Ed25519Signer){
			core.NameRemove: func(t *testing.T, e *env, alice *Ed25519Signer) {
				e.mustApply(signBody(t, e, alice, core.NameRemove,
					map[string]any{"target": alice.Pub()}, e.now-40_000))
				if _, ok := e.r.Member(alice.Pub()); ok {
					t.Fatal("remove: 仍在白名单")
				}
				if e.r.IsBlacklisted(alice.Pub()) {
					t.Fatal("remove: 被拉黑（应为退群）")
				}
			},
			core.NameKick: func(t *testing.T, e *env, alice *Ed25519Signer) {
				e.mustApply(signBody(t, e, e.creat, core.NameKick,
					map[string]any{"target": alice.Pub()}, e.now-40_000))
				if !e.r.IsBlacklisted(alice.Pub()) {
					t.Fatal("kick: 未拉黑")
				}
			},
			core.NameUnban: func(t *testing.T, e *env, alice *Ed25519Signer) {
				e.mustApply(signBody(t, e, e.creat, core.NameKick,
					map[string]any{"target": alice.Pub()}, e.now-40_000))
				e.mustApply(signBody(t, e, e.creat, core.NameUnban,
					map[string]any{"target": alice.Pub()}, e.now-30_000))
				if e.r.IsBlacklisted(alice.Pub()) {
					t.Fatal("unban: 黑名单未清")
				}
				if _, ok := e.r.Member(alice.Pub()); ok {
					t.Fatal("unban 不该直接把人人拉回白名单")
				}
			},
			core.NameGrantAdmin: func(t *testing.T, e *env, alice *Ed25519Signer) {
				e.mustApply(signBody(t, e, e.creat, core.NameGrantAdmin,
					map[string]any{"target": alice.Pub()}, e.now-40_000))
				if e.r.TierOf(alice.Pub()) != core.TierAdmin {
					t.Fatalf("grant_admin: tier=%d", e.r.TierOf(alice.Pub()))
				}
			},
			core.NameRevokeAdmin: func(t *testing.T, e *env, alice *Ed25519Signer) {
				e.mustApply(signBody(t, e, e.creat, core.NameGrantAdmin,
					map[string]any{"target": alice.Pub()}, e.now-40_000))
				e.mustApply(signBody(t, e, e.creat, core.NameRevokeAdmin,
					map[string]any{"target": alice.Pub()}, e.now-30_000))
				if e.r.TierOf(alice.Pub()) != core.TierMember {
					t.Fatalf("revoke_admin: tier=%d", e.r.TierOf(alice.Pub()))
				}
			},
		}
		for _, name := range sameShape {
			t.Run(name, func(t *testing.T) {
				se := newEnv(t, Options{})
				scenarios[name](t, se, joinViaWire(t, se))
			})
		}
	})
}

// TestKindLiesAgainstBody 是验收②的负例：kind 与 body 唯一键必须互校。
// 把 cmd 正文声明成 msg 既躲不掉名单校验，也绝不会被当成聊天显示出来。
func TestKindLiesAgainstBody(t *testing.T) {
	e := newEnv(t, Options{})
	alice := joinViaWire(t, e)
	body := mustBody(t, core.NameKick, map[string]any{"target": alice.Pub()})
	lied := core.Message{Kind: core.KindMessage, Body: body, TSms: e.now - 40_000}
	if err := SignEvent(&lied, e.creat, e.gid); err != nil {
		t.Fatal(err)
	}
	e.wantErr(lied, core.ErrMalformed)
	if _, ok := e.r.Member(alice.Pub()); !ok {
		t.Fatal("kind 谎报的 kick 竟把成员踢掉了")
	}
	// 反向：msg 正文声明成 cmd 同样拒。
	textBody := mustBody(t, core.NameText, "hi")
	lied2 := core.Message{Kind: core.KindCommand, Body: textBody, TSms: e.now - 39_000}
	if err := SignEvent(&lied2, e.creat, e.gid); err != nil {
		t.Fatal(err)
	}
	e.wantErr(lied2, core.ErrMalformed)
}
