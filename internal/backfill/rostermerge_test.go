package backfill

import (
	"testing"

	"dmesh/internal/core"
)

// TestMergeSnapshotsExistingMemberIdempotent 锁定回灌误罚修复（v17 遗留观察）：
// 邻居的双名单副本天然携带「本机已确立成员」的 join proof；重放 ApplyEvent 对
// 已存在成员必报 already-a-member，这不是违规——白名单阶段须与黑名单阶段
// IsBlacklisted 幂等跳过对称，不得差评任何来源。
func TestMergeSnapshotsExistingMemberIdempotent(t *testing.T) {
	carrier := newSigner("carrier")
	alice := newSigner("alice")
	peer := newSigner("peer")

	r := newTestRoster()
	// 拉人者持 carry（+ owner 层级）——proof 复验与 ApplyEvent 都要求。
	r.addDirect(core.MemberEntry{
		Pub: carrier.pub(), WG: carrier.wg(), Role: core.RoleOwner,
		Perms: []string{core.PermCarry, core.PermSpeak},
	})
	join := makeJoin(t, carrier, alice, []string{core.PermSpeak}, 1700000000000)
	entry := memberEntryFromJoin(t, join, joinContent{Pub: alice.pub(), WG: alice.wg(), Perms: []string{core.PermSpeak}})
	// 本机已有 alice（例如经快照恢复）——副本再回灌她的 join proof 应为幂等。
	r.addDirect(entry)

	penalties := 0
	replies := []snapReply{{
		Src:  peer.pub(),
		Snap: Snapshot{Members: []core.MemberEntry{entry}},
	}}
	mr := mergeSnapshots(replies, r, func(core.PubKey, DropReason, string) { penalties++ })

	if penalties != 0 {
		t.Fatalf("已存在成员的 join proof 回放不得差评来源，got penalties=%d drops=%+v", penalties, mr.Drops)
	}
	if mr.MembersApplied != 0 {
		t.Fatalf("已存在成员应被幂等跳过，不应重复计入 MembersApplied=%d", mr.MembersApplied)
	}
	if len(mr.Drops) != 0 {
		t.Fatalf("幂等回放不该产生任何 drop：%+v", mr.Drops)
	}
}

// TestMergeSnapshotsNewMemberStillApplied 反向保险：幂等跳过只挡「已存在成员」，
// 新成员的合法 join proof 仍须正常应用（不因守卫被误吞）。
func TestMergeSnapshotsNewMemberStillApplied(t *testing.T) {
	carrier := newSigner("carrier2")
	bob := newSigner("bob")
	peer := newSigner("peer2")

	r := newTestRoster()
	r.addDirect(core.MemberEntry{
		Pub: carrier.pub(), WG: carrier.wg(), Role: core.RoleOwner,
		Perms: []string{core.PermCarry, core.PermSpeak},
	})
	join := makeJoin(t, carrier, bob, []string{core.PermSpeak}, 1700000001000)
	entry := memberEntryFromJoin(t, join, joinContent{Pub: bob.pub(), WG: bob.wg(), Perms: []string{core.PermSpeak}})

	penalties := 0
	mr := mergeSnapshots([]snapReply{{Src: peer.pub(), Snap: Snapshot{Members: []core.MemberEntry{entry}}}},
		r, func(core.PubKey, DropReason, string) { penalties++ })

	if penalties != 0 {
		t.Fatalf("合法新成员 join 不应产生差评：%d", penalties)
	}
	if mr.MembersApplied != 1 {
		t.Fatalf("新成员应被应用一次，got MembersApplied=%d", mr.MembersApplied)
	}
	if _, ok := r.Member(bob.pub()); !ok {
		t.Fatal("bob 未进入本机白名单")
	}
}
