// app.go：ui.App 门面宿主实现（Ebitengine GUI 与 main 各包之间的桥）+ UI 事件泵。

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"dmesh/internal/core"
	"dmesh/internal/group"
	"dmesh/internal/message"
	"dmesh/internal/netdisk"
	"dmesh/internal/ui"
)

// ---- ui.App 契约 ----

func (n *node) Self() core.PubKey { return n.self }

func (n *node) Roster() core.Roster { return n.roster }

func (n *node) Signer() core.Signer { return n.id }

func (n *node) GroupID() [32]byte { return n.gid }

func (n *node) SendText(text string) error { return n.sendText(text) }

// Hide 对目标 msg_id 发 hide 事件（须与原文同 pubkey；引擎/存储软删除）。
func (n *node) Hide(msgID string) error {
	tgt, ok, err := n.st.GetMessage(msgID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("本机没有 msg_id %s 的记录", msgID[:min(12, len(msgID))])
	}
	if !tgt.Sender.Equal(n.self) {
		return fmt.Errorf("%w: hide 只能撤自己发的消息", core.ErrNotPermitted)
	}
	m, err := message.NewHide(n.id, n.gid, n.now(), msgID)
	if err != nil {
		return err
	}
	if err := n.st.MarkHidden(msgID); err != nil {
		return err
	}
	n.persist(m)
	_, err = n.engine.Publish(m)
	return err
}

// Leave 本人自签 remove 退群（v15：不进黑名单，随时可再被拉入）。
func (n *node) Leave() error {
	return n.signAndPublish(core.TypeRemove, targetContent{Target: n.self}, n.now())
}

func (n *node) Kick(target core.PubKey) error {
	return n.signAndPublish(core.TypeKick, targetContent{Target: target}, n.now())
}

func (n *node) Unban(target core.PubKey) error {
	return n.signAndPublish(core.TypeUnban, targetContent{Target: target}, n.now())
}

func (n *node) SetPerms(target core.PubKey, perms []string) error {
	return n.signAndPublish(core.TypePerms, permsContent{Target: target, Perms: perms}, n.now())
}

func (n *node) GrantAdmin(target core.PubKey) error {
	return n.signAndPublish(core.TypeGrantAdmin, targetContent{Target: target}, n.now())
}

func (n *node) RevokeAdmin(target core.PubKey) error {
	return n.signAndPublish(core.TypeRevokeAdmin, targetContent{Target: target}, n.now())
}

// Transfer v17①：现任群主（或创建者）发起移交。本机签好 transfer 原文
// （To=新 owner、EndorseSig 为空）以提案形式定向送达；生效须新 owner 对本机
// 同一原文补联署后广播（见 ApproveTransfer）。新 owner==本机时走自领快捷路径
// 一步签全（仅创建者收回合法，group 包 evTransfer 强制该规则）。
func (n *node) Transfer(newOwner core.PubKey) error {
	if n.roster.TierOf(n.self) < core.TierOwner {
		return fmt.Errorf("%w: 非群主/创建者不能发起移交", core.ErrNotPermitted)
	}
	if !n.roster.HasPerm(n.self, core.PermTransfer) {
		return fmt.Errorf("%w: 本机不持 transfer 权限", core.ErrNotPermitted)
	}
	cb, err := group.EncodeEventContent(transferContent{NewOwner: newOwner})
	if err != nil {
		return err
	}
	to := newOwner
	m := core.Message{Type: core.TypeTransfer, Content: cb, TSms: n.now(), To: &to}
	if err := group.SignEvent(&m, n.id, n.gid); err != nil {
		return err
	}
	if newOwner.Equal(n.self) {
		if err := group.EndorseEvent(&m, n.id); err != nil {
			return err
		}
		return n.publish(m)
	}
	if _, err := n.engine.PublishProposal(m); err != nil {
		return fmt.Errorf("送出 transfer 提案: %w", err)
	}
	n.log.Printf("transfer proposal sent to %s (msg_id=%s)", newOwner, m.MsgID)
	return nil
}

// PendingTransfers 返回发给本机的待决 transfer 联署提案收件箱（v17①）。
func (n *node) PendingTransfers() []ui.TransferProposal { return n.pendingTransfers() }

// ApproveTransfer 对提案同一原文补本机联署并广播生效（v17①）。
func (n *node) ApproveTransfer(msgID string) error {
	prop, ok := n.takeTransfer(msgID)
	if !ok {
		return fmt.Errorf("transfer 提案 %s 不在收件箱", msgID)
	}
	m := prop.Msg
	if err := group.EndorseEvent(&m, n.id); err != nil {
		return err
	}
	return n.publish(m) // 本机 ApplyEvent 即完成 owner 指针切换；随后 flood 全网
}

// RejectTransfer 拒绝 transfer 提案：仅本地丢弃，绝不转发、不产生任何事件。
func (n *node) RejectTransfer(msgID string) error {
	if _, ok := n.takeTransfer(msgID); !ok {
		return fmt.Errorf("transfer 提案 %s 不在收件箱", msgID)
	}
	return nil
}

// SetNetdiskMB 群主/创建者签 netdisk 事件改全局配额（0~256，越界由 netdisk/group 拒）。
func (n *node) SetNetdiskMB(mb int) error {
	m, err := netdisk.MakeNetdiskEvent(n.id, n.gid, mb, n.now())
	if err != nil {
		return err
	}
	return n.publish(m)
}

// SetOfflineAfter 本人自签 presence 更新自己的离线阈值（v13.1）。
func (n *node) SetOfflineAfter(ms int64) error {
	if ms <= 0 {
		return errors.New("offline_after 须为正毫秒数")
	}
	n.mu.Lock()
	n.offline = ms
	n.mu.Unlock()
	return n.publishPresence(n.lastSelfTS())
}

func (n *node) lastSelfTS() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastSelf
}

func (n *node) PendingJoins() []ui.JoinRequest {
	n.jmu.Lock()
	defer n.jmu.Unlock()
	out := make([]ui.JoinRequest, 0, len(n.joinQ))
	for _, r := range n.joinQ {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Msg.TSms < out[j].Msg.TSms })
	return out
}

func (n *node) ApproveJoin(reqMsgID string) error { return n.approveJoin(reqMsgID) }

func (n *node) RejectJoin(reqMsgID string) error { return n.rejectJoin(reqMsgID) }

// Audit 触发多源一致性核查（backfill 引擎）。
func (n *node) Audit() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := n.bf.Audit(ctx)
	if err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf("sources asked=%d responded=%d", rep.SourcesAsked, rep.SourcesResponded),
		fmt.Sprintf("adopted entries=%d local-entry-drops=%d local-msg-drops=%d", rep.Adopted, len(rep.LocalEntryDrops), len(rep.LocalMsgDrops)),
		fmt.Sprintf("suspicious=%d", len(rep.Suspicious)),
	}, nil
}

// Netdisk 群网盘门面；关闭/未装配时返回 nil（UI 自动降级提示）。
func (n *node) Netdisk() ui.Netdisk {
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	if n.nd == nil {
		return nil
	}
	return ndFacade{n}
}

// NextEvent 阻塞至有入站事件；宿主关闭时返回 nil（UI 退出）。
func (n *node) NextEvent() ui.Event {
	select {
	case <-n.done:
		return nil
	case ev, ok := <-n.evCh:
		if !ok {
			return nil
		}
		return ev
	}
}

func (n *node) pushEvent(ev ui.Event) {
	if !n.interactive {
		return
	}
	select {
	case n.evCh <- ev:
	default: // 积压时丢显示性事件，绝不阻塞协议路径
	}
}

// runGUI 启动 Ebitengine 原生窗口前端（v19；ui.Run 内部自带事件泵）。
func (n *node) runGUI() error { return ui.Run(n) }
