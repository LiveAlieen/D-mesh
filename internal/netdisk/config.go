package netdisk

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"dmesh/internal/core"
)

// netdiskEvent 是 cmd/netdisk 群配置命令的载荷体（core.CanonicalJSON 编码，
// 即 core.Message.Body 里 "netdisk" 键下那份字节）。
//
// 字段名必须与 group.eventNetdisk（真正落名单的那份解码结构）逐字一致：
// 判别位已在信封的 kind 与 body 唯一键里，载荷不再夹带 kind 字段——早先这里
// 多写了一个 kind、且把配额写成 netdisk_mb，group 侧严格解码直接判
// 「unknown field "kind"」，于是改配额永远不生效（v25 实测踩到）。
type netdiskEvent struct {
	MB int `json:"mb"`
}

// NetdiskEventBody 生成 netdisk 群配置事件的 body 字节（{"netdisk":{"mb":N}}）。
// 配额越界（<0 或 >core.NetdiskMaxMB）直接拒绝（PLAN v14：越界事件验证直接拒绝）。
// 群主/创建者层级判定属 group 包 ApplyEvent 的职责，本函数只管值域。
func NetdiskEventBody(mb int) ([]byte, error) {
	if !core.ValidNetdiskMB(mb) {
		return nil, fmt.Errorf("%w: %d (0..%d)", ErrBadQuotaMB, mb, core.NetdiskMaxMB)
	}
	return core.MakeBody(core.NameNetdisk, netdiskEvent{MB: mb})
}

// ValidateNetdiskBody 复验一条 netdisk 事件的 body，返回新配额值。
// 供 group 包 ApplyEvent 接线：任何畸形/越界都返回 error（事件不生效）。
func ValidateNetdiskBody(body []byte) (int, error) {
	if !utf8.Valid(body) || len(body) > 1024 {
		return 0, fmt.Errorf("%w: netdisk body", ErrBadQuotaMB)
	}
	if name, err := core.BodyName(body); err != nil || name != core.NameNetdisk {
		return 0, fmt.Errorf("%w: not a netdisk body: %v", ErrBadQuotaMB, err)
	}
	var ev netdiskEvent
	if err := core.BodyPayload(body, core.NameNetdisk, &ev); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrBadQuotaMB, err)
	}
	if !core.ValidNetdiskMB(ev.MB) {
		return 0, fmt.Errorf("%w: %d", ErrBadQuotaMB, ev.MB)
	}
	// 签名原文必须与此重编码逐字节一致（防原文/值分离伪装）。
	want, err := NetdiskEventBody(ev.MB)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(want, body) {
		return 0, fmt.Errorf("%w: body not canonical", ErrBadQuotaMB)
	}
	return ev.MB, nil
}

// MakeNetdiskEvent 由 signer（群主/创建者）签发一条 netdisk 群配置事件消息，
// 供集成层直接走消息通道全网生效。层级权限的最终判定仍在 group.ApplyEvent。
func MakeNetdiskEvent(signer core.Signer, groupID [32]byte, mb int, nowMS int64) (core.Message, error) {
	if signer == nil {
		return core.Message{}, ErrNilDependency
	}
	body, err := NetdiskEventBody(mb)
	if err != nil {
		return core.Message{}, err
	}
	m := core.Message{
		MsgID:   msgIDFor(signer.Pub(), body, nowMS),
		GroupID: groupID,
		Sender:  signer.Pub(),
		TSms:    nowMS,
		Kind:    core.KindCommand,
		Body:    body,
		Alg:     signer.Alg(),
	}
	raw, err := core.MessageSigPayload(m)
	if err != nil {
		return core.Message{}, err
	}
	sig, err := signer.Sign(raw)
	if err != nil {
		return core.Message{}, fmt.Errorf("netdisk: sign config event: %w", err)
	}
	m.Sig = sig
	return m, nil
}
