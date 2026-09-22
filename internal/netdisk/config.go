package netdisk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"dmesh/internal/core"
)

// netdiskEvent 是 TypeNetdisk 群配置事件的原文载荷（core.CanonicalJSON 编码，
// 即 core.Message.Content 与 proof.Raw 的那份字节）。
type netdiskEvent struct {
	Kind      string `json:"kind"`
	NetdiskMB int    `json:"netdisk_mb"`
}

const netdiskEventKind = "netdisk_config"

// NetdiskEventContent 生成 netdisk 群配置事件的 Content 字节。
// 配额越界（<0 或 >core.NetdiskMaxMB）直接拒绝（PLAN v14：越界事件验证直接拒绝）。
// 群主/创建者层级判定属 group 包 ApplyEvent 的职责，本函数只管值域。
func NetdiskEventContent(mb int) ([]byte, error) {
	if !core.ValidNetdiskMB(mb) {
		return nil, fmt.Errorf("%w: %d (0..%d)", ErrBadQuotaMB, mb, core.NetdiskMaxMB)
	}
	return core.CanonicalJSON(netdiskEvent{Kind: netdiskEventKind, NetdiskMB: mb})
}

// ValidateNetdiskContent 复验一条 TypeNetdisk 事件内容，返回新配额值。
// 供 group 包 ApplyEvent 接线：任何畸形/越界都返回 error（事件不生效）。
func ValidateNetdiskContent(content []byte) (int, error) {
	if !utf8.Valid(content) || len(content) > 1024 {
		return 0, fmt.Errorf("%w: netdisk content", ErrBadQuotaMB)
	}
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.DisallowUnknownFields()
	var ev netdiskEvent
	if err := dec.Decode(&ev); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrBadQuotaMB, err)
	}
	if dec.More() {
		return 0, fmt.Errorf("%w: trailing content", ErrBadQuotaMB)
	}
	if ev.Kind != netdiskEventKind {
		return 0, fmt.Errorf("%w: event kind %q", ErrBadQuotaMB, ev.Kind)
	}
	if !core.ValidNetdiskMB(ev.NetdiskMB) {
		return 0, fmt.Errorf("%w: %d", ErrBadQuotaMB, ev.NetdiskMB)
	}
	// 签名原文必须与此重编码逐字节一致（防原文/值分离伪装）。
	want, err := NetdiskEventContent(ev.NetdiskMB)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(want, content) {
		return 0, fmt.Errorf("%w: content not canonical", ErrBadQuotaMB)
	}
	return ev.NetdiskMB, nil
}

// MakeNetdiskEvent 由 signer（群主/创建者）签发一条 netdisk 群配置事件消息，
// 供集成层直接走消息通道全网生效。层级权限的最终判定仍在 group.ApplyEvent。
func MakeNetdiskEvent(signer core.Signer, groupID [32]byte, mb int, nowMS int64) (core.Message, error) {
	if signer == nil {
		return core.Message{}, ErrNilDependency
	}
	content, err := NetdiskEventContent(mb)
	if err != nil {
		return core.Message{}, err
	}
	m := core.Message{
		MsgID:   msgIDFor(signer.Pub(), content, nowMS),
		GroupID: groupID,
		Sender:  signer.Pub(),
		TSms:    nowMS,
		Type:    core.TypeNetdisk,
		Content: content,
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
