package message

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"dmesh/internal/core"
)

// fallbackSeq 只在 crypto/rand 故障时使用（保证退化路径也不产生重复 msg_id）。
var fallbackSeq atomic.Int64

// ErrNoSignature 表示消息未签名即被送去验签（结构性错误，归入 ErrMalformed 语义）。
var ErrNoSignature = fmt.Errorf("%w: message has no signature", core.ErrMalformed)

// MaxContentBytes 是单条消息 content 的软上限（超出即拒收，防内存放大；
// 网盘块不经本结构承载，见 netdisk 包）。
const MaxContentBytes = 1 << 20 // 1 MiB

// 消息类型分类（PLAN：名单事件与聊天同路广播，但聊天流只显示 text）。

// VisibleInChat 报告该类型是否出现在聊天流（仅 text；hide 与全部名单事件/presence 不显示）。
func VisibleInChat(typ string) bool { return typ == core.TypeText }

// IsRosterEvent 报告该类型是否为名单事件（经 core.Roster.ApplyEvent 验证并应用）。
// 注意 join_req 不在此列：它不改名单、走无许可中继递送的特殊路径。
func IsRosterEvent(typ string) bool {
	switch typ {
	case core.TypeJoin, core.TypeRemove, core.TypeKick, core.TypeUnban,
		core.TypePerms, core.TypeGrantAdmin, core.TypeRevokeAdmin,
		core.TypeTransfer, core.TypePresence, core.TypeNetdisk:
		return true
	}
	return false
}

// IsKnownType 报告类型是否为协议已知值（未知类型一律拒收 + 差评）。
func IsKnownType(typ string) bool {
	switch typ {
	case core.TypeText, core.TypeHide, core.TypeJoinReq:
		return true
	}
	return IsRosterEvent(typ)
}

// MsgIDOf 生成 msg_id：优先取 sigPayload 的 sha256；若为空 payload 则随机 16 字节。
// 调用方一般不必直接使用（NewMessage 会自动填充）。
func MsgIDOf(sigPayload []byte) string {
	if len(sigPayload) == 0 {
		return RandomMsgID()
	}
	sum := sha256.Sum256(sigPayload)
	return hex.EncodeToString(sum[:])
}

// RandomMsgID 输出 32 个 hex 字符的随机 id（crypto/rand；极端故障下退化为
// 时间戳 + 进程内单调计数，仍保证本机不重复）。
func RandomMsgID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		nano := time.Now().UnixNano()
		seq := fallbackSeq.Add(1)
		seed := make([]byte, 16)
		binary.LittleEndian.PutUint64(seed[0:8], uint64(nano))
		binary.LittleEndian.PutUint64(seed[8:16], uint64(seq))
		sum := sha256.Sum256(seed)
		copy(b[:], sum[:16])
	}
	return hex.EncodeToString(b[:])
}

// NewMessage 规范化打包并签名：
//
//  1. 用 signer 填 Sender/Alg；groupID 填 GroupID（签名原文含 group_id，天然绑定群与签名域）；
//
//  2. MsgID 为空时生成随机 id（同秒重复内容也不相撞；如需确定性 id 可显式传入 MsgIDOf(payload)）；
//
//  3. 签名原文 = core.MessageSigPayload（CanonicalJSON 且 Sig/EndorseSig 置空），
//     Sig = signer.Sign(原文)。
//
//  4. endorse 非空表示 transfer 类事件的新 owner 联署（它签的是同一份原文）。
func NewMessage(signer core.Signer, groupID [32]byte, m *core.Message, endorse []byte) (core.Message, error) {
	if signer == nil {
		return core.Message{}, errors.New("message: nil signer")
	}
	if m == nil {
		return core.Message{}, errors.New("message: nil message")
	}
	out := *m
	out.GroupID = groupID
	out.Sender = signer.Pub()
	out.Alg = signer.Alg()
	out.Sig = nil
	out.EndorseSig = endorse
	if !IsKnownType(out.Type) {
		return core.Message{}, fmt.Errorf("%w: unknown message type %q", core.ErrMalformed, out.Type)
	}
	if out.TSms <= 0 {
		return core.Message{}, fmt.Errorf("%w: ts_ms must be positive", core.ErrMalformed)
	}
	if out.MsgID == "" {
		out.MsgID = RandomMsgID()
	}
	payload, err := core.MessageSigPayload(out)
	if err != nil {
		return core.Message{}, err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return core.Message{}, err
	}
	out.Sig = sig
	return out, nil
}

// SigPayloadOf 返回消息的签名原文（Sig/EndorseSig 置空后的 CanonicalJSON）。
func SigPayloadOf(m core.Message) ([]byte, error) { return core.MessageSigPayload(m) }

// VerifyMessage 验签：按 m.Alg/m.Sender 分派到 core 注册表。
// 返回错误判定（用 errors.Is / core.IsUnknownAlg 区分）：
//   - 未签名 / 结构缺失     → core.ErrMalformed
//   - sender.alg 与 m.alg 不一致 → core.ErrMalformed（算法串用）
//   - 本地未注册该 sig_alg → core.ErrUnknownAlg（一律拒绝采纳 + 来源差评，绝不误信）
//   - 验签失败             → core.ErrInvalidSig
func VerifyMessage(m core.Message) error {
	if len(m.Sig) == 0 {
		return ErrNoSignature
	}
	if m.Sender.IsZero() {
		return fmt.Errorf("%w: empty sender", core.ErrMalformed)
	}
	if m.Alg == "" {
		return fmt.Errorf("%w: empty sig_alg", core.ErrMalformed)
	}
	if m.Sender.Alg != "" && m.Sender.Alg != m.Alg {
		return fmt.Errorf("%w: sender sig_alg %q != message sig_alg %q", core.ErrMalformed, m.Sender.Alg, m.Alg)
	}
	payload, err := core.MessageSigPayload(m)
	if err != nil {
		return err
	}
	return core.Verify(m.Sender, payload, m.Sig)
}

// EncodeFrame 把消息编码为一个传输帧（wire 用标准 JSON；签名原文另行由
// core.MessageSigPayload 规范化重建，wire 编码本身不要求确定性）。
func EncodeFrame(m core.Message) ([]byte, error) { return json.Marshal(m) }

// DecodeFrame 解析一个传输帧并做结构校验（类型已知、group_id 非零、字段完整）。
// 不做验签，也不查名单。
func DecodeFrame(data []byte) (core.Message, error) {
	if len(data) == 0 {
		return core.Message{}, fmt.Errorf("%w: empty frame", core.ErrMalformed)
	}
	if len(data) > MaxContentBytes+64*1024 {
		return core.Message{}, fmt.Errorf("%w: frame too large (%d bytes)", core.ErrMalformed, len(data))
	}
	var m core.Message
	if err := json.Unmarshal(data, &m); err != nil {
		return core.Message{}, fmt.Errorf("%w: frame not valid message JSON: %v", core.ErrMalformed, err)
	}
	if m.MsgID == "" {
		return m, fmt.Errorf("%w: empty msg_id", core.ErrMalformed)
	}
	if m.GroupID == ([32]byte{}) {
		return m, fmt.Errorf("%w: zero group_id", core.ErrMalformed)
	}
	if !IsKnownType(m.Type) {
		return m, fmt.Errorf("%w: unknown message type %q", core.ErrMalformed, m.Type)
	}
	if len(m.Content) > MaxContentBytes {
		return m, fmt.Errorf("%w: content too large", core.ErrMalformed)
	}
	return m, nil
}

// HideContent 是 hide 消息的 content（CanonicalJSON 编码）：要软删除的目标消息 id。
// 规则（PLAN）：target_msg_id 须与原发送者同 pubkey；hide 不可被 hide。
type HideContent struct {
	TargetMsgID string `json:"target_msg_id"`
}

// EncodeHideContent 规范化打包 hide content。
func EncodeHideContent(targetMsgID string) ([]byte, error) {
	if targetMsgID == "" {
		return nil, fmt.Errorf("%w: empty hide target", core.ErrMalformed)
	}
	return core.CanonicalJSON(HideContent{TargetMsgID: targetMsgID})
}

// DecodeHideContent 解析 hide content；容忍非规范化 JSON（wire 上游可能重组过字节）。
func DecodeHideContent(b []byte) (HideContent, error) {
	var hc HideContent
	if err := json.Unmarshal(b, &hc); err != nil {
		return hc, fmt.Errorf("%w: hide content: %v", core.ErrMalformed, err)
	}
	if hc.TargetMsgID == "" {
		return hc, fmt.Errorf("%w: hide content without target_msg_id", core.ErrMalformed)
	}
	return hc, nil
}

// NewHide 构造并签名一条 hide 事件（本人只能隐藏自己发的消息，同 pubkey 校验在接收端做）。
func NewHide(signer core.Signer, groupID [32]byte, tsMS int64, targetMsgID string) (core.Message, error) {
	content, err := EncodeHideContent(targetMsgID)
	if err != nil {
		return core.Message{}, err
	}
	return NewMessage(signer, groupID, &core.Message{Type: core.TypeHide, TSms: tsMS, Content: content}, nil)
}
