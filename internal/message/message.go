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

// MaxBodyBytes 是单条消息 body 的软上限（超出即拒收，防内存放大；
// 网盘块不经本结构承载，见 netdisk 包）。
const MaxBodyBytes = 1 << 20 // 1 MiB

// 三类判别的分类口径（v26 消息归一化，PLAN 条目 19）：kind 定大类，
// body 的唯一键定具体名字；聊天流只显示 msg，cmd/ext 一律不进气泡。

// VisibleInChat 报告该大类是否出现在聊天流（仅 KindMessage）。
func VisibleInChat(kind string) bool { return kind == core.KindMessage }

// IsRosterEvent 报告该正文名字是否须经名单（core.Roster.ApplyEvent）验证并应用。
// 注意 join_req 不在此列：它不改名单、走无许可中继递送的特殊路径；
// presence 虽归 ext 大类，仍由名单侧的在场表应用（v13 分表）。
func IsRosterEvent(name string) bool {
	switch name {
	case core.NameJoin, core.NameRemove, core.NameKick, core.NameUnban,
		core.NamePerms, core.NameGrantAdmin, core.NameRevokeAdmin,
		core.NameTransfer, core.NamePresence, core.NameNetdisk:
		return true
	}
	return false
}

// IsKnownName 报告正文名字是否为协议已知值（未知一律拒收 + 差评）。
func IsKnownName(name string) bool { return core.IsKnownName(name) }

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
//
// 出封面前先校 kind 与 body 唯一键互校（core.CheckBody），不匹配即拒绝签发。
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
	if _, err := core.CheckBody(out.Kind, out.Body); err != nil {
		return core.Message{}, err
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

// DecodeFrame 解析一个传输帧并做结构校验（kind 与 body 键互校通过、group_id
// 非零、字段完整）。不做验签，也不查名单。
func DecodeFrame(data []byte) (core.Message, error) {
	if len(data) == 0 {
		return core.Message{}, fmt.Errorf("%w: empty frame", core.ErrMalformed)
	}
	if len(data) > MaxBodyBytes+64*1024 {
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
	if _, err := core.CheckBody(m.Kind, m.Body); err != nil {
		return m, err
	}
	if len(m.Body) > MaxBodyBytes {
		return m, fmt.Errorf("%w: body too large", core.ErrMalformed)
	}
	return m, nil
}

// ErrMalformedWrap 把任意解析错误归入 ErrMalformed 语义（供调用方 errors.Is 判定）。
func ErrMalformedWrap(err error) error { return fmt.Errorf("%w: %v", core.ErrMalformed, err) }

// HideBody 是 hide 命令的载荷（tagged union 里的 {"hide": {…}}）。
// 规则（PLAN）：target_msg_id 须与原发送者同 pubkey；hide 不可被 hide。
type HideBody struct {
	TargetMsgID string `json:"target_msg_id"`
}

// EncodeHideBody 规范化打包 hide 命令正文。
func EncodeHideBody(targetMsgID string) ([]byte, error) {
	if targetMsgID == "" {
		return nil, fmt.Errorf("%w: empty hide target", core.ErrMalformed)
	}
	return core.MakeBody(core.NameHide, HideBody{TargetMsgID: targetMsgID})
}

// DecodeHideBody 解析 hide 命令正文；容忍非规范化 JSON（wire 上游可能重组过字节）。
func DecodeHideBody(b []byte) (HideBody, error) {
	var hb HideBody
	if err := core.BodyPayload(b, core.NameHide, &hb); err != nil {
		return hb, err
	}
	if hb.TargetMsgID == "" {
		return hb, fmt.Errorf("%w: hide body without target_msg_id", core.ErrMalformed)
	}
	return hb, nil
}

// NewHide 构造并签名一条 hide 命令（本人只能隐藏自己发的消息，同 pubkey 校验在接收端做）。
func NewHide(signer core.Signer, groupID [32]byte, tsMS int64, targetMsgID string) (core.Message, error) {
	body, err := EncodeHideBody(targetMsgID)
	if err != nil {
		return core.Message{}, err
	}
	return NewMessage(signer, groupID, &core.Message{Kind: core.KindCommand, TSms: tsMS, Body: body}, nil)
}
