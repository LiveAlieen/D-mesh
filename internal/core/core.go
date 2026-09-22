// Package core 是全工程唯一的跨包契约：类型、常量、接口与确定性编码工具。
//
// 约定（所有业务包 identity/group/transport/neighbor/message/store/backfill/
// netdisk/spam/ui/cmd 都必须遵守）：
//
//  1. 业务包之间不互相 import 具体实现，只 import dmesh/internal/core 并依赖本包
//     声明的类型与接口；具体实现最终在 cmd/dmesh 的 main 里接线（依赖注入）。
//  2. 本包里的类型名、字段名、常量值是 v16 设计的硬契约，不得改名、不得换类型；
//     需要扩展时优先新增而非修改。
//  3. 签名算法可插拔（v16）：公钥、签名、proof 一律自带 sig_alg，验签按 alg 分派
//     到本地注册表（见 Register / Verify）。本地未注册的 alg 一律拒绝，绝不误信。
//  4. 一切「原文」（group_id 计算、消息/事件签名、proof.Raw）都用 CanonicalJSON，
//     键按字典序、无多余空白、UTF-8 原样，跨实现字节级稳定。
package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// SigAlg 是签名算法标识，随公钥与签名一起传输（v16：算法不固定）。
type SigAlg string

// SigEd25519 是默认签名算法；未来可注册 SM2、Ed448、ECDSA-secp256r1 等。
// 未注册的 alg 在 Verify 处返回 ErrUnknownAlg。
const SigEd25519 SigAlg = "ed25519"

// PubKey 是身份/签名公钥，自带算法标识（v16）。Bytes 的语义由 Alg 决定。
type PubKey struct {
	Alg   SigAlg `json:"sig_alg"`
	Bytes []byte `json:"pub"`
}

// String 返回 "alg:hex" 形式，用于日志、map 键与调试输出。
func (p PubKey) String() string {
	return string(p.Alg) + ":" + hex.EncodeToString(p.Bytes)
}

// Equal 按 alg + 字节内容比较两个公钥（同一算法下字节相等才算同一把钥匙）。
func (p PubKey) Equal(q PubKey) bool {
	if p.Alg != q.Alg {
		return false
	}
	if len(p.Bytes) != len(q.Bytes) {
		return false
	}
	for i := range p.Bytes {
		if p.Bytes[i] != q.Bytes[i] {
			return false
		}
	}
	return true
}

// IsZero 报告公钥是否为空（未填）。
func (p PubKey) IsZero() bool { return p.Alg == "" && len(p.Bytes) == 0 }

// Key 返回可直接当 map key 用的字符串（PubKey 含切片字段，本身不可比较）。
func (p PubKey) Key() string { return p.String() }

// WGPub 是 X25519 传输公钥（wire 上以 base64 传输，见 MarshalJSON）。
type WGPub [32]byte

// String 返回 hex 表示。
func (w WGPub) String() string { return hex.EncodeToString(w[:]) }

// IsZero 报告是否全零（未填）。
func (w WGPub) IsZero() bool { return w == [32]byte{} }

// Role 是权限层级角色。层级顺序：creator > owner > admin > member。
type Role string

// 角色常量。创建者由创世种子签名固定、永久最高；owner 为当前群主指针。
const (
	RoleCreator Role = "creator"
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleMember  Role = "member"
)

// 权限位常量（MemberEntry.Perms / GroupConfig.DefaultPerms 取值）。
const (
	PermSpeak      = "speak"
	PermReceive    = "receive"
	PermCarry      = "carry"
	PermKick       = "kick"
	PermGrantAdmin = "grant_admin"
	PermUnban      = "unban"
	PermTransfer   = "transfer"
	PermNetdisk    = "netdisk"
)

// AllPerms 是已知权限位全集，供校验 perms 事件里的未知权限名。
var AllPerms = []string{
	PermSpeak, PermReceive, PermCarry, PermKick,
	PermGrantAdmin, PermUnban, PermTransfer, PermNetdisk,
}

// 入群模式（GroupConfig.Mode）。
const (
	ModeAuto   = "auto"   // 拉人者只核对种子哈希即签 join
	ModeVerify = "verify" // 还要按新人消息验证身份后才签 join
)

// 群网盘配额上限（MB）：0=关闭；越界的 netdisk 事件直接拒绝。
const (
	NetdiskMinMB = 0
	NetdiskMaxMB = 256
)

// DefaultOfflineAfterMS 是在场判定的默认阈值：成员未自报 offline_after 时，
// 「距最后一次发消息超过该毫秒数」即视为离线（v13.1）。
const DefaultOfflineAfterMS int64 = 5 * 60 * 1000

// 消息 / 名单事件类型常量。除 TypeText/TypeHide 外均为名单事件，聊天流不显示。
const (
	TypeText        = "text"
	TypeHide        = "hide"
	TypeJoinReq     = "join_req"
	TypeJoin        = "join"
	TypeRemove      = "remove"
	TypeKick        = "kick"
	TypeUnban       = "unban"
	TypePerms       = "perms"
	TypeGrantAdmin  = "grant_admin"
	TypeRevokeAdmin = "revoke_admin"
	TypeTransfer    = "transfer"
	TypePresence    = "presence"
	TypeNetdisk     = "netdisk"
)

// Proof 是名单事件的「原文 + 签名」，任意节点可独立复验（无需信任转发者）。
// Raw 为被签名事件的 CanonicalJSON 原文（见 ProofOf）。
type Proof struct {
	Raw []byte `json:"raw"`
	Alg SigAlg `json:"sig_alg"`
	Sig []byte `json:"sig"`
}

// MemberEntry 是白名单条目：身份 + 传输密钥 + 角色 + 权限位 + 来源证明 + 时间戳。
// 在场状态不在此（见 PresenceEntry，v13 分表）。
type MemberEntry struct {
	Pub   PubKey   `json:"pub"`
	WG    WGPub    `json:"wg_pub"`
	Role  Role     `json:"role"`
	Perms []string `json:"perms"`
	Proof Proof    `json:"proof"`
	TS    int64    `json:"ts"`
}

// BlacklistEntry 是黑名单条目：被封禁公钥 + 封禁证明（kick 事件原文+签名）。
type BlacklistEntry struct {
	Pub   PubKey `json:"pub"`
	Proof Proof  `json:"proof"`
	TS    int64  `json:"ts"`
}

// PresenceEntry 是在场表条目（v13/v13.1）：与权限分表，只由本人自签推进，
// 各端本地 max 合并；仅用于展示与邻居优选，不参与权限与一致性核查判定。
type PresenceEntry struct {
	Pub          PubKey `json:"pub"`
	LastMsgTS    int64  `json:"last_msg_ts"`
	OfflineAfter int64  `json:"offline_after"`
}

// Online 按 v13.1 规则判定：now-lastMsg < offline_after 即在线。
// offline_after<=0 时用 DefaultOfflineAfterMS。now/lastMsg 均为 Unix 毫秒。
func (p PresenceEntry) Online(now int64) bool {
	thr := p.OfflineAfter
	if thr <= 0 {
		thr = DefaultOfflineAfterMS
	}
	return now-p.LastMsgTS < thr
}

// Message 是唯一的传输单元：聊天消息与名单事件同构、同路（gossip flood）。
// Sig 的签名原文 = MessageSigPayload(m)（本包提供，含 GroupID 以绑定群与签名域）。
// To 非空表示定向消息（如被拉黑者发给解禁权限者的申诉）。
type Message struct {
	MsgID      string   `json:"msg_id"`
	GroupID    [32]byte `json:"group_id"`
	Sender     PubKey   `json:"sender"`
	TSms       int64    `json:"ts_ms"`
	Type       string   `json:"type"`
	Content    []byte   `json:"content"`
	To         *PubKey  `json:"to,omitempty"`
	Alg        SigAlg   `json:"sig_alg"`
	Sig        []byte   `json:"sig,omitempty"`
	EndorseSig []byte   `json:"endorse_sig,omitempty"` // transfer 等新 owner 的联署
}

// GroupConfig 是创世配置（种子内容）。group_pub 与 creator 是两把独立密钥。
//
//	GroupID = sha256( CanonicalJSON(cfg 且 CreatorSig 置空) )
//	CreatorSig = 创建者密钥对同一份原文的自签（见 GroupConfigSigPayload）
type GroupConfig struct {
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	Mode         string   `json:"mode"`
	CreatedAt    int64    `json:"created_at"`
	GroupPub     PubKey   `json:"group_pub"`
	Creator      PubKey   `json:"creator"`
	CreatorWG    WGPub    `json:"creator_wg_pub"`
	Alg          SigAlg   `json:"sig_alg"` // CreatorSig 所用算法（v16）
	DefaultPerms []string `json:"default_perms"`
	NetdiskMB    int      `json:"netdisk_mb"`
	CreatorSig   []byte   `json:"creator_sig,omitempty"`
}

// Tunnel 是 transport 层对外的抽象：已握手、已加密、已绑定对端身份的信道。
// Send 写出一个完整帧；OnData 注册的回调在收到对端帧时被调用。
type Tunnel interface {
	Send([]byte) error
	OnData(func([]byte))
	RemotePub() PubKey
	Close() error
}

// Signer 是本机持有的签名身份（identity 包实现）：Alg/Pub 指明算法与公钥。
type Signer interface {
	Alg() SigAlg
	Pub() PubKey
	Sign(msg []byte) ([]byte, error)
}

// Verifier 是某一签名算法的验签实现，注册进本包算法注册表后按 alg 分派。
type Verifier func(pub PubKey, msg, sig []byte) bool

// 契约级错误：调用方用 errors.Is 判定。
var (
	// ErrUnknownAlg 表示本地未注册该 sig_alg —— 一律拒绝采纳，绝不误信。
	ErrUnknownAlg = errors.New("core: unknown sig_alg")
	// ErrNotPermitted 表示层级或权限位不足（签名有效但无权）。
	ErrNotPermitted = errors.New("core: not permitted")
	// ErrInvalidSig 表示签名验证不通过（alg 已注册但验签失败）。
	ErrInvalidSig = errors.New("core: invalid signature")
	// ErrMalformed 表示字段缺失/长度非法/未知类型等结构问题。
	ErrMalformed = errors.New("core: malformed")
)

// IsUnknownAlg 报告错误链里是否含 ErrUnknownAlg（本地未注册该 sig_alg）。
// 协议要求：此类条目/消息/事件一律拒绝采纳并给来源差评，但不等同于「伪签」——
// 对方可能只是用了你尚未注册的算法（v16 可插拔性验证正需要区分这两者）。
func IsUnknownAlg(err error) bool { return errors.Is(err, ErrUnknownAlg) }

// IsNotPermitted 报告错误链里是否含 ErrNotPermitted（签名有效但层级/权限不足）。
func IsNotPermitted(err error) bool { return errors.Is(err, ErrNotPermitted) }

// verifierRegistry 是 sig_alg -> Verifier 的可插拔注册表。
var (
	verifierMu sync.RWMutex
	verifiers  = map[SigAlg]Verifier{}
)

// Register 注册一个验签实现（identity 包在 init 或启动时注册 ed25519 等）。
// 重复注册同一 alg 会覆盖（便于测试与热替换）；v 为 nil 视为注销该 alg。
func Register(alg SigAlg, v Verifier) {
	verifierMu.Lock()
	defer verifierMu.Unlock()
	if v == nil {
		delete(verifiers, alg)
		return
	}
	verifiers[alg] = v
}

// VerifierOf 查询某算法的验签实现；未注册返回 (nil, false)。
func VerifierOf(alg SigAlg) (Verifier, bool) {
	verifierMu.RLock()
	defer verifierMu.RUnlock()
	v, ok := verifiers[alg]
	return v, ok
}

// RegisteredAlgs 返回本地已注册的算法列表（升序），用于握手能力协商。
func RegisteredAlgs() []SigAlg {
	verifierMu.RLock()
	out := make([]SigAlg, 0, len(verifiers))
	for a := range verifiers {
		out = append(out, a)
	}
	verifierMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// AlgRegistered 报告某算法本地是否可用。
func AlgRegistered(alg SigAlg) bool {
	_, ok := VerifierOf(alg)
	return ok
}

// Verify 按 pub.Alg 分派验签：
//   - pub.Alg 未在本地注册 → ErrUnknownAlg（宁可不认，绝不误信）
//   - 已注册但验签失败 → ErrInvalidSig
//   - 成功返回 nil
func Verify(pub PubKey, msg, sig []byte) error {
	v, ok := VerifierOf(pub.Alg)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownAlg, pub.Alg)
	}
	if len(pub.Bytes) == 0 || len(sig) == 0 {
		return ErrInvalidSig
	}
	if !v(pub, msg, sig) {
		return ErrInvalidSig
	}
	return nil
}

// 层级数字（TierOfRole 返回值；与 Roster.TierOf 同一标尺，非成员为 TierNonMember）。
const (
	TierNonMember = -1
	TierMember    = 0
	TierAdmin     = 1
	TierOwner     = 2
	TierCreator   = 3
)

// TierOfRole 把角色映射成可比较的数字：creator(3) > owner(2) > admin(1) > member(0)，
// 未知/空角色返回 TierNonMember(-1)。
func TierOfRole(r Role) int {
	switch r {
	case RoleCreator:
		return TierCreator
	case RoleOwner:
		return TierOwner
	case RoleAdmin:
		return TierAdmin
	case RoleMember:
		return TierMember
	default:
		return TierNonMember
	}
}

// RoleOfTier 反向映射（3=creator，2=owner，1=admin，0=member）；越界返回 ""。
func RoleOfTier(tier int) Role {
	switch tier {
	case TierCreator:
		return RoleCreator
	case TierOwner:
		return RoleOwner
	case TierAdmin:
		return RoleAdmin
	case TierMember:
		return RoleMember
	default:
		return ""
	}
}

// ValidNetdiskMB 报告配额值是否在合法区间（0~256）。
func ValidNetdiskMB(mb int) bool { return mb >= NetdiskMinMB && mb <= NetdiskMaxMB }

// Roster 是双名单（白名单 + 黑名单）与在场表的读取/应用接口，由 group 包实现。
//
// ApplyEvent 内部完成：验签（含 sig_alg 分派）→ 层级与权限判定 → 自签规则
// （remove/presence 仅本人）→ 应用；任何一步不满足都返回 error 且不改动状态。
// 所有方法必须对并发调用安全（消息层与 transport 层会并行访问）。
type Roster interface {
	// IsBlacklisted 报告公钥是否在黑名单中（准入判定：在名单即拒连拒消息，
	// 唯一例外是 To 指向解禁权限者的定向申诉）。
	IsBlacklisted(p PubKey) bool
	// Member 查白名单条目。
	Member(p PubKey) (MemberEntry, bool)
	// ApplyEvent 验证并应用一个名单事件消息（join_req 不改名单但需受理中继）。
	ApplyEvent(m Message) error
	// TierOf 返回签名者当前层级数字（越大越高），非成员返回 -1。
	TierOf(p PubKey) int
	// HasPerm 报告该公钥当前是否持有权限位（perm 取 Perm* 常量）。
	HasPerm(p PubKey, perm string) bool
	// Presence 读在场表（无记录时返回零值条目 + OfflineAfter=0，调用方按
	// PresenceEntry.Online 的默认阈值语义处理）。
	Presence(p PubKey) PresenceEntry
	// Snapshot 导出当前两份名单副本与 owner 指针，用于副本应答与一致性核查。
	Snapshot() (members []MemberEntry, banned []BlacklistEntry, owner PubKey)
}
