package netdisk

import (
	"crypto/sha256"
	"fmt"

	"dmesh/internal/core"
)

// Kind 是条带内块的角色。
type Kind string

// 块角色常量。pos==0 恒为校验块（见 ParityPos），pos 1..K 为数据块。
const (
	KindData   Kind = "data"
	KindParity Kind = "parity"
)

func kindOfPos(pos int) Kind {
	if pos == ParityPos {
		return KindParity
	}
	return KindData
}

// Block 是网盘的最小存储/传输单元：一块定长数据 + 全部可独立复验的元数据。
// 每块携 {group_id, 内容哈希, 归属条编号, 落盘成员, 签发者 proof}（PLAN v14 完整性）。
// 签名原文（BlockSigPayload）刻意不含 Host 与 Data：
//   - Host 是动态放置信息，重平衡搬移块时不改内容、只改落盘成员，原 proof 依然有效；
//   - Data 由 ContentHash 锁定，验内容 = sha256(Data)==ContentHash + 哈希对清单交叉比对。
type Block struct {
	FileID      string      `json:"file_id"`
	GroupID     [32]byte    `json:"group_id"`
	Stripe      int         `json:"stripe"`       // 归属条编号
	Pos         int         `json:"pos"`          // 条带内位：0=校验，1..K=数据
	Kind        Kind        `json:"kind"`         // 与 Pos 一致（Pos==0 ⇔ parity）
	Host        core.PubKey `json:"host"`         // 落盘成员（放置信息，不被签名锁定）
	Publisher   core.PubKey `json:"publisher"`    // 签发者
	TS          int64       `json:"ts"`           // 签发时间（Unix 毫秒）
	ContentHash [32]byte    `json:"content_hash"` // sha256(Data)
	Data        []byte      `json:"data"`         // 定长块内容（末条零填充）
	Proof       core.Proof  `json:"proof"`        // 签发者对 BlockSigPayload 的签名
}

// BlockQuery 是按坐标取块的查询（传输层寻址用）。
type BlockQuery struct {
	FileID string `json:"file_id"`
	Stripe int    `json:"stripe"`
	Pos    int    `json:"pos"`
}

// Loc 标识一个块槽位（文件 + 条号 + 条带内位）。
type Loc struct {
	FileID string
	Stripe int
	Pos    int
}

// Placement 记录某块当前实际落盘在哪个成员（重平衡计划的输入）。
type Placement struct {
	Loc
	Host core.PubKey
}

// blockSig 是块的签名视图：不含 Host/Data/Proof。
type blockSig struct {
	FileID      string      `json:"file_id"`
	GroupID     [32]byte    `json:"group_id"`
	Stripe      int         `json:"stripe"`
	Pos         int         `json:"pos"`
	Kind        Kind        `json:"kind"`
	Publisher   core.PubKey `json:"publisher"`
	TS          int64       `json:"ts"`
	ContentHash [32]byte    `json:"content_hash"`
}

// BlockSigPayload 返回块的签名原文：CanonicalJSON(块元数据，除 Host/Data/Proof)。
func BlockSigPayload(b *Block) ([]byte, error) {
	if b == nil {
		return nil, ErrNilDependency
	}
	return core.CanonicalJSON(blockSig{
		FileID:      b.FileID,
		GroupID:     b.GroupID,
		Stripe:      b.Stripe,
		Pos:         b.Pos,
		Kind:        b.Kind,
		Publisher:   b.Publisher,
		TS:          b.TS,
		ContentHash: b.ContentHash,
	})
}

// SignBlock 用 signer 就地补全 ContentHash/Kind/Publisher/TS/Proof。
// now 提供签发时间戳（Unix 毫秒）。
func SignBlock(signer core.Signer, b *Block, now int64) error {
	if signer == nil || b == nil {
		return ErrNilDependency
	}
	if len(b.Data) == 0 {
		return fmt.Errorf("%w: block data empty", ErrBadParams)
	}
	if b.Stripe < 0 || b.Pos < 0 {
		return fmt.Errorf("%w: stripe=%d pos=%d", ErrBadParams, b.Stripe, b.Pos)
	}
	b.Kind = kindOfPos(b.Pos)
	b.ContentHash = sha256.Sum256(b.Data)
	b.Publisher = signer.Pub()
	if b.TS == 0 {
		b.TS = now
	}
	payload, err := BlockSigPayload(b)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("netdisk: sign block: %w", err)
	}
	b.Proof = core.Proof{Raw: payload, Alg: signer.Alg(), Sig: sig}
	return nil
}

// CheckBlock 独立复验一个块（无需信任转发者）：
//  1. 结构：字段合法、Kind 与 Pos 一致、GroupID 匹配本群；
//  2. 内容：sha256(Data) 必须等于 ContentHash；
//  3. 签发：Proof.Raw 必须逐字节等于重算的签名原文（防原文/签名错绑），
//     再走 core.VerifyProof（未注册 alg → ErrUnknownAlg，一律拒，绝不误信）。
func CheckBlock(b *Block, groupID [32]byte) error {
	if b == nil {
		return fmt.Errorf("%w: nil block", ErrBadBlock)
	}
	if b.FileID == "" || len(b.Data) == 0 || b.Stripe < 0 || b.Pos < 0 {
		return fmt.Errorf("%w: missing fields", ErrBadBlock)
	}
	if b.GroupID != groupID {
		return fmt.Errorf("%w: block bound to another group", ErrBadBlock)
	}
	if b.Kind != kindOfPos(b.Pos) {
		return fmt.Errorf("%w: kind %q vs pos %d", ErrBadBlock, b.Kind, b.Pos)
	}
	if got := sha256.Sum256(b.Data); got != b.ContentHash {
		return fmt.Errorf("%w: block content != content_hash", ErrHashMismatch)
	}
	payload, err := BlockSigPayload(b)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadBlock, err)
	}
	if string(b.Proof.Raw) != string(payload) {
		return fmt.Errorf("%w: proof raw != block payload", ErrBadBlock)
	}
	if err := core.VerifyProof(b.Publisher, b.Proof); err != nil {
		return fmt.Errorf("%w: %w", ErrBadBlock, err)
	}
	return nil
}

// CheckBlockAgainstManifest 把块哈希与清单里的 per-block 哈希交叉比对。
// 清单未携带 BlockHashes（omitempty 精简版）时跳过。
func CheckBlockAgainstManifest(mf *Manifest, b *Block) error {
	if mf == nil || b == nil {
		return ErrNilDependency
	}
	if len(mf.BlockHashes) == 0 {
		return nil
	}
	idx := b.Stripe*mf.Strides() + b.Pos
	if idx < 0 || idx >= len(mf.BlockHashes) {
		return fmt.Errorf("%w: block (%d,%d) outside manifest", ErrBadBlock, b.Stripe, b.Pos)
	}
	if mf.BlockHashes[idx] != b.ContentHash {
		return fmt.Errorf("%w: block hash != manifest hash at (%d,%d)", ErrHashMismatch, b.Stripe, b.Pos)
	}
	return nil
}
