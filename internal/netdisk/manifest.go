package netdisk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"dmesh/internal/core"
)

// Manifest 是一个网盘文件的清单：布局参数 + 全文件/逐块哈希 + 写入时布局 + proof。
// 清单经 TypeHide 消息全网广播后，任何成员可独立复验并据此下载/重建。
//
// BlockHashes 为可选加固（多源交叉验哈希的锚点）：索引 = stripe*(K+1)+pos，
// 覆盖校验块与数据块；缺省时逐块验签 + 组装后的全文哈希仍是底线校验。
type Manifest struct {
	FileID      string        `json:"file_id"`
	GroupID     [32]byte      `json:"group_id"`
	Name        string        `json:"name"`
	Size        int64         `json:"size"`         // 原始字节数（组装后按此截断零填充）
	BlockSize   int           `json:"block_size"`   // 定长条块
	K           int           `json:"k"`            // 每带数据块数（RS K+1）
	Stripes     int           `json:"stripes"`      // 条带数
	ContentHash [32]byte      `json:"content_hash"` // sha256(原始全文)
	BlockHashes [][32]byte    `json:"block_hashes,omitempty"`
	Hosts       []core.PubKey `json:"hosts"` // 写入时的配额成员布局（升序）
	Creator     core.PubKey   `json:"creator"`
	CreatedTS   int64         `json:"created_ts"`
	Proof       core.Proof    `json:"proof"`
}

// Strides 返回每条带的块数（K+1）。
func (mf *Manifest) Strides() int {
	if mf == nil {
		return 0
	}
	return mf.K + 1
}

// stripesFor 按参数推算条带数（空文件 0 条带）。
func stripesFor(size, blockSize, k int) int {
	if size <= 0 {
		return 0
	}
	per := k * blockSize
	return (size + per - 1) / per
}

// MakeFileID 由内容哈希 + 名字 + 时间戳派生稳定文件 id（hex, 32 位）。
func MakeFileID(groupID, contentHash [32]byte, name string, ts int64) string {
	var h = sha256.New()
	h.Write(groupID[:])
	h.Write(contentHash[:])
	h.Write([]byte(name))
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(ts >> (8 * (7 - i)))
	}
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// manifestSig 是清单的签名视图：不含 Proof 与 Creator（Creator 即签名者，
// 由 VerifyProof 的 signer 参数绑定，不重复进原文）。
type manifestSig struct {
	FileID      string        `json:"file_id"`
	GroupID     [32]byte      `json:"group_id"`
	Name        string        `json:"name"`
	Size        int64         `json:"size"`
	BlockSize   int           `json:"block_size"`
	K           int           `json:"k"`
	Stripes     int           `json:"stripes"`
	ContentHash [32]byte      `json:"content_hash"`
	BlockHashes [][32]byte    `json:"block_hashes,omitempty"`
	Hosts       []core.PubKey `json:"hosts"`
	CreatedTS   int64         `json:"created_ts"`
}

// ManifestSigPayload 返回清单签名原文。
func ManifestSigPayload(mf *Manifest) ([]byte, error) {
	if mf == nil {
		return nil, ErrNilDependency
	}
	return core.CanonicalJSON(manifestSig{
		FileID:      mf.FileID,
		GroupID:     mf.GroupID,
		Name:        mf.Name,
		Size:        mf.Size,
		BlockSize:   mf.BlockSize,
		K:           mf.K,
		Stripes:     mf.Stripes,
		ContentHash: mf.ContentHash,
		BlockHashes: mf.BlockHashes,
		Hosts:       mf.Hosts,
		CreatedTS:   mf.CreatedTS,
	})
}

// SignManifest 用 signer 补全 Creator/Proof。
func SignManifest(signer core.Signer, mf *Manifest) error {
	if signer == nil || mf == nil {
		return ErrNilDependency
	}
	mf.Creator = signer.Pub()
	payload, err := ManifestSigPayload(mf)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("netdisk: sign manifest: %w", err)
	}
	mf.Proof = core.Proof{Raw: payload, Alg: signer.Alg(), Sig: sig}
	return nil
}

// CheckManifest 独立复验清单：结构自洽（条带数/哈希表长度/布局合法）+ proof。
// 注意不要求成员数 ≥3 仍可验旧清单（成员可能已流失，读取/重建路径必须可用）。
func CheckManifest(mf *Manifest, groupID [32]byte) error {
	if mf == nil {
		return fmt.Errorf("%w: nil manifest", ErrBadManifest)
	}
	if mf.FileID == "" || mf.Name == "" || len(mf.Name) > MaxNameLen {
		return fmt.Errorf("%w: bad file_id/name", ErrBadManifest)
	}
	if mf.GroupID != groupID {
		return fmt.Errorf("%w: manifest bound to another group", ErrBadManifest)
	}
	if mf.BlockSize <= 0 || mf.K < 1 || mf.Size < 0 {
		return fmt.Errorf("%w: block_size=%d k=%d size=%d", ErrBadManifest, mf.BlockSize, mf.K, mf.Size)
	}
	if mf.Stripes < 1 || mf.Stripes != stripesFor(int(mf.Size), mf.BlockSize, mf.K) {
		return fmt.Errorf("%w: stripes=%d inconsistent", ErrBadManifest, mf.Stripes)
	}
	if want := MakeFileID(mf.GroupID, mf.ContentHash, mf.Name, mf.CreatedTS); want != mf.FileID {
		return fmt.Errorf("%w: file_id mismatch", ErrBadManifest)
	}
	if len(mf.BlockHashes) != 0 && len(mf.BlockHashes) != mf.Stripes*mf.Strides() {
		return fmt.Errorf("%w: block_hashes len %d, want %d", ErrBadManifest, len(mf.BlockHashes), mf.Stripes*mf.Strides())
	}
	hosts, err := sortedUniquePubs(mf.Hosts)
	if err != nil || len(hosts) != len(mf.Hosts) || len(mf.Hosts) < MinHosts || mf.K+1 > len(mf.Hosts) {
		return fmt.Errorf("%w: bad hosts layout (n=%d, k=%d)", ErrBadManifest, len(mf.Hosts), mf.K)
	}
	payload, err := ManifestSigPayload(mf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if string(mf.Proof.Raw) != string(payload) {
		return fmt.Errorf("%w: proof raw != manifest payload", ErrBadManifest)
	}
	if err := core.VerifyProof(mf.Creator, mf.Proof); err != nil {
		return fmt.Errorf("%w: %w", ErrBadManifest, err)
	}
	return nil
}

// NewManifest 纯逻辑：把内容切条、算全文哈希与逐块哈希，产出未签名清单。
// hosts 为本写入的配额成员集（决定布局），k<=0 取 n-1。
// 空内容产出 0 条带清单（下载即返回空字节）。
func NewManifest(groupID [32]byte, name string, content []byte, blockSize, k int, hosts []core.PubKey, ts int64) (*Manifest, error) {
	if name == "" || len(name) > MaxNameLen {
		return nil, fmt.Errorf("%w: name", ErrBadManifest)
	}
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}
	layout, err := NewLayout(hosts, k) // 校验 ≥3 成员、k+1<=n、排序去重
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: empty content", ErrBadManifest)
	}
	stripeBlocks, err := EncodeToStripes(content, blockSize, layout.K)
	if err != nil {
		return nil, err
	}
	mf := &Manifest{
		GroupID:     groupID,
		Name:        name,
		Size:        int64(len(content)),
		BlockSize:   blockSize,
		K:           layout.K,
		Stripes:     len(stripeBlocks),
		ContentHash: sha256.Sum256(content),
		Hosts:       layout.Hosts,
		CreatedTS:   ts,
	}
	mf.BlockHashes = make([][32]byte, 0, mf.Stripes*mf.Strides())
	for _, blocks := range stripeBlocks {
		for _, b := range blocks {
			mf.BlockHashes = append(mf.BlockHashes, sha256.Sum256(b))
		}
	}
	mf.FileID = MakeFileID(mf.GroupID, mf.ContentHash, mf.Name, mf.CreatedTS)
	return mf, nil
}
