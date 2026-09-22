// Package identity 负责 D-Mesh 的密钥体系与种子（创世配置）工具面：
//
//  1. 身份密钥：默认 Ed25519（可插拔，v16）。包 init 即把 ed25519 验签实现
//     注册进 core.Register —— 任何 import 本包的进程自动具备验签能力。
//  2. 传输密钥：X25519（wg_pub/wg_priv），与身份密钥一同构成成员本机
//     Identity（实现 core.Signer）。
//  3. 群密钥：建群时独立新生成、本群唯一（v12 两把密钥：群密钥=群身份锚，
//     创建者密钥=本人身份/最高层级），同样是 Ed25519 KeyPair。
//  4. 种子工具：NewSeed/SignGroupConfig 产出带 creator_sig 的 GroupConfig，
//     VerifyGroupConfig 重算 group_id + 验 creator_sig + 校验 sig_alg 已知性
//     （拉人者「核对种子文件哈希一致」复用同一实现）；BuildTorrent 生成
//     可用（可被 BT 客户端解析）的 .torrent 占位。
//
// 持久化为简单 JSON 文件（0600），字段 hex/base64 编码，便于人读与互操作。
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"dmesh/internal/core"
)

// KeyPair 是一把可插拔算法下的签名密钥对（当前实现 Ed25519），
// 满足 core.Signer 契约。同一类型既用于成员/创建者身份密钥，
// 也用于建群时新生成的群密钥（两把彼此独立，见 NewGroupKey）。
type KeyPair struct {
	priv ed25519.PrivateKey
	pub  core.PubKey
}

// NewKeyPair 生成一把新的 Ed25519 签名密钥。
func NewKeyPair() (*KeyPair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate ed25519 key: %w", err)
	}
	return keyPairFromPrivate(priv), nil
}

// NewKeyPairFromSeed 从 32 字节种子确定性地派生密钥（测试/恢复用）。
func NewKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: ed25519 seed must be %d bytes, got %d",
			core.ErrMalformed, ed25519.SeedSize, len(seed))
	}
	return keyPairFromPrivate(ed25519.NewKeyFromSeed(seed)), nil
}

func keyPairFromPrivate(priv ed25519.PrivateKey) *KeyPair {
	return &KeyPair{
		priv: priv,
		pub:  core.PubKey{Alg: core.SigEd25519, Bytes: priv.Public().(ed25519.PublicKey)},
	}
}

// Alg 实现 core.Signer：返回签名算法标识（恒为 core.SigEd25519，
// 未来注册新算法后由私钥类型决定）。
func (k *KeyPair) Alg() core.SigAlg { return k.pub.Alg }

// Pub 实现 core.Signer：返回 {sig_alg, pub} 形式的公钥。
func (k *KeyPair) Pub() core.PubKey { return k.pub }

// Sign 实现 core.Signer：对原文（通常是 CanonicalJSON 输出）签名。
func (k *KeyPair) Sign(msg []byte) ([]byte, error) {
	if k == nil || len(k.priv) == 0 {
		return nil, fmt.Errorf("identity: KeyPair has no private key")
	}
	return ed25519.Sign(k.priv, msg), nil
}

// Seed 返回 32 字节 ed25519 种子（备份/恢复用）。
func (k *KeyPair) Seed() []byte {
	out := make([]byte, ed25519.SeedSize)
	copy(out, k.priv.Seed())
	return out
}

// Private 返回完整 64 字节 ed25519 私钥（调用方妥善保管）。
func (k *KeyPair) Private() []byte {
	out := make([]byte, len(k.priv))
	copy(out, k.priv)
	return out
}

// NewGroupKey 为「一个群」新生成唯一群密钥（v12：与创建者密钥独立；
// 其公钥进创世配置，group_id 由含它的配置哈希得出）。
func NewGroupKey() (*KeyPair, error) { return NewKeyPair() }

// Identity 是成员本机长期身份：Ed25519 签名密钥 + X25519 传输密钥。
// 内嵌 *KeyPair，因此直接满足 core.Signer。
type Identity struct {
	*KeyPair
	wgPriv [curve25519.ScalarSize]byte
	wgPub  core.WGPub
}

// NewIdentity 生成新的成员身份（签名密钥 + 传输密钥各自独立随机）。
func NewIdentity() (*Identity, error) {
	kp, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	var wgPriv [curve25519.ScalarSize]byte
	if _, err := rand.Read(wgPriv[:]); err != nil {
		return nil, fmt.Errorf("identity: generate x25519 key: %w", err)
	}
	return newIdentity(kp, wgPriv)
}

// NewIdentityFromSeed 从确定性输入派生身份（ed25519 种子 32B + X25519 私钥 32B），
// 供测试与备份恢复使用。
func NewIdentityFromSeed(edSeed []byte, wgPriv [32]byte) (*Identity, error) {
	kp, err := NewKeyPairFromSeed(edSeed)
	if err != nil {
		return nil, err
	}
	return newIdentity(kp, wgPriv)
}

func newIdentity(kp *KeyPair, wgPriv [curve25519.ScalarSize]byte) (*Identity, error) {
	raw, err := curve25519.X25519(wgPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("identity: derive x25519 public: %w", err)
	}
	var pub core.WGPub
	copy(pub[:], raw)
	return &Identity{KeyPair: kp, wgPriv: wgPriv, wgPub: pub}, nil
}

// WGPub 返回本身份的 X25519 传输公钥（join/join_req 与握手携带的就是它）。
func (id *Identity) WGPub() core.WGPub { return id.wgPub }

// WGPrivate 返回 X25519 私钥（32 字节，Noise IK 静态密钥）。
func (id *Identity) WGPrivate() [32]byte { return id.wgPriv }

var (
	_ core.Signer = (*KeyPair)(nil)
	_ core.Signer = (*Identity)(nil)
)

// Ed25519Verifier 是 core.Verifier 的 Ed25519 实现（crypto/ed25519）。
// 只有当 pub.Alg==ed25519、公钥长度合法且验签通过才返回 true。
func Ed25519Verifier(pub core.PubKey, msg, sig []byte) bool {
	if pub.Alg != core.SigEd25519 {
		return false
	}
	if len(pub.Bytes) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
}

// init 把 ed25519 验签注册进 core 的可插拔注册表（v16 默认算法）。
// 未来加 SM2 等只需仿此注册，不改消息/名单结构。
func init() {
	core.Register(core.SigEd25519, Ed25519Verifier)
}
