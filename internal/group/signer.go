package group

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"

	"dmesh/internal/core"
)

// Ed25519Signer 是 core.Signer 的默认 Ed25519 实现。identity 包是正式的
// 密钥管理归属；这里提供最小实现供测试与 dmesh-tool 之类调用方复用，
// 保证事件构造原文（SignEvent）与验签路径全工程一致。
type Ed25519Signer struct {
	priv ed25519.PrivateKey
}

// NewEd25519Signer 随机生成一把新密钥。
func NewEd25519Signer() (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{priv: priv}, nil
}

// NewEd25519SignerFromSeed 从 32 字节种子确定性地生成密钥（测试夹具用）。
func NewEd25519SignerFromSeed(seed []byte) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: ed25519 seed must be %d bytes", core.ErrMalformed, ed25519.SeedSize)
	}
	return &Ed25519Signer{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Alg / Pub / Sign 实现 core.Signer。
func (s *Ed25519Signer) Alg() core.SigAlg { return core.SigEd25519 }

func (s *Ed25519Signer) Pub() core.PubKey {
	// crypto/ed25519 的 PrivateKey 布局 = seed(32) || public(32)。
	return core.PubKey{Alg: core.SigEd25519, Bytes: cloneBytes([]byte(s.priv[ed25519.SeedSize:]))}
}

func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// RegisterEd25519Verifier 把 Ed25519 验签实现注册进 core 算法注册表
// （幂等，可安全重复调用）。identity 包同样会注册；两者实现等价。
func RegisterEd25519Verifier() {
	core.Register(core.SigEd25519, func(pub core.PubKey, msg, sig []byte) bool {
		if len(pub.Bytes) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
	})
}

// SignEvent 构造并签名一个名单事件消息：
//   - 填充 m.Sender/m.Alg（来自 signer），Content 建议用 EncodeEventContent 生成；
//   - MsgID 为空时自动生成随机 hex id；
//   - 签名原文 = core.MessageSigPayload(m)（含 group_id，绑定群与签名域）。
func SignEvent(m *core.Message, signer core.Signer, groupID [32]byte) error {
	if m == nil || signer == nil {
		return fmt.Errorf("%w: nil message or signer", core.ErrMalformed)
	}
	m.Sender = signer.Pub()
	m.Alg = signer.Alg()
	m.GroupID = groupID
	if m.MsgID == "" {
		m.MsgID = newMsgID()
	}
	payload, err := core.MessageSigPayload(*m)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return err
	}
	m.Sig = sig
	return nil
}

// EndorseEvent 为 transfer 事件补上「新 owner 联署」：endorser 对同一份
// 消息原文（不含 Sig/EndorseSig）用自己的密钥签名写入 EndorseSig。
func EndorseEvent(m *core.Message, endorser core.Signer) error {
	if m == nil || endorser == nil {
		return fmt.Errorf("%w: nil message or endorser", core.ErrMalformed)
	}
	payload, err := core.MessageSigPayload(*m)
	if err != nil {
		return err
	}
	sig, err := endorser.Sign(payload)
	if err != nil {
		return err
	}
	m.EndorseSig = sig
	return nil
}
