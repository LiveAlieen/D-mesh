package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// MarshalJSON 让 X25519 传输公钥以 base64 字符串上线（而不是 32 个数字），
// 与 wire/种子文件的 JSON 习惯一致。所有包共用本实现，勿各自加壳。
func (w WGPub) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(w[:]))
}

// UnmarshalJSON 接受 base64 字符串形式的 WGPub。
func (w *WGPub) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%w: wg_pub not base64: %v", ErrMalformed, err)
	}
	if len(raw) != len(*w) {
		return fmt.Errorf("%w: wg_pub length %d, want %d", ErrMalformed, len(raw), len(*w))
	}
	copy(w[:], raw)
	return nil
}

// CanonicalJSON 输出确定性的 JSON 字节串：对象键按字典序升序、无空白、无 HTML
// 转义、非 ASCII 可打印字符原样 UTF-8、数字保持字面量（int64 不经浮点失真）。
//
// 它是一切「原文」的唯一来源：group_id、消息/事件签名原文、proof.Raw。
// 任何包需要签名域都必须走这里，否则跨节点验签必然失败。
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // 保住 int64 精度（TS / ts_ms / created_at）
	var node any
	if err := dec.Decode(&node); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing JSON content", ErrMalformed)
	}
	var buf bytes.Buffer
	buf.Grow(len(raw))
	if err := writeCanonical(&buf, node); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, node any) error {
	switch n := node.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if n {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		if n.String() == "" {
			return fmt.Errorf("%w: empty number", ErrMalformed)
		}
		buf.WriteString(n.String())
	case string:
		writeCanonicalString(buf, n)
	case []any:
		buf.WriteByte('[')
		for i, e := range n {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, n[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported JSON value %T", ErrMalformed, node)
	}
	return nil
}

// writeCanonicalString 按最小转义规则写 JSON 字符串：只转义引号、反斜杠、
// 常见控制符与其他 <0x20 控制符（\u00xx），其余字节原样输出（含 UTF-8 非 ASCII）。
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if c < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, c)
				continue
			}
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}

// GroupConfigSigPayload 返回创建者自签与 group_id 共用的那份创世原文：
// CanonicalJSON(cfg 且 CreatorSig 置空)。同一份字节既是哈希输入也是签名原文。
func GroupConfigSigPayload(cfg GroupConfig) ([]byte, error) {
	cfg.CreatorSig = nil
	return CanonicalJSON(cfg)
}

// GroupIDOf 计算群身份锚：sha256(CanonicalJSON(cfg 且 CreatorSig 置空))。
// 校验种子文件是否有效 = 重算本值 + 用 creator 公钥验 CreatorSig（原文见上）。
func GroupIDOf(cfg GroupConfig) ([32]byte, error) {
	payload, err := GroupConfigSigPayload(cfg)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

// MessageSigPayload 返回消息签名原文：CanonicalJSON(m 且 Sig/EndorseSig 置空)。
// 原文含 group_id 与 sender，因此签名天然绑定群与签名域；新 owner 的联署
// EndorseSig 不在此原文内（由 transfer 目标另用自己的密钥签同一原文）。
func MessageSigPayload(m Message) ([]byte, error) {
	m.Sig = nil
	m.EndorseSig = nil
	return CanonicalJSON(m)
}

// ProofOf 把一个已签名的名单事件消息打包成可独立复验的 Proof（存进名单条目）。
func ProofOf(m Message) (Proof, error) {
	if len(m.Sig) == 0 {
		return Proof{}, fmt.Errorf("%w: event %q/%q has no signature", ErrMalformed, m.Kind, m.Body)
	}
	raw, err := MessageSigPayload(m)
	if err != nil {
		return Proof{}, err
	}
	return Proof{Raw: raw, Alg: m.Alg, Sig: m.Sig}, nil
}

// VerifyProof 复验一条 proof：按 proof.Alg 分派验签，签名者公钥由调用方提供
// （白名单条目里 entry.Proof 的签名者通常是签发该事件的 carry/kick 者）。
//
// 判定顺序（先「不认识」再「不一致」再「验不过」，便于调用方区分差评类型）：
//  1. proof.Alg 本地未注册 → ErrUnknownAlg（一律拒绝采纳，绝不误信）
//  2. proof.Alg 与 signer.Alg 不一致 → ErrMalformed（拿 A 算法的钥匙冒充 B 的
//     proof，属降级/串用攻击，不是单纯不认识算法）
//  3. 验签失败 → ErrInvalidSig
func VerifyProof(signer PubKey, pr Proof) error {
	if len(pr.Raw) == 0 {
		return fmt.Errorf("%w: empty proof raw", ErrMalformed)
	}
	if !AlgRegistered(pr.Alg) {
		return fmt.Errorf("%w: %q", ErrUnknownAlg, pr.Alg)
	}
	if signer.Alg != "" && signer.Alg != pr.Alg {
		return fmt.Errorf("%w: proof sig_alg %q != signer sig_alg %q", ErrMalformed, pr.Alg, signer.Alg)
	}
	return Verify(PubKey{Alg: pr.Alg, Bytes: signer.Bytes}, pr.Raw, pr.Sig)
}
