// Package spam 是 M5 防垃圾层：PoW（join_req/join 工作量证明校验）、
// 消息速率限制（令牌桶）、本地屏蔽列表（区别于群黑名单，只影响本机）、
// 邻居评分（伪签/重复违规降分，供回灌与一致性核查剔除坏源）。
//
// 约定：
//
//  1. 本包只 import dmesh/internal/core，不依赖网络；一切「现在时间」通过
//     注入的 now 函数（Unix 毫秒）取得，纯逻辑可确定性单测。
//  2. PoW 不新增 core.Message 字段（契约冻结）：挑战参数与解答以 JSON 结构
//     放在 join_req / join 的 Content 里（见 pow.go 的 PowContent），由
//     message/group 包在受理入群事件前调用本包校验。
//  3. 评分对接差评来源（backfill/audit/message）：未知 sig_alg 属轻度差评
//     （core.IsUnknownAlg 语义：可能只是本地未注册算法，绝不与伪签同罚）。
package spam

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// PoW 算法标识（PowSolution.Algo / PowParams.Algo）。
const (
	// PowAlgoSHA256Prefix: sha256(payload || salt || nonce_be8) 的前 Bits 位为 0。
	PowAlgoSHA256Prefix = "sha256-prefix"
)

// 默认难度常量。v16 面向家用/普通服务器 CPU：18 bit 平均 ~35 万次哈希，
// 毫秒~秒级完成；校验端一次哈希即验证，成本可忽略。
const (
	PowDefaultBits     uint = 18
	PowDefaultMaxAgeMS      = 5 * 60 * 1000 // 解答时效（防重放旧解答）
	PowMaxBitsBits     uint = 64            // 难度上限，防对端声明离谱难度拖死自己
	PowMaxSaltBytes         = 64
)

// PowParams 是群/验证方公布的 PoW 挑战参数。
type PowParams struct {
	Algo     string `json:"algo"`       // 目前仅 PowAlgoSHA256Prefix
	Bits     uint   `json:"bits"`       // 要求的前置零位数
	MaxAgeMS int64  `json:"max_age_ms"` // 解答最大年龄；<=0 表示不校验时效
}

// DefaultPowParams 返回默认挑战参数。
func DefaultPowParams() PowParams {
	return PowParams{Algo: PowAlgoSHA256Prefix, Bits: PowDefaultBits, MaxAgeMS: PowDefaultMaxAgeMS}
}

// Validate 检查参数自身合法性（算法已知、难度在 [1, PowMaxBitsBits]）。
func (p PowParams) Validate() error {
	if p.Algo != PowAlgoSHA256Prefix {
		return fmt.Errorf("spam: unknown pow algo %q", p.Algo)
	}
	if p.Bits == 0 || p.Bits > PowMaxBitsBits {
		return fmt.Errorf("spam: pow bits %d out of range [1,%d]", p.Bits, PowMaxBitsBits)
	}
	return nil
}

// PowSolution 是申请人算出的解答，随 join_req 的 Content 传输。
type PowSolution struct {
	Algo  string `json:"algo"`
	Bits  uint   `json:"bits"`  // 解答方声明达成的难度（校验以 params.Bits 为准，此值不得低于）
	Salt  []byte `json:"salt"`  // 挑战盐值（防跨 payload/跨群复用解答）
	Nonce uint64 `json:"nonce"` // 计数
	TSms  int64  `json:"ts_ms"` // 解答生成时间（Unix 毫秒，自报，仅用于时效淘汰）
}

// PowContent 是放进 join_req（或 verify 群 join 递送链）Content 里的 JSON 结构：
// 原始申请体 + PoW 解答。message 包反序列化 Content 后即可调用 Verify。
type PowContent struct {
	Payload json.RawMessage `json:"payload"` // 被绑定计算的业务原文（如 {pub,wg_pub} 的 CanonicalJSON）
	Pow     PowSolution     `json:"pow"`
}

// PowHash 计算一次候选哈希：sha256(payload || salt || nonce 大端 8 字节)。
func PowHash(payload, salt []byte, nonce uint64) [32]byte {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	h := sha256.New()
	h.Write(payload)
	h.Write(salt)
	h.Write(nb[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HasLeadingZeroBits 报告 h 的前 bits 位是否全零（bits==0 恒真，bits>len*8 恒假）。
func HasLeadingZeroBits(h []byte, bits uint) bool {
	for i := uint(0); i < bits; i++ {
		byteIdx := i / 8
		if byteIdx >= uint(len(h)) {
			return false
		}
		if h[byteIdx]&(0x80>>(i%8)) != 0 {
			return false
		}
	}
	return true
}

// LeadingZeroBits 返回哈希前置零位数（最多返回 len(h)*8）。
func LeadingZeroBits(h []byte) uint {
	var n uint
	for _, b := range h {
		if b != 0 {
			// 数最高位的零：b<0x80... 逐位
			for mask := byte(0x80); mask&b == 0 && mask != 0; mask >>= 1 {
				n++
			}
			return n
		}
		n += 8
	}
	return n
}

// Solve 在 payload 上穷举 nonce 求出满足 p 的解答。salt 为 nil 时随机取 16 字节。
// 从 nonce 起点 0 开始顺序扫描；CPU 单核实现，够用（难度只到 64 bit，
// 集成期若嫌慢再并行化）。
func (p PowParams) Solve(payload []byte) (PowSolution, error) {
	return p.SolveFrom(payload, nil, 0)
}

// SolveFrom 是可控版本：显式给 salt（nil=随机）与 nonce 起点，便于测试与断点续算。
func (p PowParams) SolveFrom(payload, salt []byte, startNonce uint64) (PowSolution, error) {
	if err := p.Validate(); err != nil {
		return PowSolution{}, err
	}
	if len(salt) > PowMaxSaltBytes {
		return PowSolution{}, fmt.Errorf("spam: pow salt too long %d > %d", len(salt), PowMaxSaltBytes)
	}
	s := salt
	if len(s) == 0 {
		s = make([]byte, 16)
		if _, err := rand.Read(s); err != nil {
			return PowSolution{}, fmt.Errorf("spam: pow salt rand: %w", err)
		}
	}
	sol := PowSolution{Algo: p.Algo, Bits: p.Bits, Salt: s, Nonce: startNonce}
	for n := startNonce; ; n++ {
		h := PowHash(payload, s, n)
		if HasLeadingZeroBits(h[:], p.Bits) {
			sol.Nonce = n
			return sol, nil
		}
		if n == ^uint64(0) {
			return PowSolution{}, fmt.Errorf("spam: pow nonce space exhausted")
		}
	}
}

// Verify 校验解答：算法一致、解答声明难度不低于挑战、哈希达成挑战难度、
// （若 MaxAgeMS>0）时效不超限。now 为 Unix 毫秒。失败返回本包 ErrPow* 哨兵。
func (p PowParams) Verify(payload []byte, sol PowSolution, now int64) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if sol.Algo != p.Algo {
		return fmt.Errorf("%w: solution algo %q", ErrPowMalformed, sol.Algo)
	}
	if sol.Bits < p.Bits {
		return fmt.Errorf("%w: declared bits %d < required %d", ErrPowTooWeak, sol.Bits, p.Bits)
	}
	if len(sol.Salt) == 0 || len(sol.Salt) > PowMaxSaltBytes {
		return fmt.Errorf("%w: salt length %d", ErrPowMalformed, len(sol.Salt))
	}
	h := PowHash(payload, sol.Salt, sol.Nonce)
	if !HasLeadingZeroBits(h[:], p.Bits) {
		return fmt.Errorf("%w: have %d want %d", ErrPowTooWeak, LeadingZeroBits(h[:]), p.Bits)
	}
	if p.MaxAgeMS > 0 {
		age := now - sol.TSms
		if age < 0 {
			// 时钟超前/虚报时间戳：给机会但设硬容忍（不超过 MaxAgeMS 的未来偏差）
			if age < -p.MaxAgeMS {
				return fmt.Errorf("%w: solution ts %d too far in future (now %d)", ErrPowExpired, sol.TSms, now)
			}
		} else if age > p.MaxAgeMS {
			return fmt.Errorf("%w: age %dms > %dms", ErrPowExpired, age, p.MaxAgeMS)
		}
	}
	return nil
}

// EncodeContent 把 payload+解答打包成 join_req 的 Content 字节。
// sol.TSms<=0 时填 now（注入时钟），保证时效字段有值。
func EncodeContent(payload []byte, sol PowSolution, now int64) ([]byte, error) {
	if sol.TSms <= 0 {
		sol.TSms = now
	}
	return json.Marshal(PowContent{Payload: json.RawMessage(payload), Pow: sol})
}

// DecodeContent 解析 join_req 的 Content；payload 为 nil 表示非 PoW 包裹的裸申请。
func DecodeContent(content []byte) (payload []byte, sol PowSolution, err error) {
	var pc PowContent
	if e := json.Unmarshal(content, &pc); e != nil {
		return nil, PowSolution{}, fmt.Errorf("%w: content not pow json: %v", ErrPowMalformed, e)
	}
	if len(pc.Payload) == 0 || string(pc.Payload) == "null" {
		return nil, PowSolution{}, fmt.Errorf("%w: empty pow payload", ErrPowMalformed)
	}
	return pc.Payload, pc.Pow, nil
}
