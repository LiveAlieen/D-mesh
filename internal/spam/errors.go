package spam

import "errors"

// 本包哨兵错误：调用方用 errors.Is 判定并据此给来源差评/拒收。
var (
	// ErrPowTooWeak 解答哈希未达挑战难度（或声明难度不足）。→ 来源差评。
	ErrPowTooWeak = errors.New("spam: pow too weak")
	// ErrPowExpired 解答超过时效（防重放）。
	ErrPowExpired = errors.New("spam: pow expired")
	// ErrPowMalformed 解答/包裹结构非法。
	ErrPowMalformed = errors.New("spam: pow malformed")

	// ErrRateLimited 令牌桶拒绝（消息速率超限）。
	ErrRateLimited = errors.New("spam: rate limited")
)
