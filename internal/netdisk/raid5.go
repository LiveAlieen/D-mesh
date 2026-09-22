package netdisk

import (
	"fmt"
	"sort"

	"dmesh/internal/core"
)

// xorInto 就地做 dst[i] ^= src[i]；长度必须一致。
func xorInto(dst, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("%w: xor length %d vs %d", ErrBadParams, len(dst), len(src))
	}
	for i := range dst {
		dst[i] ^= src[i]
	}
	return nil
}

// EncodeToStripes 把内容切成定长条带：返回 out[stripe][pos]，
// pos 0 为 XOR 校验块、pos 1..K 为数据块（见 ParityPos）。
// 所有块定长 blockSize（末条不足零填充；填充量由 Manifest.Size 记录，
// 组装后按 Size 截断）。空内容返回零个条带。
func EncodeToStripes(content []byte, blockSize, k int) ([][][]byte, error) {
	if blockSize <= 0 || k < 1 {
		return nil, fmt.Errorf("%w: blockSize=%d k=%d", ErrBadParams, blockSize, k)
	}
	if len(content) == 0 {
		return nil, nil
	}
	perStripe := k * blockSize
	stripes := (len(content) + perStripe - 1) / perStripe
	padded := make([]byte, stripes*perStripe) // 末条零填充
	copy(padded, content)
	out := make([][][]byte, stripes)
	for s := 0; s < stripes; s++ {
		blocks := make([][]byte, k+1)
		parity := make([]byte, blockSize)
		for j := 0; j < k; j++ {
			b := make([]byte, blockSize)
			copy(b, padded[s*perStripe+j*blockSize:])
			blocks[ParityPos+j+1] = b
			if err := xorInto(parity, b); err != nil {
				return nil, err
			}
		}
		blocks[ParityPos] = parity
		out[s] = blocks
	}
	return out, nil
}

// ReconstructStripe 用同一条带其余块异或重建缺失的那一块。
// blocks[pos] 索引同 EncodeToStripes；恰好一个元素为 nil（即缺失块），
// 其余块必须等长且非空。返回缺失块的 (pos, 内容)。
// RAID5 的性质：数据块缺失与校验块缺失都是「其余全部块 XOR」。
func ReconstructStripe(blocks [][]byte) (int, []byte, error) {
	missing := -1
	var blen int
	for i, b := range blocks {
		if b == nil {
			if missing != -1 {
				return -1, nil, ErrTooManyMissing // 同条缺 ≥2 块：不可恢复
			}
			missing = i
			continue
		}
		if len(b) == 0 {
			return -1, nil, fmt.Errorf("%w: empty block at pos %d", ErrBadBlock, i)
		}
		if blen == 0 {
			blen = len(b)
		} else if len(b) != blen {
			return -1, nil, fmt.Errorf("%w: block length %d vs %d", ErrBadBlock, len(b), blen)
		}
	}
	if missing == -1 {
		return -1, nil, fmt.Errorf("%w: nothing to reconstruct", ErrBadParams)
	}
	if len(blocks) < 2 {
		return -1, nil, ErrTooManyMissing // 只剩 0 块在场，无从异或
	}
	out := make([]byte, blen)
	for _, b := range blocks {
		if b == nil {
			continue
		}
		if err := xorInto(out, b); err != nil {
			return -1, nil, err
		}
	}
	return missing, out, nil
}

// Layout 是一条 RAID5 布局：n 个配额成员（按 PubKey.Key() 升序去重）、
// 每带 K 个数据块 + 1 个校验块。放置规则（确定性、全端可复算）：
//
//	成员编号 = (pos + stripe) mod n，pos 0 为校验块
//
// 即第 i 条的校验块落在 (i mod n) 号成员——轮转散布，校验不集中（PLAN v14）。
// 要求 n >= K+1（同一条带的块不双落同一成员）。
type Layout struct {
	Hosts []core.PubKey
	K     int
}

// NewLayout 校验并规整布局。k<=0 时取经典 RAID5 的 k=n-1。
func NewLayout(hosts []core.PubKey, k int) (Layout, error) {
	sorted, err := sortedUniquePubs(hosts)
	if err != nil {
		return Layout{}, err
	}
	n := len(sorted)
	if n < MinHosts {
		return Layout{}, fmt.Errorf("%w: have %d quota hosts", ErrNotEnoughHosts, n)
	}
	if k <= 0 {
		k = n - 1
	}
	if k < 1 || k+1 > n {
		return Layout{}, fmt.Errorf("%w: k=%d, n=%d (need 1<=k, k+1<=n)", ErrBadParams, k, n)
	}
	return Layout{Hosts: sorted, K: k}, nil
}

// N 返回参与布局的配额成员数。
func (l Layout) N() int { return len(l.Hosts) }

// Slots 返回每条带的块数（K 数据 + 1 校验）。
func (l Layout) Slots() int { return l.K + 1 }

// HostFor 返回条带 stripe 内 pos 位块应落的成员。
func (l Layout) HostFor(stripe, pos int) (core.PubKey, error) {
	if l.N() == 0 {
		return core.PubKey{}, ErrNotEnoughHosts
	}
	if stripe < 0 || pos < 0 || pos > l.K {
		return core.PubKey{}, fmt.Errorf("%w: stripe=%d pos=%d", ErrBadParams, stripe, pos)
	}
	return l.Hosts[(pos+stripe)%l.N()], nil
}

// IndexFor 返回 HostFor 对应成员在 Hosts 里的下标。
func (l Layout) IndexFor(stripe, pos int) (int, error) {
	if l.N() == 0 {
		return -1, ErrNotEnoughHosts
	}
	if stripe < 0 || pos < 0 || pos > l.K {
		return -1, fmt.Errorf("%w: stripe=%d pos=%d", ErrBadParams, stripe, pos)
	}
	return (pos + stripe) % l.N(), nil
}

// Has 报告 pub 是否在布局成员集里。
func (l Layout) Has(pub core.PubKey) bool {
	for _, h := range l.Hosts {
		if h.Equal(pub) {
			return true
		}
	}
	return false
}

// sortedUniquePubs 按 Key() 升序去重（确定性布局的地基）。
func sortedUniquePubs(pubs []core.PubKey) ([]core.PubKey, error) {
	seen := map[string]bool{}
	out := make([]core.PubKey, 0, len(pubs))
	for _, p := range pubs {
		if p.IsZero() {
			return nil, fmt.Errorf("%w: zero pubkey in host set", ErrBadParams)
		}
		if k := p.Key(); !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// unionPubs 求并集（升序去重），用于收集「写入时成员 ∪ 当前成员」候选源。
func unionPubs(a, b []core.PubKey) []core.PubKey {
	all := make([]core.PubKey, 0, len(a)+len(b))
	all = append(all, a...)
	all = append(all, b...)
	out, err := sortedUniquePubs(all)
	if err != nil {
		return nil
	}
	return out
}
