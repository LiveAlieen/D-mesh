package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
)

// ---------- 小工具 ----------

func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

func putBe64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }

func decodeJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---------- 帧结构 ----------
//
// 数据帧（tagData）：'D' | sid(8) | nonce(8, 大端显式) | AEAD(ChaCha20Poly1305)
//   AEAD 明文 = fragIdx(2) | fragTotal(2) | body
//   AEAD 关联数据 ad = 'D'|sid|nonce（头部整体参与认证）。
// conf 帧（tagConf）为明文 canonical JSON + 身份签名（见 handshake.go）。
// 分片帧 nonce 连续（同一帧第 i 片 = 基 nonce + i），接收端按基 nonce 归组。

func splitFragments(total int, chunk int) int {
	return (total + chunk - 1) / chunk
}

// encodeFramePlain 生成一片分片明文：idx(2)|total(2)|body。
func encodeFramePlain(idx, total uint16, body []byte) []byte {
	pt := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(pt, idx)
	binary.BigEndian.PutUint16(pt[2:], total)
	copy(pt[4:], body)
	return pt
}

// ---------- 防重放窗口 ----------

// replay 是标准滑动窗口：next 之下 63 个序号用位图记录（乱序容忍），
// 过旧或重复一律拒绝。
type replay struct {
	next uint64
	bits uint64
}

func (r *replay) accept(n uint64) bool {
	if n >= r.next {
		shift := n - r.next + 1
		if shift >= 64 {
			r.bits = 0
		} else {
			r.bits <<= shift
		}
		r.bits |= 1 // 记录本序号：否则下一包（n==next-1 的重复）会被放行
		r.next = n + 1
		return true
	}
	if r.next-n > 63 {
		return false
	}
	bit := uint64(1) << (r.next - n - 1)
	if r.bits&bit != 0 {
		return false
	}
	r.bits |= bit
	return true
}

// ---------- 分片重组 ----------

// Reassembler 把 (nonce, fragIdx, fragTotal, body) 还原为完整帧。
// 纯逻辑组件（无网络），可独立表驱动测试。
type Reassembler struct {
	mu     sync.Mutex
	groups map[uint64]*fragGroup // key: 基 nonce（idx0 的 nonce）
	orph   map[uint64]*orphan    // key: 到达 nonce（idx>0 且基未知）
	max    int
}

type fragGroup struct {
	total uint16
	parts [][]byte
	got   int
}

type orphan struct {
	idx, total uint16
	body       []byte
}

func NewReassembler() *Reassembler {
	return &Reassembler{
		groups: map[uint64]*fragGroup{},
		orph:   map[uint64]*orphan{},
		max:    reassemblerSz,
	}
}

// Add 投入一片；(frame, true) 表示整帧就绪。非法/超限返回 error（调用方丢弃）。
func (r *Reassembler) Add(nonce uint64, idx, total uint16, body []byte) ([]byte, bool, error) {
	if total == 0 || idx >= total || total > maxFragTotal {
		return nil, false, fmt.Errorf("%w: bad fragment header %d/%d", ErrProtocol, idx, total)
	}
	if total > 1 && idx < total-1 && len(body) < maxFragBody {
		return nil, false, fmt.Errorf("%w: non-final fragment too small", ErrProtocol)
	}
	if len(body) > maxFragBody {
		return nil, false, fmt.Errorf("%w: fragment body too large", ErrProtocol)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.groups)+len(r.orph) >= r.max {
		return nil, false, fmt.Errorf("%w: reassembler overflow", ErrProtocol)
	}
	if idx == 0 {
		if _, dup := r.groups[nonce]; dup {
			return nil, false, nil // 基重复：忽略
		}
		g := &fragGroup{total: total, parts: make([][]byte, total)}
		r.groups[nonce] = g
		g.parts[0] = append([]byte(nil), body...)
		g.got++
		// 吸收已到的先头分片。
		for k := uint16(1); k < total; k++ {
			n := nonce + uint64(k)
			if o, ok := r.orph[n]; ok && o.total == total {
				if g.parts[k] == nil {
					g.parts[k] = o.body
					g.got++
				}
				delete(r.orph, n)
			}
		}
		return r.finishLocked(nonce, g)
	}
	// idx>0：先找能容纳它的组。
	for base, g := range r.groups {
		off := nonce - base
		if off < uint64(g.total) && g.parts[off] == nil {
			g.parts[off] = append([]byte(nil), body...)
			g.got++
			return r.finishLocked(base, g)
		}
	}
	if _, dup := r.orph[nonce]; !dup {
		r.orph[nonce] = &orphan{idx: idx, total: total, body: append([]byte(nil), body...)}
	}
	return nil, false, nil
}

func (r *Reassembler) finishLocked(base uint64, g *fragGroup) ([]byte, bool, error) {
	if g.got < int(g.total) {
		return nil, false, nil
	}
	n := 0
	for _, p := range g.parts {
		if p == nil {
			return nil, false, fmt.Errorf("%w: fragment hole", ErrProtocol)
		}
		n += len(p)
	}
	if n > maxFrameSize {
		delete(r.groups, base)
		return nil, false, fmt.Errorf("%w: reassembled frame too big", ErrProtocol)
	}
	out := make([]byte, 0, n)
	for _, p := range g.parts {
		out = append(out, p...)
	}
	delete(r.groups, base)
	return out, true, nil
}
