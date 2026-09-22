package neighbor

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"dmesh/internal/core"
)

// AddCandidate 登记一个潜在邻居（discovery/白名单条目均可作为来源）。
// addr 为对端 "ip:port"（可空）。同 pubkey 重复登记只刷新内容与时间戳。
// 注入了 Config.Dial 时，Run 循环会在活跃数未达上限前按分数（IPv6 与
// 低失败优先）自动拨号；未注入 Dial 时候选仅作登记/展示，由上层自行
// 握手后经 Add 接入。黑名单准入判定属 transport 职责，本表不拒登记；
// 已激活后若注入 Roster，巡检会按黑名单兜底断连。
func (nt *Table) AddCandidate(pub core.PubKey, wg core.WGPub, addr string) {
	if pub.IsZero() {
		return
	}
	now := nt.cfg.Now()
	key := pub.Key()

	nt.mu.Lock()
	if nt.closed {
		nt.mu.Unlock()
		return
	}
	if _, active := nt.peers[key]; active {
		nt.mu.Unlock()
		return
	}
	if c, ok := nt.cands[key]; ok {
		c.pub, c.wg, c.addr = pub, wg, addr
		c.added = now
		c.fails = 0
		c.nextAt = time.Time{}
		nt.mu.Unlock()
		return
	}
	for len(nt.cands) >= nt.cfg.MaxCandidates {
		// 池满：FIFO 淘汰最旧条目
		var oldestKey string
		var oldest time.Time
		first := true
		for k, c := range nt.cands {
			if first || c.added.Before(oldest) {
				oldestKey, oldest, first = k, c.added, false
			}
		}
		if first {
			break
		}
		delete(nt.cands, oldestKey)
	}
	nt.cands[key] = &candidate{pub: pub, wg: wg, addr: addr, added: now}
	nt.mu.Unlock()
}

// HandleRosterEvent 在名单事件「已验证并应用」后被调用，对相应 pubkey
// 即时断连（PLAN：除名/拉黑事件触发的即时断连）：
//
//   - remove：仅本人自签有效（v15），故 sender 即退群者 → 断连；
//   - kick：目标在 Content 里。本包对 Content 编码做宽松解析（见 kickTarget），
//     group 规范编码 {"pub":{...}} / {"target":...} / target_pub / kick_pub、
//     裸 hex 或 "alg:hex" 字符串、以及定向 To 字段都能识别；
//   - unban：无需动作（候选补充/重连由上层重新 AddCandidate）；
//   - 其他类型：不动作（批量清扫走巡检里的 Roster 兜底）。
//
// message/group 层若能直接拿到目标 pubkey，推荐改用 Drop(target, ReasonKick)，
// 语义最确切；本入口是为「只传事件原文」的接线方便。
func (nt *Table) HandleRosterEvent(m core.Message) {
	switch m.Type {
	case core.TypeRemove:
		if !nt.cfg.LocalPub.IsZero() && nt.cfg.LocalPub.Equal(m.Sender) {
			return
		}
		nt.Drop(m.Sender, ReasonRemove)
	case core.TypeKick:
		if target, ok := kickTarget(m); ok {
			if !nt.cfg.LocalPub.IsZero() && nt.cfg.LocalPub.Equal(target) {
				return // 被踢的是本机：断邻居无意义，善后由 group/backfill 层处理
			}
			nt.Drop(target, ReasonKick)
		}
	default:
	}
}

// kickTarget 从 kick 事件中宽松解析被踢 pubkey（见 HandleRosterEvent 注释）。
// 优先 Content 规范编码；Content 无法解析时退回定向字段 To。
func kickTarget(m core.Message) (core.PubKey, bool) {
	var node map[string]any
	if err := json.Unmarshal(m.Content, &node); err == nil {
		for _, key := range []string{"pub", "target", "target_pub", "kick_pub"} {
			v, ok := node[key]
			if !ok {
				continue
			}
			if p, ok := decodePub(v); ok {
				return p, true
			}
		}
	}
	// Content 直接是字符串（hex 或 "alg:hex"）
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		if p, ok := parsePubString(s); ok {
			return p, true
		}
	}
	if m.To != nil && !m.To.IsZero() {
		return *m.To, true
	}
	return core.PubKey{}, false
}

// decodePub 支持 {"sig_alg":"ed25519","pub":"<base64>"}（core.PubKey 的
// encoding/json 形态，[]byte 自动按 base64 解）与字符串形态。
func decodePub(v any) (core.PubKey, bool) {
	switch t := v.(type) {
	case map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return core.PubKey{}, false
		}
		var pk core.PubKey
		if err := json.Unmarshal(b, &pk); err != nil {
			return core.PubKey{}, false
		}
		if pk.Alg == "" {
			pk.Alg = core.SigEd25519
		}
		return pk, len(pk.Bytes) > 0
	case string:
		return parsePubString(t)
	default:
		return core.PubKey{}, false
	}
}

// parsePubString 解析 "alg:hex" 或裸 hex（默认 ed25519）。
func parsePubString(s string) (core.PubKey, bool) {
	alg := core.SigEd25519
	if i := strings.Index(s, ":"); i > 0 {
		alg = core.SigAlg(s[:i])
		s = s[i+1:]
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return core.PubKey{}, false
	}
	return core.PubKey{Alg: alg, Bytes: raw}, true
}
