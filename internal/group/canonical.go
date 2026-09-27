package group

import (
	"bytes"
	"encoding/json"
	"fmt"

	"dmesh/internal/core"
)

// strictUnmarshal 解码 CanonicalJSON 原文：拒绝未知字段与尾部多余内容。
// 事件内容字段名被改写/夹带属于结构篡改，一律 ErrMalformed。
func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

// verifyMessageSig 验证事件签名：先做 alg 一致性粗检（proof/消息 alg 与
// sender.alg 不符 = 串用降级攻击，判 ErrMalformed），再按 core.Verify 分派。
// 未知 alg 由 core.Verify 返回 ErrUnknownAlg（拒绝采纳，绝不误信）。
func verifyMessageSig(sender core.PubKey, alg core.SigAlg, payload, sig []byte) error {
	if len(sig) == 0 {
		return fmt.Errorf("%w: event has no signature", core.ErrMalformed)
	}
	if sender.IsZero() {
		return fmt.Errorf("%w: empty sender", core.ErrMalformed)
	}
	if alg == "" || (alg != sender.Alg) {
		return fmt.Errorf("%w: msg sig_alg %q != sender sig_alg %q", core.ErrMalformed, alg, sender.Alg)
	}
	return core.Verify(sender, payload, sig)
}

// proofEventName 从一条 proof 原文里取出事件名，并做 v26 的 kind↔body 键互校
// （proof.Raw 就是签名原文，即整个信封的 CanonicalJSON，含 kind 与 body）。
func proofEventName(m core.Message) (string, error) {
	name, err := core.CheckBody(m.Kind, m.Body)
	if err != nil {
		return "", fmt.Errorf("%w: proof raw body: %v", core.ErrMalformed, err)
	}
	return name, nil
}

// verifyMemberProof 复验白名单条目的 proof：
//  1. Raw 必须是结构合法的 join 事件原文（成员条目 proof 一律来自 join）；
//  2. Raw 里 sender（拉人者）+ proof.Alg 一致性粗检后按签名分派验签；
//  3. Raw 内容里的目标 pub / wg_pub 必须与条目一致（防换头拼接）。
//
// 权限集/角色/TS 允许与 Raw 不同——它们可被后续 perms/grant/transfer 事件
// 合法改写；此类链式一致性属多源核查（backfill/audit）职责。
func verifyMemberProof(e core.MemberEntry) error {
	var m core.Message
	if err := strictUnmarshal(e.Proof.Raw, &m); err != nil {
		return fmt.Errorf("%w: member proof raw not a message: %v", core.ErrMalformed, err)
	}
	if name, err := proofEventName(m); err != nil {
		return err
	} else if name != core.NameJoin {
		return fmt.Errorf("%w: member proof must be a join event", core.ErrMalformed)
	}
	if m.Alg != e.Proof.Alg {
		return fmt.Errorf("%w: member proof alg %q != raw alg %q", core.ErrMalformed, e.Proof.Alg, m.Alg)
	}
	if err := core.Verify(m.Sender, e.Proof.Raw, e.Proof.Sig); err != nil {
		return err
	}
	var c eventJoin
	if err := core.BodyPayload(m.Body, core.NameJoin, &c); err != nil {
		return fmt.Errorf("%w: member proof body: %v", core.ErrMalformed, err)
	}
	if !c.Pub.Equal(e.Pub) || c.WG != e.WG {
		return fmt.Errorf("%w: member entry pub/wg does not match its proof", core.ErrMalformed)
	}
	return nil
}

// verifyBlacklistProof 复验黑名单条目的封禁证明（必须来自合法 kick 事件原文）。
func verifyBlacklistProof(e core.BlacklistEntry) error {
	var m core.Message
	if err := strictUnmarshal(e.Proof.Raw, &m); err != nil {
		return fmt.Errorf("%w: blacklist proof raw not a message: %v", core.ErrMalformed, err)
	}
	if name, err := proofEventName(m); err != nil {
		return err
	} else if name != core.NameKick {
		return fmt.Errorf("%w: blacklist proof must be a kick event", core.ErrMalformed)
	}
	if m.Alg != e.Proof.Alg {
		return fmt.Errorf("%w: blacklist proof alg %q != raw alg %q", core.ErrMalformed, e.Proof.Alg, m.Alg)
	}
	if err := core.Verify(m.Sender, e.Proof.Raw, e.Proof.Sig); err != nil {
		return err
	}
	// kick 与 remove/unban/grant/revoke 共用 {"target": …} 载荷形状——正因如此
	// 事件名必须显式存在于 body 的键上，此处才谈得上「必须是 kick」。
	var c eventTarget
	if err := core.BodyPayload(m.Body, core.NameKick, &c); err != nil {
		return fmt.Errorf("%w: blacklist proof body: %v", core.ErrMalformed, err)
	}
	if !c.Target.Equal(e.Pub) {
		return fmt.Errorf("%w: blacklist entry pub does not match its kick proof", core.ErrMalformed)
	}
	return nil
}
