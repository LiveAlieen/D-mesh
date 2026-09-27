package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// v26 消息归一化：整个工程的消息与管理事件共用一种信封——
// 时间（ts_ms）+ 三类判别的正文（kind + body）+ 签名（sig）。
//
// 信封里没有独立的类型字段：kind 定大类，body 的**恰一个键**定具体名字，
// 二者必须互相印证（见 CheckBody）。名字之所以必须进 body 而非靠形状推断，
// 是因为 remove/kick/unban/grant_admin/revoke_admin 五条命令的 payload 完全同形
// （都是 {"target": …}），只解码字段结构在数学上无法区分它们。
const (
	KindMessage   = "msg" // 聊天正文，进气泡流显示
	KindCommand   = "cmd" // 改变名单或群配置的管理指令，聊天流不显示
	KindExtension = "ext" // 协议扩展载荷（在场心跳、网盘清单……），聊天流不显示
)

// 正文名字：协议 token，依 v20 铁律永不进语言文件、永不翻译。
// 值沿用 v25 及以前的类型字符串，让脚本与 E2E 断言不必跟着改拼写。
const (
	NameText        = "text"
	NameHide        = "hide"
	NameJoinReq     = "join_req"
	NameJoin        = "join"
	NameRemove      = "remove"
	NameKick        = "kick"
	NameUnban       = "unban"
	NamePerms       = "perms"
	NameGrantAdmin  = "grant_admin"
	NameRevokeAdmin = "revoke_admin"
	NameTransfer    = "transfer"
	NameNetdisk     = "netdisk"
	NamePresence    = "presence"
	NameManifest    = "manifest"
)

// bodyKinds 是「名字 → 所属大类」的唯一权威表。加一种消息/命令/扩展只改这里
// （再在解码端加一个分支），信封结构与验签流程一律不动——与 v16 签名算法可插拔同构。
var bodyKinds = map[string]string{
	NameText:        KindMessage,
	NameHide:        KindCommand,
	NameJoinReq:     KindCommand,
	NameJoin:        KindCommand,
	NameRemove:      KindCommand,
	NameKick:        KindCommand,
	NameUnban:       KindCommand,
	NamePerms:       KindCommand,
	NameGrantAdmin:  KindCommand,
	NameRevokeAdmin: KindCommand,
	NameTransfer:    KindCommand,
	NameNetdisk:     KindCommand,
	NamePresence:    KindExtension,
	NameManifest:    KindExtension,
}

// KindOf 返回某正文名字所属的大类；未注册的名字一律不认（ok=false）。
func KindOf(name string) (string, bool) {
	k, ok := bodyKinds[name]
	return k, ok
}

// IsKnownName 报告正文名字是否协议已知。
func IsKnownName(name string) bool { _, ok := bodyKinds[name]; return ok }

// Names 按字典序列出全部已注册正文名（契约测试与错误提示用）。
func Names() []string {
	out := make([]string, 0, len(bodyKinds))
	for n := range bodyKinds {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// MakeBody 把某个命令/消息/扩展的载荷包成 tagged union 原文：
// CanonicalJSON({"<name>": payload})。签发端构造 body 只准走这里，
// 以免各包各写一份结构导致跨包字节漂移（v25 的网盘配额事故）。
func MakeBody(name string, payload any) ([]byte, error) {
	if _, ok := KindOf(name); !ok {
		return nil, fmt.Errorf("%w: unknown body name %q", ErrMalformed, name)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	return CanonicalJSON(map[string]any{name: payload})
}

// BodyName 取出 body 的唯一键作为正文名字。零键、多键、非对象一律 malformed
// （带 `type` 字段的 v25 旧格式在此同样落空，断代重来即由此生效）。
func BodyName(body []byte) (string, error) {
	if len(body) == 0 {
		return "", fmt.Errorf("%w: empty body", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return "", fmt.Errorf("%w: body not a JSON object: %v", ErrMalformed, err)
	}
	if dec.More() {
		return "", fmt.Errorf("%w: trailing body content", ErrMalformed)
	}
	if len(fields) != 1 {
		return "", fmt.Errorf("%w: body must have exactly one key, got %d", ErrMalformed, len(fields))
	}
	for name := range fields {
		if !IsKnownName(name) {
			return "", fmt.Errorf("%w: unknown body name %q", ErrMalformed, name)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: body has no key", ErrMalformed)
}

// BodyPayload 取出 body[name] 的载荷并严格解码进 v（未知字段拒绝）。
// name 须由 BodyName 得出，两者不一致即 malformed。
func BodyPayload(body []byte, name string, v any) error {
	fields, err := bodyFields(body)
	if err != nil {
		return err
	}
	raw, ok := fields[name]
	if !ok {
		return fmt.Errorf("%w: body has no %q", ErrMalformed, name)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: body %q payload: %v", ErrMalformed, name, err)
	}
	return nil
}

// CheckBody 校验「信封声明的 kind 与 body 的唯一键互相印证」，返回该键名。
//
// 这一步是安全边界：只信 kind 会让攻击者把 kick 标成 msg 以躲开名单校验，
// 只信 body 键则 kind 成了无人核对的摆设，两者互校才堵住这个缝。
func CheckBody(kind string, body []byte) (string, error) {
	name, err := BodyName(body)
	if err != nil {
		return "", err
	}
	want, ok := KindOf(name)
	if !ok {
		return "", fmt.Errorf("%w: unknown body name %q", ErrMalformed, name)
	}
	if kind != want {
		return "", fmt.Errorf("%w: kind %q does not match body %q (want %q)", ErrMalformed, kind, name, want)
	}
	return name, nil
}

// TextBody 打包一条聊天正文的 body：{"text":"…"}.
func TextBody(text string) ([]byte, error) { return MakeBody(NameText, text) }

// TextOf 取聊天正文；非 msg/text 一律 ok=false（调用方按结构原文显示）。
func TextOf(m Message) (string, bool) {
	if m.Kind != KindMessage {
		return "", false
	}
	var s string
	if err := BodyPayload(m.Body, NameText, &s); err != nil {
		return "", false
	}
	return s, true
}

// bodyFields 解出 body 的载荷：必须恰一个键（多键/尾随数据一律 malformed），
// 键名由调用方指定的 name 决定，不做已知性判断。
func bodyFields(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return nil, fmt.Errorf("%w: body not a JSON object: %v", ErrMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing body content", ErrMalformed)
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("%w: body must have exactly one key, got %d", ErrMalformed, len(fields))
	}
	return fields, nil
}
