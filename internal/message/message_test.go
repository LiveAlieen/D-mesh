package message

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"dmesh/internal/core"
)

// TestBodyClassification 是 v26 归一化的分类真值表：每个具体消息名落在哪个大类、
// 是否进气泡流、是否走名单校验，全部钉死；并强制「注册表里不得有本表未覆盖的名字」
// （加一类消息/命令/扩展却忘了来这里登记，测试直接红）。
func TestBodyClassification(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		chat   bool
		roster bool
	}{
		{core.NameText, core.KindMessage, true, false},
		{core.NameHide, core.KindCommand, false, false},
		{core.NameJoinReq, core.KindCommand, false, false},
		{core.NameJoin, core.KindCommand, false, true},
		{core.NameRemove, core.KindCommand, false, true},
		{core.NameKick, core.KindCommand, false, true},
		{core.NameUnban, core.KindCommand, false, true},
		{core.NamePerms, core.KindCommand, false, true},
		{core.NameGrantAdmin, core.KindCommand, false, true},
		{core.NameRevokeAdmin, core.KindCommand, false, true},
		{core.NameTransfer, core.KindCommand, false, true},
		{core.NameNetdisk, core.KindCommand, false, true},
		{core.NamePresence, core.KindExtension, false, true},
		{core.NameManifest, core.KindExtension, false, false},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.name] = true
		if got, _ := core.KindOf(tc.name); got != tc.kind {
			t.Errorf("KindOf(%q)=%q want %q", tc.name, got, tc.kind)
		}
		if got := VisibleInChat(tc.kind); got != tc.chat {
			t.Errorf("VisibleInChat(%q)=%v want %v", tc.kind, got, tc.chat)
		}
		if got := IsRosterEvent(tc.name); got != tc.roster {
			t.Errorf("IsRosterEvent(%q)=%v want %v", tc.name, got, tc.roster)
		}
		if !IsKnownName(tc.name) {
			t.Errorf("IsKnownName(%q)=false", tc.name)
		}
	}
	for _, n := range core.Names() {
		if !covered[n] {
			t.Errorf("注册表新增 %q 未登记进分类真值表", n)
		}
	}
	for _, bogus := range []string{"bogus", "", "text "} {
		if IsKnownName(bogus) || core.IsKnownName(bogus) || IsRosterEvent(bogus) {
			t.Errorf("unknown name %q must not be recognised", bogus)
		}
	}
}

func TestNewMessageDeterministicPayloadAndVerify(t *testing.T) {
	s := newTestSigner()
	tb, err := core.TextBody("你好 D-Mesh")
	if err != nil {
		t.Fatal(err)
	}
	m := core.Message{Kind: core.KindMessage, TSms: 1700000000123, Body: tb, MsgID: "fixed-id"}
	signed, err := NewMessage(s, testGroupID, &m, nil)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if signed.Sender.Key() != s.pub.Key() || signed.Alg != core.SigEd25519 {
		t.Fatalf("sender/alg not filled: %+v", signed)
	}
	if signed.GroupID != testGroupID {
		t.Fatal("group id not filled")
	}
	// 签名原文必须是 CanonicalJSON（键序字典升序、无空白）。
	payload, err := SigPayloadOf(signed)
	if err != nil {
		t.Fatalf("SigPayloadOf: %v", err)
	}
	// CanonicalJSON 键按字典序，正文体排在最前（v26 归一化后 body 是首键）。
	if !bytes.HasPrefix(payload, []byte(`{"body":"`)) {
		t.Fatalf("payload not canonical (key order/whitespace wrong): %s", payload)
	}
	if !jsonValidCanonical(payload) {
		t.Fatalf("payload is not canonical JSON: %s", payload)
	}
	// 同输入两次打包 → 原文逐字节一致、验签互相可过。
	signed2, err := NewMessage(s, testGroupID, &m, nil)
	if err != nil {
		t.Fatalf("NewMessage #2: %v", err)
	}
	if p2, _ := SigPayloadOf(signed2); !bytes.Equal(payload, p2) {
		t.Fatal("MessageSigPayload not deterministic")
	}
	if err := VerifyMessage(signed); err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if err := VerifyMessage(signed2); err != nil {
		t.Fatalf("VerifyMessage #2: %v", err)
	}
}

func TestVerifyMessageRejections(t *testing.T) {
	s := newTestSigner()
	base := mustText(t, s, 1700000000000, "hello", "id-1")

	tampered := base
	tampered.Body = []byte(`{"text":"hello!"}`)
	if err := VerifyMessage(tampered); !errors.Is(err, core.ErrInvalidSig) {
		t.Fatalf("tampered content: want ErrInvalidSig, got %v", err)
	}

	unsigned := base
	unsigned.Sig = nil
	if err := VerifyMessage(unsigned); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("unsigned: want ErrMalformed, got %v", err)
	}

	// v16：本地未注册的 sig_alg → 一律拒绝采纳（ErrUnknownAlg），绝不误信。
	unknown := base
	unknown.Alg = core.SigAlg("sm2-not-registered")
	unknown.Sender.Alg = unknown.Alg
	if err := VerifyMessage(unknown); !core.IsUnknownAlg(err) {
		t.Fatalf("unknown alg: want ErrUnknownAlg, got %v", err)
	}

	// alg 串用（sender 声明 A、消息声明 B）→ 结构错误。
	mixed := base
	mixed.Alg = core.SigAlg("other")
	if err := VerifyMessage(mixed); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("alg mismatch: want ErrMalformed, got %v", err)
	}
}

func TestFrameEncodeDecodeRoundTrip(t *testing.T) {
	s := newTestSigner()
	m := mustText(t, s, 1700000000000, "flood me", "")
	raw := frameOf(t, m)
	got, err := DecodeFrame(raw)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if got.MsgID != m.MsgID || got.GroupID != m.GroupID || !got.Sender.Equal(m.Sender) ||
		got.Kind != m.Kind || !bytes.Equal(got.Body, m.Body) || !bytes.Equal(got.Sig, m.Sig) {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if got.MsgID == "" {
		t.Fatal("random msg_id not generated")
	}
	if len(got.MsgID) != 32 {
		t.Fatalf("msg_id should be 32 hex chars, got %q", got.MsgID)
	}
	// To 定向字段往返
	to := newTestSigner().pub
	m2 := mustText(t, s, 1700000000001, "appeal", "")
	m2.To = &to
	g2, err := DecodeFrame(frameOf(t, m2))
	if err != nil || g2.To == nil || !g2.To.Equal(to) {
		t.Fatalf("To round trip: %v %+v", err, g2.To)
	}
}

func TestDecodeFrameMalformedTable(t *testing.T) {
	s := newTestSigner()
	good := frameOf(t, mustText(t, s, 1, "x", "id"))
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not json", []byte("{")},
		{"no msg_id", []byte(`{"msg_id":"","group_id":[1],"kind":"msg","body":{"text":"x"}}`)},
		{"unknown name", []byte(`{"msg_id":"a","group_id":[1],"kind":"msg","body":{"dance":1}}`)},
		// v26 判别位：kind 与 body 唯一键必须互校，body 必须恰一个键。
		{"kind/name mismatch", []byte(`{"msg_id":"a","group_id":[1],"kind":"msg","body":{"kick":{"target":"x"}}}`)},
		{"no kind declared", []byte(`{"msg_id":"a","group_id":[1],"kind":"","body":{"text":"x"}}`)},
		{"body zero key", []byte(`{"msg_id":"a","group_id":[1],"kind":"msg","body":{}}`)},
		{"body two keys", []byte(`{"msg_id":"a","group_id":[1],"kind":"msg","body":{"text":"x","hide":{"target_msg_id":"t"}}}`)},
		{"body not object", []byte(`{"msg_id":"a","group_id":[1],"kind":"msg","body":"x"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeFrame(tc.data); !errors.Is(err, core.ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
		})
	}
	// 好帧 + 零 group_id 也要被拒
	var zeroM = mustText(t, s, 5, "y", "id-zero")
	zeroM.GroupID = [32]byte{}
	if _, err := DecodeFrame(frameOf(t, zeroM)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("zero group_id: want ErrMalformed, got %v", err)
	}
	if _, err := DecodeFrame(good); err != nil {
		t.Fatalf("good frame rejected: %v", err)
	}
}

func TestHideContentCodec(t *testing.T) {
	raw, err := EncodeHideBody("target-123")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"hide":{"target_msg_id":"target-123"}}` {
		t.Fatalf("hide body not canonical: %s", raw)
	}
	hc, err := DecodeHideBody(raw)
	if err != nil || hc.TargetMsgID != "target-123" {
		t.Fatalf("decode: %v %+v", err, hc)
	}
	if _, err := EncodeHideBody(""); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("empty target: want ErrMalformed, got %v", err)
	}
	if _, err := DecodeHideBody([]byte(`{}`)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("missing field: want ErrMalformed, got %v", err)
	}
	if _, err := DecodeHideBody([]byte(`[]`)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("wrong shape: want ErrMalformed, got %v", err)
	}
	// 标签位写错名字（把 hide 包成 text）同样拒。
	if _, err := DecodeHideBody([]byte(`{"text":{"target_msg_id":"t"}}`)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("wrong tag: want ErrMalformed, got %v", err)
	}
}

func TestNewHideBuildsValidMessage(t *testing.T) {
	s := newTestSigner()
	hm, err := NewHide(s, testGroupID, 1700000000000, "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if name, err := core.CheckBody(hm.Kind, hm.Body); err != nil || name != core.NameHide {
		t.Fatalf("kind/name = %q/%q err=%v", hm.Kind, name, err)
	}
	if err := VerifyMessage(hm); err != nil {
		t.Fatalf("hide verify: %v", err)
	}
	hc, err := DecodeHideBody(hm.Body)
	if err != nil || hc.TargetMsgID != "tgt-1" {
		t.Fatalf("hide content: %v %+v", err, hc)
	}
}

// jsonValidCanonical 校验 b 是否等于对自身的规范化输出（幂等即确定性）。
func jsonValidCanonical(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	c, err := core.CanonicalJSON(v)
	return err == nil && bytes.Equal(c, b)
}
