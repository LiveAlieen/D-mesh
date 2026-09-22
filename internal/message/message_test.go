package message

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"dmesh/internal/core"
)

func TestTypeClassification(t *testing.T) {
	cases := []struct {
		typ    string
		chat   bool
		roster bool
		known  bool
	}{
		{core.TypeText, true, false, true},
		{core.TypeHide, false, false, true},
		{core.TypeJoinReq, false, false, true},
		{core.TypeJoin, false, true, true},
		{core.TypeRemove, false, true, true},
		{core.TypeKick, false, true, true},
		{core.TypeUnban, false, true, true},
		{core.TypePerms, false, true, true},
		{core.TypeGrantAdmin, false, true, true},
		{core.TypeRevokeAdmin, false, true, true},
		{core.TypeTransfer, false, true, true},
		{core.TypePresence, false, true, true},
		{core.TypeNetdisk, false, true, true},
		{"bogus", false, false, false},
	}
	for _, tc := range cases {
		if got := VisibleInChat(tc.typ); got != tc.chat {
			t.Errorf("VisibleInChat(%q)=%v want %v", tc.typ, got, tc.chat)
		}
		if got := IsRosterEvent(tc.typ); got != tc.roster {
			t.Errorf("IsRosterEvent(%q)=%v want %v", tc.typ, got, tc.roster)
		}
		if got := IsKnownType(tc.typ); got != tc.known {
			t.Errorf("IsKnownType(%q)=%v want %v", tc.typ, got, tc.known)
		}
	}
}

func TestNewMessageDeterministicPayloadAndVerify(t *testing.T) {
	s := newTestSigner()
	m := core.Message{Type: core.TypeText, TSms: 1700000000123, Content: []byte("你好 D-Mesh"), MsgID: "fixed-id"}
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
	if !bytes.HasPrefix(payload, []byte(`{"content":"`)) {
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
	tampered.Content = []byte("hello!")
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
		got.Type != m.Type || !bytes.Equal(got.Content, m.Content) || !bytes.Equal(got.Sig, m.Sig) {
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
		{"no msg_id", []byte(`{"msg_id":"","group_id":[1],"type":"text"}`)},
		{"unknown type", []byte(`{"msg_id":"a","group_id":[1],"type":"dance"}`)},
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
	raw, err := EncodeHideContent("target-123")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"target_msg_id":"target-123"}` {
		t.Fatalf("hide content not canonical: %s", raw)
	}
	hc, err := DecodeHideContent(raw)
	if err != nil || hc.TargetMsgID != "target-123" {
		t.Fatalf("decode: %v %+v", err, hc)
	}
	if _, err := EncodeHideContent(""); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("empty target: want ErrMalformed, got %v", err)
	}
	if _, err := DecodeHideContent([]byte(`{}`)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("missing field: want ErrMalformed, got %v", err)
	}
	if _, err := DecodeHideContent([]byte(`[]`)); !errors.Is(err, core.ErrMalformed) {
		t.Fatalf("wrong shape: want ErrMalformed, got %v", err)
	}
}

func TestNewHideBuildsValidMessage(t *testing.T) {
	s := newTestSigner()
	hm, err := NewHide(s, testGroupID, 1700000000000, "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if hm.Type != core.TypeHide {
		t.Fatalf("type %q", hm.Type)
	}
	if err := VerifyMessage(hm); err != nil {
		t.Fatalf("hide verify: %v", err)
	}
	hc, err := DecodeHideContent(hm.Content)
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
