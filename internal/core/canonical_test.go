package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestCanonicalJSONSortsKeysAtEveryDepth(t *testing.T) {
	// map 插入顺序刻意打乱。
	v := map[string]any{
		"z": 1,
		"a": map[string]any{"b": []any{1, 2, map[string]any{"d": 4, "c": 3}}, "a": nil, "Z": true},
		"M": []any{"x", "y"},
	}
	got, err := CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"M":["x","y"],"a":{"Z":true,"a":null,"b":[1,2,{"c":3,"d":4}]},"z":1}`
	if string(got) != want {
		t.Fatalf("canonical output\n got: %s\nwant: %s", got, want)
	}
	// 键序不同的等价输入必须产出同一字节串。
	var again map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"a":{"b":[1,2,{"d":4,"c":3}],"Z":true,"a":null},"z":1,"M":["x","y"]}`))
	dec.UseNumber()
	if err := dec.Decode(&again); err != nil {
		t.Fatal(err)
	}
	other, err := CanonicalJSON(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, other) {
		t.Fatalf("not stable:\n %s\n %s", got, other)
	}
}

func TestCanonicalJSONStructFieldOrderIrrelevant(t *testing.T) {
	cfg := sampleGroupConfig()
	fromStruct, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 同一份数据以「键序被打乱」的 map 表达 -> 必须得到相同字节。
	var generic map[string]any
	if err := json.Unmarshal(fromStruct, &generic); err != nil {
		t.Fatal(err)
	}
	fromMap, err := CanonicalJSON(generic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromStruct, fromMap) {
		t.Fatalf("struct vs map differ:\n %s\n %s", fromStruct, fromMap)
	}
	// 原文里除字符串字面量内部之外不得有任何多余空白。
	name := cfg.Name
	cfg.Name = "nospaces"
	probe, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, probe); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(probe, compact.Bytes()) {
		t.Fatalf("canonical JSON must carry no insignificant whitespace:\n %s\n %s", probe, compact.Bytes())
	}
	cfg.Name = name
}

func TestCanonicalJSONKeepsInt64Precision(t *testing.T) {
	// 2^53+1 走 float64 会被舍入，必须原样保住字面量。
	const big int64 = 9007199254740993
	got, err := CanonicalJSON(map[string]any{"ts": big})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"ts":9007199254740993}` {
		t.Fatalf("int64 precision lost: %s", got)
	}
	m := Message{MsgID: "m", TSms: big, Kind: KindMessage, Body: []byte(`{"text":"hi"}`), Alg: SigEd25519}
	payload, err := MessageSigPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"ts_ms":9007199254740993`)) {
		t.Fatalf("message ts_ms not literal: %s", payload)
	}
}

func TestCanonicalJSONStringEscaping(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"s": "a\"b\\c\nd\be\ff\rg\th<>&é"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, "é") {
		t.Fatalf("non-ASCII must stay raw UTF-8: %s", s)
	}
	if strings.Contains(s, `\u003c`) || strings.Contains(s, `\u003e`) || strings.Contains(s, `\u0026`) {
		t.Fatalf("HTML escaping must be off: %s", s)
	}
	for _, want := range []string{`\"`, `\\`, `\n`, `\b`, `\f`, `\r`, `\t`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing escape %s in %s", want, s)
		}
	}
	raw, err := CanonicalJSON(map[string]any{"s": "\x01\x1f"})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"s":"\u0001\u001f"}` {
		t.Fatalf("control chars: got %s", raw)
	}
	// 产物必须是合法 JSON，能原样解回。
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("output not valid JSON (%s): %v", got, err)
	}
}

func TestCanonicalJSONRejectsUnencodable(t *testing.T) {
	if _, err := CanonicalJSON(func() {}); err == nil {
		t.Fatal("func must not be marshalable")
	}
	if _, err := CanonicalJSON(map[string]any{"n": make(chan int)}); err == nil {
		t.Fatal("chan must not be marshalable")
	}
	if _, err := CanonicalJSON(map[string]any{"n": math.NaN()}); err == nil {
		t.Fatal("NaN must be rejected by encoding/json")
	}
}

func TestWGPubJSONIsBase64(t *testing.T) {
	var w WGPub
	for i := range w {
		w[i] = byte(i)
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[0] != '"' || !json.Valid(b) {
		t.Fatalf("wg_pub must marshal as base64 string, got %s", b)
	}
	if want := `"` + base64.StdEncoding.EncodeToString(w[:]) + `"`; string(b) != want {
		t.Fatalf("wg_pub base64 mismatch:\n got %s\nwant %s", b, want)
	}
	var back WGPub
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != w {
		t.Fatalf("roundtrip mismatch: %v vs %v", back, w)
	}
	for _, bad := range []string{`"zz!!"`, `"aGk="`, `[]`, `[1,2]`, `null`, `123`, `""`} {
		var v WGPub
		if err := json.Unmarshal([]byte(bad), &v); err == nil {
			t.Fatalf("wg_pub accepted invalid input %s", bad)
		}
	}
	var ok WGPub
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := json.Unmarshal([]byte(`"`+long+`"`), &ok); err != nil {
		t.Fatalf("valid wg_pub rejected: %v", err)
	}
	if ok != w2(7) {
		t.Fatalf("wg_pub content mismatch after decode: %s", ok)
	}
	// 嵌进结构体后仍走 base64（CanonicalJSON 依赖 json.Marshal）。
	type holder struct {
		W WGPub `json:"wg_pub"`
	}
	hb, err := CanonicalJSON(holder{W: w})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(hb, []byte(`{"wg_pub":"`)) {
		t.Fatalf("canonical wg_pub not base64: %s", hb)
	}
}

func w2(b byte) WGPub {
	var w WGPub
	for i := range w {
		w[i] = b
	}
	return w
}

func sampleGroupConfig() GroupConfig {
	return GroupConfig{
		Name:         "去中心化测试群 <v2>",
		Version:      1,
		Mode:         ModeAuto,
		CreatedAt:    1_700_000_000_123,
		GroupPub:     PubKey{Alg: SigEd25519, Bytes: bytes.Repeat([]byte{1}, 32)},
		Creator:      PubKey{Alg: SigEd25519, Bytes: bytes.Repeat([]byte{2}, 32)},
		CreatorWG:    w2(0xAB),
		Alg:          SigEd25519,
		DefaultPerms: []string{PermSpeak, PermReceive},
		NetdiskMB:    32,
	}
}

func TestGroupIDOfDeterministicAndSigIndependent(t *testing.T) {
	cfg := sampleGroupConfig()
	id1, err := GroupIDOf(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 幂等：重复计算完全一致。
	for i := 0; i < 8; i++ {
		again, err := GroupIDOf(sampleGroupConfig())
		if err != nil {
			t.Fatal(err)
		}
		if again != id1 {
			t.Fatal("group_id not deterministic")
		}
	}
	// CreatorSig 只是附加签名，绝不参与哈希（否则自签后才能算 id，鸡生蛋）。
	signed := cfg
	signed.CreatorSig = bytes.Repeat([]byte{0x5A}, 64)
	id2, err := GroupIDOf(signed)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("group_id changed with creator_sig: %x vs %x", id1, id2)
	}
	// 与手算的 sha256(CanonicalJSON(cfg 且 CreatorSig=nil)) 一致。
	payload, err := GroupConfigSigPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(payload); want != id1 {
		t.Fatalf("group_id != sha256(sig payload)")
	}
	// payload 可解回且不含 creator_sig 键。
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("sig payload not valid JSON: %v", err)
	}
	if _, ok := m["creator_sig"]; ok {
		t.Fatal("sig payload must omit empty creator_sig")
	}
	if got, _ := m["sig_alg"].(string); got != string(SigEd25519) {
		t.Fatalf("sig_alg missing from genesis payload: %s", payload)
	}
	if got, _ := m["mode"].(string); got != ModeAuto {
		t.Fatalf("mode wrong in genesis payload: %s", payload)
	}
	// GroupConfigSigPayload 不得改动调用方的切片。
	if len(signed.CreatorSig) != 64 {
		t.Fatal("GroupConfigSigPayload mutated caller CreatorSig")
	}
}

func TestGroupIDSensitiveToAnchorFields(t *testing.T) {
	baseID := mustGroupID(t, sampleGroupConfig())
	cases := map[string]func(*GroupConfig){
		"mode":          func(c *GroupConfig) { c.Mode = ModeVerify },
		"group_pub":     func(c *GroupConfig) { c.GroupPub.Bytes[0] ^= 0xFF },
		"group_pub_alg": func(c *GroupConfig) { c.GroupPub.Alg = SigAlg("sm2") },
		"creator":       func(c *GroupConfig) { c.Creator.Bytes[3] ^= 0x01 },
		"creator_wg":    func(c *GroupConfig) { c.CreatorWG[7] ^= 0x01 },
		"netdisk":       func(c *GroupConfig) { c.NetdiskMB = 0 },
		"default_perms": func(c *GroupConfig) { c.DefaultPerms = []string{PermReceive} },
		"name":          func(c *GroupConfig) { c.Name = "other" },
		"version":       func(c *GroupConfig) { c.Version = 2 },
		"created_at":    func(c *GroupConfig) { c.CreatedAt++ },
		"alg":           func(c *GroupConfig) { c.Alg = SigAlg("sm2") },
	}
	for k, mut := range cases {
		c := sampleGroupConfig()
		mut(&c)
		if mustGroupID(t, c) == baseID {
			t.Fatalf("group_id must change when %s changes", k)
		}
	}
}

func mustGroupID(t *testing.T, cfg GroupConfig) [32]byte {
	t.Helper()
	id, err := GroupIDOf(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMessageSigPayloadExcludesSigsOnly(t *testing.T) {
	m := Message{
		MsgID:   "01JABC",
		GroupID: mustGroupID(t, sampleGroupConfig()),
		Sender:  PubKey{Alg: SigEd25519, Bytes: bytes.Repeat([]byte{2}, 32)},
		TSms:    1_700_000_001_000,
		Kind:    KindMessage,
		Body:    []byte(`{"text":"你好，P2P"}`),
		Alg:     SigEd25519,
	}
	base, err := MessageSigPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	// 签名与联署自身不得进入原文（否则无法验）。
	withSigs := m
	withSigs.Sig = bytes.Repeat([]byte{9}, 64)
	withSigs.EndorseSig = bytes.Repeat([]byte{8}, 64)
	got, err := MessageSigPayload(withSigs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base, got) {
		t.Fatal("MessageSigPayload must ignore Sig/EndorseSig")
	}
	if bytes.Contains(base, []byte("endorse_sig")) || bytes.Contains(base, []byte(`"sig":`)) {
		t.Fatalf("sig fields must be omitted from payload: %s", base)
	}
	// 原文必须绑定群与发送者（防跨群重放）。
	if !bytes.Contains(base, []byte(`"group_id":`)) || !bytes.Contains(base, []byte(`"sender":`)) {
		t.Fatalf("payload must carry group_id/sender: %s", base)
	}
	if bytes.Contains(base, []byte(`"to":`)) {
		t.Fatal("empty To must be omitted from payload")
	}
	if len(withSigs.Sig) != 64 || len(m.Sig) != 0 {
		t.Fatal("MessageSigPayload mutated caller Sig")
	}
	// To 非空时参与签名域。
	to := PubKey{Alg: SigEd25519, Bytes: bytes.Repeat([]byte{3}, 32)}
	withTo := m
	withTo.To = &to
	other, err := MessageSigPayload(withTo)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, other) || !bytes.Contains(other, []byte(`"to":`)) {
		t.Fatal("payload must depend on To")
	}
	// 任何语义字段变化都必须改变原文。
	mut := func(f func(*Message)) []byte {
		c := m
		f(&c)
		b, err := MessageSigPayload(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, p := range map[string][]byte{
		"msg_id":  mut(func(c *Message) { c.MsgID = "01JABD" }),
		"body":    mut(func(c *Message) { c.Body = []byte(`{"hide":{"target_msg_id":"x"}}`) }),
		"kind":    mut(func(c *Message) { c.Kind = KindCommand }),
		"ts":      mut(func(c *Message) { c.TSms++ }),
		"group":   mut(func(c *Message) { c.GroupID[0] ^= 0x01 }),
		"sig_alg": mut(func(c *Message) { c.Alg = SigAlg("sm2") }),
	} {
		if bytes.Equal(base, p) {
			t.Fatalf("payload must change with %s", name)
		}
	}
}

func TestProofOfAndVerifyProof(t *testing.T) {
	const alg = SigAlg("test-mac")
	Register(alg, func(pub PubKey, msg, sig []byte) bool {
		return bytes.Equal(sig, append(append([]byte{}, pub.Bytes...), msg...))
	})
	defer Register(alg, nil)

	carrier := PubKey{Alg: alg, Bytes: bytes.Repeat([]byte{0xC4}, 32)}
	ev := Message{
		MsgID:   "join-1",
		GroupID: mustGroupID(t, sampleGroupConfig()),
		Sender:  carrier,
		TSms:    1_700_000_002_000,
		Kind:    KindCommand,
		Body:    []byte(`{"join":{"pub":"newbie"}}`),
		Alg:     alg,
	}
	if _, err := ProofOf(ev); err == nil {
		t.Fatal("unsigned event must not produce a proof")
	}
	raw, err := MessageSigPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.Sig = append(append([]byte{}, carrier.Bytes...), raw...)
	pr, err := ProofOf(ev)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Alg != alg || !bytes.Equal(pr.Sig, ev.Sig) {
		t.Fatalf("proof fields: %+v", pr)
	}
	if !bytes.Equal(pr.Raw, raw) {
		t.Fatal("proof.Raw must be the signed canonical payload")
	}
	if err := VerifyProof(carrier, pr); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// proof 可 JSON 往返（存盘 / 副本应答）。
	b, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}
	var back Proof
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(carrier, back); err != nil {
		t.Fatalf("proof lost in JSON roundtrip: %v", err)
	}
	// 原文被改即拒。
	tampered := back
	tampered.Raw = append(append([]byte{}, tampered.Raw...), ' ')
	if err := VerifyProof(carrier, tampered); err == nil {
		t.Fatal("tampered proof accepted")
	}
	// 换签名者公钥即拒（采纳只看原文里的签署者，与转发者无关）。
	if err := VerifyProof(PubKey{Alg: alg, Bytes: bytes.Repeat([]byte{0xFF}, 32)}, back); err == nil {
		t.Fatal("proof verified under wrong signer")
	}
	// 空 proof / 未注册算法的 proof 一律拒。
	if err := VerifyProof(carrier, Proof{Alg: alg, Sig: back.Sig}); err == nil {
		t.Fatal("empty proof.Raw accepted")
	}
	unknownAlg := back
	unknownAlg.Alg = SigAlg("sm9")
	if err := VerifyProof(carrier, unknownAlg); !IsUnknownAlg(err) {
		t.Fatalf("unknown alg proof must be rejected, got %v", err)
	}
	// proof 声明了另一把已注册算法、却用 test-mac 的钥匙 -> 串用/降级，ErrMalformed。
	const alg2 = SigAlg("test-mac2")
	Register(alg2, func(PubKey, []byte, []byte) bool { return false })
	defer Register(alg2, nil)
	cross := back
	cross.Alg = alg2
	if err := VerifyProof(carrier, cross); !errors.Is(err, ErrMalformed) {
		t.Fatalf("cross-algorithm proof: want ErrMalformed, got %v", err)
	}
	// signer.Alg 留空时以 proof.Alg 为准，仍可验。
	if err := VerifyProof(PubKey{Bytes: carrier.Bytes}, back); err != nil {
		t.Fatalf("empty signer.Alg should fall back to proof.Alg: %v", err)
	}
	// 只有 proof 有效还不够：签名者层级由调用方用 Roster.TierOf 判定（这里确认标尺一致）。
	if TierOfRole(RoleMember) >= TierOfRole(RoleAdmin) {
		t.Fatal("tier scale inconsistent")
	}
}

// TestRosterEntryJSONRoundTrip 确认名单条目（含 proof、wg_pub、perms）能过 JSON 往返，
// group/store/backfill 的双名单副本应答直接依赖这一点。
func TestRosterEntryJSONRoundTrip(t *testing.T) {
	e := MemberEntry{
		Pub:   PubKey{Alg: SigEd25519, Bytes: bytes.Repeat([]byte{1}, 32)},
		WG:    w2(2),
		Role:  RoleAdmin,
		Perms: []string{PermSpeak, PermReceive, PermCarry},
		Proof: Proof{Raw: []byte("raw"), Alg: SigEd25519, Sig: bytes.Repeat([]byte{3}, 64)},
		TS:    1_700_000_003_000,
	}
	b, err := CanonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	var back MemberEntry
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("member entry JSON not decodable: %v (%s)", err, b)
	}
	again, err := CanonicalJSON(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, again) {
		t.Fatalf("member entry canonical not idempotent:\n %s\n %s", b, again)
	}
	if back.Role != RoleAdmin || len(back.Perms) != 3 || back.TS != e.TS || back.WG != e.WG {
		t.Fatalf("member entry lost fields: %+v", back)
	}

	bl := BlacklistEntry{Pub: e.Pub, Proof: e.Proof, TS: e.TS}
	bb, err := CanonicalJSON(bl)
	if err != nil {
		t.Fatal(err)
	}
	var blBack BlacklistEntry
	if err := json.Unmarshal(bb, &blBack); err != nil {
		t.Fatal(err)
	}
	if !blBack.Pub.Equal(e.Pub) || blBack.TS != e.TS {
		t.Fatalf("blacklist entry lost fields: %+v", blBack)
	}

	ps := PresenceEntry{Pub: e.Pub, LastMsgTS: 1_700_000_004_000, OfflineAfter: 60_000}
	pb, err := CanonicalJSON(ps)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pb, []byte(`"last_msg_ts":1700000004000`)) || !bytes.Contains(pb, []byte(`"offline_after":60000`)) {
		t.Fatalf("presence canonical wrong: %s", pb)
	}
}

// TestImplementsInterfaces 保证 core 声明的接口形状可被最小实现满足（编译期契约检查）。
func TestImplementsInterfaces(t *testing.T) {
	var _ Signer = stubSigner{}
	var _ Tunnel = stubTunnel{}
	var _ Roster = stubRoster{}
	var _ Verifier = fakeVerifier
	if TierOfRole(RoleCreator) <= TierOfRole(RoleOwner) {
		t.Fatal("tier ordering broken")
	}
}

type stubSigner struct{}

func (stubSigner) Alg() SigAlg                   { return SigEd25519 }
func (stubSigner) Pub() PubKey                   { return PubKey{} }
func (stubSigner) Sign(b []byte) ([]byte, error) { return b, nil }

type stubTunnel struct{}

func (stubTunnel) Send([]byte) error   { return nil }
func (stubTunnel) OnData(func([]byte)) {}
func (stubTunnel) RemotePub() PubKey   { return PubKey{} }
func (stubTunnel) Close() error        { return nil }

type stubRoster struct{}

func (stubRoster) IsBlacklisted(PubKey) bool         { return false }
func (stubRoster) Member(PubKey) (MemberEntry, bool) { return MemberEntry{}, false }
func (stubRoster) ApplyEvent(Message) error          { return nil }
func (stubRoster) TierOf(PubKey) int                 { return TierNonMember }
func (stubRoster) HasPerm(PubKey, string) bool       { return false }
func (stubRoster) Presence(PubKey) PresenceEntry     { return PresenceEntry{} }
func (stubRoster) Snapshot() ([]MemberEntry, []BlacklistEntry, PubKey) {
	return nil, nil, PubKey{}
}
