package spam

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestHasLeadingZeroBits(t *testing.T) {
	all0 := make([]byte, 32)
	hashWith := func(b0 byte) []byte {
		h := make([]byte, 32)
		h[0] = b0
		return h
	}
	firstByte80 := hashWith(0x80)
	firstByte40 := hashWith(0x40)
	firstByte20 := hashWith(0x20) // 前 2 位零，第 3 位为 1
	fifthBit := hashWith(0x08)    // 前 4 位零，第 5 位为 1

	tests := []struct {
		name string
		h    []byte
		bits uint
		want bool
	}{
		{"all-zero passes any", all0, 64, true},
		{"0 bits always true", firstByte80, 0, true},
		{"top bit set fails 1", firstByte80, 1, false},
		{"top bit zero passes 1", firstByte40, 1, true},
		{"2 zero bits", firstByte20, 2, true},
		{"3 zero bits fails at bit3", firstByte20, 3, false},
		{"4 zero bits", fifthBit, 4, true},
		{"5 zero bits fails", fifthBit, 5, false},
		{"beyond hash length fails", all0[:1], 9, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasLeadingZeroBits(tc.h, tc.bits); got != tc.want {
				t.Fatalf("HasLeadingZeroBits(%v, %d) = %v, want %v", tc.h, tc.bits, got, tc.want)
			}
		})
	}
}

func TestLeadingZeroBitsMatchesHas(t *testing.T) {
	// 与 PowHash 真实输出的前缀零计数交叉验证两个函数的自洽性。
	payload := []byte(`{"pub":"abc"}`)
	for n := uint64(0); n < 200; n++ {
		h := PowHash(payload, []byte("salt"), n)
		lead := LeadingZeroBits(h[:])
		if !HasLeadingZeroBits(h[:], lead) {
			t.Fatalf("hash %x: LeadingZeroBits=%d but Has(%d)=false", h, lead, lead)
		}
		if lead < 255 && HasLeadingZeroBits(h[:], lead+1) {
			t.Fatalf("hash %x: LeadingZeroBits=%d but Has(%d)=true", h, lead, lead+1)
		}
	}
}

func TestPowSolveVerifyRoundtrip(t *testing.T) {
	params := PowParams{Algo: PowAlgoSHA256Prefix, Bits: 12, MaxAgeMS: 60_000}
	payload := []byte(`{"sig_alg":"ed25519","pub":"AAEC"}`)
	now := int64(1_700_000_000_000)

	sol, err := params.SolveFrom(payload, []byte("group-salt"), 0)
	if err != nil {
		t.Fatalf("SolveFrom: %v", err)
	}
	if sol.Bits != params.Bits {
		t.Fatalf("sol.Bits = %d, want %d", sol.Bits, params.Bits)
	}
	sol.TSms = now // SolveFrom 不盖时钟戳（纯函数）；实际发送时由 EncodeContent 补
	if err := params.Verify(payload, sol, now); err != nil {
		t.Fatalf("Verify fresh solution: %v", err)
	}
	// 时效窗口内仍可验
	if err := params.Verify(payload, sol, now+59_000); err != nil {
		t.Fatalf("Verify near expiry: %v", err)
	}
	// 过期拒
	if err := params.Verify(payload, sol, now+60_001); !errors.Is(err, ErrPowExpired) {
		t.Fatalf("Verify expired err = %v, want ErrPowExpired", err)
	}
	// 同参数同盐同起点解是确定的（纯函数）
	sol2, _ := params.SolveFrom(payload, []byte("group-salt"), 0)
	if sol2.Nonce != sol.Nonce {
		t.Fatalf("solve not deterministic: %d vs %d", sol.Nonce, sol2.Nonce)
	}
}

func TestPowVerifyNegativeCases(t *testing.T) {
	params := PowParams{Algo: PowAlgoSHA256Prefix, Bits: 10, MaxAgeMS: 0} // 0=不校验时效
	payload := []byte(`{"a":1}`)
	sol, err := params.SolveFrom(payload, []byte("s"), 0)
	if err != nil {
		t.Fatalf("SolveFrom: %v", err)
	}
	sol.TSms = 12345 // 时效关闭时任意 ts 都放行

	// 篡改 nonce：确定性地找一个不满足难度的 nonce（避免碰运气的 flaky 测试）
	badNonce := sol.Nonce + 1
	for {
		h := PowHash(payload, sol.Salt, badNonce)
		if !HasLeadingZeroBits(h[:], params.Bits) {
			break
		}
		badNonce++
	}

	tests := []struct {
		name    string
		mutate  func(*PowSolution)
		wantErr error
	}{
		{"tampered nonce", func(s *PowSolution) { s.Nonce = badNonce }, ErrPowTooWeak},
		{"wrong payload", nil, ErrPowTooWeak}, // 用另一 payload 校验（见下特判）
		{"empty salt", func(s *PowSolution) { s.Salt = nil }, ErrPowMalformed},
		{"wrong algo", func(s *PowSolution) { s.Algo = "md5" }, ErrPowMalformed},
		{"declared below required", func(s *PowSolution) { s.Bits = 5 }, ErrPowTooWeak},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := sol
			if tc.name == "wrong payload" {
				if err := params.Verify([]byte(`{"a":2}`), s, 0); !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			s.Algo = sol.Algo
			s.Bits = sol.Bits
			s.Salt = append([]byte{}, sol.Salt...)
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			err := params.Verify(payload, s, 0)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPowParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  PowParams
		wantErr bool
	}{
		{"default ok", DefaultPowParams(), false},
		{"unknown algo", PowParams{Algo: "sha1", Bits: 8}, true},
		{"zero bits", PowParams{Algo: PowAlgoSHA256Prefix, Bits: 0}, true},
		{"bits too high", PowParams{Algo: PowAlgoSHA256Prefix, Bits: PowMaxBitsBits + 1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
			_, serr := tc.params.SolveFrom([]byte("x"), []byte("s"), 0)
			if (serr != nil) != tc.wantErr {
				t.Fatalf("SolveFrom err = %v, wantErr %v", serr, tc.wantErr)
			}
			verr := tc.params.Verify([]byte("x"), PowSolution{Algo: tc.params.Algo, Bits: tc.params.Bits, Salt: []byte{1}}, 0)
			if tc.wantErr && !errors.Is(verr, ErrPowMalformed) && verr == nil {
				t.Fatalf("Verify err = nil, want error")
			}
		})
	}
}

func TestPowContentEncodeDecode(t *testing.T) {
	params := PowParams{Algo: PowAlgoSHA256Prefix, Bits: 8, MaxAgeMS: 1000}
	payload := []byte(`{"sig_alg":"ed25519","pub":"AA","wg_pub":"aa=="}`)
	now := int64(1_000_000)
	sol, err := params.SolveFrom(payload, nil, 0)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	content, err := EncodeContent(payload, sol, now)
	if err != nil {
		t.Fatalf("EncodeContent: %v", err)
	}
	if !json.Valid(content) {
		t.Fatalf("content not valid JSON: %s", content)
	}
	gotPayload, gotSol, err := DecodeContent(content)
	if err != nil {
		t.Fatalf("DecodeContent: %v", err)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload = %s, want %s", gotPayload, payload)
	}
	if gotSol.Nonce != sol.Nonce || gotSol.TSms != now {
		t.Fatalf("solution mismatch: %+v (ts want %d)", gotSol, now)
	}
	if err := params.Verify(gotPayload, gotSol, now+999); err != nil {
		t.Fatalf("Verify decoded: %v", err)
	}

	if _, _, err := DecodeContent([]byte("not json")); !errors.Is(err, ErrPowMalformed) {
		t.Fatalf("DecodeContent(garbage) err = %v, want ErrPowMalformed", err)
	}
	if _, _, err := DecodeContent([]byte(`{"payload":null,"pow":{}}`)); !errors.Is(err, ErrPowMalformed) {
		t.Fatalf("DecodeContent(empty payload) err = %v, want ErrPowMalformed", err)
	}
}

func TestPowFutureTimestamp(t *testing.T) {
	params := PowParams{Algo: PowAlgoSHA256Prefix, Bits: 8, MaxAgeMS: 5000}
	payload := []byte(`{"x":1}`)
	sol, err := params.SolveFrom(payload, []byte("s"), 0)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	sol.TSms = 10_000
	if err := params.Verify(payload, sol, 6_000); err != nil { // 未来 4000ms，容忍内
		t.Fatalf("verify modest future ts: %v", err)
	}
	if err := params.Verify(payload, sol, 1); !errors.Is(err, ErrPowExpired) { // 未来 9999ms，超容忍
		t.Fatalf("verify far future ts err = %v, want ErrPowExpired", err)
	}
}
