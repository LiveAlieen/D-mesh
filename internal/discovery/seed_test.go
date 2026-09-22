package discovery

import (
	"encoding/hex"
	"strings"
	"testing"
)

func testHash(b byte) [InfoHashLen]byte {
	var h [InfoHashLen]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// TestSeedZeroAndValidate 覆盖 Seed 含 [][]string 字段后的判空/校验：
// 不得再用 == 直接比较（编译期即报错），改走显式字段判空。
func TestSeedZeroAndValidate(t *testing.T) {
	var empty Seed
	if !empty.IsZero() {
		t.Fatal("零值种子应为 IsZero")
	}
	if err := empty.Validate(); err == nil {
		t.Fatal("空种子 Validate 应报错")
	}

	nameOnly := Seed{Name: "g"}
	if nameOnly.IsZero() {
		t.Fatal("仅带名字也非零值")
	}
	if err := nameOnly.Validate(); err == nil {
		t.Fatal("info hash 全零应报错")
	}

	trackersOnly := Seed{Trackers: [][]string{{"http://t/announce"}}}
	if trackersOnly.IsZero() {
		t.Fatal("仅带 trackers（切片字段）也应判为非零")
	}
	// 仅 dht / peer 列表各判一次非零，确保每个字段都纳入判空。
	if (Seed{DhtNodes: []string{"1.1.1.1:1"}}).IsZero() {
		t.Fatal("仅带 dht 节点应判为非零")
	}
	if (Seed{PeerAddrs: []string{"1.1.1.1:1"}}).IsZero() {
		t.Fatal("仅带 peer 地址应判为非零")
	}

	valid := Seed{InfoHash: testHash(0x11), Trackers: [][]string{{"http://t/announce"}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("带合法 info hash 的种子不应报错: %v", err)
	}
}

func TestSeedKeyAndString(t *testing.T) {
	s := Seed{InfoHash: testHash(0xab), Name: "grp"}
	if got, want := s.Key(), strings.Repeat("ab", InfoHashLen); got != want {
		t.Fatalf("Key=%s，期望 %s", got, want)
	}
	if s.String() != "grp("+s.Key()+")" {
		t.Fatalf("带名 String 异常: %s", s.String())
	}
	noName := Seed{InfoHash: testHash(0x00)}
	noName.InfoHash[0] = 1
	if noName.String() != noName.Key() {
		t.Fatalf("无名 String 应等于 Key: %s", noName.String())
	}
}

func TestSeedFromInfoHashHex(t *testing.T) {
	s, err := SeedFromInfoHashHex(strings.Repeat("ab", InfoHashLen))
	if err != nil {
		t.Fatalf("合法 40 位 hex 应成功: %v", err)
	}
	if s.InfoHash != testHash(0xab) {
		t.Fatalf("解析出的 info hash 不符: %x", s.InfoHash)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("应通过校验: %v", err)
	}
	if _, err := SeedFromInfoHashHex("zz"); err == nil {
		t.Fatal("非 hex 应报错")
	}
	if _, err := SeedFromInfoHashHex("ab"); err == nil {
		t.Fatal("长度不足 40 位应报错")
	}
}

func TestParseSeedFromMagnet(t *testing.T) {
	ih := strings.Repeat("cd", InfoHashLen)
	uri := "magnet:?xt=urn:btih:" + ih +
		"&dn=mygroup&tr=http%3A%2F%2Ftracker%2Fannounce&x.pe=1.2.3.4%3A6881"
	s, err := ParseSeedFromMagnet(uri)
	if err != nil {
		t.Fatalf("解析磁力链失败: %v", err)
	}
	if s.InfoHash != testHash(0xcd) {
		t.Fatalf("info hash 不符: %x", s.InfoHash)
	}
	if s.Name != "mygroup" {
		t.Fatalf("展示名=%q，期望 mygroup", s.Name)
	}
	if len(s.Trackers) == 0 || s.Trackers[0][0] != "http://tracker/announce" {
		t.Fatalf("trackers 未解析: %+v", s.Trackers)
	}
	// x.pe 应作为初始端点。
	peers, _ := s.BootstrapPeers(1000)
	if len(peers) != 1 || peers[0].Addr != "1.2.3.4:6881" || peers[0].Origin != OriginSeed {
		t.Fatalf("x.pe 直连端点解析异常: %+v", peers)
	}
}

func TestSeedBootstrapDhtNodes(t *testing.T) {
	s := Seed{
		InfoHash: testHash(0x01),
		DhtNodes: []string{"5.5.5.5:6", "非法地址", "1.2.3.4"},
	}
	nodes := s.BootstrapDhtNodes()
	if len(nodes) != 1 {
		t.Fatalf("应只保留合法节点，实际 %+v", nodes)
	}
	if nodes[0] != "5.5.5.5:6" {
		t.Fatalf("节点规范化异常: %+v", nodes)
	}
}

// TestSeedHexRoundTrip 保证 Key 与 metainfo 主题一致（回归用）。
func TestSeedHexRoundTrip(t *testing.T) {
	h := testHash(0x7f)
	s := Seed{InfoHash: h}
	if _, err := hex.DecodeString(s.Key()); err != nil {
		t.Fatalf("Key 不是合法 hex: %v", err)
	}
}
