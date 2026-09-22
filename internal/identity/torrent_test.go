package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildTorrentStructure(t *testing.T) {
	data := make([]byte, 40000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	tr, err := BuildTorrent("group-test.json", data)
	if err != nil {
		t.Fatal(err)
	}
	root, err := bencDecodeMap(tr.Meta)
	if err != nil {
		t.Fatalf("root dict not decodable: %v", err)
	}
	if _, ok := root["announce"]; !ok {
		t.Fatal("missing announce key")
	}
	info, ok := root["info"].(map[string]any)
	if !ok {
		t.Fatalf("info not a dict: %T", root["info"])
	}
	if info["name"] != "group-test.json" {
		t.Fatalf("name = %v", info["name"])
	}
	if info["length"] != int64(len(data)) {
		t.Fatalf("length = %v", info["length"])
	}
	if info["piece length"] != int64(torrentPieceLength) {
		t.Fatalf("piece length = %v", info["piece length"])
	}
	if info["private"] != int64(1) {
		t.Fatalf("private = %v", info["private"])
	}
	pieces, ok := info["pieces"].(string)
	if !ok {
		t.Fatal("pieces not a string")
	}
	wantPieces := (len(data) + torrentPieceLength - 1) / torrentPieceLength
	if len(pieces) != wantPieces*sha1.Size {
		t.Fatalf("pieces len %d, want %d", len(pieces), wantPieces*sha1.Size)
	}
	// 第 0 块哈希正确性。
	if got := pieces[:sha1.Size]; !bytes.Equal([]byte(got), sha1Sum(data[:torrentPieceLength])) {
		t.Fatal("piece 0 hash mismatch")
	}
	// info_hash = sha1(info 的 bencode 原文)，且 Meta 内嵌同一份 info 字节。
	if !bytes.Contains(tr.Meta, tr.InfoBenc) {
		t.Fatal("meta does not embed info bytes verbatim")
	}
	if tr.InfoHash != sha1.Sum(tr.InfoBenc) {
		t.Fatal("info hash mismatch")
	}
	if tr.FileName() != "group-test.json" {
		t.Fatalf("FileName() = %q", tr.FileName())
	}
	if !strings.HasPrefix(tr.Magnet(), "magnet:?xt=urn:btih:") ||
		!strings.Contains(tr.Magnet(), hex.EncodeToString(tr.InfoHash[:])) {
		t.Fatalf("magnet malformed: %s", tr.Magnet())
	}
}

func TestBuildTorrentEmptyPayloadStillValid(t *testing.T) {
	tr, err := BuildTorrent("group.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := bencDecodeMap(tr.InfoBenc)
	if err != nil {
		t.Fatal(err)
	}
	if info["length"] != int64(0) {
		t.Fatalf("length = %v", info["length"])
	}
	pieces := info["pieces"].(string)
	// 空内容也应保留一个 piece：sha1("")。
	empty := sha1.Sum(nil)
	if pieces != string(empty[:]) {
		t.Fatalf("pieces = %x, want sha1(empty)", pieces)
	}
}

func TestBuildTorrentRequiresName(t *testing.T) {
	if _, err := BuildTorrent("", []byte("x")); err == nil {
		t.Fatal("empty torrent name must fail")
	}
}

func TestBencodeDictKeyOrder(t *testing.T) {
	tr, err := BuildTorrent("n", []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	root := string(tr.Meta)
	idxA := strings.Index(root, "8:announce")
	idxCB := strings.Index(root, "10:created by")
	idxCD := strings.Index(root, "13:creation date")
	idxInfo := strings.Index(root, "4:info")
	if idxA < 0 || idxA > idxCB || idxCB > idxCD || idxCD > idxInfo {
		t.Fatalf("root dict keys not in bencode sorted order: %q", root[:min(48, len(root))])
	}
	// info 内键序：length < name < piece length < pieces < private。
	if !strings.HasPrefix(string(tr.InfoBenc), "d6:length") {
		t.Fatalf("info dict does not start with d6:length: %q", tr.InfoBenc[:min(32, len(tr.InfoBenc))])
	}
	if !strings.HasSuffix(string(tr.InfoBenc), "7:privatei1ee") {
		t.Fatalf("info dict does not end with private: %q", tr.InfoBenc[len(tr.InfoBenc)-min(24, len(tr.InfoBenc)):])
	}
}
