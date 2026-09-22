package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"testing"

	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

// TestTorrentParseableByAnacrolix 用发现层真正会用的 anacrolix 解析器验证
// .torrent 占位是「可用」的：MetaInfo 可解、info 可解、info_hash 一致、
// 每个 piece 哈希与内容自洽。
func TestTorrentParseableByAnacrolix(t *testing.T) {
	data := make([]byte, 33333)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	tr, err := BuildTorrent("group-anacrolix.json", data)
	if err != nil {
		t.Fatal(err)
	}
	var mi metainfo.MetaInfo
	if err := bencode.Unmarshal(tr.Meta, &mi); err != nil {
		t.Fatalf("anacrolix bencode cannot parse our .torrent: %v", err)
	}
	if !bytes.Equal(mi.InfoBytes, tr.InfoBenc) {
		t.Fatal("anacrolix decoded different info bytes (bencode embedding broken)")
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		t.Fatalf("info dict not upconvertable: %v", err)
	}
	if info.Name != "group-anacrolix.json" || info.Length != int64(len(data)) {
		t.Fatalf("info fields wrong: name=%q length=%d", info.Name, info.Length)
	}
	if info.PieceLength != torrentPieceLength {
		t.Fatalf("piece length %d", info.PieceLength)
	}
	if info.Private == nil || !*info.Private {
		t.Fatal("private flag must be set (纯 DHT/PEX)")
	}
	if want := (len(data) + torrentPieceLength - 1) / torrentPieceLength; info.NumPieces() != want {
		t.Fatalf("NumPieces %d, want %d", info.NumPieces(), want)
	}
	if mi.HashInfoBytes().HexString() != hexLower(tr.InfoHash[:]) {
		t.Fatalf("anacrolix info hash %s != ours %s",
			mi.HashInfoBytes().HexString(), hexLower(tr.InfoHash[:]))
	}
	// 逐 piece 校验：anacrolix 读到的 pieces 必须就是内容 sha1。
	wantPieces := make([]byte, 0, info.NumPieces()*sha1.Size)
	for i := 0; i < len(data); i += torrentPieceLength {
		hi := min(i+torrentPieceLength, len(data))
		wantPieces = append(wantPieces, sha1Sum(data[i:hi])...)
	}
	if !bytes.Equal(info.Pieces, wantPieces) {
		t.Fatal("pieces do not match content hashes")
	}
}
