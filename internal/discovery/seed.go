package discovery

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anacrolix/torrent/metainfo"
)

// InfoHashLen 是 BT v1 info hash 的字节数（sha1），也就是 DHT/PEX 里标识 swarm 的主题长度。
const InfoHashLen = 20

// Seed 是发现层的输入：一个 BT 主题（种子/磁力链的 info hash）+ 可用的 bootstrap 线索。
//
// 注意：种子内容的真伪（重算 group_id + 验 creator_sig）不由本层判定，
// 那是 group/tools 的职责；本层只把 InfoHash 当作「哪个 swarm」的查询主题。
type Seed struct {
	// InfoHash 是 torrent 的 v1 info hash：DHT get_peers / announce 与 PEX 的主题。
	InfoHash [InfoHashLen]byte `json:"info_hash"`
	// Name 是种子里的展示名（group.json 的文件名或 torrent name），仅用于日志。
	Name string `json:"name,omitempty"`
	// Trackers 是 announce-list（BEP 12），分层列表，空表示纯 DHT 发现。
	Trackers [][]string `json:"trackers,omitempty"`
	// DhtNodes 是种子自带的 DHT 节点（BEP 5），可作为 bootstrap 候选。
	DhtNodes []string `json:"dht_nodes,omitempty"`
	// PeerAddrs 是种子/磁力链自带的直连地址（BEP 9 的 x.pe），作为初始端点。
	PeerAddrs []string `json:"peer_addrs,omitempty"`
}

// Key 返回 info hash 的 hex，用于 map 键与日志。
func (s Seed) Key() string { return hex.EncodeToString(s.InfoHash[:]) }

// IsZero 报告种子是否为空主题（未填任何字段）。Seed 含切片字段（Trackers 等）
// 不可用 == 直接比较，这里逐字段判空：全零 info hash 无意义，且各列表/名字皆空。
func (s Seed) IsZero() bool {
	var zero [InfoHashLen]byte
	return s.InfoHash == zero && s.Name == "" &&
		len(s.Trackers) == 0 && len(s.DhtNodes) == 0 && len(s.PeerAddrs) == 0
}

// String 供日志使用。
func (s Seed) String() string {
	if s.Name != "" {
		return fmt.Sprintf("%s(%s)", s.Name, s.Key())
	}
	return s.Key()
}

// Validate 报告主题是否可用。
func (s Seed) Validate() error {
	if s.IsZero() {
		return fmt.Errorf("discovery: empty seed")
	}
	var zero [InfoHashLen]byte
	if s.InfoHash == zero {
		return fmt.Errorf("discovery: seed info hash is all zero")
	}
	return nil
}

// BootstrapPeers 把种子自带的直连地址（x.pe）转成端点，作为第一轮候选。
// 非法地址被跳过（第一条错误一并返回，便于调用方记日志但不必中断）。
func (s Seed) BootstrapPeers(now int64) ([]Peer, error) {
	return ParsePeers(s.PeerAddrs, OriginSeed, now)
}

// BootstrapDhtNodes 把 DhtNodes 转成规范化地址（transport 无关，仅作 bootstrap 用）。
func (s Seed) BootstrapDhtNodes() []string {
	out := make([]string, 0, len(s.DhtNodes))
	for _, n := range s.DhtNodes {
		if norm, err := NormalizeAddr(n); err == nil {
			out = append(out, norm)
		}
	}
	return out
}

// LoadSeedFile 从磁盘读取 .torrent 种子并解析出主题。
func LoadSeedFile(path string) (Seed, error) {
	f, err := os.Open(path)
	if err != nil {
		return Seed{}, fmt.Errorf("discovery: open seed: %w", err)
	}
	defer f.Close()
	seed, err := LoadSeed(f)
	if err != nil {
		return Seed{}, fmt.Errorf("discovery: seed %s: %w", path, err)
	}
	return seed, nil
}

// LoadSeed 从 bencode 流（.torrent 内容）解析种子主题。要求 info 段存在（否则没有主题）。
func LoadSeed(r io.Reader) (Seed, error) {
	mi, err := metainfo.Load(r)
	if err != nil {
		return Seed{}, fmt.Errorf("discovery: parse seed: %w", err)
	}
	return seedFromMetaInfo(mi)
}

func seedFromMetaInfo(mi *metainfo.MetaInfo) (Seed, error) {
	if len(mi.InfoBytes) == 0 {
		return Seed{}, fmt.Errorf("discovery: seed has no info section (no swarm topic)")
	}
	h := mi.HashInfoBytes()
	s := Seed{
		InfoHash: [InfoHashLen]byte(h),
		Trackers: [][]string(mi.AnnounceList),
	}
	if len(s.Trackers) == 0 && mi.Announce != "" {
		s.Trackers = [][]string{{mi.Announce}}
	}
	for _, n := range mi.Nodes {
		s.DhtNodes = append(s.DhtNodes, string(n))
	}
	if info, err := mi.UnmarshalInfo(); err == nil {
		s.Name = info.BestName()
	}
	return s, s.Validate()
}

// ParseSeedFromMagnet 解析磁力链（urn:btih:<hex|base32>），取主题、tr 与 x.pe。
// 磁力链没有 DHT 节点信息，需要靠公共节点 bootstrap。
func ParseSeedFromMagnet(uri string) (Seed, error) {
	m, err := metainfo.ParseMagnetUri(uri)
	if err != nil {
		return Seed{}, fmt.Errorf("discovery: parse magnet: %w", err)
	}
	s := Seed{
		InfoHash: [InfoHashLen]byte(m.InfoHash),
		Name:     m.DisplayName,
	}
	var tiers [][]string
	for _, tr := range m.Trackers {
		tr = strings.TrimSpace(tr)
		if tr != "" {
			tiers = append(tiers, []string{tr})
		}
	}
	s.Trackers = tiers
	s.PeerAddrs = append(s.PeerAddrs, m.Params["x.pe"]...) // BEP 9
	return s, s.Validate()
}

// SeedFromInfoHashHex 用裸 info hash（40 位 hex）构造种子——用于「只有群 id 对应主题」
// 的调试路径（dmesh-tool 可直接打印种子 info hash）。
func SeedFromInfoHashHex(hexStr string) (Seed, error) {
	var h metainfo.Hash
	if err := h.FromHexString(strings.TrimSpace(hexStr)); err != nil {
		return Seed{}, fmt.Errorf("discovery: bad info hash %q: %w", hexStr, err)
	}
	s := Seed{InfoHash: [InfoHashLen]byte(h)}
	return s, s.Validate()
}
