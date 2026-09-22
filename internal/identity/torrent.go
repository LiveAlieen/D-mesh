package identity

import (
	"crypto/sha1"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strconv"

	"dmesh/internal/core"
)

// 种子（.torrent）在本设计里只是 BT swarm 的入场券：真实内容就是一份
// group.json（创世配置），发现层用它经 DHT/PEX 收集成员 IP:port。
// BuildTorrent 生成结构合法、可被标准 BT 客户端解析的单文件私有种子占位。

const torrentPieceLength = 16384

// Torrent 是生成出的占位种子字节与其元信息。
type Torrent struct {
	Meta     []byte   // 完整 .torrent 文件字节（bencode）
	InfoBenc []byte   // info 字典的 bencode 原文（info_hash 的哈希输入）
	InfoHash [20]byte // sha1(infoBenc)，即 DHT 中的 topic
	NumFiles int64    // 文件数（恒为 1）
	Length   int64    // 内容长度
}

// BuildTorrent 用 seedJSON（group.json 内容）构建 .torrent 占位。
// name 为种子内的文件名（如 "group-abc123.json"）。
func BuildTorrent(name string, seedJSON []byte) (*Torrent, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: torrent name empty", core.ErrMalformed)
	}
	info := bencMap{
		"length":       bencInt(len(seedJSON)),
		"name":         bencStr(name),
		"piece length": bencInt(torrentPieceLength),
		"pieces":       bencStr(concatPieceHashes(seedJSON)),
		"private":      bencInt(1),
	}
	infoBenc := info.bencEncode()
	root := bencMap{
		"announce":      bencStr(""), // 纯 DHT/PEX：无 tracker
		"created by":    bencStr("dmesh-tool"),
		"creation date": bencInt(0),
		"info":          bencRaw(infoBenc),
	}
	var ih [20]byte
	if len(infoBenc) == 0 {
		return nil, fmt.Errorf("identity: empty info dict")
	}
	ih = sha1.Sum(infoBenc)
	return &Torrent{
		Meta:     root.bencEncode(),
		InfoBenc: infoBenc,
		InfoHash: ih,
		NumFiles: 1,
		Length:   int64(len(seedJSON)),
	}, nil
}

// Magnet 返回磁力链（DHT 检索用）：magnet:?xt=urn:btih:<hex>&dn=<name>。
func (t *Torrent) Magnet() string {
	return fmt.Sprintf("magnet:?xt=urn:btih:%s&dn=%s",
		hexLower(t.InfoHash[:]), url.QueryEscape(t.FileName()))
}

// FileName 从 info 字典取文件名（best-effort，仅用于展示）。
func (t *Torrent) FileName() string {
	m, err := bencDecodeMap(t.InfoBenc)
	if err != nil {
		return ""
	}
	if s, ok := m["name"].(string); ok {
		return s
	}
	return ""
}

func concatPieceHashes(data []byte) []byte {
	n := (len(data) + torrentPieceLength - 1) / torrentPieceLength
	if n == 0 {
		n = 1 // 空内容也保留一个 piece（sha1 of ""），保证种子结构合法
	}
	out := make([]byte, 0, n*sha1.Size)
	var zero [torrentPieceLength]byte
	for i := 0; i < n; i++ {
		lo := i * torrentPieceLength
		hi := min(lo+torrentPieceLength, len(data))
		var chunk []byte
		if lo < len(data) {
			chunk = data[lo:hi]
		} else {
			chunk = zero[:0]
		}
		out = append(out, sha1Sum(chunk)...)
	}
	return out
}

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

// ---- 最小 bencode 实现（编码 + 解码 info/root，测试与发现层可复用）----

type bencData interface{ bencEncode() []byte }

type bencStr string

func (s bencStr) bencEncode() []byte {
	return append([]byte(strconv.Itoa(len(s))+":"), []byte(s)...)
}

type bencInt int64

func (i bencInt) bencEncode() []byte {
	return []byte("i" + strconv.FormatInt(int64(i), 10) + "e")
}

type bencRaw []byte // 已编码好的原文，直接嵌入

func (r bencRaw) bencEncode() []byte { return append([]byte(nil), r...) }

type bencMap map[string]bencData

func (m bencMap) bencEncode() []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // bencode 字典键必须字典序
	buf := []byte("d")
	for _, k := range keys {
		buf = append(buf, bencStr(k).bencEncode()...)
		buf = append(buf, m[k].bencEncode()...)
	}
	return append(buf, 'e')
}

func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xF])
	}
	return string(out)
}

// bencDecodeMap 解码一个 bencode 字典（'d'..'e'），返回 key→值。
// 值映射：string→string、int→int64、list→[]any、嵌套 dict→map[string]any、
// 其余原始字节保留为 []byte。仅覆盖种子文件所需子集。
func bencDecodeMap(data []byte) (map[string]any, error) {
	v, rest, err := bencDecode(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing bencode data", core.ErrMalformed)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not a bencode dict", core.ErrMalformed)
	}
	return m, nil
}

func bencDecode(data []byte) (any, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%w: unexpected end of bencode", core.ErrMalformed)
	}
	switch data[0] {
	case 'd':
		return bencDecodeDict(data[1:])
	case 'l':
		return bencDecodeList(data[1:])
	case 'i':
		return bencDecodeInt(data[1:])
	default:
		return bencDecodeStr(data)
	}
}

func bencDecodeDict(data []byte) (any, []byte, error) {
	m := map[string]any{}
	for {
		if len(data) == 0 {
			return nil, nil, fmt.Errorf("%w: unterminated bencode dict", core.ErrMalformed)
		}
		if data[0] == 'e' {
			return m, data[1:], nil
		}
		k, rest, err := bencDecodeStr(data)
		if err != nil {
			return nil, nil, err
		}
		key, ok := k.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%w: bencode dict key not a string", core.ErrMalformed)
		}
		v, rest2, err := bencDecode(rest)
		if err != nil {
			return nil, nil, err
		}
		m[key] = v
		data = rest2
	}
}

func bencDecodeList(data []byte) (any, []byte, error) {
	out := []any{}
	for {
		if len(data) == 0 {
			return nil, nil, fmt.Errorf("%w: unterminated bencode list", core.ErrMalformed)
		}
		if data[0] == 'e' {
			return out, data[1:], nil
		}
		v, rest, err := bencDecode(data)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
		data = rest
	}
}

func bencDecodeInt(data []byte) (any, []byte, error) {
	i := 0
	for i < len(data) && data[i] != 'e' {
		i++
	}
	if i >= len(data) {
		return nil, nil, fmt.Errorf("%w: unterminated bencode int", core.ErrMalformed)
	}
	n, ok := new(big.Int).SetString(string(data[:i]), 10)
	if !ok {
		return nil, nil, fmt.Errorf("%w: bad bencode int %q", core.ErrMalformed, data[:i])
	}
	return n.Int64(), data[i+1:], nil
}

func bencDecodeStr(data []byte) (any, []byte, error) {
	i := 0
	for i < len(data) && data[i] >= '0' && data[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(data) || data[i] != ':' {
		return nil, nil, fmt.Errorf("%w: bad bencode string header", core.ErrMalformed)
	}
	n, err := strconv.Atoi(string(data[:i]))
	if err != nil || n < 0 || i+1+n > len(data) {
		return nil, nil, fmt.Errorf("%w: bad bencode string length", core.ErrMalformed)
	}
	return string(data[i+1 : i+1+n]), data[i+1+n:], nil
}
