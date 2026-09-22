package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/anacrolix/dht/v2"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

// SwarmConfig 是真实网络源（anacrolix torrent swarm）的参数。零值即可用：
// 随机监听端口、启用 DHT 与 PEX、启用 tracker（种子带 announce 时才起作用）、
// 不做 UPnP 端口映射、不写任何文件数据。
type SwarmConfig struct {
	// ListenPort 是 ModeFull swarm 的 BT/uTP 监听端口；0 表示让系统分配空闲端口。
	// 退化通路（ModeDHTOnly）另起一个 client，端口取 ListenPort+1（为 0 时同样随机）。
	ListenPort int
	// PortForwarding 置 true 才允许 anacrolix 尝试 UPnP 映射（默认关：发现层不需要）。
	PortForwarding bool
	// DisableTrackers 置 true 后只用 DHT（种子即使带 announce 也不去问）。
	DisableTrackers bool
	// DisableUTP / DisableTCP 关掉对应传输（默认都开，uTP 对 NAT 更友好）。
	DisableUTP bool
	DisableTCP bool
	// BootstrapNodes 覆盖 DHT 起始节点（"host:port"）。空则用 anacrolix 内置公共节点。
	BootstrapNodes []string
	// ConnsPerTorrent 是每个 swarm 主题维持的 BT 连接上限（PEX 靠这些连接扩散）。
	// <=0 用 DefaultConnsPerTorrent。
	ConnsPerTorrent int
	// NoPeriodicAnnounce 置 true 后只在加入 swarm 时 announce 一次，不周期性重announce。
	NoPeriodicAnnounce bool
	// Logger 接收 anacrolix 内部日志；nil 时全部丢弃（TUI 可传自己的 slog.Logger）。
	Logger *slog.Logger
}

// DefaultConnsPerTorrent 是发现层默认的每主题 BT 连接上限：PEX 通过连接扩散，
// 少量连接即可滚起雪球，太多会挤占本机带宽与邻居层的连接预算。
const DefaultConnsPerTorrent = 25

// SwarmFactory 用 anacrolix/torrent + anacrolix/dht 实现 SourceFactory：
// 同一 Mode 下所有种子共享一个 swarm client（一个监听端口），每个种子对应一个
// torrent 主题，只做 announce/get_peers/PEX，不参与文件传输。
//
// 它是 discovery.Config.Factory / DegradeFactory 的生产实现：
//
//	f, _ := discovery.NewSwarmFactory(discovery.SwarmConfig{})
//	m, _ := discovery.New(discovery.Config{Factory: f.Source})
type SwarmFactory struct {
	cfg SwarmConfig

	mu     sync.Mutex
	swarms map[Mode]*swarm
	closed bool
}

// NewSwarmFactory 建工厂。此刻不打开任何端口——第一次为该 Mode 造源时才懒启动 client，
// 这样只 Track 一个 mock 源的测试不会碰网络。
func NewSwarmFactory(cfg SwarmConfig) (*SwarmFactory, error) {
	if cfg.ConnsPerTorrent <= 0 {
		cfg.ConnsPerTorrent = DefaultConnsPerTorrent
	}
	if len(cfg.BootstrapNodes) > 0 {
		if _, err := parseDhtAddrs(cfg.BootstrapNodes); err != nil {
			return nil, err
		}
	}
	return &SwarmFactory{cfg: cfg, swarms: make(map[Mode]*swarm)}, nil
}

// Source 实现 SourceFactory：为种子在指定通路上加入 swarm 并返回可读源。
func (f *SwarmFactory) Source(seed Seed, mode Mode) (Source, error) {
	if err := seed.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, ErrClosed
	}
	sw := f.swarms[mode]
	if sw == nil {
		sw = &swarm{cfg: f.cfg, mode: mode, torrents: make(map[[InfoHashLen]byte]*torrent.Torrent)}
		f.swarms[mode] = sw
	}
	f.mu.Unlock()

	ts, err := sw.torrentFor(context.Background(), seed)
	if err != nil {
		return nil, err
	}
	return &swarmSource{sw: sw, ts: ts, seed: seed, name: "swarm/" + mode.String()}, nil
}

// Close 关闭全部 swarm client（每个 Mode 一个），之后 Source 报废。
func (f *SwarmFactory) Close() error {
	f.mu.Lock()
	swarms := make([]*swarm, 0, len(f.swarms))
	for mode, sw := range f.swarms {
		swarms = append(swarms, sw)
		delete(f.swarms, mode)
	}
	f.closed = true
	f.mu.Unlock()
	var errs []error
	for _, sw := range swarms {
		if err := sw.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// swarm 是一个 anacrolix torrent client 的包装：按 Mode 建一次，供多种子共享。
type swarm struct {
	cfg  SwarmConfig
	mode Mode

	mu       sync.Mutex
	cl       *torrent.Client
	torrents map[[InfoHashLen]byte]*torrent.Torrent
	closed   bool
}

// listenPort 给两种通路分配互不冲突的监听端口（0 表示随机）。
func (s *swarm) listenPort() int {
	if s.cfg.ListenPort <= 0 {
		return 0
	}
	if s.mode == ModeDHTOnly {
		return s.cfg.ListenPort + 1
	}
	return s.cfg.ListenPort
}

// client 懒启动底层 client。
func (s *swarm) client() (*torrent.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.cl != nil {
		return s.cl, nil
	}
	cc := torrent.NewDefaultClientConfig()
	cc.ListenPort = s.listenPort()
	cc.NoDefaultPortForwarding = !s.cfg.PortForwarding
	cc.DisablePEX = s.mode == ModeDHTOnly // 退化通路：只靠 DHT get_peers/announce
	cc.DisableTrackers = s.cfg.DisableTrackers
	cc.DisableUTP = s.cfg.DisableUTP
	cc.DisableTCP = s.cfg.DisableTCP
	cc.NoDHT = false // 发现层的主动脉，永不关
	cc.EstablishedConnsPerTorrent = s.cfg.ConnsPerTorrent
	cc.PeriodicallyAnnounceTorrentsToDht = !s.cfg.NoPeriodicAnnounce
	// 本层不做文件传输：数据一律挂 discard 存储，绝不落盘。
	cc.DataDir = ""
	cc.DefaultStorage = discardStorage{}
	cc.Slogger = orDefaultLogger(s.cfg.Logger)
	if len(s.cfg.BootstrapNodes) > 0 {
		addrs, err := parseDhtAddrs(s.cfg.BootstrapNodes)
		if err != nil {
			return nil, err
		}
		cc.DhtStartingNodes = func(string) dht.StartingNodesGetter {
			return func() ([]dht.Addr, error) { return addrs, nil }
		}
	}
	cl, err := torrent.NewClient(cc)
	if err != nil {
		return nil, fmt.Errorf("discovery: start swarm client (%s): %w", s.mode, err)
	}
	s.cl = cl
	return cl, nil
}

// torrentFor 把种子加入 client（幂等：同 info hash 复用）。
func (s *swarm) torrentFor(ctx context.Context, seed Seed) (*torrent.Torrent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cl, err := s.client()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts, ok := s.torrents[seed.InfoHash]; ok {
		return ts, nil
	}
	spec := &torrent.TorrentSpec{
		Trackers:    seed.Trackers,
		DisplayName: seed.Name,
		DhtNodes:    seed.BootstrapDhtNodes(),
		PeerAddrs:   append([]string(nil), seed.PeerAddrs...),
	}
	spec.InfoHash = metainfo.Hash(seed.InfoHash)
	// 不下载也不上传任何 piece：只保留发现通路。
	spec.DisallowDataDownload = true
	spec.DisallowDataUpload = true
	spec.DisableInitialPieceCheck = true
	ts, _, err := cl.AddTorrentSpec(spec)
	if err != nil {
		return nil, fmt.Errorf("discovery: join swarm %s: %w", seed, err)
	}
	s.torrents[seed.InfoHash] = ts
	return ts, nil
}

// removeTorrent 从 client 里丢掉一个主题（源关闭时调用）。
func (s *swarm) removeTorrent(ih [InfoHashLen]byte) {
	s.mu.Lock()
	ts, ok := s.torrents[ih]
	if ok {
		delete(s.torrents, ih)
	}
	s.mu.Unlock()
	if ok {
		ts.Drop()
	}
}

// Close 关闭底层 client。
func (s *swarm) Close() error {
	s.mu.Lock()
	cl := s.cl
	s.cl = nil
	s.closed = true
	s.torrents = map[[InfoHashLen]byte]*torrent.Torrent{}
	s.mu.Unlock()
	if cl == nil {
		return nil
	}
	errs := cl.Close()
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("discovery: close swarm client: %w", errors.Join(errs...))
}

// swarmSource 是真实网络源：一个 (client, torrent 主题) 对的只读视图。
type swarmSource struct {
	sw   *swarm
	ts   *torrent.Torrent
	seed Seed
	name string
}

// Name 实现 Source。
func (x *swarmSource) Name() string { return x.name }

// Seed 返回该源绑定的种子。
func (x *swarmSource) Seed() Seed { return x.seed }

// Fetch 实现 Source：取 swarm 当前已知的所有端点（DHT get_peers 回包、PEX 扩展消息、
// tracker 回包、种子自带地址都在内），映射成本包的 Source 后返回。
//
// anacrolix 内部已按地址去重，这里再过一遍 PeerSet 只是为了规范化地址与来源。
func (x *swarmSource) Fetch(ctx context.Context) ([]Peer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	known := x.ts.KnownSwarm()
	now := defaultNow()
	out := make([]Peer, 0, len(known))
	for _, pi := range known {
		if pi.Addr == nil {
			continue
		}
		p, err := NewPeer(pi.Addr.String(), mapPeerSource(pi.Source), now)
		if err != nil {
			continue // 非法/无法解析的地址直接忽略
		}
		out = append(out, p)
	}
	return out, nil
}

// Feed 实现 Feeder：把发现层已知的端点回灌给 swarm，让它主动去连，从而从新对端的
// PEX 列表里带出更多成员（滚雪球）。返回 swarm 实际新增的条数。
func (x *swarmSource) Feed(peers []Peer) int {
	infos := make([]torrent.PeerInfo, 0, len(peers))
	for _, p := range peers {
		if pi, ok := peerInfoFromPeer(p); ok {
			infos = append(infos, pi)
		}
	}
	if len(infos) == 0 {
		return 0
	}
	return x.ts.AddPeers(infos)
}

// Close 实现 Source：只把本主题从 swarm 里摘掉，client 留给同 Mode 的其它源继续用。
func (x *swarmSource) Close() error {
	x.sw.removeTorrent(x.seed.InfoHash)
	return nil
}

// peerInfoFromPeer 把本包端点转成 anacrolix 的 PeerInfo（回灌用）。
// 地址用 StringAddr 承载规范化后的 "ip:port"，来源记为 Direct（我们主动给的）。
func peerInfoFromPeer(p Peer) (torrent.PeerInfo, bool) {
	norm, err := NormalizeAddr(p.Addr)
	if err != nil {
		return torrent.PeerInfo{}, false
	}
	return torrent.PeerInfo{
		Addr:   torrent.StringAddr(norm),
		Source: torrent.PeerSourceDirect,
	}, true
}

// peerInfoToPeer 是反向映射（单测覆盖，环回地址即可，不碰网络）。
func peerInfoToPeer(pi torrent.PeerInfo, now int64) (Peer, bool) {
	if pi.Addr == nil {
		return Peer{}, false
	}
	p, err := NewPeer(pi.Addr.String(), mapPeerSource(pi.Source), now)
	if err != nil {
		return Peer{}, false
	}
	return p, true
}

// mapPeerSource 把 anacrolix 的来源码映射到本包 Source。
// 未知码归 OriginUnknown（仍会输出，只是权重最低）。
func mapPeerSource(src torrent.PeerSource) Origin {
	switch string(src) {
	case torrent.PeerSourcePex:
		return OriginPEX
	case torrent.PeerSourceDhtGetPeers, torrent.PeerSourceDhtAnnouncePeer, torrent.PeerSourceUtHolepunch:
		return OriginDHT
	case torrent.PeerSourceTracker:
		return OriginTracker
	case torrent.PeerSourceDirect:
		return OriginSeed
	case torrent.PeerSourceIncoming:
		return OriginPEX // 对端主动连进来并上报了这个主题，等价于 PEX 通路有效
	default:
		return OriginUnknown
	}
}

// parseDhtAddrs 把 "host:port" 列表解析成 dht.Addr（bootstrap 用）；非法条目报错。
func parseDhtAddrs(nodes []string) ([]dht.Addr, error) {
	out := make([]dht.Addr, 0, len(nodes))
	for _, n := range nodes {
		host, portStr, err := net.SplitHostPort(n)
		if err != nil {
			return nil, fmt.Errorf("discovery: bad dht node %q: %w", n, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("discovery: bad dht node port %q", n)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// bootstrap 节点常写成域名，交给 anacrolix 使用时先解析。
			addrs, err := net.LookupIP(host)
			if err != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("discovery: cannot resolve dht node %q", n)
			}
			ip = addrs[0]
		}
		out = append(out, dht.NewAddr(&net.UDPAddr{IP: ip, Port: port}))
	}
	return out, nil
}

func orDefaultLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// discardStorage 是「绝不落盘」的 anacrolix 存储后端：发现层不传输文件，
// 任何 piece 读写请求都被丢弃，Completion 永远报告「未完成、无错误」。
type discardStorage struct{}

func (discardStorage) OpenTorrent(
	_ context.Context, _ *metainfo.Info, _ metainfo.Hash,
) (storage.TorrentImpl, error) {
	return storage.TorrentImpl{
		Piece: func(metainfo.Piece) storage.PieceImpl { return discardPiece{} },
		Close: func() error { return nil },
	}, nil
}

type discardPiece struct{}

func (discardPiece) ReadAt(b []byte, _ int64) (int, error) { return 0, io.EOF }
func (discardPiece) WriteAt(b []byte, _ int64) (int, error) {
	return len(b), nil
}
func (discardPiece) MarkComplete() error    { return nil }
func (discardPiece) MarkNotComplete() error { return nil }
func (discardPiece) Completion() storage.Completion {
	return storage.Completion{Complete: false, Ok: true}
}
