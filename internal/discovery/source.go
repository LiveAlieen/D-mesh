package discovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Mode 是一个源所使用的发现通路。
type Mode int

const (
	// ModeFull：DHT + PEX 双通路（默认，anacrolix swarm）。
	ModeFull Mode = iota
	// ModeDHTOnly：退化通路——关掉 PEX，只靠 DHT 的 get_peers/announce。
	// PEX 不生效（NAT 后握手不成、对端不支持扩展）时由 Manager 自动启用。
	ModeDHTOnly
)

// String 供日志与源命名使用。
func (m Mode) String() string {
	switch m {
	case ModeFull:
		return "dht+pex"
	case ModeDHTOnly:
		return "dht-only"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

// Source 是「某个种子的 peer 来源」抽象。真实实现是 anacrolix swarm（DHT+PEX），
// 单测里注入 mock 即可完全离线地验证去重、合并、退化与滚雪球回灌逻辑。
//
// Fetch 是拉模型：返回该源当前已知的全部端点（可反复调用，Manager 轮询它）。
// 实现必须并发安全，并在 ctx 取消时尽快返回。
type Source interface {
	// Name 是源标识（如 "swarm/dht+pex"），用于日志与 Status.Sources。
	Name() string
	// Fetch 返回当前已知端点（地址应已规范化；未带 LastSeen 的由容器补时钟）。
	Fetch(ctx context.Context) ([]Peer, error)
	// Close 释放底层资源（连接、监听端口）。重复调用应无害。
	Close() error
}

// Feeder 是可选接口：源愿意接收「别处发现的端点」并主动去勾搭，从而形成滚雪球
// （新发现的 peer 又能从它那里带出更多 peer）。Manager 每轮把全量列表回灌一次。
type Feeder interface {
	Feed(peers []Peer) int // 返回新接受的条数
}

// SourceFactory 为一个种子按通路造一个源。真实实现见 NewSwarmFactory；
// 测试注入自己的实现即可离线驱动 Manager。
type SourceFactory func(seed Seed, mode Mode) (Source, error)

// ErrSourceClosed 表示源已关闭，Fetch 不再工作。
var ErrSourceClosed = errors.New("discovery: source closed")

// FuncSource 把「函数 + 关闭钩子」包装成 Source（测试、临时源用）。
type FuncSource struct {
	NameStr string
	FetchFn func(ctx context.Context) ([]Peer, error)
	CloseFn func() error

	mu     sync.Mutex
	closed bool
}

// NewFuncSource 建一个函数源。name 为空时用 "func"。
func NewFuncSource(name string, fetch func(ctx context.Context) ([]Peer, error)) *FuncSource {
	if name == "" {
		name = "func"
	}
	return &FuncSource{NameStr: name, FetchFn: fetch}
}

// Name 实现 Source。
func (s *FuncSource) Name() string { return s.NameStr }

// Fetch 实现 Source。
func (s *FuncSource) Fetch(ctx context.Context) ([]Peer, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrSourceClosed
	}
	if s.FetchFn == nil {
		return nil, nil
	}
	return s.FetchFn(ctx)
}

// Close 实现 Source。
func (s *FuncSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	fn := s.CloseFn
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

// Closed 报告源是否已关闭。
func (s *FuncSource) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// MultiSource 把多个源并成一个源：Fetch 结果按地址去重合并（保留来源权重高的），
// 任一子源报错不影响其余结果（错误经 errors.Join 汇总返回，Manager 记日志但继续采纳）。
// 它本身也是纯逻辑，可直接单测。
type MultiSource struct {
	name string
	mu   sync.Mutex
	srcs []Source
}

// NewMultiSource 组合若干源为一个源。name 为空时用 "multi"。
func NewMultiSource(name string, srcs ...Source) *MultiSource {
	return &MultiSource{name: orDefault(name, "multi"), srcs: append([]Source(nil), srcs...)}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Add 追加子源（并发安全；用于运行期挂上退化通路）。
func (m *MultiSource) Add(s Source) {
	m.mu.Lock()
	m.srcs = append(m.srcs, s)
	m.mu.Unlock()
}

// Name 实现 Source。
func (m *MultiSource) Name() string { return m.name }

// Sources 返回子源名字列表（稳定顺序，日志用）。
func (m *MultiSource) Sources() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.srcs))
	for _, s := range m.srcs {
		out = append(out, s.Name())
	}
	sort.Strings(out)
	return out
}

// Fetch 实现 Source：拉取所有子源并合并去重。
func (m *MultiSource) Fetch(ctx context.Context) ([]Peer, error) {
	m.mu.Lock()
	srcs := append([]Source(nil), m.srcs...)
	m.mu.Unlock()

	set := NewPeerSet(0, 0)
	var errs []error
	for _, s := range srcs {
		ps, err := s.Fetch(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
		set.AddAll(ps)
	}
	return set.Snapshot(), errors.Join(errs...)
}

// Feed 实现 Feeder：把端点全量回灌给所有实现了 Feeder 的子源，返回总接收条数。
func (m *MultiSource) Feed(peers []Peer) int {
	m.mu.Lock()
	srcs := append([]Source(nil), m.srcs...)
	m.mu.Unlock()
	n := 0
	for _, s := range srcs {
		if f, ok := s.(Feeder); ok {
			n += f.Feed(peers)
		}
	}
	return n
}

// Close 实现 Source：关闭全部子源并汇总错误。
func (m *MultiSource) Close() error {
	m.mu.Lock()
	srcs := m.srcs
	m.srcs = nil
	m.mu.Unlock()
	var errs []error
	for _, s := range srcs {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}
