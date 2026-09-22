package discovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// 默认调度参数。
const (
	// DefaultPollInterval 是拉取各源端点列表的间隔。
	DefaultPollInterval = 2 * time.Second
	// DefaultDegradeAfter 是「PEX 零产出」多久后判定 PEX 通路不生效并挂上纯 DHT 退化源。
	// 取 30s：够一次 DHT announce 加若干轮 PEX 交换。
	DefaultDegradeAfter = 30 * time.Second
)

// Config 是 Manager 的装配参数。除 Factory 必填外零值可用，字段为 0 时取上面的默认值。
type Config struct {
	// Factory 必填：为一个种子按通路造源。真实实现是 (*SwarmFactory).Source；
	// 测试注入 mock 源即可离线跑完整套调度逻辑。
	Factory SourceFactory
	// DegradeFactory 可选：覆盖退化通路（ModeDHTOnly）的造源方式；nil 时复用 Factory。
	DegradeFactory SourceFactory
	// PollInterval 轮询间隔；<=0 用 DefaultPollInterval。
	PollInterval time.Duration
	// DegradeAfter PEX 失效判据窗口；<=0 用 DefaultDegradeAfter。
	DegradeAfter time.Duration
	// PeerTTL 端点保鲜期；0 表示不过期（见 DefaultPeerTTL）。
	PeerTTL time.Duration
	// MaxPeers 单种子端点上限；<=0 用 DefaultMaxPeers。
	MaxPeers int
	// NoSnowball 置 true 时不把已发现端点回灌给源（默认回灌，滚雪球加速收敛）。
	NoSnowball bool
	// OnPeers 增量回调：每轮把首次出现的端点交给调用方（transport/neighbor 挂这里）。
	// 在 Manager 锁外调用，回调里可安全再调 Manager 的读方法。
	OnPeers func(seed Seed, added []Peer)
	// OnError 源报错回调（含退化过程中造源失败）；nil 时错误只由 PollOnce/Run 返回。
	OnError func(seed Seed, source string, err error)
	// Clock 返回 Unix 毫秒，测试可注入假时钟；nil 用 time.Now。
	Clock func() int64
}

func (c *Config) withDefaults() error {
	if c.Factory == nil {
		return errors.New("discovery: Config.Factory is required")
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.DegradeAfter <= 0 {
		c.DegradeAfter = DefaultDegradeAfter
	}
	if c.MaxPeers <= 0 {
		c.MaxPeers = DefaultMaxPeers
	}
	if c.Clock == nil {
		c.Clock = defaultNow
	}
	if c.DegradeFactory == nil {
		c.DegradeFactory = c.Factory
	}
	return nil
}

// Status 是单个种子的发现状态快照。
type Status struct {
	Seed     Seed           `json:"seed"`
	Peers    int            `json:"peers"`     // 当前保留的端点数
	ByOrigin map[Origin]int `json:"by_source"` // 各来源端点数分布（PEX 是否生效看这里）
	Sources  []string       `json:"sources"`   // 活动中的源名
	Degraded bool           `json:"degraded"`  // 是否已退化到纯 DHT get_peers
	AddedAt  int64          `json:"added_at"`  // 开始跟踪时间（Unix 毫秒）
	LastErr  string         `json:"last_err,omitempty"`
}

// seedState 是 Manager 内部按主题（info hash）维护的跟踪记录。
// 字段由 Manager 的 mu 保护；set 自带锁，可在锁外读写。
type seedState struct {
	seed     Seed
	set      *PeerSet
	addedAt  int64
	degraded bool
	sources  []Source // 活动源（退化后追加 DHT-only 源）
	lastErr  string
}

func (st *seedState) copySources() []Source {
	out := make([]Source, len(st.sources))
	copy(out, st.sources)
	return out
}

// Manager 是发现层的调度器：跟踪多个种子 → 轮询 DHT+PEX 源 → 去重合并 →
// 增量回调或轮询读取 → PEX 不生效时自动挂上纯 DHT 退化源 → 把全量列表回灌以滚雪球。
//
// 所有方法可并发调用。Run 没启动时，调用方也可自己按节奏调 PollOnce（TUI 事件循环、测试）。
type Manager struct {
	cfg Config

	mu       sync.Mutex
	states   map[[InfoHashLen]byte]*seedState
	running  bool
	closed   bool
	closeErr error
	doneCh   chan struct{}
}

// New 装配 Manager。cfg.Factory 为空时报错，其余字段取默认值。
func New(cfg Config) (*Manager, error) {
	if err := cfg.withDefaults(); err != nil {
		return nil, err
	}
	return &Manager{
		cfg:    cfg,
		states: make(map[[InfoHashLen]byte]*seedState),
		doneCh: make(chan struct{}),
	}, nil
}

// Track 开始跟踪一个种子：立刻以 ModeFull 造源，并把种子自带的直连地址作为初始端点。
// 幂等——同一 info hash 重复 Track 只补注入端点，不重建源。
func (m *Manager) Track(seed Seed) error {
	if err := seed.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if st, ok := m.states[seed.InfoHash]; ok {
		m.mu.Unlock()
		m.injectBootstrap(st, seed)
		return nil
	}
	src, err := m.cfg.Factory(seed, ModeFull)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("discovery: start source for %s: %w", seed, err)
	}
	st := &seedState{
		seed:    seed,
		set:     NewPeerSet(m.cfg.MaxPeers, m.cfg.PeerTTL),
		addedAt: m.cfg.Clock(),
		sources: []Source{src},
	}
	st.set.SetClock(m.cfg.Clock)
	m.states[seed.InfoHash] = st
	m.mu.Unlock()

	m.injectBootstrap(st, seed)
	return nil
}

// injectBootstrap 把种子自带端点（磁力链 x.pe 等）注入集合。
func (m *Manager) injectBootstrap(st *seedState, seed Seed) {
	peers, err := seed.BootstrapPeers(m.cfg.Clock())
	if err != nil && m.cfg.OnError != nil {
		m.cfg.OnError(seed, "seed", err)
	}
	if len(peers) == 0 {
		return
	}
	if added := st.set.AddAll(peers); len(added) > 0 {
		m.notify(seed, added)
	}
}

// ErrClosed 表示 Manager 已 Close。
var ErrClosed = errors.New("discovery: manager closed")

// Untrack 停止跟踪一个种子并关闭其源。返回是否存在该记录。
func (m *Manager) Untrack(infoHash [InfoHashLen]byte) bool {
	m.mu.Lock()
	st, ok := m.states[infoHash]
	if ok {
		delete(m.states, infoHash)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	for _, s := range st.copySources() {
		_ = s.Close()
	}
	return true
}

// AddPeers 由调用方注入已知端点（join 事件携带的地址、CLI 指定等），来源记为
// OriginManual（权重最高，不被别的来源覆盖），并回灌给各源以滚雪球。
// 非法地址被跳过（第一条错误一并返回）。返回首次出现的端点条数。
func (m *Manager) AddPeers(infoHash [InfoHashLen]byte, addrs []string) (int, error) {
	m.mu.Lock()
	st, ok := m.states[infoHash]
	m.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("discovery: unknown seed %x", infoHash)
	}
	now := m.cfg.Clock()
	var peers []Peer
	var firstErr error
	for _, a := range addrs {
		p, err := NewPeer(a, OriginManual, now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		peers = append(peers, p)
	}
	added := st.set.AddAll(peers)
	if len(added) > 0 {
		m.notify(st.seed, added)
		m.refeed(st)
	}
	return len(added), firstErr
}

// Peers 返回某种子当前的端点列表（稳定排序：来源权重 → 新近 → 地址）。
func (m *Manager) Peers(infoHash [InfoHashLen]byte) []Peer {
	m.mu.Lock()
	st, ok := m.states[infoHash]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return st.set.Snapshot()
}

// AllPeers 返回所有被跟踪种子的端点并集（按地址去重，稳定排序）。
func (m *Manager) AllPeers() []Peer {
	m.mu.Lock()
	states := m.stateListLocked()
	m.mu.Unlock()
	out := NewPeerSet(0, 0)
	out.SetClock(m.cfg.Clock)
	for _, st := range states {
		out.Merge(st.set)
	}
	return out.Snapshot()
}

// Seeds 返回当前被跟踪的种子（按 info hash 升序）。
func (m *Manager) Seeds() []Seed {
	m.mu.Lock()
	states := m.stateListLocked()
	m.mu.Unlock()
	out := make([]Seed, 0, len(states))
	for _, st := range states {
		out = append(out, st.seed)
	}
	sort.Slice(out, func(i, j int) bool { return SeedKeyLess(out[i], out[j]) })
	return out
}

// SeedKeyLess 按 info hash 字典序比较两个种子（排序用）。
func SeedKeyLess(a, b Seed) bool {
	for i := range a.InfoHash {
		if a.InfoHash[i] != b.InfoHash[i] {
			return a.InfoHash[i] < b.InfoHash[i]
		}
	}
	return false
}

// Status 返回某种子的发现状态。
func (m *Manager) Status(infoHash [InfoHashLen]byte) (Status, bool) {
	m.mu.Lock()
	st, ok := m.states[infoHash]
	if !ok {
		m.mu.Unlock()
		return Status{}, false
	}
	out := Status{
		Seed:     st.seed,
		Degraded: st.degraded,
		AddedAt:  st.addedAt,
		LastErr:  st.lastErr,
	}
	names := make([]string, 0, len(st.sources))
	for _, s := range st.sources {
		names = append(names, s.Name())
	}
	m.mu.Unlock()

	sort.Strings(names)
	out.Sources = names
	out.ByOrigin = st.set.Origins()
	out.Peers = st.set.Len()
	return out, true
}

// StatusAll 返回全部种子的状态，按 info hash 升序。
func (m *Manager) StatusAll() []Status {
	m.mu.Lock()
	states := m.stateListLocked()
	m.mu.Unlock()
	out := make([]Status, 0, len(states))
	for _, st := range states {
		if s, ok := m.Status(st.seed.InfoHash); ok {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return SeedKeyLess(out[i].Seed, out[j].Seed) })
	return out
}

func (m *Manager) stateListLocked() []*seedState {
	out := make([]*seedState, 0, len(m.states))
	for _, st := range m.states {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return SeedKeyLess(out[i].seed, out[j].seed) })
	return out
}

// PollOnce 驱动一轮：从每个活动源拉取端点 → 合并去重 → 判定是否退化 →
// 触发增量回调 → 回灌滚雪球。返回本轮遇到的错误汇总（不影响已采纳的结果）。
// 调用方可自行按 PollInterval 节奏调它，也可以交给 Run。
func (m *Manager) PollOnce(ctx context.Context) error {
	m.mu.Lock()
	states := m.stateListLocked()
	m.mu.Unlock()

	var errs []error
	for _, st := range states {
		if err := ctx.Err(); err != nil {
			return err
		}
		srcs := st.copySources()
		var perSource []Peer
		for _, src := range srcs {
			ps, err := src.Fetch(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
				m.report(st.seed, src.Name(), err)
			}
			perSource = append(perSource, ps...)
		}
		added := st.set.AddAll(perSource)

		// PEX 失效判定：窗口内一个 PEX 端点都没有 → 挂纯 DHT 退化源（只挂一次）。
		var fallback Source
		if decideDegrade(m.cfg.Clock(), st.addedAt, st.set.CountOrigin(OriginPEX), m.cfg.DegradeAfter) {
			src, err := m.cfg.DegradeFactory(st.seed, ModeDHTOnly)
			m.mu.Lock()
			if !st.degraded {
				st.degraded = true
				if err != nil {
					st.lastErr = fmt.Sprintf("degrade source: %v", err)
				} else {
					st.sources = append(st.sources, src)
					fallback = src
				}
			}
			m.mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("degrade source: %w", err))
				m.report(st.seed, "degrade", err)
			}
		}
		if fallback != nil {
			ps, err := fallback.Fetch(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				errs = append(errs, fmt.Errorf("%s: %w", fallback.Name(), err))
				m.report(st.seed, fallback.Name(), err)
			}
			added = append(added, st.set.AddAll(ps)...)
		}

		if len(added) > 0 {
			m.notify(st.seed, added)
			if !m.cfg.NoSnowball {
				m.refeed(st)
			}
		}
	}
	return errors.Join(errs...)
}

// report 把源错误交给 OnError 回调（必须在锁外调用）。
func (m *Manager) report(seed Seed, source string, err error) {
	if m.cfg.OnError != nil {
		m.cfg.OnError(seed, source, err)
	}
}

// decideDegrade 是退化判定的纯函数：从开始跟踪算起，经过 after 窗口仍没有任何
// PEX 来源的端点，就判定 PEX 通路不生效（关键风险 1：anacrolix PEX 覆盖度）。
// after<=0 表示禁用退化；已有 PEX 端点则永不退化。
func decideDegrade(now, addedAt int64, pexPeers int, after time.Duration) bool {
	if after <= 0 || pexPeers > 0 {
		return false
	}
	return now-addedAt >= after.Milliseconds()
}

// refeed 把某状态的全量端点回灌给实现了 Feeder 的源（滚雪球：让源主动去勾搭新对端，
// 从它们那里再换一批 PEX 列表）。
func (m *Manager) refeed(st *seedState) {
	peers := st.set.Snapshot()
	if len(peers) == 0 {
		return
	}
	for _, src := range st.copySources() {
		if f, ok := src.(Feeder); ok {
			f.Feed(peers)
		}
	}
}

// notify 触发增量回调（锁外调用）。
func (m *Manager) notify(seed Seed, added []Peer) {
	if len(added) == 0 {
		return
	}
	SortPeers(added)
	if m.cfg.OnPeers != nil {
		m.cfg.OnPeers(seed, added)
	}
}

// Run 阻塞式轮询循环，直到 ctx 取消（返回 ctx.Err()）或 Manager 被 Close（返回 nil）。
// 每轮之间睡 PollInterval；Close/ctx 取消会立刻打断睡眠。
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()
	for {
		if err := m.PollOnce(ctx); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.doneCh:
			return nil
		case <-ticker.C:
		}
	}
}

// WaitFor 等到某种子至少 n 个端点为止（超时返回 ErrTimeout，同时带上当前列表，
// 便于「发现了 3 个但没到 5 个」这种继续开干的情况）。Run 未启动时它自己驱动轮询
// （间隔取 PollInterval 与 200ms 的较小值），所以单测/一次性发现都能直接用。
func (m *Manager) WaitFor(ctx context.Context, infoHash [InfoHashLen]byte, n int, timeout time.Duration) ([]Peer, error) {
	if n <= 0 {
		return m.Peers(infoHash), nil
	}
	deadline := time.Now().Add(timeout)
	interval := m.cfg.PollInterval
	if interval > 200*time.Millisecond || interval <= 0 {
		interval = 200 * time.Millisecond
	}
	for {
		if ps := m.Peers(infoHash); len(ps) >= n {
			return ps, nil
		}
		if err := ctx.Err(); err != nil {
			return m.Peers(infoHash), err
		}
		if timeout > 0 && !time.Now().Before(deadline) {
			return m.Peers(infoHash), fmt.Errorf("%w: got %d of %d peers", ErrTimeout, len(m.Peers(infoHash)), n)
		}
		if !m.isRunning() {
			_ = m.PollOnce(ctx)
		}
		if timeout > 0 {
			if d := time.Until(deadline); d < interval {
				interval = d
			}
		}
		if interval <= 0 {
			continue
		}
		time.Sleep(interval)
	}
}

// ErrTimeout 表示等待端点数量达标超时。
var ErrTimeout = errors.New("discovery: wait peers timeout")

// Close 关闭全部源。重复调用无害。
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return m.closeErr
	}
	m.closed = true
	states := m.stateListLocked()
	m.states = map[[InfoHashLen]byte]*seedState{}
	m.mu.Unlock()

	var errs []error
	for _, st := range states {
		for _, s := range st.copySources() {
			if err := s.Close(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			}
		}
	}
	m.closeErr = errors.Join(errs...)
	return m.closeErr
}

func (m *Manager) isRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}
