package netdisk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"dmesh/internal/core"
)

// HostInfo 报告一个成员对群网盘的配额贡献（集成层从群配置 + 该成员
// 「我已预留 netdisk_mb」的自报组装；QuotaBytes<=0 即未出配额，可读不可写）。
type HostInfo struct {
	Pub        core.PubKey
	QuotaBytes int64
}

// Transport 是块在成员间收发的抽象，集成层桥接到 gossip / 按需拉取通道
// （网盘块走与消息同路的通道，PLAN v14）。Push/Fetch 收到的块必须原样
// 携带 Proof，接收侧一律独立复验，绝不信任传输方。
type Transport interface {
	Push(to core.PubKey, b *Block) error
	Fetch(from core.PubKey, q BlockQuery) (*Block, error)
	List(from core.PubKey, fileID string) ([]*Block, error)
	Remove(from core.PubKey, q BlockQuery) error
}

// Options 是 Manager 的接线参数。
type Options struct {
	GroupID   [32]byte
	Signer    core.Signer              // 本机身份（签发块与清单）
	Store     BlockStore               // 本机定额目录（承载分给我的块）
	Tx        Transport                // 远端收发；nil 时远端一律 ErrHostUnreachable（纯本地/测试可用）
	BlockSize int                      // <=0 取 DefaultBlockSize
	K         int                      // <=0 取 n-1（经典 RAID5）
	Now       func() int64             // Unix 毫秒；nil 取 time.Now
	OnSuspect func(core.PubKey, error) // 坏源差评回调（与回灌/核查同一套机制）
}

// Manager 是全网盘逻辑的接线中枢：切条上传、降级下载、重平衡计划与执行。
// 并发安全（内部读写锁保护成员布局状态；单次 Upload/Download 非重入串行）。
type Manager struct {
	groupID   [32]byte
	signer    core.Signer
	self      core.PubKey
	store     BlockStore
	tx        Transport
	blockSize int
	k         int
	now       func() int64

	suspect func(core.PubKey, error)

	mu       sync.RWMutex
	allHosts []HostInfo // 全部成员（含未出配额者，读取候选源用）
	layout   Layout     // 当前 RAID5 布局（仅配额成员；零值 = 未成组）
	quorum   bool       // 配额成员是否 ≥3（成员流失后即使布局停更，也禁写）
	frozen   bool       // 降级冻结开关（PLAN 已知限制 8：降级期暂停新写入）
}

// Manager 构造默认值。
const (
	// DefaultK 是每带数据块数默认值（2 数据 + 1 校验 = 经典 3 成员 RAID5）。
	// 刻意不随成员数取 n-1：固定 K 下任何成员增减都只需搬移/重建个别块
	// （「只补缺失块 + 重平衡」），而 K=n-1 在成员缩容时被迫整体重写。
	DefaultK = MinHosts - 1
)

// New 构造 Manager。Signer 必需；Store 必需（本机落盘/缓存）。
func New(o Options) (*Manager, error) {
	if o.Signer == nil || o.Store == nil {
		return nil, fmt.Errorf("%w: Signer and Store are required", ErrNilDependency)
	}
	m := &Manager{
		groupID:   o.GroupID,
		signer:    o.Signer,
		self:      o.Signer.Pub(),
		store:     o.Store,
		tx:        o.Tx,
		blockSize: o.BlockSize,
		k:         o.K,
		now:       o.Now,
		suspect:   o.OnSuspect,
	}
	if m.blockSize <= 0 {
		m.blockSize = DefaultBlockSize
	}
	if m.k <= 0 {
		m.k = DefaultK
	}
	if m.now == nil {
		m.now = time.Now().UnixMilli
	}
	return m, nil
}

// SetHosts 更新成员配额视图并尝试重建 RAID5 布局。
// 配额成员 <3 时返回 ErrNotEnoughHosts——布局维持旧值（可能为零），
// 此时禁写但读取/重建路径仍按 Manifest.Hosts（写入时布局）工作。
func (m *Manager) SetHosts(hs []HostInfo) error {
	var contributing []core.PubKey
	for _, h := range hs {
		if h.QuotaBytes > 0 {
			contributing = append(contributing, h.Pub)
		}
	}
	lay, err := NewLayout(contributing, m.k)
	m.mu.Lock()
	m.allHosts = append([]HostInfo(nil), hs...)
	m.quorum = len(contributing) >= MinHosts
	if err == nil {
		m.layout = lay
	}
	m.mu.Unlock()
	if err != nil {
		return fmt.Errorf("netdisk: set hosts: %w", err)
	}
	return nil
}

// Layout 返回当前 RAID5 布局副本。
func (m *Manager) Layout() Layout {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.layout
}

// AllHosts 返回全部已知成员（含未出配额者）。
func (m *Manager) AllHosts() []HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]HostInfo(nil), m.allHosts...)
}

// ContributingHosts 返回当前出配额成员（升序）。
func (m *Manager) ContributingHosts() []core.PubKey {
	lay := m.Layout()
	return append([]core.PubKey(nil), lay.Hosts...)
}

// SetWriteFrozen 手动冻结/解冻新写入（重平衡完成前置 true，完成后置 false）。
func (m *Manager) SetWriteFrozen(frozen bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = frozen
}

// CanWrite 判定本机此刻可否写入：未冻结、布局成立（≥3 配额成员）、
// 本机出了配额（无配额只读），且本机定额目录放得下分给我那份。
func (m *Manager) CanWrite(size int64) error {
	m.mu.RLock()
	frozen, lay, quorum := m.frozen, m.layout, m.quorum
	m.mu.RUnlock()
	if frozen {
		return ErrDegradedFrozen
	}
	if !quorum || lay.N() < MinHosts {
		return ErrNotEnoughHosts
	}
	if !lay.Has(m.self) {
		return ErrNotWritable
	}
	perHost := size / int64(lay.Slots())
	if q := m.store.Quota(); q > 0 && m.store.Usage()+perHost > q {
		return fmt.Errorf("%w: local share %d of quota %d (used %d)", ErrQuotaFull, perHost, q, m.store.Usage())
	}
	return nil
}

func (m *Manager) suspectFrom(host core.PubKey, cause error) {
	if m.suspect != nil {
		m.suspect(host, cause)
	}
}

// deliver 把块交给目标成员：自己 → 本地定额目录；其他 → Transport。
func (m *Manager) deliver(host core.PubKey, b *Block) error {
	if host.Equal(m.self) {
		return m.store.Put(b)
	}
	if m.tx == nil {
		return fmt.Errorf("%w: %s (no transport)", ErrHostUnreachable, host)
	}
	return m.tx.Push(host, b)
}

func (m *Manager) fetchRemote(host core.PubKey, q BlockQuery) (*Block, error) {
	if host.Equal(m.self) {
		return m.store.Get(q.FileID, q.Stripe, q.Pos)
	}
	if m.tx == nil {
		return nil, fmt.Errorf("%w: %s", ErrHostUnreachable, host)
	}
	return m.tx.Fetch(host, q)
}

func (m *Manager) listRemote(host core.PubKey, fileID string) ([]*Block, error) {
	if host.Equal(m.self) {
		return m.store.List(fileID)
	}
	if m.tx == nil {
		return nil, fmt.Errorf("%w: %s", ErrHostUnreachable, host)
	}
	return m.tx.List(host, fileID)
}

func (m *Manager) removeRemote(host core.PubKey, q BlockQuery) error {
	if host.Equal(m.self) {
		return m.store.Delete(q.FileID, q.Stripe, q.Pos)
	}
	if m.tx == nil {
		return fmt.Errorf("%w: %s", ErrHostUnreachable, host)
	}
	return m.tx.Remove(host, q)
}

// verifyBlock 对「某源交来的块」做全套复验：块 proof + 哈希 + 对清单交叉比对。
// 任一不过即回调差评。
func (m *Manager) verifyBlock(mf *Manifest, host core.PubKey, b *Block) error {
	if b == nil || b.FileID != mf.FileID {
		err := fmt.Errorf("%w: block for another file", ErrBadBlock)
		m.suspectFrom(host, err)
		return err
	}
	if err := CheckBlock(b, m.groupID); err != nil {
		m.suspectFrom(host, err)
		return err
	}
	if err := CheckBlockAgainstManifest(mf, b); err != nil {
		m.suspectFrom(host, err)
		return err
	}
	return nil
}

// candidateHosts 汇总全部可能持块的成员：写入时布局 ∪ 当前布局 ∪ 所有已知成员
// （除名者善后前其残留块仍是多源交叉验的候选；伪签会被逐块复验挡掉）。
func (m *Manager) candidateHosts(mf *Manifest) []core.PubKey {
	m.mu.RLock()
	all := make([]core.PubKey, 0, len(m.allHosts)+len(m.layout.Hosts)+len(mf.Hosts))
	for _, h := range m.allHosts {
		all = append(all, h.Pub)
	}
	all = append(all, m.layout.Hosts...)
	m.mu.RUnlock()
	all = append(all, mf.Hosts...)
	out, err := sortedUniquePubs(all)
	if err != nil {
		return mf.Hosts
	}
	return out
}

// gatherVerified 向所有候选源拉取本文件的块并逐块复验，返回
// verified[loc]=已验块（首个通过验证的源胜出 = 多源交叉验哈希）。
func (m *Manager) gatherVerified(mf *Manifest) (map[Loc]*Block, error) {
	if err := CheckManifest(mf, m.groupID); err != nil {
		return nil, err
	}
	byLoc := map[Loc]*Block{}
	for _, host := range m.candidateHosts(mf) {
		blocks, err := m.listRemote(host, mf.FileID)
		if err != nil {
			continue // 离线/无此文件：降级路径会处理
		}
		for _, b := range blocks {
			if b == nil || b.Stripe < 0 || b.Stripe >= mf.Stripes || b.Pos < 0 || b.Pos > mf.K {
				continue
			}
			loc := Loc{mf.FileID, b.Stripe, b.Pos}
			if _, dup := byLoc[loc]; dup {
				continue // 已有经多源验证的同位块
			}
			if err := m.verifyBlock(mf, host, b); err != nil {
				continue // 单源坏块：丢弃 + 差评，换源或重建
			}
			byLoc[loc] = b
		}
	}
	return byLoc, nil
}

// Upload 执行完整写路径：配额可写校验 → 本地切条 + 算校验 → 逐块签发 →
// 按轮转布局推给各目标成员落盘（任一成员拒收即回滚已推块）。
// 返回已签名的 Manifest（集成层应经 ManifestMessage 广播全网使全员可见）。
func (m *Manager) Upload(name string, content []byte) (*Manifest, error) {
	if err := m.CanWrite(int64(len(content))); err != nil {
		return nil, err
	}
	mf, stripes, err := m.buildManifest(name, content)
	if err != nil {
		return nil, err
	}
	if err := SignManifest(m.signer, mf); err != nil {
		return nil, err
	}
	lay := Layout{Hosts: mf.Hosts, K: mf.K}
	placed := make([]Loc, 0, mf.Stripes*lay.Slots())
	for s, blocks := range stripes {
		for p := 0; p < lay.Slots(); p++ {
			host, err := lay.HostFor(s, p)
			if err != nil {
				m.rollback(placed)
				return nil, err
			}
			b := &Block{
				FileID:  mf.FileID,
				GroupID: m.groupID,
				Stripe:  s,
				Pos:     p,
				Host:    host,
				Data:    blocks[p],
			}
			if err := SignBlock(m.signer, b, m.now()); err != nil {
				m.rollback(placed)
				return nil, err
			}
			if err := m.deliver(host, b); err != nil {
				m.rollback(placed)
				return nil, fmt.Errorf("netdisk: place block (%d,%d) on %s: %w", s, p, host, err)
			}
			placed = append(placed, Loc{mf.FileID, s, p})
		}
	}
	return mf, nil
}

// buildManifest 切条并生成清单（含逐块哈希），同时把块字节返回给调用方复用，
// 避免二次编码。K 取群级配置 m.k（默认 DefaultK，固定 K 保证增员只需搬移）。
func (m *Manager) buildManifest(name string, content []byte) (*Manifest, [][][]byte, error) {
	lay := m.Layout()
	mf, err := NewManifest(m.groupID, name, content, m.blockSize, m.k, lay.Hosts, m.now())
	if err != nil {
		return nil, nil, err
	}
	stripes, err := EncodeToStripes(content, mf.BlockSize, mf.K)
	if err != nil {
		return nil, nil, err
	}
	return mf, stripes, nil
}

// rollback 尽力撤回上传中途已落盘的块。
func (m *Manager) rollback(placed []Loc) {
	for _, loc := range placed {
		b, err := m.store.Get(loc.FileID, loc.Stripe, loc.Pos)
		if err == nil {
			_ = m.removeRemote(b.Host, BlockQuery{loc.FileID, loc.Stripe, loc.Pos})
			continue
		}
		// 本地没有 → 不知道落给谁了，按布局重算（确定性）。
		m.mu.RLock()
		lay := m.layout
		m.mu.RUnlock()
		if host, err2 := lay.HostFor(loc.Stripe, loc.Pos); err2 == nil {
			_ = m.removeRemote(host, BlockQuery{loc.FileID, loc.Stripe, loc.Pos})
		}
	}
}

// Download 读取文件全文：向所有候选源收块（逐块验签 + 对清单交叉验哈希）→
// 缺失块由同条其余块异或重建（单块降级读）→ 截断零填充 → 全文哈希终检。
// 同条缺 ≥2 块返回 ErrTooManyMissing（RAID5 已知限制）。
func (m *Manager) Download(mf *Manifest) ([]byte, error) {
	byLoc, err := m.gatherVerified(mf)
	if err != nil {
		return nil, err
	}
	return assembleFromBlocks(mf, byLoc)
}

// assembleFromBlocks 纯逻辑：从已验证块集合拼回原文（单块缺失走异或重建）。
func assembleFromBlocks(mf *Manifest, byLoc map[Loc]*Block) ([]byte, error) {
	out := make([]byte, 0, mf.Size)
	scratch := make([][]byte, mf.Strides())
	for s := 0; s < mf.Stripes; s++ {
		for i := range scratch {
			scratch[i] = nil
		}
		missing := 0
		for p := 0; p < mf.Strides(); p++ {
			if b, ok := byLoc[Loc{mf.FileID, s, p}]; ok {
				scratch[p] = b.Data
			} else {
				missing++
			}
		}
		switch {
		case missing == 0:
		case missing == 1:
			pos, rec, err := ReconstructStripe(scratch)
			if err != nil {
				return nil, fmt.Errorf("netdisk: stripe %d: %w", s, err)
			}
			if len(mf.BlockHashes) > 0 {
				h := sha256.Sum256(rec)
				if h != mf.BlockHashes[s*mf.Strides()+pos] {
					return nil, fmt.Errorf("%w: reconstructed stripe %d pos %d", ErrHashMismatch, s, pos)
				}
			}
			scratch[pos] = rec
		default:
			return nil, fmt.Errorf("%w: stripe %d misses %d blocks", ErrTooManyMissing, s, missing)
		}
		for j := 0; j < mf.K; j++ {
			out = append(out, scratch[ParityPos+j+1]...)
		}
	}
	if int64(len(out)) > mf.Size {
		out = out[:mf.Size]
	}
	if got := sha256.Sum256(out); got != mf.ContentHash {
		return nil, fmt.Errorf("%w: assembled %x want %x", ErrFileCorrupt, got, mf.ContentHash)
	}
	return out, nil
}

// CollectPlacements 收集各块当前的落盘位置（只含通过复验的块），
// 作为 PlanRebalance 的输入。
func (m *Manager) CollectPlacements(mf *Manifest) ([]Placement, error) {
	byLoc, err := m.gatherVerified(mf)
	if err != nil {
		return nil, err
	}
	ps := make([]Placement, 0, len(byLoc))
	for loc, b := range byLoc {
		ps = append(ps, Placement{Loc: loc, Host: b.Host})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Stripe != ps[j].Stripe {
			return ps[i].Stripe < ps[j].Stripe
		}
		return ps[i].Pos < ps[j].Pos
	})
	return ps, nil
}

// MissingByStripe 统计每条带缺失块数（TUI「条带健康度」与降级冻结判定用）。
func MissingByStripe(mf *Manifest, ps []Placement) map[int]int {
	have := map[Loc]bool{}
	for _, p := range ps {
		have[p.Loc] = true
	}
	out := map[int]int{}
	for s := 0; s < mf.Stripes; s++ {
		n := 0
		for p := 0; p < mf.Strides(); p++ {
			if !have[Loc{mf.FileID, s, p}] {
				n++
			}
		}
		if n > 0 {
			out[s] = n
		}
	}
	return out
}

// ActionKind 是重平衡动作类型。
type ActionKind string

// 重平衡动作：move=块还在世（成员变动只是换放置），recover=块已丢（异或重建）。
const (
	ActionMove    ActionKind = "move"
	ActionRecover ActionKind = "recover"
)

// Action 描述一次「只补缺失块 + 重平衡」的最小搬移单元。
type Action struct {
	Kind ActionKind
	Loc
	From core.PubKey // move 的原持有者（recover 为空）
	To   core.PubKey // 新布局下该槽位的归属成员
}

// PlanRebalance 依据当前布局（SetHosts 之后的 m.layout）对manifest 的
// 现存放置做差分：
//   - 块在某在世成员、但新轮转公式指向另一成员 → ActionMove（纯放置变更）；
//   - 块彻底不见（携带者退群/kick/离线且无处可验）→ ActionRecover（重建到目标位）；
//   - 位置本就正确 → 无动作（「只补缺失块」，不整体重写）。
//
// 同条缺失 ≥2 块时返回 ErrTooManyMissing——不可恢复，不再生成半途计划。
func (m *Manager) PlanRebalance(mf *Manifest, ps []Placement) ([]Action, error) {
	lay := m.Layout()
	if lay.N() < MinHosts {
		return nil, ErrNotEnoughHosts
	}
	if err := CheckManifest(mf, m.groupID); err != nil {
		return nil, err
	}
	cur := map[Loc]core.PubKey{}
	for _, p := range ps {
		cur[p.Loc] = p.Host
	}
	// 该文件的条带在成员缩容后放不下（K+1 > n）：只能重编码，不做半途计划。
	if mf.K+1 > lay.N() {
		return nil, fmt.Errorf("%w: file k=%d, hosts=%d", ErrReencodeRequired, mf.K, lay.N())
	}
	layF := Layout{Hosts: lay.Hosts, K: mf.K} // 按文件自身 K 复算轮转放置
	// 先确认每条带至多丢 1 块（丢失 = 该槽位没有在世持有者）。
	for s := 0; s < mf.Stripes; s++ {
		lost := 0
		for p := 0; p < mf.Strides(); p++ {
			h, ok := cur[Loc{mf.FileID, s, p}]
			if !ok || !lay.Has(h) {
				lost++
			}
		}
		if lost > 1 {
			return nil, fmt.Errorf("%w: stripe %d lost %d blocks", ErrTooManyMissing, s, lost)
		}
	}
	var actions []Action
	for s := 0; s < mf.Stripes; s++ {
		for p := 0; p < mf.Strides(); p++ {
			loc := Loc{mf.FileID, s, p}
			want, err := layF.HostFor(s, p)
			if err != nil {
				return nil, err
			}
			h, ok := cur[loc]
			switch {
			case ok && h.Equal(want):
				// 位置正确，跳过。
			case ok && lay.Has(h):
				actions = append(actions, Action{Kind: ActionMove, Loc: loc, From: h, To: want})
			default:
				// 彻底丢失（或仅剩已除名者持有的孤本）→ 重建。
				actions = append(actions, Action{Kind: ActionRecover, Loc: loc, To: want})
			}
		}
	}
	return actions, nil
}

// ExecutePlan 执行重平衡计划：先 recover（趁同条块还齐）、后 move
// （push 成功再删原块，两阶段避免搬移途中断电丢双份）。
// 重建出的块由执行者重新签发（原块 proof 随携带者同归；新 proof 的
// Publisher=执行者 + 内容哈希对清单交叉验，信任不依赖执行者本人）。
func (m *Manager) ExecutePlan(mf *Manifest, actions []Action) error {
	byLoc, err := m.gatherVerified(mf)
	if err != nil {
		return err
	}
	hostOf := map[Loc]core.PubKey{}
	for loc, b := range byLoc {
		hostOf[loc] = b.Host
	}
	// 1) recover：按条带聚合，同条其余块必须都在世。
	for _, a := range actions {
		if a.Kind != ActionRecover {
			continue
		}
		blocks := make([][]byte, mf.Strides())
		for p := 0; p < mf.Strides(); p++ {
			if p == a.Pos {
				continue
			}
			loc := Loc{a.FileID, a.Stripe, p}
			holder, ok := hostOf[loc]
			if !ok {
				return fmt.Errorf("%w: stripe %d peer pos %d unavailable for recover of pos %d",
					ErrTooManyMissing, a.Stripe, p, a.Pos)
			}
			src, err := m.fetchRemote(holder, BlockQuery{a.FileID, a.Stripe, p})
			if err != nil {
				return fmt.Errorf("netdisk: fetch peer (%d,%d): %w", a.Stripe, p, err)
			}
			if err := m.verifyBlock(mf, holder, src); err != nil {
				return err
			}
			blocks[p] = src.Data
		}
		pos, data, err := ReconstructStripe(blocks)
		if err != nil {
			return fmt.Errorf("netdisk: reconstruct stripe %d: %w", a.Stripe, err)
		}
		if pos != a.Pos {
			return fmt.Errorf("%w: reconstructed %d, planned %d", ErrBadBlock, pos, a.Pos)
		}
		nb := &Block{
			FileID: a.FileID, GroupID: m.groupID, Stripe: a.Stripe, Pos: a.Pos,
			Host: a.To, Data: data,
		}
		if err := SignBlock(m.signer, nb, m.now()); err != nil {
			return err
		}
		if err := CheckBlockAgainstManifest(mf, nb); err != nil {
			return err // 重建结果与清单哈希不符：数据已双损或被污染
		}
		if err := m.deliver(a.To, nb); err != nil {
			return fmt.Errorf("netdisk: deliver recovered (%d,%d) to %s: %w", a.Stripe, a.Pos, a.To, err)
		}
	}
	// 2) move：先推新家、验收后再删旧家。
	for _, a := range actions {
		if a.Kind != ActionMove {
			continue
		}
		q := BlockQuery{a.FileID, a.Stripe, a.Pos}
		b, err := m.fetchRemote(a.From, q)
		if err != nil {
			return fmt.Errorf("netdisk: fetch move (%d,%d) from %s: %w", a.Stripe, a.Pos, a.From, err)
		}
		if err := m.verifyBlock(mf, a.From, b); err != nil {
			return err
		}
		nb := *b
		nb.Host = a.To // Host 是放置信息，不在签名原文内：搬移不换 proof
		if err := m.deliver(a.To, &nb); err != nil {
			return fmt.Errorf("netdisk: deliver move (%d,%d) to %s: %w", a.Stripe, a.Pos, a.To, err)
		}
		if err := m.removeRemote(a.From, q); err != nil {
			return fmt.Errorf("netdisk: remove old (%d,%d) on %s: %w", a.Stripe, a.Pos, a.From, err)
		}
	}
	return nil
}

// RemoveFile 删除网盘文件：向所有候选源发出定向删除（除名者善后/用户删除入口）。
func (m *Manager) RemoveFile(mf *Manifest) error {
	var errs []error
	for _, host := range m.candidateHosts(mf) {
		for s := 0; s < mf.Stripes; s++ {
			for p := 0; p < mf.Strides(); p++ {
				if err := m.removeRemote(host, BlockQuery{mf.FileID, s, p}); err != nil && !errors.Is(err, ErrNotFound) {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// ---------- 清单的 TypeHide 消息封装（「全员按 msg 事件确认后可见」） ----------

const manifestKind = "netdisk_manifest"

type manifestEnvelope struct {
	Kind     string    `json:"kind"`
	Manifest *Manifest `json:"manifest"`
}

// msgIDFor 确定性派生 msg_id（sender+content+ts 的哈希前 32 hex）：
// 同一清单/事件在任何节点重算都得到同一 id，天然支持消息层按 msg_id 去重。
func msgIDFor(sender core.PubKey, content []byte, ts int64) string {
	h := sha256.New()
	h.Write(sender.Bytes)
	h.Write(content)
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(ts >> (8 * (7 - i)))
	}
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ManifestMessage 把清单打包成 TypeHide 消息并由本机签名（MsgID 确定性派生，
// 天然支持消息层按 msg_id 去重）。集成层负责 flood/存储后全网可见。
func (m *Manager) ManifestMessage(mf *Manifest) (core.Message, error) {
	if mf == nil {
		return core.Message{}, ErrNilDependency
	}
	content, err := core.CanonicalJSON(manifestEnvelope{Kind: manifestKind, Manifest: mf})
	if err != nil {
		return core.Message{}, err
	}
	ts := m.now()
	msg := core.Message{
		MsgID:   msgIDFor(m.self, content, ts),
		GroupID: m.groupID,
		Sender:  m.self,
		TSms:    ts,
		Type:    core.TypeHide,
		Content: content,
		Alg:     m.signer.Alg(),
	}
	raw, err := core.MessageSigPayload(msg)
	if err != nil {
		return core.Message{}, err
	}
	sig, err := m.signer.Sign(raw)
	if err != nil {
		return core.Message{}, fmt.Errorf("netdisk: sign manifest message: %w", err)
	}
	msg.Sig = sig
	return msg, nil
}

// ManifestFromMessage 解出一条清单广播消息：验消息签名域原文（不要求信任
// 转发者——签名在 Sender 上）+ 逐字段复验清单（CheckManifest 含 proof 复验）。
// 签名者是否群成员由集成层结合 roster 判定（与消息层同一准入）。
func ManifestFromMessage(msg core.Message, groupID [32]byte) (*Manifest, core.PubKey, error) {
	if msg.Type != core.TypeHide || msg.GroupID != groupID {
		return nil, core.PubKey{}, fmt.Errorf("%w: not a netdisk manifest message", ErrBadManifest)
	}
	raw, err := core.MessageSigPayload(msg)
	if err != nil {
		return nil, core.PubKey{}, err
	}
	if err := core.Verify(msg.Sender, raw, msg.Sig); err != nil {
		return nil, msg.Sender, fmt.Errorf("%w: %w", ErrBadManifest, err)
	}
	dec := json.NewDecoder(bytes.NewReader(msg.Content))
	var env manifestEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, msg.Sender, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if env.Kind != manifestKind || env.Manifest == nil {
		return nil, msg.Sender, fmt.Errorf("%w: wrong envelope kind", ErrBadManifest)
	}
	if err := CheckManifest(env.Manifest, groupID); err != nil {
		return nil, msg.Sender, err
	}
	return env.Manifest, msg.Sender, nil
}
