// Package group 实现 D-Mesh 的双名单模型（PLAN v16）：
// 白名单（成员/权限/角色）+ 黑名单（准入）+ 在场表 + owner 指针，
// 全部由 core.Message 承载的签名名单事件驱动、各端独立验签收敛。
//
// 类型 Roster 实现 core.Roster 接口。v26 起事件正文统一为 tagged-union Body
// （`{"<事件名>": 载荷}`，CanonicalJSON，结构见本文件），本包同时导出
// EncodeEventBody 与 SignEvent/EndorseEvent（signer.go），供 message/cmd
// 构造事件，保证跨包使用同一验签原文。
//
// 信任规则（逐条对应 PLAN）：
//   - 验签按 sig_alg 分派（core.Verify），未知 alg → ErrUnknownAlg，一律丢弃；
//   - 权限确立事件签名者层级严格高于目标（本人自签 remove 除外）；
//   - join 只认 carry 权限者签名，新人自签 join 一律无效；
//   - remove 仅本人自签 = 退群（删白名单、不进黑名单）；除名必须显式 kick；
//   - kick 需 kick 权限位且目标层级严格更低；unban 需 kick 或 unban 权限位；
//   - presence 仅本人自签、max 合并、不占白名单；
//   - netdisk 越界（0~256 之外）直接拒绝，且仅群主/创建者可签；
//   - 黑名单优先：黑名单中的 pub 不得作为成员出现在 join/快照/恢复里；
//   - transfer 是唯一可带 to 的名单事件（v17①：提案定向发给新 owner，
//     新 owner 的联署原文含 to，故生效事件仍带 to=新 owner）；
//   - 本机脏条目走 DropMember/DropBan 纯本地清洗（clean.go，v17 点 10c）。
package group

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"dmesh/internal/core"
)

// ---------------------------------------------------------------------------
// 事件内容结构（core.Message.Content = CanonicalJSON(下列之一)）
// ---------------------------------------------------------------------------

// eventJoinReq 是新人入群申请：pub（带 sig_alg）+ 传输密钥，可选种子文件
// 内容哈希引用与 PoW 透传字段。仅自签受理，不构成入群。
type eventJoinReq struct {
	Pub core.PubKey    `json:"pub"`
	WG  core.WGPub     `json:"wg_pub"`
	Ref string         `json:"ref,omitempty"` // 种子文件内容哈希（hex），供拉人者核对
	PoW map[string]any `json:"pow,omitempty"` // spam 包 PoW 透传
}

// eventJoin 是拉人者放行的新人条目：perms 须为种子默认权限子集（群主以下）。
type eventJoin struct {
	Pub   core.PubKey `json:"pub"`
	WG    core.WGPub  `json:"wg_pub"`
	Perms []string    `json:"perms"`
}

// eventTarget 复用给 remove / kick / unban / grant_admin / revoke_admin。
type eventTarget struct {
	Target core.PubKey `json:"target"`
}

type eventPerms struct {
	Target core.PubKey `json:"target"`
	Perms  []string    `json:"perms"`
}

type eventTransfer struct {
	NewOwner core.PubKey `json:"new_owner"`
}

type eventPresence struct {
	Pub          core.PubKey `json:"pub"`
	LastMsgTS    int64       `json:"last_msg_ts"`
	OfflineAfter int64       `json:"offline_after"`
}

type eventNetdisk struct {
	MB int `json:"mb"`
}

// EncodeEventBody 把一个名单事件的载荷包成 v26 的 tagged-union 正文
// （`{"<事件名>": 载荷}`，CanonicalJSON）。全工程签发端统一走这里：事件名由
// 调用方显式给出，与解码端 decodeEventBody 共用同一个 core.Name* 常量，
// 从根上堵住「生产端与解码端各写一份结构」的跨包字节漂移（v25 网盘配额事故）。
func EncodeEventBody(name string, payload any) ([]byte, error) { return core.MakeBody(name, payload) }

// decodeEventBody 按事件名严格解出正文载荷：键名不符、未知字段、尾部多余数据
// 一律拒绝（字段名被改写/夹带即判结构篡改）。
func decodeEventBody(m core.Message, name string, v any) error {
	return core.BodyPayload(m.Body, name, v)
}

// ---------------------------------------------------------------------------
// 权限位纯函数
// ---------------------------------------------------------------------------

// tierGatedPerms 是「只能由群主/创建者层级赋予」的敏感权限位：
// PLAN 点 5 —— 任命/收放管理权、授 carry 归群主（或创建者）；
// transfer/netdisk 本质同为群主权柄。
var tierGatedPerms = map[string]bool{
	core.PermCarry:      true,
	core.PermKick:       true,
	core.PermUnban:      true,
	core.PermGrantAdmin: true,
	core.PermTransfer:   true,
	core.PermNetdisk:    true,
}

// IsTierGatedPerm 报告某权限位是否属于敏感位（供 UI/审计复用）。
func IsTierGatedPerm(perm string) bool { return tierGatedPerms[perm] }

func validPermName(perm string) bool {
	for _, p := range core.AllPerms {
		if p == perm {
			return true
		}
	}
	return false
}

// checkPermsList 校验 perms 列表：非空、无重复、全为已知权限位。
func checkPermsList(perms []string) error {
	if len(perms) == 0 {
		return fmt.Errorf("%w: empty perms list", core.ErrMalformed)
	}
	seen := map[string]bool{}
	for _, p := range perms {
		if !validPermName(p) {
			return fmt.Errorf("%w: unknown perm %q", core.ErrMalformed, p)
		}
		if seen[p] {
			return fmt.Errorf("%w: duplicate perm %q", core.ErrMalformed, p)
		}
		seen[p] = true
	}
	return nil
}

func permsSubset(sub, set []string) bool {
	m := map[string]bool{}
	for _, p := range set {
		m[p] = true
	}
	for _, p := range sub {
		if !m[p] {
			return false
		}
	}
	return true
}

func containsPerm(set []string, p string) bool {
	for _, x := range set {
		if x == p {
			return true
		}
	}
	return false
}

func copyPerms(perms []string) []string {
	if perms == nil {
		return nil
	}
	out := make([]string, len(perms))
	copy(out, perms)
	return out
}

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

// memberCopy / blacklistCopy 返回深拷贝，防止外部持有内部 map 引用。
func memberCopy(e core.MemberEntry) core.MemberEntry {
	e.Perms = copyPerms(e.Perms)
	e.Proof.Raw = cloneBytes(e.Proof.Raw)
	e.Proof.Sig = cloneBytes(e.Proof.Sig)
	return e
}

func blacklistCopy(e core.BlacklistEntry) core.BlacklistEntry {
	e.Proof.Raw = cloneBytes(e.Proof.Raw)
	e.Proof.Sig = cloneBytes(e.Proof.Sig)
	return e
}

// pubMatches 把 content 自报 pub 与签名原文中的 sender 核对（sender 权威）。
func pubMatches(a, b core.PubKey) bool { return a.Equal(b) }

func clonePub(p core.PubKey) core.PubKey {
	p.Bytes = cloneBytes(p.Bytes)
	return p
}

func clonePubPtr(p core.PubKey) *core.PubKey {
	c := clonePub(p)
	return &c
}

// ---------------------------------------------------------------------------
// Roster：内存态双名单 + 在场表 + owner 指针
// ---------------------------------------------------------------------------

// Options 是 Roster 可选项，零值为合理默认。
type Options struct {
	// ReorderWindowMS 乱序重排窗口：ts 高于水位的事件在缓存中最短滞留时长，
	// 到期（或水位衔接）后由 FlushPending 按 ts 升序应用。
	ReorderWindowMS int64
	// MaxClockSkewMS 容忍的最大未来时钟偏差：ts_ms 超过 now+该值直接拒绝。
	MaxClockSkewMS int64
	// LowWaterGraceMS 乱序下限宽限：ts_ms 低于（已应用最小时间戳-该值）的
	// 事件视为远古重放，拒绝。
	LowWaterGraceMS int64
	// MaxPendingEvents 乱序短暂缓存上限，满时按 ts 排出最老的一条腾位。
	MaxPendingEvents int
	// SeenLimit 最近已应用事件 msg_id 环形去重缓存容量（幂等应用）。
	SeenLimit int
}

func (o Options) withDefaults() Options {
	if o.ReorderWindowMS <= 0 {
		o.ReorderWindowMS = 2000
	}
	if o.MaxClockSkewMS <= 0 {
		o.MaxClockSkewMS = 30_000
	}
	if o.LowWaterGraceMS <= 0 {
		o.LowWaterGraceMS = 10 * 60 * 1000
	}
	if o.MaxPendingEvents <= 0 {
		o.MaxPendingEvents = 512
	}
	if o.SeenLimit <= 0 {
		o.SeenLimit = 4096
	}
	return o
}

type pendingEvent struct {
	msg      core.Message
	heldAtMS int64
}

// Roster 是单个群的名单状态机，实现 core.Roster。所有方法并发安全。
type Roster struct {
	mu      sync.Mutex
	opt     Options
	cfg     core.GroupConfig
	haveCfg bool
	groupID [32]byte

	netdiskMB int
	owner     core.PubKey

	members   map[string]*core.MemberEntry
	blacklist map[string]*core.BlacklistEntry
	presence  map[string]core.PresenceEntry

	// 乱序处理：watermark=已应用事件的最大 ts；heldMin=已应用事件的最小 ts
	// （低水位，配合 grace 拒绝远古事件）；pending=ts 高于水位的短暂缓存。
	watermark   int64
	heldMin     int64
	heldMinInit bool
	pending     []pendingEvent

	seen     map[string]bool
	seenRing []string
	seenNext int

	joinReqs []core.Message // 已验签 join_req 收件箱（入群面板轮询；不改名单）

	// drops 是 v17③ 本机清洗（DropMember/DropBan）的有界审计日志。
	drops []DropRecord

	notifier func(RosterEvent)
	nowFn    func() time.Time // 测试注入时钟
}

var _ core.Roster = (*Roster)(nil)

// New 创建名单状态机。给定种子 cfg（Name/Creator/CreatedAt 任一非零即视为
// 已绑定）时：计算并强制校验事件 group_id；cfg.Creator 非零则自动生成创建者
// 创世白名单条目（RoleCreator 永久最高、owner 指针指向创建者、权限=默认权限∪
// 全部群主/管理权柄位，无需 proof——信任锚是种子本身而非事件）。
// cfg 传零值表示暂不绑定群（尚未加载种子），只按其中的 Creator/DefaultPerms
// 初始化（若有）。
func New(cfg core.GroupConfig, opt Options) *Roster {
	opt = opt.withDefaults()
	r := &Roster{
		opt:       opt,
		cfg:       cfg,
		members:   map[string]*core.MemberEntry{},
		blacklist: map[string]*core.BlacklistEntry{},
		presence:  map[string]core.PresenceEntry{},
		seen:      map[string]bool{},
		netdiskMB: cfg.NetdiskMB,
	}
	if cfg.Name != "" || !cfg.Creator.IsZero() || cfg.CreatedAt != 0 || len(cfg.DefaultPerms) > 0 {
		r.haveCfg = true
		r.groupID, _ = core.GroupIDOf(cfg)
	}
	if !cfg.Creator.IsZero() {
		r.owner = cfg.Creator
		r.members[cfg.Creator.Key()] = &core.MemberEntry{
			Pub:   cfg.Creator,
			WG:    cfg.CreatorWG,
			Role:  core.RoleCreator,
			Perms: creatorPerms(cfg.DefaultPerms),
			TS:    cfg.CreatedAt,
		}
	}
	return r
}

// creatorPerms：创建者条目权限 = 默认权限 + 全部权柄位（最终裁决权）。
func creatorPerms(defaults []string) []string {
	out := append([]string{}, defaults...)
	for _, p := range []string{core.PermCarry, core.PermKick, core.PermUnban, core.PermGrantAdmin, core.PermTransfer, core.PermNetdisk} {
		if !containsPerm(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// SetClock 注入自定义时钟（仅测试）。
func (r *Roster) SetClock(f func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nowFn = f
}

func (r *Roster) nowMS() int64 {
	if r.nowFn != nil {
		return r.nowFn().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// ---------------------------------------------------------------------------
// core.Roster 读接口
// ---------------------------------------------------------------------------

// IsBlacklisted 报告公钥是否在黑名单中（准入判定）。
func (r *Roster) IsBlacklisted(p core.PubKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.blacklist[p.Key()]
	return ok
}

// Member 查白名单条目。
func (r *Roster) Member(p core.PubKey) (core.MemberEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.members[p.Key()]
	if !ok {
		return core.MemberEntry{}, false
	}
	return memberCopy(*e), true
}

// TierOf 返回该公钥当前层级（creator=3 > owner=2 > admin=1 > member=0），
// 非成员返回 -1。
func (r *Roster) TierOf(p core.PubKey) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tierOf(p)
}

func (r *Roster) tierOf(p core.PubKey) int {
	if r.cfg.Creator.Equal(p) {
		return core.TierCreator // 创建者由创世固定，永久最高
	}
	e, ok := r.members[p.Key()]
	if !ok {
		return core.TierNonMember
	}
	t := core.TierOfRole(e.Role)
	if e.Pub.Equal(r.owner) && t < core.TierOwner {
		t = core.TierOwner // owner 指针兜底
	}
	return t
}

// HasPerm 报告该公钥当前是否持有权限位（perm 取 core.Perm* 常量）。
func (r *Roster) HasPerm(p core.PubKey, perm string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasPerm(p, perm)
}

func (r *Roster) hasPerm(p core.PubKey, perm string) bool {
	e, ok := r.members[p.Key()]
	return ok && containsPerm(e.Perms, perm)
}

// Presence 读在场表；无记录返回零值条目。
func (r *Roster) Presence(p core.PubKey) core.PresenceEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.presence[p.Key()]
}

// Snapshot 导出白名单/黑名单副本与 owner 指针（确定性排序），用于副本应答
// 与一致性核查。
func (r *Roster) Snapshot() (members []core.MemberEntry, banned []core.BlacklistEntry, owner core.PubKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	members = make([]core.MemberEntry, 0, len(r.members))
	for _, e := range r.members {
		members = append(members, memberCopy(*e))
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Pub.Key() < members[j].Pub.Key() })
	banned = make([]core.BlacklistEntry, 0, len(r.blacklist))
	for _, e := range r.blacklist {
		banned = append(banned, blacklistCopy(*e))
	}
	sort.Slice(banned, func(i, j int) bool { return banned[i].Pub.Key() < banned[j].Pub.Key() })
	return members, banned, clonePub(r.owner)
}

// ---------------------------------------------------------------------------
// 附加访问器
// ---------------------------------------------------------------------------

// Config 返回种子配置（含最新 netdisk_mb）；未绑定种子时 ok=false。
func (r *Roster) Config() (core.GroupConfig, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg, r.haveCfg
}

// GroupID 返回绑定的群 id（未绑定返回零值）。
func (r *Roster) GroupID() [32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.groupID
}

// Owner 返回当前群主指针。
func (r *Roster) Owner() core.PubKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return clonePub(r.owner)
}

// NetdiskMB 返回当前群网盘配额（0~256）。
func (r *Roster) NetdiskMB() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.netdiskMB
}

// MemberCount 返回白名单规模。
func (r *Roster) MemberCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.members)
}

// PresenceList 导出在场表全量（按 pub 排序）。
func (r *Roster) PresenceList() []core.PresenceEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]core.PresenceEntry, 0, len(r.presence))
	for _, e := range r.presence {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pub.Key() < out[j].Pub.Key() })
	return out
}

// PendingCount 返回乱序缓存中待衔接的事件数。
func (r *Roster) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// PollJoinReqs 取走并清空已验签的 join_req 收件箱（入群面板轮询）。
func (r *Roster) PollJoinReqs() []core.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.joinReqs
	r.joinReqs = nil
	return out
}

// ---------------------------------------------------------------------------
// 持久化恢复（store 包启动时喂回已验证过的条目）
// ---------------------------------------------------------------------------

// LoadSnapshot 从本地存储恢复内存态。条目必须携带当初应用时验证过的 proof，
// 此处逐条复验（本地数据被篡改/伪造即整体拒绝并返回错误），并执行黑名单
// 优先清理与 netdisk 越界校验。创建者条目以创世为准，不采信存储版本。
// owner 为零值时不改动当前指针。
func (r *Roster) LoadSnapshot(members []core.MemberEntry, banned []core.BlacklistEntry, presence []core.PresenceEntry, owner core.PubKey, netdiskMB int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !core.ValidNetdiskMB(netdiskMB) {
		return fmt.Errorf("%w: restored netdisk_mb %d out of range", core.ErrMalformed, netdiskMB)
	}
	for _, e := range banned {
		if e.Pub.IsZero() {
			return fmt.Errorf("%w: restored blacklist with empty pub", core.ErrMalformed)
		}
		if err := verifyBlacklistProof(e); err != nil {
			return fmt.Errorf("group: restored blacklist %s proof failed: %w", e.Pub, err)
		}
	}
	for _, e := range members {
		if e.Pub.IsZero() {
			return fmt.Errorf("%w: restored member with empty pub", core.ErrMalformed)
		}
		if r.cfg.Creator.Equal(e.Pub) {
			continue // 创建者条目以创世为准
		}
		if err := verifyMemberProof(e); err != nil {
			return fmt.Errorf("group: restored member %s proof failed: %w", e.Pub, err)
		}
	}
	for _, e := range presence {
		if e.Pub.IsZero() || e.LastMsgTS < 0 || e.OfflineAfter < 0 {
			return fmt.Errorf("%w: bad restored presence entry", core.ErrMalformed)
		}
	}
	// 先装黑名单（优先），再装白名单并剔除被拉黑条目。
	for i := range banned {
		cp := blacklistCopy(banned[i])
		r.blacklist[cp.Pub.Key()] = &cp
	}
	for i := range members {
		cp := memberCopy(members[i])
		if _, bad := r.blacklist[cp.Pub.Key()]; bad {
			continue
		}
		r.members[cp.Pub.Key()] = &cp
	}
	for _, e := range presence {
		key := e.Pub.Key()
		if old, ok := r.presence[key]; !ok || e.LastMsgTS >= old.LastMsgTS {
			r.presence[key] = e
		}
	}
	if !owner.IsZero() {
		if !r.cfg.Creator.Equal(owner) {
			if oe, ok := r.members[owner.Key()]; !ok || core.TierOfRole(oe.Role) < core.TierOwner {
				return fmt.Errorf("%w: restored owner %s is not at owner tier", core.ErrMalformed, owner)
			}
		}
		r.owner = clonePub(owner)
	} else if r.owner.IsZero() && !r.cfg.Creator.IsZero() {
		r.owner = r.cfg.Creator
	}
	r.netdiskMB = netdiskMB
	if r.haveCfg {
		r.cfg.NetdiskMB = netdiskMB
	}
	return nil
}

// ---------------------------------------------------------------------------
// 去重缓存与水位
// ---------------------------------------------------------------------------

func (r *Roster) markSeen(msgID string) {
	if r.seen[msgID] {
		return
	}
	r.seen[msgID] = true
	if len(r.seenRing) == 0 {
		r.seenRing = make([]string, r.opt.SeenLimit)
	}
	if old := r.seenRing[r.seenNext]; old != "" && old != msgID {
		delete(r.seen, old) // 环形 eviction：覆盖最老一条
	}
	r.seenRing[r.seenNext] = msgID
	r.seenNext = (r.seenNext + 1) % len(r.seenRing)
}

func (r *Roster) advanceWatermark(ts int64) {
	if ts > r.watermark {
		r.watermark = ts
	}
	if !r.heldMinInit || ts < r.heldMin {
		r.heldMin = ts
		r.heldMinInit = true
	}
}

func newMsgID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
