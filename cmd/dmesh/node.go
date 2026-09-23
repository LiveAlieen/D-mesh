// node.go：cmd/dmesh 的集成装配层——把 internal 各包按 PLAN v16 的接线纪律
// 组装为一个运行中的群节点（依赖注入，不含任何协议逻辑本体）。

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dmesh/internal/backfill"
	"dmesh/internal/core"
	"dmesh/internal/discovery"
	"dmesh/internal/group"
	"dmesh/internal/identity"
	"dmesh/internal/message"
	"dmesh/internal/neighbor"
	"dmesh/internal/netdisk"
	"dmesh/internal/spam"
	"dmesh/internal/store"
	"dmesh/internal/transport"
	"dmesh/internal/ui"
)

// node 是一个「一进程一群」的 D-Mesh 节点。
type node struct {
	o   opts
	log *log.Logger
	now func() int64 // Unix 毫秒

	id   *identity.Identity
	self core.PubKey
	cfg  core.GroupConfig
	gid  [32]byte
	seed []byte // 种子原文（join_req 的 ref 哈希核对用）

	st     *store.Store
	roster *group.Roster
	engine *message.Engine
	ep     *transport.Endpoint
	nt     *neighbor.Table
	disc   *discovery.Manager
	bf     *backfill.Engine

	// spam 层：速率限制 / 本地屏蔽列表 / 邻居评分
	chatLim *spam.Limiter
	presLim *spam.Limiter
	joinLim *spam.Limiter
	blockl  *spam.Blocklist
	scores  *spam.ScoreTracker

	interactive bool

	mu       sync.Mutex
	pending  map[string]chan rpcFrame // rpc 响应关联
	lastSelf int64                    // 本人最后发消息时间（在场自报）
	offline  int64                    // 本人配置的 offline_after（v13.1）

	jmu      sync.Mutex
	joinQ    map[string]ui.JoinRequest // 待处理 join_req（msg_id → 解析结果）
	joinSeen map[string]bool

	// transfer 联署提案收件箱（v17①）：定向发给本机、EndorseSig 为空的 transfer
	// 原文，绝不能进 ApplyEvent（缺联署必被拒并给现任 owner 差评）。
	tmu       sync.Mutex
	transQ    map[string]ui.TransferProposal
	transSeen map[string]bool
	propLim   *spam.Limiter

	// netdisk（仅 netdisk_mb>0 时装配，见 netdisk.go）
	ndMu      sync.Mutex
	nd        *netdisk.Manager
	ndStore   *netdisk.DirStore
	manifests map[string]*netdisk.Manifest // fileID → 已验清单
	maniSeen  map[string]bool              // flood 一轮去重

	evCh chan ui.Event
	done chan struct{}
}

// newNode 按依赖顺序接线：spam → transport → neighbor → message → backfill → discovery。
func newNode(ctx context.Context, o *opts, logger *log.Logger, id *identity.Identity,
	cfg core.GroupConfig, gid [32]byte, seed []byte, st *store.Store, roster *group.Roster) (*node, error) {
	nowMS := func() int64 { return time.Now().UnixMilli() }
	n := &node{
		o: *o, log: logger, now: nowMS,
		id: id, self: id.Pub(), cfg: cfg, gid: gid, seed: seed,
		st: st, roster: roster,
		chatLim:     spam.NewLimiter(spam.ChatRate(), nowMS),
		presLim:     spam.NewLimiter(spam.PresenceRate(), nowMS),
		joinLim:     spam.NewLimiter(spam.JoinReqRate(), nowMS),
		blockl:      spam.NewBlocklist(nowMS),
		scores:      spam.NewScoreTracker(spam.DefaultScoreConfig(), nowMS),
		pending:     map[string]chan rpcFrame{},
		joinQ:       map[string]ui.JoinRequest{},
		joinSeen:    map[string]bool{},
		transQ:      map[string]ui.TransferProposal{},
		transSeen:   map[string]bool{},
		propLim:     spam.NewLimiter(spam.JoinReqRate(), nowMS),
		manifests:   map[string]*netdisk.Manifest{},
		maniSeen:    map[string]bool{},
		offline:     o.offline,
		evCh:        make(chan ui.Event, 256),
		done:        make(chan struct{}),
		interactive: !o.noUI && stdinInteractive(),
	}

	// 名单事件生效 → 持久化 + UI 刷新（fire 在 Roster 锁外同步回调，不得重入写状态）。
	roster.SetNotifier(func(ev group.RosterEvent) { n.onRosterChange(ev) })

	// transport：准入判定（黑名单 + 解禁权限者定向申诉例外）全部由现成 API 完成，
	// 这里只注入 Roster / 身份 / 群锚。
	bind, err := net.ResolveUDPAddr("udp", o.listen)
	if err != nil {
		return nil, fmt.Errorf("--listen %q: %w", o.listen, err)
	}
	n.ep, err = transport.Listen(transport.Config{
		BindAddr: bind,
		Static:   id.WGPrivate(),
		Identity: id,
		Roster:   roster,
		GroupIDs: [][32]byte{gid},
	})
	if err != nil {
		return nil, fmt.Errorf("transport listen: %w", err)
	}
	logger.Printf("listening udp %s (wg_pub=%s)", n.ep.LocalAddr(), n.ep.LocalWG())

	// neighbor：邻居表；Dial 走 transport，Receive 先过 rpc 解复用再进消息层。
	n.nt, err = neighbor.New(neighbor.Config{
		MinNeighbors: o.minN,
		MaxNeighbors: o.maxN,
		LocalPub:     n.self,
		Roster:       roster,
		Dial:         n.dial,
		Receive:      n.demux,
		OnJoin:       n.onJoin,
		OnLeave:      func(pub core.PubKey, reason neighbor.Reason) { logger.Printf("neighbor leave %s: %s", pub, reason) },
	})
	if err != nil {
		return nil, fmt.Errorf("neighbor table: %w", err)
	}

	// message：验证 + 去重 + flood 流水线；Handlers 把消息层接到 store 与 ui。
	h := message.Handlers{
		Chat:             n.onChat,
		RosterEvent:      n.onRosterMsg,
		Hide:             n.onHideMsg,
		Appeal:           n.onAppeal,
		JoinReq:          n.onJoinReq,
		TransferProposal: n.onTransferProposal,
		SoftDelete:       func(idStr string) { _ = st.MarkHidden(idStr) },
		Lookup: func(msgID string) (core.Message, bool) {
			m, ok, err := st.GetMessage(msgID)
			return m, err == nil && ok
		},
		Penalty:    n.onPenalty,
		PeerOnline: func(p core.PubKey) bool { return n.isNeighbor(p) },
	}
	n.engine = message.NewEngine(gid, n.self, roster, msgTransport{n.nt}, msgPeers{n.nt}, h)

	// backfill：重上线自动回灌 + /audit。Source 由 rpc.go 的邻居协议粘合，
	// Cleaner 接 group.Roster（v17③）：审计发现的本机脏名单条目实际删除，
	// rosterCleaner 适配层只加日志，清洗语义全部在 group 包 clean.go。
	n.bf, err = backfill.New(backfill.Deps{
		Roster:  roster,
		Store:   &bfStore{st},
		Cleaner: &rosterCleaner{r: roster, log: logger},
		Sources: n.bfSources,
		Config:  backfill.Config{Scope: backfill.ScopeMode(o.scope)},
		Now:     nowMS,
		Penalize: func(peer core.PubKey, reason backfill.DropReason, detail string) {
			n.scores.PenalizePub(peer, spam.EvConflictingData)
			logger.Printf("backfill penalty %s: %s %s", peer, reason, detail)
		},
		Disconnect: func(peer core.PubKey, reason string) {
			n.nt.Drop(peer, neighbor.Reason("backfill:"+reason))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("backfill: %w", err)
	}

	// netdisk：仅当群配置 netdisk_mb>0 时初始化（M6）。
	if cfg.NetdiskMB > 0 {
		if err := n.initNetdisk(cfg.NetdiskMB); err != nil {
			logger.Printf("WARN: netdisk init failed: %v", err)
		}
	}

	// discovery：anacrolix DHT+PEX 滚雪球 → neighbor 候选。失败只降级不致命。
	if !o.noDiscovery {
		n.startDiscovery(ctx)
	}
	return n, nil
}

// serve 启动全部后台循环并阻塞（ctx 结束即干净退出）。
func (n *node) serve(ctx context.Context) error {
	ctx, stop := notifyShutdown(ctx)
	defer stop()

	go func() {
		if err := n.nt.Run(ctx); err != nil && ctx.Err() == nil {
			n.log.Printf("neighbor run stopped: %v", err)
		}
	}()
	go n.acceptLoop(ctx)

	// 手工候选（离线联调：--peer 指到已有成员实例即可组网）。
	for _, addr := range n.o.peers {
		n.addCandidateForMembers(addr)
	}

	go n.presenceLoop(ctx)
	go n.flushLoop(ctx)
	go n.startupBackfill(ctx)

	<-ctx.Done()
	return nil
}

func (n *node) shutdown() {
	select {
	case <-n.done:
	default:
		close(n.done)
	}
	if n.disc != nil {
		_ = n.disc.Close()
	}
	if n.nt != nil {
		_ = n.nt.Close()
	}
	if n.ep != nil {
		_ = n.ep.Close()
	}
	if n.st != nil {
		_ = n.st.Close()
	}
}

// ---------------------------------------------------------------------------
// transport / neighbor 粘合
// ---------------------------------------------------------------------------

// dial 供 neighbor 候选自动拨号：WG 已知走 IK，未知退化 XX（transport 内部判断）。
func (n *node) dial(c neighbor.Candidate) (core.Tunnel, error) {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return n.ep.Dial(ctx, addr, transport.Remote{Identity: c.Pub, WG: c.WG})
}

// acceptLoop 把入站隧道挂进邻居表（准入判定已在握手层由 transport 按 Roster 完成：
// 黑名单拒连、唯一例外=解禁权限者接受黑名单成员的定向申诉隧道）。
func (n *node) acceptLoop(ctx context.Context) {
	for {
		t, err := n.ep.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				n.log.Printf("accept stopped: %v", err)
			}
			return
		}
		addr := ""
		if pa := t.PeerAddr(); pa != nil {
			addr = pa.String()
		}
		if err := n.nt.Add(t, addr); err != nil {
			n.log.Printf("reject inbound %s: %v", t.RemotePub(), err)
			_ = t.Close()
		} else {
			n.log.Printf("inbound neighbor %s from %s", t.RemotePub(), addr)
		}
	}
}

func (n *node) onJoin(pub core.PubKey) {
	n.log.Printf("neighbor joined %s", pub)
	n.scores.RewardPub(pub, spam.EvTimelyData)
	// v11：重上线/新握手恢复即自动回灌（先名单、后消息，多源交叉比对）。
	if n.o.scope != string(backfill.ScopeNone) {
		go func() {
			if rep, err := n.bf.RunOnce(context.Background()); err != nil {
				if !errors.Is(err, backfill.ErrTooFewSources) {
					n.log.Printf("backfill: %v", err)
				}
			} else if rep != nil && !rep.Skipped {
				n.log.Printf("backfill done: accepted=%d asked=%d responded=%d", rep.Accepted, rep.SourcesAsked, rep.SourcesResponded)
			}
		}()
	}
}

func (n *node) startupBackfill(ctx context.Context) {
	if n.o.scope == string(backfill.ScopeNone) {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}
	if _, err := n.bf.RunOnce(ctx); err != nil && !errors.Is(err, backfill.ErrTooFewSources) {
		n.log.Printf("startup backfill: %v", err)
	}
}

// addCandidateForMembers：同一地址登记给创建者 + 全体已知成员（谁是这台机器
// 由握手定，错了自然拒）。
func (n *node) addCandidateForMembers(addr string) {
	n.nt.AddCandidate(n.cfg.Creator, n.cfg.CreatorWG, addr)
	members, _, _ := n.roster.Snapshot()
	for _, m := range members {
		n.nt.AddCandidate(m.Pub, m.WG, addr)
	}
}

func (n *node) isNeighbor(p core.PubKey) bool {
	for _, q := range n.nt.PublicNeighbors() {
		if q.Equal(p) {
			return true
		}
	}
	return false
}

// msgTransport / msgPeers：message.Transport 与 message.PeerSource 的 neighbor 适配。
type msgTransport struct{ nt *neighbor.Table }

func (t msgTransport) Send(to core.PubKey, frame []byte) error { return t.nt.SendTo(to, frame) }

type msgPeers struct{ nt *neighbor.Table }

func (p msgPeers) Peers() []core.PubKey { return p.nt.PublicNeighbors() }

// ---------------------------------------------------------------------------
// discovery 接线
// ---------------------------------------------------------------------------

func (n *node) startDiscovery(ctx context.Context) {
	seedPath := filepath.Join(n.o.data, "groups", hex.EncodeToString(n.gid[:]), "seed.torrent")
	seed, err := discovery.LoadSeedFile(seedPath)
	if err != nil {
		n.log.Printf("discovery disabled: no usable .torrent (%v)；可用 --peer 手工组网", err)
		return
	}
	f, err := discovery.NewSwarmFactory(discovery.SwarmConfig{})
	if err != nil {
		n.log.Printf("discovery factory: %v", err)
		return
	}
	mgr, err := discovery.New(discovery.Config{
		Factory: f.Source,
		OnPeers: func(_ discovery.Seed, added []discovery.Peer) {
			for _, p := range added {
				n.addCandidateForMembers(p.Addr)
			}
		},
		OnError: func(_ discovery.Seed, source string, err error) {
			n.log.Printf("discovery source %s: %v", source, err)
		},
	})
	if err != nil {
		n.log.Printf("discovery manager: %v", err)
		return
	}
	if err := mgr.Track(seed); err != nil {
		n.log.Printf("discovery track: %v", err)
		return
	}
	n.disc = mgr
	go func() {
		if err := mgr.Run(ctx); err != nil && ctx.Err() == nil {
			n.log.Printf("discovery run: %v", err)
		}
	}()
}

// ---------------------------------------------------------------------------
// message Handlers：收/发流水线
// ---------------------------------------------------------------------------

func (n *node) onChat(m core.Message) {
	n.persist(m)
	if !n.interactive {
		fmt.Fprintln(os.Stdout, ui.FormatChatLine(m))
	}
	n.pushEvent(ui.TextEvent{Msg: m})
}

func (n *node) onRosterMsg(m core.Message) { n.persist(m) }

func (n *node) onHideMsg(m core.Message) { n.persist(m) }

func (n *node) onAppeal(m core.Message) {
	n.persist(m)
	if !n.interactive {
		fmt.Fprintf(os.Stdout, "[appeal] %s -> %s: %s\n", m.Sender, m.To, string(m.Content))
	}
	n.pushEvent(ui.AppealEvent{Msg: m})
}

func (n *node) onPenalty(from core.PubKey, reason message.RejectReason, m *core.Message, err error) {
	if reason == message.ReasonDuplicate {
		return
	}
	switch reason {
	case message.ReasonBadSig:
		n.scores.PenalizePub(from, spam.EvBadSignature)
		n.blockl.Add(from, "bad_signature", 30_000)
	case message.ReasonUnknownAlg:
		n.scores.PenalizePub(from, spam.EvUnknownAlg) // v16：未知算法轻罚（宁拒不误信）
	case message.ReasonMalformed, message.ReasonUnknownType:
		n.scores.PenalizePub(from, spam.EvSpam)
	default: // 越权/黑名单/非成员/无 speak：spam/差评
		n.scores.PenalizePub(from, spam.EvRepeatViolation)
	}
	if n.scores.ShouldDrop(from.Key()) && !n.blockl.Blocked(from) {
		n.log.Printf("blocklisting %s (score=%d last=%s)", from, n.scores.ScorePub(from), reason)
		n.blockl.Add(from, string(reason), 5*60_000)
	}
	mtype := "<nil>"
	if m != nil {
		mtype = m.Type
	}
	n.log.Printf("penalty %s from=%s type=%s: %v", reason, from, mtype, err)
}

// persist 把已受理消息写入 JSONL（幂等；真相源）。
func (n *node) persist(m core.Message) {
	if _, err := n.st.AppendMessage(m); err != nil {
		n.log.Printf("store append %s: %v", m.MsgID, err)
	}
}

// ---------------------------------------------------------------------------
// 出站：聊天 / 事件 / 在场
// ---------------------------------------------------------------------------

// publish 把本机已签名消息：①名单事件先过本机 ApplyEvent（同样的验签/层级规则）
// ②写 store ③engine.Publish flood。
func (n *node) publish(m core.Message) error {
	if message.IsRosterEvent(m.Type) {
		if err := n.roster.ApplyEvent(m); err != nil {
			return fmt.Errorf("local apply %s: %w", m.Type, err)
		}
	}
	n.persist(m)
	if _, err := n.engine.Publish(m); err != nil {
		return fmt.Errorf("publish %s: %w", m.Type, err)
	}
	return nil
}

// signAndPublish 构造/签名并广播一个名单事件（Content 用 group.EncodeEventContent）。
func (n *node) signAndPublish(typ string, content any, tsMS int64) error {
	cb, err := group.EncodeEventContent(content)
	if err != nil {
		return err
	}
	m := core.Message{Type: typ, Content: cb, TSms: tsMS}
	if err := group.SignEvent(&m, n.id, n.gid); err != nil {
		return err
	}
	return n.publish(m)
}

// sendText 发送一条聊天消息，并顺带推进本人在场（v13：任何消息自带发送时间戳，
// 这里以配套 presence 事件把 last_msg_ts 分发给全员）。
func (n *node) sendText(text string) error {
	if n.roster.TierOf(n.self) < 0 {
		return fmt.Errorf("%w: 本机还不是群成员（等待拉人者签 join）", core.ErrNotPermitted)
	}
	if !n.roster.HasPerm(n.self, core.PermSpeak) {
		return fmt.Errorf("%w: 无 speak 权限", core.ErrNotPermitted)
	}
	if !n.chatLim.Allow("self") {
		return fmt.Errorf("本机发送过快，稍后再试")
	}
	ts := n.now()
	m := core.Message{Type: core.TypeText, Content: []byte(text), TSms: ts}
	signed, err := message.NewMessage(n.id, n.gid, &m, nil)
	if err != nil {
		return err
	}
	n.persist(signed)
	if _, err := n.engine.Publish(signed); err != nil {
		return err
	}
	n.setLastSelf(ts)
	return n.publishPresence(ts)
}

// publishPresence 本人自签在场报告（max 合并；offline_after 随报告分发，v13.1）。
func (n *node) publishPresence(lastTS int64) error {
	if !n.presLim.Allow("self|presence") {
		return nil // 心跳限速：静默跳过本轮
	}
	ts := n.now()
	if lastTS > ts {
		lastTS = ts
	}
	return n.signAndPublish(core.TypePresence, presenceContent{
		Pub: n.self, LastMsgTS: lastTS, OfflineAfter: n.getOffline(),
	}, ts)
}

func (n *node) presenceLoop(ctx context.Context) {
	interval := n.o.heartbeat
	if interval <= 0 {
		interval = 60 * time.Second
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			n.mu.Lock()
			last := n.lastSelf
			n.mu.Unlock()
			if last == 0 {
				last = n.now()
			}
			if err := n.publishPresence(last); err != nil {
				n.log.Printf("presence heartbeat: %v", err)
			}
		}
	}
}

// flushLoop 周期排空名单事件乱序缓存（group.Options 的重排窗口到期即应用）。
func (n *node) flushLoop(ctx context.Context) {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if ap, failed := n.roster.FlushPending(); ap > 0 || len(failed) > 0 {
				n.log.Printf("flush pending: applied=%d failed=%d", ap, len(failed))
			}
			n.scores.Advance()
		}
	}
}

func (n *node) setLastSelf(ts int64) {
	n.mu.Lock()
	if ts > n.lastSelf {
		n.lastSelf = ts
	}
	n.mu.Unlock()
}

func (n *node) getOffline() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.offline
}

// ---------------------------------------------------------------------------
// 名单变更 → 持久化 + UI
// ---------------------------------------------------------------------------

func (n *node) onRosterChange(ev group.RosterEvent) {
	var err error
	switch ev.Kind {
	case group.KindMemberUpsert:
		err = n.st.PutMember(*ev.Member)
	case group.KindMemberDelete:
		err = n.st.DeleteMember(ev.Pub)
	case group.KindBlacklistAdd:
		err = n.st.PutBlacklist(*ev.Banned)
	case group.KindBlacklistDelete:
		err = n.st.DeleteBlacklist(ev.Pub)
	case group.KindPresenceSet:
		_, err = n.st.UpsertPresence(*ev.Presence)
	case group.KindOwnerChanged:
		err = n.st.SetOwner(*ev.Owner)
	case group.KindMemberDroppedLocal:
		err = n.st.DeleteMember(ev.Pub) // v17③ 本机清洗：持久化副本同步删除
	case group.KindBlacklistDroppedLocal:
		err = n.st.DeleteBlacklist(ev.Pub)
	case group.KindNetdiskChanged:
		cfg := n.cfg
		cfg.NetdiskMB = ev.NetdiskMB
		_, err = n.st.PutGroupConfig(cfg)
		n.onNetdiskQuota(ev.NetdiskMB)
	case group.KindJoinReqReceived:
		// join_req 不经 ApplyEvent（engine 直接调 Handlers.JoinReq），此处忽略。
		return
	}
	if err != nil {
		n.log.Printf("persist roster change %d/%s: %v", ev.Kind, ev.Pub, err)
	}
	switch ev.Kind {
	case group.KindMemberUpsert, group.KindMemberDelete, group.KindBlacklistAdd, group.KindBlacklistDelete,
		group.KindMemberDroppedLocal, group.KindBlacklistDroppedLocal:
		n.refreshNetdiskHosts() // 成员变动 → 网盘出配额集更新（含重平衡触发由 netdisk 包内部按调用处理）
	}
	note := rosterNote(ev)
	if !n.interactive && note != "" {
		n.log.Printf("roster: %s", note) // 无 UI 模式下面名单变更进日志（v17③ 清洗可见）
	}
	n.pushEvent(ui.RosterEvent{Note: note})
}

func rosterNote(ev group.RosterEvent) string {
	switch ev.Kind {
	case group.KindMemberUpsert:
		return "member upsert " + ev.Pub.String()
	case group.KindMemberDelete:
		return "member removed " + ev.Pub.String()
	case group.KindBlacklistAdd:
		return "blacklisted " + ev.Pub.String()
	case group.KindBlacklistDelete:
		return "unbanned " + ev.Pub.String()
	case group.KindOwnerChanged:
		return "owner -> " + ev.Pub.String()
	case group.KindNetdiskChanged:
		return fmt.Sprintf("netdisk_mb -> %d", ev.NetdiskMB)
	case group.KindMemberDroppedLocal:
		return "local clean: dropped member " + ev.Pub.String() + " (" + ev.Reason + ")"
	case group.KindBlacklistDroppedLocal:
		return "local clean: dropped ban " + ev.Pub.String() + " (" + ev.Reason + ")"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// join_req 收件箱（入群面板宿主）
// ---------------------------------------------------------------------------

// joinReqContent 与 group 包 eventJoinReq 的 JSON 形态一致（协议契约在 core/group）。
type joinReqContent struct {
	Pub core.PubKey `json:"pub"`
	WG  core.WGPub  `json:"wg_pub"`
	Ref string      `json:"ref,omitempty"`
}

type joinContent struct {
	Pub   core.PubKey `json:"pub"`
	WG    core.WGPub  `json:"wg_pub"`
	Perms []string    `json:"perms"`
}

type targetContent struct {
	Target core.PubKey `json:"target"`
}

type permsContent struct {
	Target core.PubKey `json:"target"`
	Perms  []string    `json:"perms"`
}

type transferContent struct {
	NewOwner core.PubKey `json:"new_owner"`
}

type presenceContent struct {
	Pub          core.PubKey `json:"pub"`
	LastMsgTS    int64       `json:"last_msg_ts"`
	OfflineAfter int64       `json:"offline_after"`
}

// onJoinReq：本机具 carry 权限时受理入群请求（engine 已验签，这里补语义校验）。
func (n *node) onJoinReq(m core.Message) {
	var c joinReqContent
	if err := json.Unmarshal(m.Content, &c); err != nil {
		return
	}
	if !c.Pub.Equal(m.Sender) || c.WG.IsZero() {
		return
	}
	if _, ok := n.roster.Member(m.Sender); ok || n.roster.IsBlacklisted(m.Sender) {
		return
	}
	if !n.joinLim.Allow(m.Sender.Key()) {
		return
	}
	n.jmu.Lock()
	if n.joinSeen[m.MsgID] {
		n.jmu.Unlock()
		return
	}
	n.joinSeen[m.MsgID] = true
	req := ui.JoinRequest{
		Msg: m, ApplicantWG: c.WG, Mode: n.cfg.Mode,
		SeedOK: c.Ref != "" && c.Ref == sha256Hex(n.seed),
	}
	if req.Mode == core.ModeVerify && req.SeedOK {
		req.IdentityNote = "mode=verify：核对通过，还需按申请人消息人工验身份后再签 join"
	}
	n.joinQ[m.MsgID] = req
	out := req
	n.jmu.Unlock()

	n.pushEvent(ui.JoinReqEvent{Req: out})
	if out.Mode == core.ModeAuto && out.SeedOK && n.o.autoApprove {
		if err := n.approveJoin(m.MsgID); err != nil {
			n.log.Printf("auto-approve %s: %v", m.Sender, err)
		} else {
			n.log.Printf("auto-approved join for %s", m.Sender)
		}
	}
}

// approveJoin：种子哈希核对是两种模式的共同前提（PLAN §进群-4）；新人按种子
// 默认权限记入白名单，perm 规则由 group 包 ApplyEvent 统一把关。
func (n *node) approveJoin(msgID string) error {
	n.jmu.Lock()
	req, ok := n.joinQ[msgID]
	n.jmu.Unlock()
	if !ok {
		return fmt.Errorf("join_req %s 不在队列", msgID)
	}
	if !req.SeedOK {
		return fmt.Errorf("拒绝：种子文件哈希未核对一致（/seedcheck 或 join_req 需携带 ref）")
	}
	if !n.roster.HasPerm(n.self, core.PermCarry) {
		return fmt.Errorf("%w: 本机不持 carry 权限", core.ErrNotPermitted)
	}
	perms := n.cfg.DefaultPerms
	if len(perms) == 0 {
		perms = []string{core.PermSpeak, core.PermReceive}
	}
	if err := n.signAndPublish(core.TypeJoin, joinContent{Pub: req.Msg.Sender, WG: req.ApplicantWG, Perms: perms}, n.now()); err != nil {
		return err
	}
	n.jmu.Lock()
	delete(n.joinQ, msgID)
	n.jmu.Unlock()
	return nil
}

func (n *node) rejectJoin(msgID string) error {
	n.jmu.Lock()
	delete(n.joinQ, msgID)
	n.jmu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// transfer 联署提案收件箱（v17①，宿主侧；UI 面板走 ui.TransferProposalEvent）
// ---------------------------------------------------------------------------

// onTransferProposal：engine 已核过签名者层级/权限（handleTransferProposal），
// 这里只做速率与重复抑制后入箱。提案原文绝不喂 ApplyEvent（缺联署必拒）。
func (n *node) onTransferProposal(m core.Message) {
	if !m.To.Equal(n.self) {
		return
	}
	if !n.propLim.Allow(m.Sender.Key() + "|proposal") {
		return
	}
	n.tmu.Lock()
	if n.transSeen[m.MsgID] {
		n.tmu.Unlock()
		return
	}
	n.transSeen[m.MsgID] = true
	prop := ui.TransferProposal{Msg: m, FromOwner: true}
	n.transQ[m.MsgID] = prop
	n.tmu.Unlock()

	if !n.interactive {
		fmt.Fprintf(os.Stdout, "[transfer-proposal] %s -> me (msg_id=%s)\n", m.Sender, m.MsgID)
	}
	n.pushEvent(ui.TransferProposalEvent{Prop: prop})
}

// pendingTransfers 按时间序返回收件箱快照。
func (n *node) pendingTransfers() []ui.TransferProposal {
	n.tmu.Lock()
	out := make([]ui.TransferProposal, 0, len(n.transQ))
	for _, p := range n.transQ {
		out = append(out, p)
	}
	n.tmu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Msg.TSms < out[j].Msg.TSms })
	return out
}

// takeTransfer 按 msgID 取出提案（支持 "latest" 与唯一前缀匹配），取出即出箱。
func (n *node) takeTransfer(msgID string) (ui.TransferProposal, bool) {
	n.tmu.Lock()
	defer n.tmu.Unlock()
	if p, ok := n.transQ[msgID]; ok {
		delete(n.transQ, msgID)
		return p, true
	}
	cands := n.pendingTransfersLocked()
	if msgID == "latest" || msgID == "" {
		if len(cands) == 0 {
			return ui.TransferProposal{}, false
		}
		p := cands[len(cands)-1]
		delete(n.transQ, p.Msg.MsgID)
		return p, true
	}
	var hit []ui.TransferProposal
	for _, p := range cands {
		if strings.HasPrefix(p.Msg.MsgID, msgID) {
			hit = append(hit, p)
		}
	}
	if len(hit) != 1 {
		return ui.TransferProposal{}, false
	}
	delete(n.transQ, hit[0].Msg.MsgID)
	return hit[0], true
}

func (n *node) pendingTransfersLocked() []ui.TransferProposal {
	out := make([]ui.TransferProposal, 0, len(n.transQ))
	for _, p := range n.transQ {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Msg.TSms < out[j].Msg.TSms })
	return out
}

// headlessCommands 无头模式的 stdin 脚本通道：普通行=发言，"/…" 复用 ui 的
// 命令解析器派发到 ui.App 宿主方法（v17：transfer/approve 可脚本化，也供
// E2E 联调）。不支持的交互命令给出提示而非静默丢弃。
func (n *node) headlessCommands(ctx context.Context) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 16<<10), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			if err := n.SendText(line); err != nil {
				fmt.Fprintf(os.Stderr, "[cmd] send: %v\n", err)
			}
			continue
		}
		c, err := ui.ParseCommand(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[cmd] %v\n", err)
			continue
		}
		switch c.Kind {
		case ui.CmdText:
			err = n.SendText(c.Text)
		case ui.CmdTransfer:
			err = n.Transfer(c.Target)
		case ui.CmdApprove:
			id := c.MsgID
			if id == "" {
				id = "latest"
			}
			err = n.ApproveTransfer(id)
		case ui.CmdDeny:
			id := c.MsgID
			if id == "" {
				id = "latest"
			}
			err = n.RejectTransfer(id)
		case ui.CmdTransfers:
			for _, p := range n.PendingTransfers() {
				fmt.Fprintf(os.Stdout, "%s\n", ui.FormatTransferLine(p, time.Now()))
			}
		case ui.CmdKick:
			err = n.Kick(c.Target)
		case ui.CmdUnban:
			err = n.Unban(c.Target)
		case ui.CmdGrantAdmin:
			err = n.GrantAdmin(c.Target)
		case ui.CmdRevokeAdmin:
			err = n.RevokeAdmin(c.Target)
		case ui.CmdPerms:
			err = n.SetPerms(c.Target, c.Perms)
		case ui.CmdHide:
			err = n.Hide(c.MsgID)
		case ui.CmdRemove:
			err = n.Leave()
		case ui.CmdOfflineAfter:
			err = n.SetOfflineAfter(c.Millis)
		case ui.CmdAudit:
			rows, aerr := n.Audit()
			for _, r := range rows {
				fmt.Fprintf(os.Stdout, "[audit] %s\n", r)
			}
			err = aerr
		case ui.CmdQuit:
			n.shutdown()
			return
		default:
			fmt.Fprintf(os.Stderr, "[cmd] 该命令需 GUI 交互模式: %s\n", line)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[cmd] %s: %v\n", line, err)
		}
	}
}

// ---------------------------------------------------------------------------
// backfill.Store 适配（本地消息视图）
// ---------------------------------------------------------------------------

type bfStore struct{ st *store.Store }

func (b *bfStore) MaxTS() int64 {
	ts, err := b.st.MaxMsgTS()
	if err != nil {
		return 0
	}
	return ts
}

func (b *bfStore) Has(msgID string) bool {
	ok, err := b.st.HasMessage(msgID)
	return err == nil && ok
}

func (b *bfStore) Get(msgID string) (core.Message, bool) {
	m, ok, err := b.st.GetMessage(msgID)
	return m, err == nil && ok
}

func (b *bfStore) Append(m core.Message) error {
	_, err := b.st.AppendMessage(m)
	return err
}

func (b *bfStore) MsgIDs(afterTS int64) []string {
	msgs, err := b.st.QueryMessages(store.MessageQuery{SinceMS: afterTS})
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.MsgID)
	}
	return ids
}

func (b *bfStore) Reject(msgID string, reason string) error {
	return b.st.MarkHidden(msgID)
}

// ---------------------------------------------------------------------------
// backfill.Cleaner 适配（v17③：审计发现的本机脏名单条目实际删除）
// ---------------------------------------------------------------------------

// rosterCleaner 只加日志转接：清洗语义全部在 group.Roster.DropMember/DropBan
// （纯本地删除、不产生网络事件、创建者/现任 owner 锚点保护、删了等补）。
type rosterCleaner struct {
	r   *group.Roster
	log *log.Logger
}

var _ backfill.Cleaner = (*rosterCleaner)(nil)

func (c *rosterCleaner) DropMember(p core.PubKey, reason string) {
	c.log.Printf("backfill audit: DropMember %s reason=%s", p, reason)
	c.r.DropMember(p, reason)
}

func (c *rosterCleaner) DropBan(p core.PubKey, reason string) {
	c.log.Printf("backfill audit: DropBan %s reason=%s", p, reason)
	c.r.DropBan(p, reason)
}
