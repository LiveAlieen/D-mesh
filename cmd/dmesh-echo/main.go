// dmesh-echo 是最小联调工具（PLAN M2/M3 验证脚本位）：两个不同 --data 实例
// 互连后，把 stdin 行作为群消息发出、把收到的消息打到 stdout。
//
// 全部语义都复用 internal 现成 API（transport Noise+黑名单准入、neighbor、
// message 验证/去重/flood、group 事件签发），不新增协议逻辑；相比 dmesh 主
// 程序砍掉：TUI/store/backfill/spam/netdisk/discovery（改用 --peer 手工寻址）。
//
// 典型对拍（A=创建者实例，B=新人实例）：
//
//	A: dmesh-echo --data /tmp/a --seed group.json --listen 127.0.0.1:9601 --auto-approve
//	B: dmesh-echo --data /tmp/b --seed group.json --join --peer 127.0.0.1:9601
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dmesh/internal/core"
	"dmesh/internal/group"
	"dmesh/internal/identity"
	"dmesh/internal/message"
	"dmesh/internal/neighbor"
	"dmesh/internal/transport"
)

type peersFlag []string

func (p *peersFlag) String() string { return strings.Join(*p, ",") }
func (p *peersFlag) Set(v string) error {
	for _, one := range strings.Split(v, ",") {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		if _, err := net.ResolveUDPAddr("udp", one); err != nil {
			return fmt.Errorf("bad --peer %q: %w", one, err)
		}
		*p = append(*p, one)
	}
	return nil
}

type echoJoinReq struct {
	Pub core.PubKey `json:"pub"`
	WG  core.WGPub  `json:"wg_pub"`
	Ref string      `json:"ref,omitempty"`
}

type echoJoin struct {
	Pub   core.PubKey `json:"pub"`
	WG    core.WGPub  `json:"wg_pub"`
	Perms []string    `json:"perms"`
}

type echoTarget struct {
	Target core.PubKey `json:"target"`
}

type echoPresence struct {
	Pub          core.PubKey `json:"pub"`
	LastMsgTS    int64       `json:"last_msg_ts"`
	OfflineAfter int64       `json:"offline_after"`
}

func main() {
	var (
		data        = flag.String("data", "", "实例根目录（必填，两实例须不同）")
		seedPath    = flag.String("seed", "", "群种子 group.json（必填）")
		idPath      = flag.String("identity", "", "身份密钥文件（默认 <data>/identity.json）")
		listen      = flag.String("listen", "127.0.0.1:0", "UDP 监听地址")
		peers       peersFlag
		join        = flag.Bool("join", false, "启动后向 --peer 递交 join_req（本人非成员时）")
		autoApprove = flag.Bool("auto-approve", false, "具 carry 权限时：auto 群 join_req 种子哈希一致即自动签 join")
		heartbeat   = flag.Duration("heartbeat", 30*time.Second, "presence 心跳周期（0=关闭）")
		runFor      = flag.Duration("run-for", 0, "到期干净退出（0=到 stdin EOF）")
		offline     = flag.Int64("offline-after", int64(core.DefaultOfflineAfterMS), "本人 offline_after 毫秒")
	)
	flag.Var(&peers, "peer", "对端实例 ip:port（可重复/逗号分隔）")
	flag.Parse()

	if *data == "" || *seedPath == "" {
		fmt.Fprintln(os.Stderr, "usage: dmesh-echo --data <dir> --seed group.json [--join --peer ip:port | --auto-approve] ...")
		os.Exit(2)
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		fatal(err)
	}
	ip := *idPath
	if ip == "" {
		ip = filepath.Join(*data, "identity.json")
	}
	id, err := identity.LoadOrCreateIdentity(ip)
	if err != nil {
		fatal(fmt.Errorf("identity: %w", err))
	}
	cfg, err := identity.LoadGroupConfig(*seedPath)
	if err != nil {
		fatal(fmt.Errorf("seed: %w", err))
	}
	gid, err := identity.VerifyGroupConfig(cfg)
	if err != nil {
		fatal(fmt.Errorf("seed verification failed: %w", err))
	}
	seedRaw, _ := os.ReadFile(*seedPath)
	seedRef := fmt.Sprintf("%x", sha256.Sum256(seedRaw))

	logger := log.New(os.Stderr, "[echo] ", log.Ltime|log.Lmsgprefix)
	self := id.Pub()
	logger.Printf("identity %s group_id=%x", self, gid[:6])

	roster := group.New(cfg, group.Options{})

	bind, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fatal(err)
	}
	ep, err := transport.Listen(transport.Config{
		BindAddr: bind, Static: id.WGPrivate(), Identity: id,
		Roster: roster, GroupIDs: [][32]byte{gid},
	})
	if err != nil {
		fatal(fmt.Errorf("transport: %w", err))
	}
	logger.Printf("listening %s", ep.LocalAddr())

	e := &echoer{id: id, cfg: cfg, gid: gid, seedRef: seedRef, roster: roster,
		logger: logger, autoApprove: *autoApprove, offline: *offline}

	nt, err := neighbor.New(neighbor.Config{
		MinNeighbors: 1, MaxNeighbors: 8,
		LocalPub: self, Roster: roster,
		Dial:    dialer(ep),
		Receive: func(from core.PubKey, data []byte) { e.engine.Ingest(from, data) },
		OnJoin:  e.onJoin,
	})
	if err != nil {
		fatal(err)
	}
	e.nt = nt
	e.engine = message.NewEngine(gid, self, roster, msgTx{nt}, msgPeers{nt}, message.Handlers{
		Chat:    func(m core.Message) { fmt.Printf("CHAT %s: %s\n", short(m.Sender), string(m.Content)) },
		Appeal:  func(m core.Message) { fmt.Printf("APPEAL %s: %s\n", short(m.Sender), string(m.Content)) },
		JoinReq: e.handleJoinReq,
	})

	base := context.Background()
	if *runFor > 0 {
		var cancel context.CancelFunc
		base, cancel = context.WithTimeout(base, *runFor)
		defer cancel()
	}
	ctx, stop := signal.NotifyContext(base, os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, p := range peers {
		nt.AddCandidate(cfg.Creator, cfg.CreatorWG, p)
	}
	go func() { _ = nt.Run(ctx) }()
	go func() {
		for {
			t, err := ep.Accept(ctx)
			if err != nil {
				return
			}
			if err := nt.Add(t, t.PeerAddr().String()); err != nil {
				logger.Printf("inbound rejected: %v", err)
				_ = t.Close()
			} else {
				logger.Printf("inbound neighbor %s", t.RemotePub())
			}
		}
	}()
	if *heartbeat > 0 {
		go e.presenceLoop(ctx, *heartbeat)
	}
	if *join {
		go e.ensureJoined(ctx, self)
	}

	fmt.Println("# dmesh-echo ready — 输入行即发送，Ctrl-D/quit 退出")
	sc := bufio.NewScanner(os.Stdin)
	lines := make(chan string, 16)
	go func() {
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for {
		select {
		case <-ctx.Done():
			logger.Printf("shutdown")
			return
		case line, ok := <-lines:
			if !ok {
				// stdin 结束：交互模式退出；带 --run-for 的测试/后台模式继续跑。
				if *runFor > 0 {
					lines = nil
					continue
				}
				logger.Printf("stdin closed, exiting")
				return
			}
			line = strings.TrimSpace(line)
			if line == "quit" || line == "/quit" {
				return
			}
			if line == "" {
				continue
			}
			if err := e.sendText(line); err != nil {
				logger.Printf("send: %v", err)
			}
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}

func short(p core.PubKey) string {
	if len(p.Bytes) > 5 {
		return hex.EncodeToString(p.Bytes[:5])
	}
	return hex.EncodeToString(p.Bytes)
}

func dialer(ep *transport.Endpoint) func(neighbor.Candidate) (core.Tunnel, error) {
	return func(c neighbor.Candidate) (core.Tunnel, error) {
		addr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return ep.Dial(ctx, addr, transport.Remote{Identity: c.Pub, WG: c.WG})
	}
}

type msgTx struct{ nt *neighbor.Table }

func (t msgTx) Send(to core.PubKey, frame []byte) error { return t.nt.SendTo(to, frame) }

type msgPeers struct{ nt *neighbor.Table }

func (p msgPeers) Peers() []core.PubKey { return p.nt.PublicNeighbors() }

// ---------------------------------------------------------------------------

type echoer struct {
	id          *identity.Identity
	cfg         core.GroupConfig
	gid         [32]byte
	seedRef     string
	roster      *group.Roster
	nt          *neighbor.Table
	engine      *message.Engine
	logger      *log.Logger
	autoApprove bool
	offline     int64
}

func (e *echoer) onJoin(pub core.PubKey) {
	e.logger.Printf("neighbor joined %s (peers=%d)", pub, e.nt.Count())
}

// sendText：文本消息 + 配套 presence（PLAN v13：消息自带发送时间戳推进在场表）。
func (e *echoer) sendText(text string) error {
	if e.roster.TierOf(e.id.Pub()) < 0 {
		return errors.New("还不是成员（等 join 生效或去掉 --join 检查拉人端）")
	}
	ts := time.Now().UnixMilli()
	m := core.Message{Type: core.TypeText, Content: []byte(text), TSms: ts}
	signed, err := message.NewMessage(e.id, e.gid, &m, nil)
	if err != nil {
		return err
	}
	if _, err := e.engine.Publish(signed); err != nil {
		return err
	}
	return e.publishPresence(ts)
}

func (e *echoer) publishPresence(lastTS int64) error {
	ts := time.Now().UnixMilli()
	if lastTS > ts {
		lastTS = ts
	}
	return e.signAndPublish(core.TypePresence, echoPresence{Pub: e.id.Pub(), LastMsgTS: lastTS, OfflineAfter: e.offline}, ts)
}

func (e *echoer) presenceLoop(ctx context.Context, d time.Duration) {
	tk := time.NewTicker(d)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			_ = e.publishPresence(time.Now().UnixMilli())
		}
	}
}

func (e *echoer) signAndPublish(typ string, content any, tsMS int64) error {
	cb, err := group.EncodeEventContent(content)
	if err != nil {
		return err
	}
	m := core.Message{Type: typ, Content: cb, TSms: tsMS}
	if err := group.SignEvent(&m, e.id, e.gid); err != nil {
		return err
	}
	if message.IsRosterEvent(m.Type) {
		if err := e.roster.ApplyEvent(m); err != nil {
			return fmt.Errorf("local apply %s: %w", m.Type, err)
		}
	}
	_, err = e.engine.Publish(m)
	return err
}

// ensureJoined：连上任一邻居后，若本机不在白名单则向 carry 权限邻居递交 join_req
// （自签仅证明持私钥并触发中继，不构成入群 —— PLAN §名单表 join_req 行）。
func (e *echoer) ensureJoined(ctx context.Context, self core.PubKey) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		if _, ok := e.roster.Member(self); ok {
			return
		}
		if e.nt.Count() == 0 {
			continue
		}
		wg := e.id.WGPub()
		content := echoJoinReq{Pub: self, WG: wg, Ref: e.seedRef}
		if err := e.signAndPublish(core.TypeJoinReq, content, time.Now().UnixMilli()); err != nil {
			e.logger.Printf("join_req: %v", err)
			continue
		}
		e.logger.Printf("join_req 已递交，等待拉人者签 join…")
		// 等名单生效（对端 auto-approve 或人工批准后 flood 回来）
		for i := 0; i < 60; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			if _, ok := e.roster.Member(self); ok {
				e.logger.Printf("已入群（carry 者已签 join）")
				return
			}
		}
		e.logger.Printf("60s 内未获批准，重试 join_req")
	}
}

// handleJoinReq：本机具 carry 权限时受理；核对种子哈希（两种模式的共同前提）；
// auto 模式 + --auto-approve 即放行签 join。
func (e *echoer) handleJoinReq(m core.Message) {
	var c echoJoinReq
	if err := json.Unmarshal(m.Content, &c); err != nil || !c.Pub.Equal(m.Sender) || c.WG.IsZero() {
		return
	}
	if _, ok := e.roster.Member(m.Sender); ok || e.roster.IsBlacklisted(m.Sender) {
		return
	}
	fmt.Printf("JOINREQ %s seed_ref_match=%v\n", short(m.Sender), c.Ref == e.seedRef)
	if !e.autoApprove || e.cfg.Mode != core.ModeAuto || c.Ref != e.seedRef {
		return
	}
	if !e.roster.HasPerm(e.id.Pub(), core.PermCarry) {
		e.logger.Printf("本机无 carry 权限，无法批 join")
		return
	}
	perms := e.cfg.DefaultPerms
	if len(perms) == 0 {
		perms = []string{core.PermSpeak, core.PermReceive}
	}
	if err := e.signAndPublish(core.TypeJoin, echoJoin{Pub: m.Sender, WG: c.WG, Perms: perms}, time.Now().UnixMilli()); err != nil {
		e.logger.Printf("sign join: %v", err)
		return
	}
	fmt.Printf("JOINED %s\n", short(m.Sender))
}
