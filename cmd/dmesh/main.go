// dmesh 是 D-Mesh 的主客户端单二进制入口（PLAN v16 · 集成接线层）。
//
// 本包只做「依赖注入」：把 internal 各包按 PLAN 的接线纪律组装成一个
// 运行中的群节点，不含任何协议逻辑本体：
//
//	identity(密钥/种子验签) → core.Register(ed25519, 经 identity 包 init 自动注册)
//	→ 先 VerifySeedConfig 载入并验证创世配置（关键顺序：种子未载入前不得接受任何名单事件）
//	→ store(JSONL+SQLite) 打开 + 恢复双名单
//	→ transport(黑名单准入 + 定向申诉例外，用现成 Roster 注入) → neighbor(邻居表)
//	→ message(验证/去重/flood) → ui(Ebitengine 原生窗口 GUI / 无头模式)
//	→ backfill(重上线自动回灌 + /audit)、spam(限速/评分/本地屏蔽)、netdisk(仅 netdisk_mb>0)
//
// 一进程一群：--data 指定实例根目录（多实例隔离），群目录为 <data>/groups/<group_id>/。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"dmesh/internal/store"
	"dmesh/internal/ui"
)

// opts 是命令行配置。
type opts struct {
	data        string        // --data 实例根目录（必填，多实例隔离）
	seed        string        // --seed group.json 创世种子文件（首启必填；之后从 <data> 内副本载入）
	torrent     string        // --torrent 发现用 .torrent（默认取 seed 同名 .torrent）
	group       string        // --group group_id hex 前缀：无 --seed 时在 --data 下选群
	identity    string        // --identity 身份密钥文件（默认 <data>/identity.json）
	listen      string        // --listen UDP 监听地址（默认 0.0.0.0:0 随机端口）
	peers       stringList    // --peer ip:port 手工候选端点（可重复；走种子创建者身份）
	noUI        bool          // --no-ui 无头模式（或 stdin 非交互时自动进入）
	noDiscovery bool          // --no-discovery 关闭 BT/DHT 发现
	autoApprove bool          // --auto-approve auto 群且种子哈希核对通过时自动签 join
	minN        int           // --min-neighbors
	maxN        int           // --max-neighbors
	offline     int64         // --offline-after ms（本人自报离线阈值）
	heartbeat   time.Duration // --heartbeat presence 心跳周期
	scope       string        // --backfill-scope incremental|all|recent|none
	runFor      time.Duration // --run-for 到期干净退出（0=常驻；冒烟测试用）
}

// stringList 支持重复 flag（--peer）。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("empty peer address")
	}
	if _, err := net.ResolveUDPAddr("udp", v); err != nil {
		return fmt.Errorf("bad peer %q: %w", v, err)
	}
	*s = append(*s, v)
	return nil
}

func main() {
	var o opts
	flag.StringVar(&o.data, "data", "", "实例根目录（必填，多实例隔离）")
	flag.StringVar(&o.seed, "seed", "", "群种子文件 group.json（首次启动必填，之后自动从 <data> 内副本载入）")
	flag.StringVar(&o.torrent, "torrent", "", "发现用 .torrent 文件（默认取 --seed 同名 .torrent）")
	flag.StringVar(&o.group, "group", "", "group_id hex 前缀：不带 --seed 时在 --data 下选择该群")
	flag.StringVar(&o.identity, "identity", "", "身份密钥文件（默认 <data>/identity.json）")
	flag.StringVar(&o.listen, "listen", "0.0.0.0:0", "UDP 监听地址")
	flag.Var(&o.peers, "peer", "手工邻居候选 ip:port（可重复；按种子创建者身份握手），与 --seed 配合可完全离线联调")
	flag.BoolVar(&o.noUI, "no-ui", false, "无头模式（聊天打到 stdout；stdin 非终端时自动开启）")
	flag.BoolVar(&o.noDiscovery, "no-discovery", false, "关闭 BT/DHT 发现（只用 --peer 手工候选）")
	flag.BoolVar(&o.autoApprove, "auto-approve", false, "auto 群：join_req 种子哈希核对通过后自动签 join")
	flag.IntVar(&o.minN, "min-neighbors", 3, "活跃邻居下限")
	flag.IntVar(&o.maxN, "max-neighbors", 8, "活跃邻居上限")
	flag.Int64Var(&o.offline, "offline-after", int64(core.DefaultOfflineAfterMS), "本人离线阈值毫秒（v13.1，自签分发）")
	flag.DurationVar(&o.heartbeat, "heartbeat", 60*time.Second, "presence 心跳周期")
	flag.StringVar(&o.scope, "backfill-scope", "incremental", "回灌范围 incremental|all|recent|none")
	flag.DurationVar(&o.runFor, "run-for", 0, "运行该时长后干净退出（0=常驻，冒烟测试用）")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dmesh --data <dir> [--seed group.json] [--peer ip:port] [--no-ui] ...")
		flag.PrintDefaults()
	}
	flag.Parse()

	if o.data == "" {
		fmt.Fprintln(os.Stderr, "error: --data 必填（多实例隔离运行目录）")
		os.Exit(2)
	}
	if err := run(&o); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(o *opts) error {
	// 0. 日志：GUI 模式写文件避免污染界面；无头模式走 stderr。
	if err := os.MkdirAll(o.data, 0o700); err != nil {
		return fmt.Errorf("mkdir --data: %w", err)
	}
	logger := log.New(os.Stderr, "[dmesh] ", log.LstdFlags|log.Lmsgprefix)
	if !o.noUI && stdinInteractive() {
		lf, err := os.OpenFile(filepath.Join(o.data, "dmesh.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			logger = log.New(lf, "[dmesh] ", log.LstdFlags|log.Lmsgprefix)
			defer lf.Close()
		}
	}

	// 0.5 外置语言目录（v21）：<data>/langs/*.json 叠加进内置 go:embed 词条，
	//     新文件=新语言、同名文件=覆盖词条——加语言只放文件，不改代码不重编译。
	if err := ui.LoadLangDir(filepath.Join(o.data, "langs")); err != nil {
		logger.Printf("langs: %v", err)
	}

	// 0.6 外置主题目录（v24）：<data>/themes/*.json 叠加进内置 go:embed 主题，
	//     新文件=新主题、同名文件=按 token 覆盖——加主题只放文件不改代码。
	//     GUI 与 headless 都加载（headless 只是不读 ui_prefs.json 的主题偏好）。
	if err := ui.LoadThemeDir(filepath.Join(o.data, "themes")); err != nil {
		logger.Printf("themes: %v", err)
	}

	// 1. 身份密钥（identity 包 import/init 即把 ed25519 验签注册进 core.Register，
	//    即 core 的算法注册表入口；group.RegisterEd25519Verifier 幂等再兜一次）。
	idPath := o.identity
	if idPath == "" {
		idPath = filepath.Join(o.data, "identity.json")
	}
	id, err := identity.LoadOrCreateIdentity(idPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	group.RegisterEd25519Verifier()

	// 2. 关键顺序：先加载并验证 seed/群配置（VerifyGroupConfig = 重算 group_id +
	//    验 creator_sig，验签按 cfg.Alg 分派到 core 注册表），之后才允许 roster
	//    接受任何名单事件（group.New 无 SetSeed 路径，种子必须先于事件进入状态机）。
	cfg, seedBytes, gid, err := loadAndVerifySeed(o, id, logger)
	if err != nil {
		return err
	}
	dirName := hex.EncodeToString(gid[:])
	groupDir := filepath.Join(o.data, "groups", dirName)
	if err := os.MkdirAll(groupDir, 0o700); err != nil {
		return err
	}
	// 种子副本落盘（供重启与 join_req 的 seed ref 哈希核对）。
	if err := ensureSeedCopies(groupDir, o, seedBytes); err != nil {
		return err
	}
	logger.Printf("identity %s (alg=%s)", id.Pub(), id.Alg())
	logger.Printf("group %q group_id=%s mode=%s netdisk_mb=%d", cfg.Name, dirName, cfg.Mode, cfg.NetdiskMB)

	// 3. 存储：JSONL(真相源) + SQLite(索引)。
	st, err := store.Open(groupDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	if _, err := st.PutGroupConfig(cfg); err != nil {
		st.Close()
		return fmt.Errorf("cache group config: %w", err)
	}

	// 4. 名单状态机：种子先载入（见上），再从存储恢复已验证的双名单副本。
	roster := group.New(cfg, group.Options{})
	members, banned, owner, err := st.RosterSnapshot()
	if err != nil {
		st.Close()
		return fmt.Errorf("restore roster snapshot: %w", err)
	}
	presences, err := st.Presences()
	if err != nil {
		st.Close()
		return fmt.Errorf("restore presence: %w", err)
	}
	if len(members) > 0 || len(banned) > 0 {
		if err := roster.LoadSnapshot(members, banned, presences, owner, cfg.NetdiskMB); err != nil {
			logger.Printf("WARN: restore roster snapshot rejected: %v（回退到仅创世状态）", err)
		}
	}

	// 5. 组装节点（transport/neighbor/message/backfill/spam/netdisk/ui 接线见 node.go）。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if o.runFor > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.runFor)
		defer cancel()
	}
	n, err := newNode(ctx, o, logger, id, cfg, gid, seedBytes, st, roster)
	if err != nil {
		st.Close()
		return err
	}
	defer n.shutdown()

	// 6. 事件循环：GUI（Ebitengine 原生窗口）或无头。
	errCh := make(chan error, 1)
	go func() { errCh <- n.serve(ctx) }()

	if n.interactive {
		err = n.runGUI()
	} else {
		go n.headlessCommands(ctx) // 无头脚本通道：每行文本=发言，"/…" 走 ui.ParseCommand
		select {
		case <-ctx.Done():
		case err = <-errCh:
		}
	}
	if err != nil {
		cancel()
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// loadAndVerifySeed 定位并验证创世种子：
//   - 有 --seed：读文件 → identity.VerifyGroupConfig（重算 group_id + 验 creator_sig，
//     含 cfg.Alg 分派；未知 alg 直接拒绝）→ 与 --group（若给）比对；
//   - 无 --seed：扫 <data>/groups/ 下的 seed.json 副本（--group hex 前缀选群；
//     恰一个群时可自动选中），同样全量验证后才可用。
func loadAndVerifySeed(o *opts, id *identity.Identity, logger *log.Logger) (core.GroupConfig, []byte, [32]byte, error) {
	var raw []byte
	var path string
	switch {
	case o.seed != "":
		path = o.seed
	default:
		cands, err := filepath.Glob(filepath.Join(o.data, "groups", "*", "seed.json"))
		if err != nil {
			return core.GroupConfig{}, nil, [32]byte{}, err
		}
		if o.group != "" {
			var hit []string
			for _, c := range cands {
				if strings.HasPrefix(filepath.Base(filepath.Dir(c)), strings.ToLower(o.group)) {
					hit = append(hit, c)
				}
			}
			cands = hit
		}
		if len(cands) == 0 {
			return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf(
				"no --seed given and no verified seed copy under %s (首次启动必须提供 --seed group.json)", o.data)
		}
		if len(cands) > 1 {
			return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf(
				"multiple groups under --data, use --group <group_id_hex> 或 --seed 指定: %s", strings.Join(cands, ", "))
		}
		path = cands[0]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf("read seed %s: %w", path, err)
	}
	cfg, err := identity.LoadGroupConfig(path)
	if err != nil {
		return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf("parse seed %s: %w", path, err)
	}
	gid, err := identity.VerifyGroupConfig(cfg)
	if errors.Is(err, core.ErrUnknownAlg) {
		return cfg, raw, gid, fmt.Errorf("seed sig_alg %q 本地未注册（未知算法一律拒绝采纳）: %w", cfg.Alg, err)
	}
	if err != nil {
		return cfg, raw, gid, fmt.Errorf("seed INVALID (group_id/creator_sig 校验失败): %w", err)
	}
	if !cfg.Creator.Equal(id.Pub()) {
		logger.Printf("本机身份不是该群创建者/成员，入群需由具 carry 权限者签 join（join_req 将自动递交）")
	}
	return cfg, raw, gid, nil
}

// ensureSeedCopies 把种子原文与 .torrent 复制进群目录（幂等；内容变化才覆盖）。
func ensureSeedCopies(groupDir string, o *opts, seedBytes []byte) error {
	dst := filepath.Join(groupDir, "seed.json")
	if cur, err := os.ReadFile(dst); err != nil || !equalBytes(cur, seedBytes) {
		if err := os.WriteFile(dst, seedBytes, 0o600); err != nil {
			return err
		}
	}
	if o.seed == "" {
		return nil // 非首启：副本即事实源
	}
	tor := o.torrent
	if tor == "" {
		tor = strings.TrimSuffix(o.seed, filepath.Ext(o.seed)) + ".torrent"
	}
	tb, err := os.ReadFile(tor)
	if err != nil {
		return nil // 发现层降级为 --peer/PEX，不算致命
	}
	dstT := filepath.Join(groupDir, "seed.torrent")
	if cur, err := os.ReadFile(dstT); err != nil || !equalBytes(cur, tb) {
		if err := os.WriteFile(dstT, tb, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	sa, sb := sha256.Sum256(a), sha256.Sum256(b)
	return sa == sb
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func stdinInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// signals 交给 serve() 使用（干净退出）。
func notifyShutdown(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}
