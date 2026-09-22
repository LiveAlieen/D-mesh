package ui

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"dmesh/internal/core"
)

// CmdKind 是输入行解析后的命令类别。
type CmdKind int

const (
	CmdText CmdKind = iota // 非斜杠开头：普通发言
	CmdHelp
	CmdClear
	CmdQuit
	CmdHide       // /hide <msg_id>
	CmdAudit      // /audit
	CmdRemove     // /remove 本人退群（自签 remove，v15）
	CmdKick       // /kick <pub>
	CmdUnban      // /unban <pub>
	CmdPerms      // /perms <pub> <p1,p2,...>
	CmdGrantAdmin // /grant-admin <pub>
	CmdRevokeAdmin
	CmdTransfer
	CmdOfflineAfter // /offline-after <ms> 本人自报在场阈值（v13.1）
	CmdSeedCheck    // /seedcheck <path> 核对种子文件哈希与创世配置（M3 入群前提）
	CmdNetdisk      // /netdisk 打开面板
	CmdNDStatus     // /netdisk status
	CmdNDUpload     // /netdisk upload <path>
	CmdNDDownload   // /netdisk download <name>
	CmdNDDelete     // /netdisk delete <name>
	CmdNDSet        // /netdisk set <MB> 签 netdisk 事件改配额
)

// Command 是解析结果：Kind + 按类别有效的参数字段。
type Command struct {
	Kind   CmdKind
	Text   string      // CmdText
	MsgID  string      // CmdHide
	Target core.PubKey // kick/unban/perms/grant/revoke/transfer
	Perms  []string    // CmdPerms
	MB     int         // CmdNDSet
	Millis int64       // CmdOfflineAfter
	Path   string      // CmdNDUpload / CmdSeedCheck
	Name   string      // CmdNDDownload / CmdNDDelete
}

// ParseCommand 把一行输入解析成 Command；以 '/' 开头但不是已知命令时报错。
// 纯函数，不触碰任何 IO，table-driven 测试覆盖。
func ParseCommand(line string) (Command, error) {
	s := strings.TrimSpace(line)
	if s == "" {
		return Command{}, fmt.Errorf("empty input")
	}
	if !strings.HasPrefix(s, "/") {
		return Command{Kind: CmdText, Text: s}, nil
	}
	fields := strings.Fields(s)
	name := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	rest := strings.TrimSpace(strings.TrimPrefix(s, fields[0]))

	switch name {
	case "help", "h":
		return Command{Kind: CmdHelp}, nil
	case "clear":
		return Command{Kind: CmdClear}, nil
	case "quit", "exit":
		return Command{Kind: CmdQuit}, nil
	case "hide":
		if rest == "" {
			return Command{}, fmt.Errorf("usage: /hide <msg_id>")
		}
		return Command{Kind: CmdHide, MsgID: rest}, nil
	case "audit":
		return Command{Kind: CmdAudit}, nil
	case "remove":
		return Command{Kind: CmdRemove}, nil
	case "kick":
		t, err := parseTarget(rest, "kick")
		return Command{Kind: CmdKick, Target: t}, err
	case "unban":
		t, err := parseTarget(rest, "unban")
		return Command{Kind: CmdUnban, Target: t}, err
	case "perms":
		return parsePermsCmd(rest)
	case "grant-admin":
		t, err := parseTarget(rest, "grant-admin")
		return Command{Kind: CmdGrantAdmin, Target: t}, err
	case "revoke-admin":
		t, err := parseTarget(rest, "revoke-admin")
		return Command{Kind: CmdRevokeAdmin, Target: t}, err
	case "transfer":
		t, err := parseTarget(rest, "transfer")
		return Command{Kind: CmdTransfer, Target: t}, err
	case "offline-after":
		return parseOfflineAfter(rest)
	case "seedcheck":
		if rest == "" {
			return Command{}, fmt.Errorf("usage: /seedcheck <path>")
		}
		return Command{Kind: CmdSeedCheck, Path: rest}, nil
	case "netdisk", "nd":
		return parseNetdisk(s, rest)
	default:
		return Command{}, fmt.Errorf("unknown command %q (try /help)", "/"+name)
	}
}

func parseTarget(rest, cmd string) (core.PubKey, error) {
	if rest == "" {
		return core.PubKey{}, fmt.Errorf("usage: /%s <pubkey>", cmd)
	}
	return ParsePubKey(rest)
}

// ParsePubKey 解析 "alg:hex" 或裸 hex（默认 ed25519）形式的公钥。
// 注意：本函数只做结构解析，不拒绝未注册算法——按 v16 规则，未注册 alg 在
// 验签（core.Verify）处必然失败并被拒，UI 层无需重复判定。
func ParsePubKey(s string) (core.PubKey, error) {
	alg := core.SigEd25519
	body := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		alg = core.SigAlg(s[:i])
		body = s[i+1:]
	}
	if body == "" {
		return core.PubKey{}, fmt.Errorf("empty pubkey hex")
	}
	b, err := hex.DecodeString(body)
	if err != nil {
		return core.PubKey{}, fmt.Errorf("pubkey not hex: %v", err)
	}
	if len(b) == 0 {
		return core.PubKey{}, fmt.Errorf("empty pubkey")
	}
	return core.PubKey{Alg: alg, Bytes: b}, nil
}

func parsePermsCmd(rest string) (Command, error) {
	fields := strings.Fields(rest)
	if len(fields) != 2 {
		return Command{}, fmt.Errorf("usage: /perms <pubkey> <p1,p2,...>")
	}
	t, err := ParsePubKey(fields[0])
	if err != nil {
		return Command{}, err
	}
	perms, err := ParsePermList(fields[1])
	if err != nil {
		return Command{}, err
	}
	return Command{Kind: CmdPerms, Target: t, Perms: perms}, nil
}

// ParsePermList 解析逗号分隔权限集，逐项对照 core.AllPerms 校验并去重。
func ParsePermList(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("empty perm name in list")
		}
		if !validPerm(p) {
			return nil, fmt.Errorf("unknown perm %q (known: %s)", p, strings.Join(core.AllPerms, ", "))
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty perm list")
	}
	return out, nil
}

func validPerm(p string) bool {
	for _, k := range core.AllPerms {
		if p == k {
			return true
		}
	}
	return false
}

func parseOfflineAfter(rest string) (Command, error) {
	fields := strings.Fields(rest)
	if len(fields) != 1 {
		return Command{}, fmt.Errorf("usage: /offline-after <ms>")
	}
	ms, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Command{}, fmt.Errorf("offline-after must be integer ms")
	}
	if ms <= 0 {
		return Command{}, fmt.Errorf("offline-after must be > 0 ms")
	}
	return Command{Kind: CmdOfflineAfter, Millis: ms}, nil
}

func parseNetdisk(full, rest string) (Command, error) {
	if rest == "" {
		return Command{Kind: CmdNetdisk}, nil
	}
	fields := strings.Fields(rest)
	sub := strings.ToLower(fields[0])
	arg := ""
	if len(fields) > 1 {
		// 保留原始大小写与完整剩余（文件名/路径可含非 hex 字符）
		idx := strings.Index(full, rest)
		argTail := full[idx+len(fields[0]):]
		arg = strings.TrimSpace(argTail)
	}
	switch sub {
	case "status":
		return Command{Kind: CmdNDStatus}, nil
	case "upload":
		if arg == "" {
			return Command{}, fmt.Errorf("usage: /netdisk upload <path>")
		}
		return Command{Kind: CmdNDUpload, Path: arg}, nil
	case "download":
		if arg == "" {
			return Command{}, fmt.Errorf("usage: /netdisk download <name>")
		}
		return Command{Kind: CmdNDDownload, Name: arg}, nil
	case "delete", "rm":
		if arg == "" {
			return Command{}, fmt.Errorf("usage: /netdisk delete <name>")
		}
		return Command{Kind: CmdNDDelete, Name: arg}, nil
	case "set":
		fields2 := strings.Fields(rest)
		if len(fields2) != 2 {
			return Command{}, fmt.Errorf("usage: /netdisk set <MB>")
		}
		mb, err := strconv.Atoi(fields2[1])
		if err != nil {
			return Command{}, fmt.Errorf("netdisk quota must be integer MB")
		}
		if !core.ValidNetdiskMB(mb) {
			return Command{}, fmt.Errorf("netdisk quota out of range %d..%d MB", core.NetdiskMinMB, core.NetdiskMaxMB)
		}
		return Command{Kind: CmdNDSet, MB: mb}, nil
	default:
		return Command{}, fmt.Errorf("unknown /netdisk subcommand %q", sub)
	}
}
