// dmesh-tool 是 D-Mesh 的建群/造种子/密钥调试工具（M0）。
//
// 子命令：
//
//	dmesh-tool genkey   -out identity.json           生成成员身份密钥（ed25519 + X25519）
//	dmesh-tool newgroup -name 群名 [-identity ...]   新建群：生成群密钥→签创世配置→
//	                                                 写 group.json + group.torrent + 磁力链
//	dmesh-tool verify   [-group group.json] [-expect <group_id hex>]
//	                                                 重算 group_id + 验 creator_sig +
//	                                                 sig_alg 已知性（拉人者核对种子同一实现）
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"dmesh/internal/core"
	"dmesh/internal/identity"
)

const usage = `usage:
  dmesh-tool genkey   [-out identity.json] [-force]
  dmesh-tool newgroup [-name NAME] [-identity PATH] [-mode auto|verify]
                      [-perms speak,receive] [-netdisk 0] [-out group] [-groupkey-out ""] [-force]
  dmesh-tool verify   [-group group.json] [-expect GROUP_ID_HEX]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = runGenkey(os.Args[2:])
	case "newgroup":
		err = runNewgroup(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "identity.json", "身份密钥输出路径")
	force := fs.Bool("force", false, "允许覆盖已存在文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s 已存在（-force 覆盖）", *out)
	}
	id, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	if err := identity.SaveIdentity(*out, id); err != nil {
		return err
	}
	fmt.Printf("identity saved: %s\n", *out)
	fmt.Printf("  sig_alg: %s\n", id.Alg())
	fmt.Printf("  pub:     %s\n", hex.EncodeToString(id.Pub().Bytes))
	fmt.Printf("  wg_pub:  %s\n", id.WGPub().String())
	return nil
}

func runNewgroup(args []string) error {
	fs := flag.NewFlagSet("newgroup", flag.ExitOnError)
	name := fs.String("name", "dmesh-group", "群名")
	ident := fs.String("identity", "identity.json", "创建者身份密钥文件（不存在则新生成）")
	mode := fs.String("mode", core.ModeAuto, "入群模式 auto|verify")
	perms := fs.String("perms", "speak,receive", "成员默认权限，逗号分隔")
	netdisk := fs.Int("netdisk", 0, "群网盘每人预留 MB（0~256，0=关闭）")
	out := fs.String("out", "group", "输出基名（写 <out>.json 与 <out>.torrent）")
	gkOut := fs.String("groupkey-out", "", "可选：群密钥私钥另存路径")
	force := fs.Bool("force", false, "允许覆盖已存在种子")
	if err := fs.Parse(args); err != nil {
		return err
	}
	jsonPath, torrentPath := *out+".json", *out+".torrent"
	if !_forceOK(*force, jsonPath, torrentPath) {
		return fmt.Errorf("%s / %s 已存在（-force 覆盖）", jsonPath, torrentPath)
	}
	creator, err := identity.LoadOrCreateIdentity(*ident)
	if err != nil {
		return fmt.Errorf("load/create creator identity: %w", err)
	}
	cfg, groupKey, id, err := identity.NewSeed(creator, creator.WGPub(), identity.SeedParams{
		Name:         *name,
		Mode:         *mode,
		DefaultPerms: splitPerms(*perms),
		NetdiskMB:    *netdisk,
	})
	if err != nil {
		return err
	}
	if err := identity.SaveGroupConfig(jsonPath, cfg); err != nil {
		return err
	}
	seedBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	t, err := identity.BuildTorrent(filepath.Base(jsonPath), seedBytes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(torrentPath, t.Meta, 0o644); err != nil {
		return err
	}
	if *gkOut != "" {
		if err := identity.SaveKeyPair(*gkOut, groupKey); err != nil {
			return err
		}
	}
	// 建完立刻自检（与 verify 同一实现）。
	if _, err := identity.VerifyGroupConfig(cfg); err != nil {
		return fmt.Errorf("self-check failed: %w", err)
	}
	fmt.Printf("group created: %s\n", cfg.Name)
	fmt.Printf("  group_id:    %s\n", hex.EncodeToString(id[:]))
	fmt.Printf("  mode:        %s\n", cfg.Mode)
	fmt.Printf("  netdisk_mb:  %d\n", cfg.NetdiskMB)
	fmt.Printf("  group_pub:   %s\n", hex.EncodeToString(cfg.GroupPub.Bytes))
	fmt.Printf("  creator:     %s (%s)\n", hex.EncodeToString(cfg.Creator.Bytes), cfg.Alg)
	fmt.Printf("  seed:        %s\n  torrent:     %s\n", jsonPath, torrentPath)
	fmt.Printf("  magnet:      %s\n", t.Magnet())
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	group := fs.String("group", "group.json", "种子文件路径")
	expect := fs.String("expect", "", "可选：期望的 group_id（hex），不一致即失败")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.VerifySeedFile(*group)
	if errors.Is(err, core.ErrUnknownAlg) {
		fmt.Fprintln(os.Stderr, "FAIL: sig_alg 本地未注册（拒绝采纳，绝不误信）:", err)
		return err
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL: 种子无效:", err)
		return err
	}
	got := hex.EncodeToString(id[:])
	if *expect != "" {
		want, err := hex.DecodeString(strings.ToLower(*expect))
		if err != nil || len(want) != len(id) {
			return fmt.Errorf("bad -expect %q: want %d-byte hex group_id", *expect, len(id))
		}
		if hex.EncodeToString(want) != got {
			return fmt.Errorf("group_id mismatch: seed=%s expect=%s", got, *expect)
		}
	}
	cfg, err := identity.LoadGroupConfig(*group)
	if err != nil {
		return err
	}
	fmt.Printf("OK: seed valid\n")
	fmt.Printf("  group_id:  %s\n", got)
	fmt.Printf("  name:      %s\n", cfg.Name)
	fmt.Printf("  mode:      %s\n", cfg.Mode)
	fmt.Printf("  sig_alg:   %s\n", cfg.Alg)
	fmt.Printf("  creator:   %s\n", hex.EncodeToString(cfg.Creator.Bytes))
	return nil
}

func splitPerms(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func _forceOK(force bool, paths ...string) bool {
	if force {
		return true
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return false
		}
	}
	return true
}
