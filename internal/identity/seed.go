package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"dmesh/internal/core"
)

// SeedParams 是建群（newgroup）时的创世参数。
type SeedParams struct {
	Name         string   // 群名
	Mode         string   // core.ModeAuto / core.ModeVerify；空则默认 auto
	DefaultPerms []string // 成员默认权限；空则 [speak, receive]
	NetdiskMB    int      // 群网盘每人预留配额（0~256），0=关闭
	CreatedAt    int64    // Unix 毫秒；0=取当前时间
}

func (p SeedParams) normalized() SeedParams {
	if p.Mode == "" {
		p.Mode = core.ModeAuto
	}
	if len(p.DefaultPerms) == 0 {
		p.DefaultPerms = []string{core.PermSpeak, core.PermReceive}
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().UnixMilli()
	}
	return p
}

// NewSeed 为一次建群生成创世配置：
// 新生成一把本群唯一的群密钥（v12：与创建者密钥独立），组装 GroupConfig
// （含 mode/default_perms/netdisk_mb/sig_alg/creator/group_pub/creator_wg），
// 用创建者密钥自签 CreatorSig，并算出 group_id。
// 返回带签名的配置、群密钥（私钥由调用方决定是否备份）与 group_id。
func NewSeed(creator core.Signer, creatorWG core.WGPub, p SeedParams) (core.GroupConfig, *KeyPair, [32]byte, error) {
	if creator == nil {
		return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf("%w: nil creator signer", core.ErrMalformed)
	}
	if creatorWG.IsZero() {
		return core.GroupConfig{}, nil, [32]byte{}, fmt.Errorf("%w: creator wg_pub is zero", core.ErrMalformed)
	}
	gk, err := NewGroupKey()
	if err != nil {
		return core.GroupConfig{}, nil, [32]byte{}, err
	}
	p = p.normalized()
	cfg := core.GroupConfig{
		Name:         p.Name,
		Version:      1,
		Mode:         p.Mode,
		CreatedAt:    p.CreatedAt,
		GroupPub:     gk.Pub(),
		Creator:      creator.Pub(),
		CreatorWG:    creatorWG,
		Alg:          creator.Alg(),
		DefaultPerms: slices.Clone(p.DefaultPerms),
		NetdiskMB:    p.NetdiskMB,
	}
	if err := validateUnsigned(cfg); err != nil {
		return core.GroupConfig{}, nil, [32]byte{}, err
	}
	signed, id, err := SignGroupConfig(cfg, creator)
	if err != nil {
		return core.GroupConfig{}, nil, [32]byte{}, err
	}
	return signed, gk, id, nil
}

// validateUnsigned 校验除 creator_sig 外的全部创世字段。
func validateUnsigned(cfg core.GroupConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("%w: group name empty", core.ErrMalformed)
	}
	if cfg.Version == 0 {
		return fmt.Errorf("%w: group config version missing", core.ErrMalformed)
	}
	switch cfg.Mode {
	case core.ModeAuto, core.ModeVerify:
	case "":
		return fmt.Errorf("%w: group mode missing", core.ErrMalformed)
	default:
		return fmt.Errorf("%w: unknown mode %q (want auto|verify)", core.ErrMalformed, cfg.Mode)
	}
	if !core.ValidNetdiskMB(cfg.NetdiskMB) {
		return fmt.Errorf("%w: netdisk_mb %d out of [%d,%d]",
			core.ErrMalformed, cfg.NetdiskMB, core.NetdiskMinMB, core.NetdiskMaxMB)
	}
	if len(cfg.DefaultPerms) == 0 {
		return fmt.Errorf("%w: default_perms empty", core.ErrMalformed)
	}
	for _, p := range cfg.DefaultPerms {
		if !slices.Contains(core.AllPerms, p) {
			return fmt.Errorf("%w: unknown default perm %q", core.ErrMalformed, p)
		}
	}
	if cfg.Creator.IsZero() || len(cfg.Creator.Bytes) == 0 {
		return fmt.Errorf("%w: creator pubkey missing", core.ErrMalformed)
	}
	if cfg.GroupPub.IsZero() || len(cfg.GroupPub.Bytes) == 0 {
		return fmt.Errorf("%w: group_pub missing", core.ErrMalformed)
	}
	if cfg.CreatorWG.IsZero() {
		return fmt.Errorf("%w: creator wg_pub missing", core.ErrMalformed)
	}
	return nil
}

// SignGroupConfig 用创建者密钥对创世原文（CanonicalJSON 且 CreatorSig 置空）
// 自签 CreatorSig，并返回签名后的配置与 group_id。cfg.Alg 为空时取创建者算法。
func SignGroupConfig(cfg core.GroupConfig, creator core.Signer) (core.GroupConfig, [32]byte, error) {
	if creator == nil {
		return cfg, [32]byte{}, fmt.Errorf("%w: nil creator signer", core.ErrMalformed)
	}
	if cfg.Alg == "" {
		cfg.Alg = creator.Alg()
	}
	if !creator.Pub().Equal(cfg.Creator) {
		return cfg, [32]byte{}, fmt.Errorf("%w: creator pubkey %s != signer pubkey %s",
			core.ErrMalformed, cfg.Creator.String(), creator.Pub().String())
	}
	payload, err := core.GroupConfigSigPayload(cfg)
	if err != nil {
		return cfg, [32]byte{}, err
	}
	sig, err := creator.Sign(payload)
	if err != nil {
		return cfg, [32]byte{}, fmt.Errorf("identity: creator sign: %w", err)
	}
	cfg.CreatorSig = sig
	id, err := core.GroupIDOf(cfg)
	if err != nil {
		return cfg, [32]byte{}, err
	}
	return cfg, id, nil
}

// VerifyGroupConfig 是「有效种子判定」的唯一标准（拉人者核对种子哈希复用本实现）：
//  1. sig_alg 已知性：cfg.Alg / creator / group_pub 所用算法都必须在本地注册
//     （未注册一律拒绝，绝不误信）；
//  2. 结构合法性（ValidateGroupConfig）；
//  3. 用 creator 公钥验 CreatorSig（原文 = GroupConfigSigPayload）；
//  4. 重算 group_id = sha256(同一份原文)。
func VerifyGroupConfig(cfg core.GroupConfig) ([32]byte, error) {
	if err := ValidateGroupConfig(cfg); err != nil {
		return [32]byte{}, err
	}
	if !core.AlgRegistered(cfg.Alg) {
		return [32]byte{}, fmt.Errorf("%w: group config sig_alg %q", core.ErrUnknownAlg, cfg.Alg)
	}
	if !core.AlgRegistered(cfg.Creator.Alg) {
		return [32]byte{}, fmt.Errorf("%w: creator sig_alg %q", core.ErrUnknownAlg, cfg.Creator.Alg)
	}
	if cfg.Alg != cfg.Creator.Alg {
		return [32]byte{}, fmt.Errorf("%w: config sig_alg %q != creator key alg %q",
			core.ErrMalformed, cfg.Alg, cfg.Creator.Alg)
	}
	if !core.AlgRegistered(cfg.GroupPub.Alg) {
		return [32]byte{}, fmt.Errorf("%w: group_pub sig_alg %q", core.ErrUnknownAlg, cfg.GroupPub.Alg)
	}
	payload, err := core.GroupConfigSigPayload(cfg)
	if err != nil {
		return [32]byte{}, err
	}
	if err := core.Verify(cfg.Creator, payload, cfg.CreatorSig); err != nil {
		return [32]byte{}, fmt.Errorf("identity: creator_sig invalid: %w", err)
	}
	return core.GroupIDOf(cfg)
}

// ValidateGroupConfig 做与签名无关的结构校验：必填字段、mode 枚举、
// netdisk_mb 区间、default_perms 全部为已知权限位、group_id 域密钥非空。
func ValidateGroupConfig(cfg core.GroupConfig) error {
	if err := validateUnsigned(cfg); err != nil {
		return err
	}
	if len(cfg.CreatorSig) == 0 {
		return fmt.Errorf("%w: creator_sig missing", core.ErrMalformed)
	}
	return nil
}

// SaveGroupConfig 把种子（group.json）以缩进 JSON 写盘（0644，可分发）。
// 签名/哈希不受影响：原文永远经 core.GroupConfigSigPayload 规范化。
func SaveGroupConfig(path string, cfg core.GroupConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadGroupConfig 读取 group.json。
func LoadGroupConfig(path string) (core.GroupConfig, error) {
	var cfg core.GroupConfig
	if err := readJSONFile(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// VerifySeedFile 组合入口：读种子文件 → VerifyGroupConfig，返回 group_id。
// dmesh-tool verify 与「拉人者核对种子文件」都走这里。
func VerifySeedFile(path string) ([32]byte, error) {
	cfg, err := LoadGroupConfig(path)
	if err != nil {
		return [32]byte{}, err
	}
	return VerifyGroupConfig(cfg)
}
