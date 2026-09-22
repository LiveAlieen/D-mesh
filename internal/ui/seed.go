package ui

import (
	"encoding/json"
	"fmt"

	"dmesh/internal/core"
)

// ParseSeed 把种子文件字节（group.json 原文）解析成 GroupConfig。
// 只做结构校验（mode/alg/关键字段非空），不验签。
func ParseSeed(raw []byte) (core.GroupConfig, error) {
	var cfg core.GroupConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("seed not valid JSON: %w", err)
	}
	if cfg.Name == "" {
		return cfg, fmt.Errorf("%w: seed missing name", core.ErrMalformed)
	}
	if cfg.Mode != core.ModeAuto && cfg.Mode != core.ModeVerify {
		return cfg, fmt.Errorf("%w: seed mode %q not auto|verify", core.ErrMalformed, cfg.Mode)
	}
	if cfg.GroupPub.IsZero() || cfg.Creator.IsZero() {
		return cfg, fmt.Errorf("%w: seed missing group_pub/creator", core.ErrMalformed)
	}
	if !core.ValidNetdiskMB(cfg.NetdiskMB) {
		return cfg, fmt.Errorf("%w: seed netdisk_mb %d out of range", core.ErrMalformed, cfg.NetdiskMB)
	}
	return cfg, nil
}

// VerifySeedConfig 执行拉人者的「核对种子哈希」前提（PLAN v9/M3 步骤 4）：
//  1. 重算 group_id = sha256(CanonicalJSON(cfg 且 CreatorSig 置空))；
//  2. sig_alg 一致性与已知性：cfg.Alg（CreatorSig 所用算法，v16）必须与
//     cfg.Creator.Alg 一致，且按 cfg.Alg 走 core.Verify 分派——本地未注册的
//     alg 由 core.Verify 返回 ErrUnknownAlg，一律视为核对失败，绝不误信；
//  3. 用创建者公钥验 CreatorSig（原文同为 GroupConfigSigPayload）——
//     有效种子只有创建者能签，payload 任何字段被篡改验签必失败。
//
// 任一不符即拒绝。返回重算出的 group_id；err != nil 表示核对不通过。纯函数，
// 可在测试中用注册进 core 注册表的假验签器覆盖。
func VerifySeedConfig(cfg core.GroupConfig) (groupID [32]byte, err error) {
	gid, err := core.GroupIDOf(cfg)
	if err != nil {
		return gid, fmt.Errorf("recompute group_id: %w", err)
	}
	payload, err := core.GroupConfigSigPayload(cfg)
	if err != nil {
		return gid, err
	}
	if cfg.Alg == "" || cfg.Alg != cfg.Creator.Alg {
		return gid, fmt.Errorf("%w: seed sig_alg %q != creator key sig_alg %q",
			core.ErrMalformed, cfg.Alg, cfg.Creator.Alg)
	}
	if err := core.Verify(core.PubKey{Alg: cfg.Alg, Bytes: cfg.Creator.Bytes}, payload, cfg.CreatorSig); err != nil {
		return gid, fmt.Errorf("creator_sig check failed: %w", err)
	}
	return gid, nil
}

// CheckSeedBytes 串起 ParseSeed + VerifySeedConfig + 与本群 group_id 比对，
// 供 /seedcheck 与入群面板使用。match=false 且 err=nil 表示「种子有效但不属于本群」。
func CheckSeedBytes(raw []byte, wantGroupID [32]byte) (cfg core.GroupConfig, match bool, err error) {
	cfg, err = ParseSeed(raw)
	if err != nil {
		return cfg, false, err
	}
	gid, err := VerifySeedConfig(cfg)
	if err != nil {
		return cfg, false, err
	}
	return cfg, gid == wantGroupID, nil
}
