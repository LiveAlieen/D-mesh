// Package netdisk 实现群网盘 RAID5（PLAN.md v14/v16 · M6）。
//
// 设计要点（与 PLAN「群网盘（RAID5，v14）」一节逐条对应）：
//
//  1. 配额来源：群配置 netdisk_mb（0=关闭、上限 256MB，越界的 netdisk 事件
//     直接拒绝，见 MakeNetdiskEvent / ValidateNetdiskContent）。每个成员在本地
//     预留一个定额目录（OpenDirStore），全员配额聚合成群共享网盘。
//  2. RAID5 布局：上传文件切定长条块（stripe），每 K 个数据块配 1 个 XOR 校验块
//     （RS K+1）；第 i 条的校验块落在 (i mod n) 号配额成员，轮转散布避免校验集中
//     （见 Layout.HostFor，pos 0 恒为校验块位）。出配额成员须 ≥3（MinHosts）。
//  3. 容错：任一单成员块丢失（离线/退群/kick）由同条其余块异或重建
//     （ReconstructStripe / Manager 降级读路径）；成员变动经 PlanRebalance
//     只补缺失块 + 按新布局重平衡（搬移是纯放置变更，不重写内容）。
//  4. 读写权限：仅出配额成员可写（CanWrite/Upload 强校验）；无配额成员可读不可写。
//  5. 完整性：每块携 {GroupID, 内容哈希 ContentHash, 条号 Stripe, 落盘成员 Host,
//     签发者 Proof}（core.Proof，raw=BlockSigPayload）；下载对每个候选源逐块验
//     哈希 + 验签 + 与 Manifest.BlockHashes 交叉比对，坏源回调 OnSuspect（差评）。
//
// 本包只 import dmesh/internal/core，与其他业务包互不 import；块在成员间的
// 收发经 Transport 接口由集成层（cmd/dmesh）桥接到 gossip/拉取通道。
package netdisk

import "errors"

// 参数硬约束。
const (
	// MinHosts 是组不成 RAID5 的下限：出配额成员须 ≥3（PLAN v14）。
	MinHosts = 3
	// DefaultBlockSize 是默认条块大小（64KiB，定长；末条数据块零填充）。
	DefaultBlockSize = 64 << 10
	// MaxNameLen 限制 Manifest.Name 长度，防塞大包。
	MaxNameLen = 512
)

// ParityPos 是校验块在条带内的固定逻辑位（数据块为 1..K），
// 轮转放置公式 HostFor(stripe,pos) 里第 i 条的校验落在 (i mod n) 号成员。
const ParityPos = 0

// 契约级错误：调用方用 errors.Is 判定。
var (
	// ErrNotEnoughHosts 表示出配额成员不足 3，组不成 RAID5：禁写，读仍可行。
	ErrNotEnoughHosts = errors.New("netdisk: not enough quota hosts (need >=3)")
	// ErrBadParams 表示条块参数（blockSize/K/pos 等）非法。
	ErrBadParams = errors.New("netdisk: bad raid5 params")
	// ErrNotWritable 表示无配额成员尝试写入（可读不可写）。
	ErrNotWritable = errors.New("netdisk: member without quota is read-only")
	// ErrQuotaFull 表示成员预留目录已满，块放不下。
	ErrQuotaFull = errors.New("netdisk: quota directory full")
	// ErrNotFound 表示本地/远端存储里没有该块。
	ErrNotFound = errors.New("netdisk: block not found")
	// ErrHostUnreachable 表示目标成员不可达（离线/无传输通道）。
	ErrHostUnreachable = errors.New("netdisk: host unreachable")
	// ErrHashMismatch 表示块内容与其 ContentHash（或 Manifest.BlockHashes）不符。
	ErrHashMismatch = errors.New("netdisk: content hash mismatch")
	// ErrBadBlock 表示块结构/proof 校验不过（伪签、字段不一致等），丢弃 + 差评。
	ErrBadBlock = errors.New("netdisk: invalid block")
	// ErrBadManifest 表示清单缺字段/自相矛盾/proof 无效。
	ErrBadManifest = errors.New("netdisk: invalid manifest")
	// ErrFileCorrupt 表示组装后的全文哈希与清单 ContentHash 不符（双块同损等）。
	ErrFileCorrupt = errors.New("netdisk: file failed final hash check")
	// ErrTooManyMissing 表示同条缺失 ≥2 块——RAID5 只容单块损失（PLAN 已知限制 8）。
	ErrTooManyMissing = errors.New("netdisk: too many blocks missing in stripe")
	// ErrReencodeRequired 表示成员缩容后条带槽位多于在世成员数：该文件需
	// 下载后按更小 K 重新上传（重编码），无法只靠搬移重平衡。
	ErrReencodeRequired = errors.New("netdisk: file stripe wider than surviving hosts, re-encode required")
	// ErrDegradedFrozen 表示降级模式下新写入被暂停（重平衡完成前应冻结写入）。
	ErrDegradedFrozen = errors.New("netdisk: writes paused while stripes are degraded")
	// ErrBadQuotaMB 表示 netdisk 事件的配额越界（0~256 之外）。
	ErrBadQuotaMB = errors.New("netdisk: netdisk_mb out of range")
	// ErrNilDependency 表示接线缺少必需依赖（Signer/Store 等）。
	ErrNilDependency = errors.New("netdisk: missing dependency")
)
