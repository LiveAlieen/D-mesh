# D-Mesh 群网盘扩展计划（RAID5 over 成员预留配额）

> 本文是从 `PLAN.md` 中**单独拎出**的群网盘专项计划。网盘是**可选扩展**：群配置
> `netdisk_mb = 0` 时整套装配都不发生，核心群聊（发现/传输/双名单/消息/回灌）
> 与网盘零耦合。凡本文与 `PLAN.md` 冲突，以本文为准（网盘范围内）。

- **拆分依据（用户原话，2026-09-27）**：「将网盘计划单独拎出来写成扩展的md计划」
- 本文性质：**文档结构调整 + 实现现状对账 + 后续排期**。不改协议、不改代码语义。
- 代码归属：`internal/netdisk`（纯逻辑，只 import `internal/core`）+ `cmd/dmesh/netdisk.go`
  与 `cmd/dmesh/rpc.go`（集成层接线与线上帧）+ `internal/ui`（5·网盘 面板）。

---

## 1. 设计沿革（原话口径，勿回退）

| 版 | 定稿内容 |
| --- | --- |
| v14 | 「群主可配置每一个群成员需要预留多少空间作为群网盘组成 RAID5，默认为 0 最高 256mb」→ 群配置字段 `netdisk_mb`（0=关闭、上限 256、越界事件直接拒收）；各端本地划定额预留目录，聚合成分条 + 1 个 XOR 校验块的 RAID5（RS k+1），校验轮转散布；参与须 ≥3 个出空间成员；单块容错自动重建；出配额才可写、无配额只读 |
| v17 | 网盘清单**严禁借 `hide` 承载**（`hide` 语义锁死 `{target_msg_id}`），改走独立的签名清单通道 |
| v25 | 网盘操作全面 GUI 化：上传=原生文件选择框、配额=数字输入框（0~256 越界即时报错）、下载/删除=文件行按钮、刷新=按钮；GUI 内不再解析 `/netdisk` |
| v26 | 消息归一化：配额变更 = `cmd/netdisk`，清单 = `ext/manifest`，与聊天/命令同一信封（时间 + 三类正文 + 签名）；配额载荷契约定为 `{"netdisk":{"mb":N}}` |

## 2. 协议面（跨包字节契约，改动须同步契约测试）

- **群配置**：`GroupConfig.netdisk_mb`，值域 `0..256`（`core.ValidNetdiskMB`）。初始值由
  创建者在种子里写死；运行期只能由 `cmd/netdisk` 事件改。
- **命令 `cmd/netdisk`**：body = `core.MakeBody("netdisk", {"mb":N})`，即
  `{"netdisk":{"mb":6}}`。生产端 `netdisk.NetdiskEventBody`、权威解码端
  `group.ApplyEvent`，两侧结构必须逐字一致（`internal/group/events_test.go`、
  `internal/group/registry_contract_test.go` 钉住）。**教训**：v14~v25 期间生产端
  多写 `kind` 字段、配额写成 `netdisk_mb`，被严格解码判 unknown field，
  导致「改配额」全网从未生效过（v25 GUI 首次点出来）。
- **权限位**：成员可写另受名单权限 `netdisk` 位约束（写路径 = 出配额 **且** 有写权限）。
- **扩展 `ext/manifest`**：一条上传清单 = 一条 `core.Message{Kind:"ext"}`，
  body 唯一键 `manifest`，载荷 = 清单原文；由 `Manager.ManifestMessage` 构造
  （`internal/netdisk/manager.go:657`）、`ManifestFromMessage` 消费（同文件 `:690`）。
  清单原文自签（`Proof`，签名域 = CanonicalJSON 去掉 proof 与 creator 后的字段集）。
- **块级 RPC**：邻居隧道上的 JSON 请求/应答帧 `nd.put` / `nd.get` / `nd.list` /
  `nd.del` / `nd.manifest`（`cmd/dmesh/rpc.go:31-52`），由 `netdisk.Transport`
  抽象桥接（`manager.go:25`），超时 15s 帧 / 30s 调用 / 10s 清单泛洪。

## 3. 数据布局

- 条块定长 `DefaultBlockSize = 64 KiB`，末条零填充；条带内 `pos 0` 恒为校验块位、
  数据块 `1..K`（`netdisk.go:29-37`）。
- 默认 `K = MinHosts-1 = 2`（两条数据 + 一校验，`manager.go:70`）。
- 放置：`host = hosts[(pos + stripe) mod n]`，`hosts` 为出配额成员按公钥升序
  （`raid5.go:141,166`）——校验块随条带轮转，不集中在同一成员。
- `n < 3` → `ErrNotEnoughHosts`：**禁写**，读与重建仍按清单冻结的写入时布局工作。

## 4. 本地存储

- 配额目录：`<data>/groups/<gid hex>/netdisk_quota/`，一块一文件
  `fileID/%09d_%03d.blk`（块的完整 JSON 序列化）；清单落在同级 `manifests/<fileID>.json`。
- 配额计量 = 目录内 `*.blk` 字节求和，打开时重盘点 → **重启后占用不丢**。
- 写入原子：先 `.tmp` 再 rename；`Put` 超配额返回 `ErrQuotaFull`。
- 路径注入防护：`safeFileID` 白名单 + `filepath.Base` 复核（`store.go:169`）。
- 已知缺口：块是**明文 JSON 落盘**（只签不密），且没有 `SetQuota`——见 §7 待办。

## 5. 完整性与多源

- 每块携 `{group_id, content_hash, stripe, pos, host, proof}`；收块侧一律独立复验
  （`CheckBlock`：sha256 + proof 原文逐字节 + 验签），再与
  `Manifest.BlockHashes[stripe*(K+1)+pos]` 交叉比对（`block.go:129-175`）。
- 坏源回调 `OnSuspect` → 邻居差评（与回灌/核查同一惩罚通道）。
- 现状是「逐候选源验，**首个验过者采用**」（`manager.go:275`），还**不是**
  「多源取值比对取多数派」——后者排在 §7 待办 N3。

## 6. 三条主流程 + 成员变动

- **上传**（`manager.go:290`，UI：5·网盘 →「上传」→ 原生选择框）：`CanWrite` 估额
  （`size/(K+1)` 落本机份额）→ 切条 + 算校验 + 签清单 → 逐块 `deliver`（本机
  `Put` / 远端 `nd.put`），任一块失败即 `rollback` 撤销已放块 → 清单泛洪全网。
- **下载**（`manager.go:368`）：`gatherVerified` 收齐可验块 → 同条缺 1 块则异或重建
  并验哈希，缺 ≥2 块 `ErrTooManyMissing`（RAID5 只容单块）→ 全文哈希终检，
  不符 `ErrFileCorrupt`。UI 目前把文件落到**进程工作目录**（`actions.go:431`），
  应改原生「另存为」——见 §7 N2。
- **删除**（`manager.go:625`）：本机清单移除 + 向候选持有者逐个 `nd.del`。
- **成员/配额变动**：`node.go:634` 触发 `SetHosts` 刷新出配额集与布局。
  `PlanRebalance`/`ExecutePlan`（先重建缺失、后「推新再删旧」搬移；缩容致条带宽于
  在世成员数则 `ErrReencodeRequired`）**目前生产路径无人调用**，只有
  `rebalance_test.go` 的内存仿真在跑——见 §7 N1。
- **除名善后**：设计承诺「先把被除名者承载的块重建迁移，再作废其副本」，
  现状**未接**：成员消失后其块直接让相关条带进入降级态。

## 7. 实现现状与待办排期

### 现状小结（诚实口径）
- 纯逻辑（切条/校验/重建/重平衡计划/清单验签/配额守卫）**代码 + 单测齐备**；
  13 包门禁全绿。
- **一次真网络多成员网盘 E2E 都没跑过**：所有 ≥3 成员场景都是 `simNet` 内存假网络；
  `cmd/dmesh`（真实接线层）网盘部分零测试；`run/life/lifecycle.sh` 无上传/下载断言。
  真窗口侧只验证过「配额对话框 → `{"mb":6}` 落盘并生效」这一段。
- 下列缺口按优先级排期。每项都要求：**原操作零影响 + 拿证据**
  （改动 diff 范围、13 包全量门禁、真环境实测），不得顺手改无关判定路径。

| # | 缺口 | 为什么排这个优先级 | 验收 |
| --- | --- | --- | --- |
| **N0** | `nd.get`/`nd.list`/`nd.del` **服务端不判权限**，任何已连邻居可取走/删掉任意块；且 RPC 帧绕过 `demux` 的黑名单/防垃圾闸（`rpc.go:73-76,161-221`） | 安全洞，与网盘是否好用无关，独立于其余各项先修 | 新增负例：非配额成员/被拉黑者发 `nd.get`/`nd.del` → 拒 + 差评；正例：合法持有者照常服务；真双实例复验 |
| **N1** | 重平衡与「除前者迁移」未接线（`SetHosts` 只刷布局）；降级期不冻结新写入（`SetWriteFrozen` 仅测试调用） | 承诺的容错语义在真实成员变动下不发生 | 成员退群/kick/带配额上线三条路径各自触发计划并执行；降级期间上传被 `ErrDegradedFrozen` 拒；仿真 + 真双实例各一遍 |
| **N2** | 配额变更不落 `DirStore`（`initNetdisk` 已初始化即 no-op），`mb→0` 不关闭；下载落工作目录 | 「群主改配额」目前只改名单不改变本机预留 | 改大→可写更多、改小→低于占用时的明确策略与提示、`mb=0`→面板置灰且拒写；下载走原生「另存为」 |
| **N3** | 多源「比对」未落实（首个验过即采用）；块未与回灌/`/audit` 的多数派核查打通；块明文落盘 | 与项目信任模型（防单源投毒）对齐 | 同一块向 ≥2 源取，内容不一致即丢弃 + 差评 + 取多数派；`/audit` 覆盖块与清单；加密方案先出设计再落地 |
| **N4** | 真实网络 ≥3 配额成员的网盘 E2E 从未跑过（含并发上传、盘满、离线一半） | 前四项修完必须有真环境回归，否则仍是「只在假网络里对」 | 三实例（可含本机回环 + 第二主机）上传→杀其一→异或重建读出→补块重平衡，落 `run/life/` 脚本化断言 |
| **N5** | 文档/注释漂移：`internal/netdisk/manifest.go:12` 注释仍写「TypeHide 消息」、本包头注释仍引用 PLAN 旧章节、`progress.go` 的 M6 完成度口径 | 误导后来者走已被 v17/v26 推翻的老路 | 全部改指本文；`progress.go` M6 按「代码+测试」真实口径重估 |

### 粗估（未开工，先报备量级）
N0 ≈ 0.5 天；N1 ≈ 1 天；N2 ≈ 0.5 天；N3 ≈ 1~1.5 天（加密另计）；
N4 ≈ 1 天（要第二台可写主机或三回环实例）；N5 ≈ 0.2 天。合计约 4~5 个工作日。

## 8. 关键风险

1. **双块同损**：同一 stripe 的数据块 + 校验块同时不可得（两配额成员同时永久离线）
   → 该条**永久丢失**，RAID5 的固有边界。缓解 = 降级期暂停写入 + 优先重建 +
   配额成员 <3 直接禁写（现状已有禁写，缺自动冻结，见 N1）。
2. **配额≠意愿**：成员预留空间是本地约定，磁盘实际满溢只能靠 `ErrQuotaFull` 事后拒。
3. **自报贡献**：出配额集当前按「白名单成员全算」组装（`netdisk.go:87`），没有
   本人自报「我已预留」这一步，与 `HostInfo` 注释所述不符（见 N2/N3 一并处理）。
4. **无中心存储节点**：所有块都寄存在成员盘上，成员流失速度 > 重平衡速度时
   降级窗口会拉长（N1 的直接动机）。

## 9. 与其他子系统的边界

- `internal/netdisk` 只 import `internal/core`，业务包互不 import（`deps` 锁依赖）。
- 清单/配额事件的**签发与验签**复用统一信封与注册表（v26），网盘包不复制一份
  结构体——跨包字段契约由 `group` 侧全表往返测试守。
- UI 只经 `ui.Netdisk` 门面（`Status/List/Upload/Download/Delete`）访问；门面返回
  nil 即「网盘未装配」，面板按钮置灰并给提示。
- 差评通道唯一：`OnSuspect` → `internal/spam`/邻居评分，网盘不自建惩罚口径。
