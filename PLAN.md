# D-Mesh 去中心化 P2P 群聊 — 实施规划（v2）

## Context

基于两份设计文档（`F:\Users\LiveA\Desktop\pp\1.md` 底层连接层、`1.1.md` 群聊方案）在 `H:\2` 从零实现纯 P2P 群聊。v1 忠实文档；**v2 按用户三项修改重设计**：

1. **种子即名单**：群组种子内容包含全体成员的 WG 公钥 + Ed25519 公钥/签名。不再需要 BT 扩展信令交换密钥，BT swarm 只提供 IP:port。
2. **Git 不同步、只作本地记录** → 进一步弃用 Git，本地改追加式 JSONL + SQLite 索引；消息实时推送，无 2 分钟批次窗口。
3. **无撤回**：只有新发的 `hide` 指令消息让目标消息在本机不显示。
4. **防篡改 = 多成员一致性**：不做周期性摘要广播；仅在需要核查时从多个节点拉取消息集对比，与多数派/签名不符的数据直接丢弃。

## 技术选型

| 项 | 选择 | 理由 |
|---|---|---|
| 语言 | Go（单模块单二进制） | 纯 Go 依赖，一次编译，无 C++ 工具链 |
| 发现 | `anacrolix/torrent` + `anacrolix/dht` | 公共 DHT + PEX 收集 swarm peer |
| 传输 | WG 风格加密信道：Noise IK 式握手（X25519，静态密钥来自种子名单）+ ChaCha20Poly1305 over UDP；真 WireGuard（wintun）为二期可插拔后端 | Windows 真 WG 需管理员+驱动；握手即完成身份绑定，无需另设信令层 |
| 存储 | 追加式 JSONL（真相源）+ SQLite（`modernc.org/sqlite` 索引/去重/隐藏标记） | Git 的存在理由（哈希链+同步）已消失 |
| 签名 | Ed25519（`golang.org/x/crypto`） | 消息、hide 指令、成员名单均签名 |
| UI | TUI（`bubbletea` + `lipgloss`） | 单进程集成最简 |

## 核心协议设计

### 群组与种子
```json
// group.json（种子内容，group_id = sha256(创世配置)）
{
  "name": "...", "version": 1, "mode": "open|closed",
  "members": [
    { "ed25519_pub": "...", "wg_pub": "...", "added_at": 0, "sig": "..." }
  ],
  "sig_chain": [ { "members_root": "...", "signer": "...", "sig": "..." } ]
}
```
- 成员变更：老成员对新的 `members_root` 联署，作为 special message 实时传播；客户端本地维护「最新已签名单」，种子只是入口不是真相。
- 陌生人准入：open 群凭种子直连；closed 群凭名单内成员签名背书。

### 消息（实时推送 + Gossip flood）
```json
{ "msg_id": "...", "group_id": "...", "sender": "...", "ts_ms": 0,
  "type": "text|hide|member_update", "content": "...", "sig": "..." }
```
- 发送即经 Tunnel 推给全部邻居，邻居去重后继续转发（TTL/来源抑制防风暴）。
- `hide`：`target_msg_id` 必须与原发送者同 pubkey，且 hide 不可被 hide；本机软删除（不显示），SQLite 记录。
- 验签失败 / 发送者不在最新名单 → 丢弃 + 邻居评分降权。

### 回灌（新成员 / 重连）
- 向 ≥3 个邻居分别请求消息集，scope 可选：全部 / 最近 N 天 / 仅增量（本机 max_ts 之后）/ 不同步。
- 按 msg_id 去重合并，单源不采信。

### 按需一致性核查（取代周期摘要）
- 触发时机：回灌时、手动 `/audit`、或某邻居数据可疑时。
- 过程：向多个邻居请求 msg_id 集合（或分段哈希），对比差异；差异消息逐条验签 + 对名单核查；与多数派不符 → 丢弃并给来源打差评/断连。
- 边界（已知限制）：整段遗漏只在核查时暴露；多数派造假靠 closed 群成员准入防，open 群靠 PoW 抬高成本。

## 项目结构

```text
H:\2\
├── go.mod
├── cmd/
│   ├── dmesh/          # 主客户端（TUI）
│   └── dmesh-tool/     # 建群/造种子/名单签发工具
├── internal/
│   ├── identity/       # Ed25519/X25519 密钥生成、加载
│   ├── group/          # group.json、group_id、名单签名与变更验证
│   ├── discovery/      # DHT+PEX → peer IP:port 列表
│   ├── transport/      # 打洞 + Noise IK 式加密信道 + Tunnel 抽象（Send/OnData/Close/RemotePub）
│   ├── neighbor/       # 邻居表：3~8 活跃、keepalive 25s、RTT/IPv6 优先、候选补充
│   ├── message/        # 消息结构、签名、去重缓存、flood 转发、hide 语义
│   ├── store/          # JSONL 追加写 + SQLite 索引
│   ├── backfill/       # 多源回灌 + 按需一致性核查
│   ├── spam/           # PoW、速率限制、黑名单、邻居评分
│   └── ui/             # bubbletea TUI
└── docs/               # 协议 spec（握手/消息/回灌/核查）
```

## 里程碑（每步可独立验证）

### M0 骨架与建群工具（0.5 天）
identity 生成持久化；`dmesh-tool newgroup` 产 group.json + group.torrent；`verify` 校验 group_id/名单签名。

### M1 发现层（1 天）
anacrolix 加载种子，DHT+PEX 滚雪球输出 peer IP 列表（不做文件传输）。
验证：本机 3 实例互相发现全量列表。

### M2 传输层 + 邻居维护（2~2.5 天，最高风险）
UDP 打洞；加密信道握手（IK：静态密钥来自种子名单，一次握手完成密钥确认+身份绑定）；Tunnel 抽象；邻居表状态机与替换策略。
验证：`dmesh-echo` 经 Tunnel 收发；负例（非名单公钥/错群）拒连；公网对拍记录成功率。

### M3 消息与存储（1 天）
实时推送 + flood 去重；JSONL+SQLite 落盘；hide 指令；最小 TUI（收发消息/列表/隐藏）。
验证：3 实例互发；hide 后各端不显示且原记录仍在盘；伪造签名消息被丢。

### M4 回灌与一致性核查（1 天）
多源回灌（scope 可配）；按需 msg_id 集合对比、差异验签、差评断连。
验证：新实例晚加入补齐历史；单节点删改本地文件后核查能揪出并丢弃其数据。

### M5 防垃圾与打磨（1 天）
PoW、速率限制、黑名单、邻居评分、IPv6 优先、状态面板、README（Windows 防火墙放行说明）。

### 总计：约 6.5~7 个工作日到「两人公网真实群聊可用」

## 关键风险与对策

1. **anacrolix PEX 覆盖度** — 不生效则退化纯 DHT `get_peers`，发现能力不丢；M1 首先验证。
2. **对称 NAT** — 接受失败不设中继，邻居表补偿；transport 可插拔。
3. **Windows 防火墙** — README + 启动自检给出明确放行指引。
4. **flood 消息风暴** — msg_id 去重 + 每源仅记一跳 TTL；邻居数 8 封顶天然限流。
5. **实时推送 vs 名单同步竞态** — 消息按「接收时已验证名单」判定，名单变更消息带 seq，回灌时重放核查。

## 验证方式（端到端）

1. 本机：`dmesh-tool newgroup` → 3 实例加载种子 → 互发/hide/杀进程重启回灌补齐 → 手动 `/audit` 全绿；改一个实例的 JSONL 后再 audit 验证其被揪出。
2. 局域网两机：直连路径。
3. 公网两机（不同 NAT）：打洞成功率、推送时延、回灌收敛时间。
