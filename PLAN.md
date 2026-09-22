# D-Mesh 去中心化 P2P 群聊 — 实施规划

## Context

用户提供了两份设计文档（`1.md` 底层 P2P 连接层、`1.1.md` D-Mesh 群聊整体方案），要求在 `H:\2`（当前为空目录）从零规划实现。核心目标：无自建服务器，用公共 BT DHT/PEX 做节点发现、BT 扩展协议做信令、WireGuard 做加密传输、本地 Git 做不可篡改消息存储、2 分钟批次提交 + 撤回窗口、Pull 式 Gossip 同步。

## 技术选型（决策与理由）

| 项 | 选择 | 理由 |
|---|---|---|
| 语言 | **Go**（单模块单二进制） | anacrolix/torrent 纯 Go 支持 DHT/PEX/自定义 BT 扩展；wireguard-go 纯 Go；无 C++ 工具链，一次编译符合用户偏好 |
| BT 层 | `github.com/anacrolix/torrent` + `anacrolix/dht` | 内置 DHT、PEX、BEP-10 扩展消息注册（可挂 `p2p_hello` 自定义扩展） |
| 传输层 | **两阶段**：MVP 用「WG 风格加密信道」（noise 式握手 + ChaCha20Poly1305，直接跑 UDP 消息，不建 TUN 网卡）；二期可选真 WireGuard（wintun 驱动） | Windows 真 WG 需要管理员权限 + wintun 驱动，严重阻碍迭代；加密信道语义上等价（点对点加密+签名身份），且打洞逻辑相同。真 TUN 隧道作为可插拔升级 |
| 存储 | Git CLI（`os/exec` 调 `git commit / bundle / fetch`）+ `git bundle` 做历史传输 | bundle 天然满足 `genesis.bundle` 与新成员历史同步；比 go-git 少一大块依赖 |
| 消息索引 | SQLite（`modernc.org/sqlite`，纯 Go） | 只作本地检索缓存，Git 才是真相源 |
| UI | TUI（`bubbletea` + `lipgloss`） | 与文档建议一致，单进程集成最简单 |
| 签名 | Ed25519（`golang.org/x/crypto`），X25519 用于握手 | 与文档一致 |

## 项目结构

```text
H:\2\dmesh\
├── go.mod                      # 单模块，cmd/ 下多入口
├── cmd/
│   ├── dmesh/                  # 主客户端（TUI）
│   └── dmesh-tool/             # 建群/造种子/genesis bundle 工具
├── internal/
│   ├── identity/               # Ed25519/X25519 密钥生成、加载、签名编码
│   ├── group/                  # group.json 创世配置、group_id 计算、成员/邀请验证
│   ├── discovery/              # anacrolix torrent session：DHT+PEX，peer 列表输出
│   ├── signaling/              # BT 扩展 p2p_hello / p2p_hello_ack、验签、候选表
│   ├── transport/              # UDP 打洞 + 加密信道抽象（可换真 WG）
│   ├── neighbor/               # 邻居表状态机 IDLE→HANDSHAKING→CONNECTED→STALE，3~8 邻居，优先级评分
│   ├── message/                # 消息结构、msg_id、签名、缓冲区、2 分钟窗口、revoke
│   ├── store/                  # Git 仓库封装：批次 commit、bundle 导出/导入、签名 trailer
│   ├── sync/                   # HEAD 交换、拉取缺失 commit（经 tunnel 跑 git upload-pack）
│   ├── spam/                   # PoW 验证、速率限制、黑名单、邻居评分
│   └── ui/                     # bubbletea TUI
└── docs/                       # 协议 spec（握手、消息、批次、HEAD）
```

## 里程碑（每步可独立验证）

### M0 骨架与身份（0.5 天）
- go.mod、cobra 骨架、identity 生成/持久化（`~/.dmesh/identity.json`）。
- `dmesh-tool newgroup`：生成 group.json + 自签成员项 + 创建最小 torrent 文件（group.json + README.txt + genesis.bundle）→ `group.torrent`。
- 验证：`dmesh-tool verify` 校验 group_id 与签名。

### M1 发现层（1 天）
- anacrolix session 加载 group.torrent，只走元数据交换不做种下载（或做种 1 个填充文件即可）；开 DHT + PEX；输出 `[IP:Port, source]` 列表。
- 验证：本机起 3 个实例（不同监听端口），打乱启动顺序，每实例都能列出全部 peer；断一个后列表收敛。

### M2 信令层（1 天）
- BT 扩展注册 `p2p_hello`/`p2p_hello_ack`（BEP-10，JSON payload），按文档完成 network_id/签名/成员白名单三重校验 → 候选 WG 邻居表。
- 验证：两实例互验身份；篡改/错群/非成员三种负例全部拒连。

### M3 传输层 + 邻居维护（2~3 天，最高风险）
- UDP 打洞：双方经 BT 信令知道对方公网 IP:port 后同时互发探测包；锥形 NAT 成功即建立加密信道（X25519 握手 + Ed25519 身份绑定 + 重放保护）；同机回环/局域网先行。
- 邻居表：max 8 / min 3、keepalive 25s、RTT 探测、IPv6>IPv4>打洞优先级、掉线自动从候选补充。
- `Tunnel` 抽象落地：`Send([]byte) / OnData / Close / RemotePub`（对齐 1.md §4.5 API）。
- 验证：`dmesh-echo` 测试程序经 Tunnel 收发；公网对拍（两台真实机器）记录打洞成功率。

### M4 消息与存储（1.5 天）
- 发送：签名入内存缓冲区，UI 倒计时 2:00；窗口内撤回=直接删。
- 定时器每 2 分钟：缓冲排序写 `messages/<date>/<ts>-batch.jsonl` → `git add+commit`，commit message 带 batch_id/prev_commit/sender/signature trailer。
- 超窗撤回=revoke 消息进下一批次，UI 标记；SQLite 建索引。
- 验证：改历史文件后 `git fsck`/签名校验能发现；撤回窗口边界用例。

### M5 同步层（2 天）
- HEAD 通告/问询消息走 Tunnel（30s 周期 + 新 commit 即时宣告）；分叉时经 Tunnel 流式跑 `git fetch`（对端 upload-pack）。
- 新成员：从邻居拉最新 group.json、成员表、bundle 历史（支持「最近 N 天」截断）。
- 验证：3 节点 A 发消息 → 仅与 A 相连的 B → 再传给 C，收敛；离线节点重启后补齐。

### M6 防垃圾与打磨（1 天）
- 可选 PoW、每公钥速率限制、本地黑名单、垃圾邻居降级断连；IPv6 优先排序；日志与状态面板。

### 总计：约 9~10 个工作日到「两人公网真实群聊可用」

## 关键技术风险与对策

1. **anacrolix PEX 对纯做种场景支持度** — 若 PEX 消息不生效，退化为只靠 DHT `get_peers`（同一 info_hash），发现能力不丢，只是滚雪球慢；M1 优先验证。
2. **对称 NAT 打洞失败** — 按文档接受失败（不设中继），邻居表用其他节点补偿；预留 transport 后端可插拔，后续如确有需要再接真 WG。
3. **Windows 防火墙** — 首次运行需放行 UDP 端口，README 写明；探测脚本给出明确报错。
4. **批次 2 分钟延迟** — MVP 按文档实现；后续可加「经 Tunnel 的即时消息旁路」（预览流），Git 仍是最终事实。
5. **成员列表变更** — closed 群用成员签名邀请消息作为 special message 写入批次，group.json 以「最新已签名的成员状态 commit」为准；不改种子。

## 交付顺序建议

底层（M0–M3）即 `1.md` 的 p2p-conn，可独立成包复用 + echo 演示；上层（M4–M6）即 `1.1.md` 群聊。两文档天然分层，按里程碑串行推进，每个里程碑结束跑一次多实例集成测试。

## 验证方式（端到端）

1. 本机：`dmesh-tool newgroup` 产种子 → 同机 3 实例加载种子 → 互发/撤回/杀进程重启补齐，观察 Git 历史线性 + 签名校验通过。
2. 局域网两台机器：验证直连路径。
3. 公网两台（不同 NAT）：统计打洞成功率与收敛时间，记录已知限制表现。
