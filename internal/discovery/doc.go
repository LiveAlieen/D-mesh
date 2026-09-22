// Package discovery 是 D-Mesh 的发现层（M1）：把群种子（.torrent / 磁力链 / 裸 info hash）
// 塞进 BT swarm，靠公共 DHT + PEX 滚雪球收集该群成员在线时的 IP:port 列表。
//
// 职责边界（v16 设计）：
//
//   - 本层只产出「候选端点」（IP:port + 发现来源 + 最后见到时间），不做任何身份判定：
//     pubkey↔IP 的绑定发生在 transport 层的 Noise 握手（静态密钥取自白名单 wg_pub），
//     准入判定（黑名单优先）由 transport/neighbor 负责。BT swarm 只提供 IP:port。
//   - 不做文件传输：加入 swarm 的 torrent 一律挂 discard 存储并禁传数据，
//     只保留「announce + get_peers + PEX」这条发现通路。
//   - 种子有效性（重算 group_id + 验 creator_sig）不属于本层，归 group/tools。
//
// 对外主要类型：
//
//	Peer / PeerSet   —— 端点及其去重合并容器（纯逻辑，可单测）
//	Seed             —— 发现主题（torrent info hash）+ bootstrap 线索，含 .torrent 加载
//	Source           —— peer 来源抽象：真实实现是 anacrolix swarm（DHT+PEX），测试可注入 mock
//	Mode             —— ModeFull（DHT+PEX）/ ModeDHTOnly（PEX 不生效时退化：纯 DHT get_peers）
//	Manager          —— 多种子滚雪球调度：轮询/回调输出增量与全量列表、退化判定、回灌滚雪球
//	SwarmFactory     —— 真实网络源工厂（NewSwarmFactory）
//
// 接线示例（cmd/dmesh）：
//
//	f, err := discovery.NewSwarmFactory(discovery.SwarmConfig{})  // 默认即可
//	m, err := discovery.New(discovery.Config{Factory: f.Source, OnPeers: onPeers})
//	m.Track(seed)                                                  // seed 来自 discovery.LoadSeedFile
//	go m.Run(ctx)                                                  // 后台滚雪球
//	peers := m.Peers(seed.InfoHash)                                // 交给 neighbor 作候选
package discovery
