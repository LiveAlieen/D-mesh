// Package message 实现 D-Mesh 的消息层（PLAN.md v16「消息（实时推送 + Gossip flood）」一节）：
//
//   - 规范化打包与签名/验签：一切签名原文走 core.MessageSigPayload（CanonicalJSON），
//     验签走 core.Verify（按 sig_alg 分派到可插拔注册表；本地未注册的 alg 一律拒绝 + 来源差评）。
//   - 去重缓存：msg_id + TTL + 来源抑制（同一来源再次见到同一 msg_id 一律静默丢弃，防 flood 风暴）。
//   - 发送即推全部邻居；外部进来的消息验签/验权限通过后去重，再 flood 转发（不回送给来源）。
//   - 名单事件与聊天消息同路广播，但聊天流不显示（VisibleInChat 仅 text）。
//   - join_req 无许可中继：不 flood，而是定向转给在场表在线、具 carry 权限的邻居。
//   - hide：target_msg_id 的原消息须与 hide 同一发送者 pubkey；hide 不可被 hide；
//     本机软删除（经 Handlers.SoftDelete），目标未达时进入短期待补队列。
//   - 定向 To：黑名单成员的群聊消息一律拒收拒转，唯一例外是 To 指向本机且本机具解禁
//     权限（unban/kick 位或群主以上）的申诉消息。
//
// 本包只 import dmesh/internal/core；transport/neighbor/group/spam 的具体实现经
// Transport / PeerSource / core.Roster / Handlers 接口在 cmd/dmesh 接线（依赖注入）。
package message
