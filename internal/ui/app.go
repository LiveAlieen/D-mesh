// Package ui 是 dmesh 的 Ebitengine 原生窗口 GUI 层（PLAN.md v19；
// 继承 v16 / M3、M4、M6 的 UI 部分）。
//
// 依赖纪律（core 包注释第 1 条）：本包只 import dmesh/internal/core 与
// 第三方（ebiten/v2、x/image 字体回退、atotto/clipboard），不 import 任何
// 其它业务包。与外界的全部交互都经由本包
// 自定义的 App 门面接口（内部暴露 core.Roster / core.Signer 语义），具体实现
// 由 cmd/dmesh 的 main 在 Integration 阶段接线（message/group/netdisk/backfill
// 等包各自实现 App 的一个子集，main 聚合成一个 App 实例注入）。
//
// 分层：viewModel（纯状态机，无窗口可测）+ game（ebiten 壳：Update 把
// 键盘/鼠标/滚轮翻译成 viewModel 调用，Draw 按 Snapshot 绘制）。
//
// 面板（Tab/数字键 1..6/鼠标点顶部标签切换）：
//   - chat     发言 / 接收 / /hide 软删除 / /audit / /netdisk 等命令
//   - members  成员列表：按在场表渲染 在线/离线/最后活跃（v13.1）
//   - join     入群面板：join_req 队列 / 核对种子哈希 / verify 模式人工审 / 签 join
//   - admin    群管面板：kick 除名 / unban / 改权限 / 移交 / v17 transfer 提案
//     收件箱（a/d）/ 黑名单定向申诉队列（u=unban / i=忽略）
//   - netdisk  网盘面板：配额、贡献成员、条带健康度、上传/下载/删除
//   - progress 进度面板：v18 /progress 欠账占位
package ui

import "dmesh/internal/core"

// App 是 UI 对宿主（main 接线层）要求实现的全部能力。UI 只触发语义动作，
// 事件的组包、签名（用 core.Signer）、广播、持久化全部由宿主完成，
// 从而避免 UI 与 message 包的内容编码形成第二份契约。
//
// 并发要求：所有方法可能被 UI 在工作线程（事件泵/异步任务 goroutine）里并发
// 调用，宿主必须自行保证并发安全。SendText/Kick 等发送类方法允许异步（真正
// 广播完成后经 NextEvent 以 SystemEvent 回报），但返回 error 表示「受理失败」。
type App interface {
	// Self 返回本机身份公钥。
	Self() core.PubKey
	// Roster 返回双名单 + 在场表（读接口，group 包实现）。
	Roster() core.Roster
	// Signer 返回本机签名器（UI 仅用于展示算法与身份，不直接签事件）。
	Signer() core.Signer
	// GroupID 返回当前群的 group_id（种子核对时比对用）。
	GroupID() [32]byte

	// ---- 出站动作（宿主组包 + 签名 + 广播 + 落盘）----

	// SendText 发送一条 type=text 聊天消息。
	SendText(text string) error
	// Hide 对目标 msg_id 发起软删除（hide 事件，须与原文发送者同 pubkey，见 PLAN）。
	Hide(msgID string) error
	// Leave 本人自签 remove 退群（不进黑名单，v15）。
	Leave() error
	// Kick 显式发送 kick 事件：删白名单 + 进黑名单（须具 kick 权限，否则宿主报错）。
	Kick(target core.PubKey) error
	// Unban 签 unban 事件把目标移出黑名单（须具解禁权限）。
	Unban(target core.PubKey) error
	// SetPerms 签 perms 事件设置目标权限集（签名者层级须严格高于目标）。
	SetPerms(target core.PubKey, perms []string) error
	// GrantAdmin 签 grant_admin 任命管理（群主/创建者）。
	GrantAdmin(target core.PubKey) error
	// RevokeAdmin 签 revoke_admin 收放管理权（群主/创建者）。
	RevokeAdmin(target core.PubKey) error
	// Transfer 发起群主移交：宿主签好 transfer 原文并以定向提案（to=新 owner、
	// endorse_sig 为空）送达新 owner；生效须新 owner 联署（v17①，见下方提案接口）。
	// 新 owner==本机时宿主走自领快捷路径（自签联署一步广播）。
	Transfer(newOwner core.PubKey) error
	// SetNetdiskMB 签 netdisk 事件改全局配额（0~256，越界宿主直接报错）。
	SetNetdiskMB(mb int) error
	// SetOfflineAfter 本人自签 presence 更新自己的离线阈值（v13.1）。
	SetOfflineAfter(ms int64) error

	// ---- 入群面板 ----

	// PendingJoins 返回待处理的 join_req 队列（宿主已解出申请人 pub/wg 与
	// verify 模式身份材料）。
	PendingJoins() []JoinRequest
	// ApproveJoin 由具 carry 权限的本机对队列中的申请签 join 并广播。
	ApproveJoin(reqMsgID string) error
	// RejectJoin 拒绝申请（不广播任何事件，仅本地出队）。
	RejectJoin(reqMsgID string) error

	// ---- transfer 联署提案（v17①）----

	// PendingTransfers 返回发给本机的待决 transfer 提案收件箱（现任 owner/
	// 创建者定向送达、endorse_sig 为空的原文副本）。
	PendingTransfers() []TransferProposal
	// ApproveTransfer 对提案同一原文补上本机的联署（EndorseSig）并广播生效；
	// msgID 支持 "latest" 与唯一前缀匹配。
	ApproveTransfer(msgID string) error
	// RejectTransfer 拒绝提案：仅本地丢弃，绝不转发、不产生任何事件。
	RejectTransfer(msgID string) error

	// ---- 一致性核查（M4，/audit）----

	// Audit 触发多源核查，返回若干行人类可读摘要。
	Audit() ([]string, error)

	// ---- 群网盘（M6）----

	// Netdisk 返回网盘操作门面；群网盘关闭（netdisk_mb=0）时返回 nil。
	Netdisk() Netdisk

	// NextEvent 阻塞直到有入站事件（新消息/名单变化/join_req/申诉/进度），
	// 返回 nil 表示宿主已关闭（UI 随即退出）。
	NextEvent() Event
}

// TextIDAck 是 App 的可选扩展（v25）：宿主发送文本后回报落盘的真实 msg_id。
// GUI 的「隐藏本条」只能针对本机自己发的那条，而 msg_id 由宿主签名时才产生，
// 因此实现本接口的宿主能让回显行立刻可隐藏；未实现时回退 SendText，自己发的
// 消息只支持「复制正文」。协议与事件面不受影响（纯 UI 侧回执通道）。
type TextIDAck interface {
	SendTextID(text string) (msgID string, err error)
}

// JoinRequest 是一条待处理的入群申请（宿主从 join_req 事件解码后的呈现形态）。
type JoinRequest struct {
	// Msg 是原始 join_req 消息（申请人自签；MsgID 用于 Approve/Reject 定位）。
	Msg core.Message
	// ApplicantWG 是申请人的 X25519 传输公钥（join_req 携带）。
	ApplicantWG core.WGPub
	// Mode 是入群模式（core.ModeAuto / core.ModeVerify，取自群配置）。
	Mode string
	// IdentityNote 是 verify 模式下申请人自证身份的材料摘要（auto 模式为空）。
	IdentityNote string
	// SeedOK 表示宿主已核对随申请递交的种子文件哈希与创世配置一致。
	SeedOK bool
}

// TransferProposal 是一条发给本机的待决 transfer 联署提案（v17①）。宿主在
// 帧接收点截获定向 transfer 提案（Type=transfer、To=本机、EndorseSig 为空、
// 签名者核对为现任 owner/创建者）后入箱展示，绝不喂 ApplyEvent。
type TransferProposal struct {
	// Msg 是收到的定向 transfer 原文（批准时机必须对这同一份消息联署，
	// EndorseSig 由宿主补签后广播生效）。
	Msg core.Message
	// FromOwner 表示宿主已核对签名者确为当前 owner/创建者。
	FromOwner bool
}

// Netdisk 是群网盘面板所需的最小门面（netdisk 包实现，main 接线）。
type Netdisk interface {
	// Status 返回总容量、贡献者、条带健康度等汇总视图。
	Status() (NetdiskStatus, error)
	// List 列出网盘内的文件。
	List() ([]NetdiskFile, error)
	// Upload 把本地路径的文件切条+校验散布到配额成员（未出配额者写会被拒）。
	Upload(localPath string) error
	// Download 按名字拉取并重组文件写入 destPath。
	Download(name, destPath string) error
	// Delete 删除网盘文件。
	Delete(name string) error
}

// NetdiskContributor 是网盘面板里一行贡献成员。
type NetdiskContributor struct {
	Pub           core.PubKey
	QuotaBytes    int64
	ProvidedBytes int64
	Online        bool
}

// NetdiskStatus 是网盘总览（PLAN M6：总容量/贡献配额/在线可写/健康度）。
type NetdiskStatus struct {
	QuotaMB         int // 每成员应预留配额（0=关闭）
	TotalBytes      int64
	UsedBytes       int64
	Contributors    []NetdiskContributor
	OnlineWritable  int
	DegradedStripes int // 处于「单块降级、待重建」的条带数
	Note            string
}

// NetdiskFile 是网盘文件条目。
type NetdiskFile struct {
	Name    string
	Size    int64
	Stripes int
	Healthy bool
}

// Event 是宿主 → UI 的入站事件（chat 流内不可见的名单事件也由宿主翻译成
// RosterEvent 通知 UI 刷新）。
type Event interface{ isUIEvent() }

// TextEvent 是一条可在聊天流渲染的入站消息（text，或定向申诉之外的可展示类型）。
type TextEvent struct{ Msg core.Message }

// SystemEvent 是状态/结果提示行（发送完成、错误、心跳统计等）。
type SystemEvent struct{ Note string }

// RosterEvent 表示双名单或在场表发生变化，UI 应刷新成员/群管面板。
type RosterEvent struct{ Note string }

// JoinReqEvent 把新到达/新中继的 join_req 推进入群面板队列。
type JoinReqEvent struct{ Req JoinRequest }

// TransferProposalEvent 把新到达的发给本机的 transfer 联署提案推进收件箱队列（v17①）。
type TransferProposalEvent struct{ Prop TransferProposal }

// AppealEvent 是黑名单成员发给本机（具解禁权限者）的定向申诉消息。
type AppealEvent struct{ Msg core.Message }

// HideEvent 通知聊天流把 msg_id 软删除不显示。
type HideEvent struct{ MsgID string }

// NetdiskEvent 是网盘进度/健康度变化提示。
type NetdiskEvent struct{ Note string }

func (TextEvent) isUIEvent()             {}
func (SystemEvent) isUIEvent()           {}
func (RosterEvent) isUIEvent()           {}
func (JoinReqEvent) isUIEvent()          {}
func (TransferProposalEvent) isUIEvent() {}
func (AppealEvent) isUIEvent()           {}
func (HideEvent) isUIEvent()             {}
func (NetdiskEvent) isUIEvent()          {}
