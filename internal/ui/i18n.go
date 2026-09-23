// i18n.go：GUI 用户可见文案的多语言目录（v20）。
//
// en 为源语言（目录键值与 v19 英文字面一致，保证既有测试/断言不漂移），
// zh 为对照。全部取串走 Tr/Tf：命令名（/kick…）与协议 token（sig_alg、
// perm 名、pubkey hex、mode、seed=OK 之类的结构位）不翻译——它们是协议
// 面而非 UI 文案；消息正文永远原样显示。
//
// 语言选择：启动按系统显示语言自动判定（见 detectSystemLang），
// /lang zh|en 运行期切换即时生效（每帧绘制都现取目录）。

package ui

import "fmt"

// Lang 是受支持的界面语言。
type Lang string

const (
	LangEn Lang = "en"
	LangZh Lang = "zh"
)

// SupportedLangs 是 /lang 可接受的语言集合。
func SupportedLangs() []Lang { return []Lang{LangEn, LangZh} }

var curLang = detectSystemLang()

// SetLang 切换界面语言；未知语言返回 false 且不变。
func SetLang(l Lang) bool {
	switch l {
	case LangEn, LangZh:
		curLang = l
		return true
	}
	return false
}

// GetLang 返回当前界面语言。
func GetLang() Lang { return curLang }

// Tr 按当前语言取模板串；当前语言缺键回退 en，再缺则原样返回键。
func Tr(key string) string {
	if m, ok := catalogs[curLang][key]; ok {
		return m
	}
	if m, ok := catalogs[LangEn][key]; ok {
		return m
	}
	return key
}

// Tf 按当前语言取模板并格式化。
func Tf(key string, args ...any) string {
	if len(args) == 0 {
		return Tr(key)
	}
	return fmt.Sprintf(Tr(key), args...)
}

var catalogs = map[Lang]map[string]string{
	LangEn: catalogEn,
	LangZh: catalogZh,
}

var catalogEn = map[string]string{
	"panel.chat":     "chat",
	"panel.members":  "members",
	"panel.join":     "join",
	"panel.admin":    "admin",
	"panel.netdisk":  "netdisk",
	"panel.progress": "progress",

	"top.line":          "me=%s · group=%s · members=%d(online %d) · banned=%d · joins=%d · panel=%s",
	"status.hint":       "tab=switch panel [%s] · 1..6 jump · esc=chat · close window quits · /help for commands",
	"input.listFocus":   "%s  (list focus: keys act on selection · Enter=/ edits)",
	"input.placeholder": "type a message…  /help lists commands",

	"act.submitted":        "%s submitted",
	"act.failed":           "%s failed: %v",
	"act.sent":             "sent",
	"act.hide":             "hide",
	"act.leave":            "remove(leave) signed",
	"act.kick":             "kick",
	"act.unban":            "unban",
	"act.perms":            "perms",
	"act.grantAdmin":       "grant_admin",
	"act.revokeAdmin":      "revoke_admin",
	"act.transfer":         "transfer event (needs new owner endorse)",
	"act.endorsed":         "transfer endorsed & broadcast",
	"act.deniedLine":       "· transfer proposal %s denied (dropped locally, never forwarded)",
	"act.joinSigned":       "join signed & broadcast",
	"act.kickEvent":        "kick event",
	"act.unbanEvent":       "unban event",
	"act.grantAdminEvent":  "grant_admin event",
	"act.revokeAdminEvent": "revoke_admin event",
	"act.permsEvent":       "perms event",
	"act.presence":         "presence threshold update",
	"act.ndQuota":          "netdisk quota -> %d MB",
	"act.upload":           "upload %s",
	"act.download":         "download %s",
	"act.delete":           "delete %s",

	"ev.appeal":      "new appeal from %s (admin panel)",
	"ev.joinreq":     "new join_req from %s (tab to join panel)",
	"ev.xferChat":    "· transfer proposal from %s — admin panel (a/d) or /approve %s | /deny %s",
	"ev.xferStatus":  "transfer proposal from %s (admin panel / approve with /approve)",
	"ev.roster":      "· roster: %s",
	"ev.netdisk":     "· netdisk: %s",
	"ev.ndStatusErr": "netdisk status: %v",

	"st.inputErr":       "input error: %v",
	"st.noSpeak":        "no speak permission on this group (or not a member)",
	"st.ndUnavailable":  "netdisk not available (quota 0 or backend not wired)",
	"st.cancelled":      "cancelled",
	"st.emptyCancelled": "empty input, cancelled",
	"st.permsErr":       "perms error: %v",
	"st.rejectFail":     "reject failed: %v",
	"st.denyFail":       "deny failed: %v",
	"st.seedGate":       "seed hash not verified for %s — press s to check the seed file first",
	"st.appealIgnored":  "appeal ignored (kept in log only)",
	"st.notOwner":       "proposal signer is not current owner/creator — refusing to endorse",
	"st.langNow":        "current language: %s (switch with /lang zh|en)",
	"st.langSet":        "language set to %s",
	"st.langBad":        "unknown language %q (use: zh, en)",

	"prompt.seedPath": "seed file path to verify",
	"prompt.permsFor": "new perms for %s (csv)",

	"lf.none":   "transfer proposals: none pending",
	"lf.title":  "transfer proposals (%d):",
	"lf.hint":   "  /approve <msg_id|latest|唯一前缀> · /deny <same>",
	"au.failed": "audit failed: %s",
	"au.line":   "audit: %s",

	"sc.err":        "seedcheck: %s",
	"sc.rejected":   "seedcheck REJECTED: %s",
	"sc.wrongGroup": "seedcheck: valid seed (%s) but NOT this group",
	"sc.ok":         "seedcheck OK: %s (mode=%s)",
	"sc.okReq":      "seedcheck OK for req from %s: group=%s mode=%s — press a to sign join",

	"p.members.header": "members — online/offline/last active (v13.1 · this panel is read-only)",
	"p.members.empty":  "(no members)",
	"p.join.header":    "join_req queue (carry holders sign join; applicant self-signing never valid)",
	"p.join.hint":      "  a=approve(sign join) d=deny s=check seed file · seed must hash-match genesis (creator-signed only)",
	"p.admin.members":  "members (K=kick P=perms G=grant-admin R=revoke-admin T=transfer)",
	"p.admin.banned":   "blacklist (kicked — appeal channel only reaches unban-authorized members; U=unban)",
	"p.admin.xfers":    "transfer proposals addressed to me (a=endorse+broadcast, d=deny)",
	"p.admin.xferHint": "  a=endorse the exact proposal & broadcast d=drop (never forwarded) · green signer = current owner/creator",
	"p.admin.appeals":  "directed appeals from blacklisted members (u=sign unban, i=ignore)",
	"p.empty":          "  (empty)",
	"p.none":           "  (none)",
	"p.nd.header":      "netdisk",
	"p.nd.off":         "netdisk_mb=0 disabled (or backend not wired) — owner/creator: /netdisk set <MB> to enable",
	"p.nd.cmds":        "commands: /netdisk upload <path> · download <name> · delete <name> · set <MB> · r=refresh",
	"p.progress.title": "v18 /progress — outstanding debt, pending implementation",
	"p.progress.note":  "Two-track progress (PLAN v18): design finalized, code not landed yet — this panel is the reserved slot.",

	"role.creator": "creator",
	"role.owner":   "owner",
	"role.admin":   "admin",
	"role.member":  "member",

	"mem.active":  "active %s",
	"mem.never":   "offline (never seen)",
	"mem.offline": "offline %s",
	"mem.me":      " (me)",
	"ban.line":    "x %-22s kicked %s by proof(sig_alg=%s)",

	"join.line":       "req %.10s from %s wg=%s mode=%s %s%s%s",
	"join.seedOK":     "seed=OK",
	"join.seedBad":    "seed=unverified",
	"join.note":       " note=%s",
	"xfer.line":       "xfer %.10s from %s -> me (%s, pending my endorse)%s",
	"xfer.unverified": "signer-unverified!",
	"xfer.owner":      "owner/creator",
	"age.ago":         " (%s ago)",

	"nd.quota":    "quota/member: %d MB   total: %s   used: %s",
	"nd.contrib":  "contributors: %d   online-writable: %d   degraded stripes: %d",
	"nd.note":     "note: %s",
	"nd.degraded": "! RAID5 degraded: single-block loss tolerated, rebuilding preferred; writes may pause",
	"nd.disabled": "netdisk disabled (netdisk_mb=0). Owner/creator: /netdisk set <MB> (<=256)",
	"nd.files":    "-- files --",
	"nd.fileLine": "  %-28s %8s stripes=%d %s",
	"nd.ok":       "ok",
	"nd.degr":     "DEGRADED",

	"help.text": `commands:
  <text>                     send chat message (speak perm required)
  /hide <msg_id>             soft-delete a message you sent (hide event)
  /audit                     on-demand multi-source consistency check
  /remove                    leave group (self-signed remove; not blacklisted)
  /kick <pub>                explicit kick event -> member removed + blacklisted
  /unban <pub>               lift a blacklist entry
  /perms <pub> <p1,p2,...>   set perms (signer must outrank target)
  /grant-admin <pub> /revoke-admin <pub> /transfer <pub>
  /transfers                 list transfer endorsement proposals addressed to me
  /approve <id|latest>       endorse a transfer proposal (same bytes) + broadcast
  /deny <id|latest>          drop a transfer proposal (never forwarded)
  /offline-after <ms>        self presence threshold (v13.1)
  /seedcheck <path>          verify seed file: recompute group_id + creator_sig
  /netdisk                   open netdisk panel
  /netdisk upload <path> | download <name> | delete <name> | set <MB>
  /lang zh|en                switch UI language (v20)
  /help /clear /quit         misc
  pub forms: ed25519:<hex> or bare <hex> (defaults ed25519)
panels: tab/shift-tab cycle; chat members join admin netdisk progress
keys: 1..6 jump · esc=back to chat · up/down/pgup/pgdn=chat scroll ·
      on list panels keys act on selection, Enter or '/' focuses input`,
}

var catalogZh = map[string]string{
	"panel.chat":     "聊天",
	"panel.members":  "成员",
	"panel.join":     "入群",
	"panel.admin":    "群管",
	"panel.netdisk":  "网盘",
	"panel.progress": "进度",

	"top.line":          "本机=%s · 群组=%s · 成员=%d（在线 %d）· 黑名单=%d · 待审入群=%d · 面板=%s",
	"status.hint":       "tab=切换面板 [%s] · 1..6 直达 · esc=回聊天 · 关闭窗口即退出 · /help 查看命令",
	"input.listFocus":   "%s  （列表焦点：按键作用于选中行 · Enter 或 / 进入编辑）",
	"input.placeholder": "输入消息…  输入 /help 查看命令",

	"act.submitted":        "%s · 已提交",
	"act.failed":           "%s · 失败：%v",
	"act.sent":             "发送",
	"act.hide":             "隐藏",
	"act.leave":            "退群 remove 事件已签发",
	"act.kick":             "除名 kick",
	"act.unban":            "解禁 unban",
	"act.perms":            "改权限 perms",
	"act.grantAdmin":       "任命管理",
	"act.revokeAdmin":      "撤销管理",
	"act.transfer":         "transfer 事件（待新 owner 联署）",
	"act.endorsed":         "transfer 已联署并广播",
	"act.deniedLine":       "· transfer 提案 %s 已拒绝（仅本地丢弃，绝不转发）",
	"act.joinSigned":       "join 已签发并广播",
	"act.kickEvent":        "kick 事件",
	"act.unbanEvent":       "unban 事件",
	"act.grantAdminEvent":  "grant_admin 事件",
	"act.revokeAdminEvent": "revoke_admin 事件",
	"act.permsEvent":       "perms 事件",
	"act.presence":         "在场阈值更新",
	"act.ndQuota":          "网盘配额 -> %d MB",
	"act.upload":           "上传 %s",
	"act.download":         "下载 %s",
	"act.delete":           "删除 %s",

	"ev.appeal":      "收到 %s 的新申诉（群管面板处理）",
	"ev.joinreq":     "收到 %s 的 join_req 入群申请（切到入群面板）",
	"ev.xferChat":    "· 收到 %s 的 transfer 提案 — 群管面板（a/d）或 /approve %s | /deny %s",
	"ev.xferStatus":  "收到 %s 的 transfer 提案（群管面板，或 /approve 联署）",
	"ev.roster":      "· 名单更新：%s",
	"ev.netdisk":     "· 网盘：%s",
	"ev.ndStatusErr": "网盘状态查询失败：%v",

	"st.inputErr":       "输入错误：%v",
	"st.noSpeak":        "本机在该群无发言权限（或不在成员名单）",
	"st.ndUnavailable":  "网盘不可用（配额为 0 或后端未接线）",
	"st.cancelled":      "已取消",
	"st.emptyCancelled": "输入为空，已取消",
	"st.permsErr":       "权限解析错误：%v",
	"st.rejectFail":     "拒绝失败：%v",
	"st.denyFail":       "拒绝失败：%v",
	"st.seedGate":       "%s 的种子哈希尚未核对——先按 s 核对种子文件",
	"st.appealIgnored":  "已忽略该申诉（仅保留在日志中）",
	"st.notOwner":       "提案签名者不是现任 owner/创建者——拒绝联署",
	"st.langNow":        "当前语言：%s（/lang zh|en 切换）",
	"st.langSet":        "语言已切换为 %s",
	"st.langBad":        "未知语言 %q（可选：zh、en）",

	"prompt.seedPath": "要核对的种子文件路径",
	"prompt.permsFor": "为 %s 设置新权限（逗号分隔）",

	"lf.none":   "transfer 提案：暂无待决",
	"lf.title":  "%d 条待决 transfer 提案：",
	"lf.hint":   "  /approve <msg_id|latest|唯一前缀> · /deny <同上>",
	"au.failed": "核查失败：%s",
	"au.line":   "核查：%s",

	"sc.err":        "种子核对：%s",
	"sc.rejected":   "种子核对被拒：%s",
	"sc.wrongGroup": "种子核对：种子有效（%s）但不属于本群",
	"sc.ok":         "种子核对通过：%s（mode=%s）",
	"sc.okReq":      "%s 的申请种子核对通过：群=%s mode=%s — 按 a 签 join",

	"p.members.header": "成员 — 在线/离线/最后活跃（v13.1，本面板只读）",
	"p.members.empty":  "（暂无成员）",
	"p.join.header":    "join_req 队列（join 由具 carry 权限者签发；申请人自签永远无效）",
	"p.join.hint":      "  a=批准（签 join） d=拒绝 s=核对种子文件 · 种子哈希须与创世配置一致（只有创建者能签）",
	"p.admin.members":  "成员（K=除名 P=改权限 G=任命管理 R=撤销管理 T=移交）",
	"p.admin.banned":   "黑名单（被除名者——申诉通道仅可达具解禁权限的成员；U=解禁）",
	"p.admin.xfers":    "发给本机的 transfer 联署提案（a=联署+广播，d=拒绝）",
	"p.admin.xferHint": "  a=按提案原文联署并广播 d=丢弃（绝不转发）· 绿色签名者=现任 owner/创建者",
	"p.admin.appeals":  "被拉黑成员的定向申诉（u=签 unban 解禁，i=忽略）",
	"p.empty":          "  （空）",
	"p.none":           "  （无）",
	"p.nd.header":      "群网盘",
	"p.nd.off":         "netdisk_mb=0 已关闭（或后端未接线）— 群主/创建者可 /netdisk set <MB> 开启",
	"p.nd.cmds":        "命令：/netdisk upload <路径> · download <名称> · delete <名称> · set <MB> · r=刷新",
	"p.progress.title": "v18 /progress 欠账挂账，待补做",
	"p.progress.note":  "进度双轨制（PLAN v18）：设计已定稿，代码未落地 —— 本面板为预留占位。",

	"role.creator": "创建者",
	"role.owner":   "群主",
	"role.admin":   "管理",
	"role.member":  "成员",

	"mem.active":  "%s 前活跃",
	"mem.never":   "离线（从未见其发言）",
	"mem.offline": "离线 %s",
	"mem.me":      "（本人）",
	"ban.line":    "x %-22s 除名于 %s 前（proof sig_alg=%s）",

	"join.line":       "申请 %.10s 来自 %s wg=%s mode=%s %s%s%s",
	"join.seedOK":     "种子=OK",
	"join.seedBad":    "种子未核对",
	"join.note":       " 备注=%s",
	"xfer.line":       "transfer %.10s 来自 %s -> 本机（%s，待本机联署）%s",
	"xfer.unverified": "签名者非现任！",
	"xfer.owner":      "owner/创建者",
	"age.ago":         "（%s 前）",

	"nd.quota":    "每人配额：%d MB   总量：%s   已用：%s",
	"nd.contrib":  "贡献成员：%d   在线可写：%d   降级条带：%d",
	"nd.note":     "提示：%s",
	"nd.degraded": "！RAID5 降级：容忍单块丢失，宜尽快重建；期间写入可能暂停",
	"nd.disabled": "网盘已关闭（netdisk_mb=0）。群主/创建者：/netdisk set <MB>（≤256）",
	"nd.files":    "— 文件列表 —",
	"nd.fileLine": "  %-28s %8s 条带=%d %s",
	"nd.ok":       "正常",
	"nd.degr":     "降级",

	"help.text": `命令：
  <文本>                     发送聊天消息（需 speak 权限）
  /hide <msg_id>             软删除自己发的一条消息（hide 事件）
  /audit                     按需多源一致性核查
  /remove                    退群（本人自签 remove；不进黑名单）
  /kick <pub>                显式 kick 事件 → 移出成员 + 进黑名单
  /unban <pub>               解除一条黑名单
  /perms <pub> <p1,p2,...>   改权限（签名者须高过目标层级）
  /grant-admin <pub> /revoke-admin <pub> /transfer <pub>
  /transfers                 列出发给本机的待决 transfer 联署提案
  /approve <id|latest>       按提案原文联署并广播
  /deny <id|latest>          拒绝提案（丢弃，绝不转发）
  /offline-after <ms>        本人自报在场离线阈值（v13.1）
  /seedcheck <path>          核对种子文件：重算 group_id + creator_sig
  /netdisk                   打开网盘面板
  /netdisk upload <路径> | download <名称> | delete <名称> | set <MB>
  /lang zh|en                切换界面语言（v20）
  /help /clear /quit         其他
  公钥写法：ed25519:<hex> 或裸 <hex>（默认 ed25519）
面板：tab/shift-tab 循环切换；聊天 成员 入群 群管 网盘 进度
按键：1..6 直达 · esc=回聊天 · 上/下/pgup/pgdn=滚动聊天 ·
      列表面板下按键作用于选中行，Enter 或 / 聚焦输入栏`,
}
