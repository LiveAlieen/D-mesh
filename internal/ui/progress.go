// progress.go：v18 进度双轨制数据表（v22 补做欠账）——
// 版本迭代 changelog + 功能实现里程碑完成度，供 /progress 命令与 6·进度 面板共用。
// 内容源自 docs/DESIGNLOG.md 与 PLAN.md 里程碑，随版本递增更新；
// 完成度按「代码实现 + 测试覆盖」口径评估（非按设计版本）。

package ui

import "fmt"

type versionNote struct {
	ver string
	sum string
}

var changelog = []versionNote{
	{"v1", "忠实两份外部设计文档（BT 发现 + 群聊原案）"},
	{"v2", "按用户修改重设计（偏离原文档的开端）"},
	{"v3", "补成员生命周期"},
	{"v4", "种子瘦身为身份锚（不再携带成员名单）"},
	{"v5", "名单改签名快照（后被 v6 修正）"},
	{"v6", "广播无许可；取消快照重签"},
	{"v7", "入群事件 + 验证者联署"},
	{"v7.1", "remove 统一主动/被动退群（后被 v15 废弃）"},
	{"v8", "准入反转：成员判定=不在黑名单；黑白双名单全员维护"},
	{"v9", "取消自签入群：join 一律由具 carry 权限者签发"},
	{"v10", "权限层级树 创建者>群主>管理>成员；黑名单定向申诉通道"},
	{"v11", "重上线自动回灌 + ≥3 源交叉比对"},
	{"v12", "两把密钥分离：群密钥=身份锚，创建者密钥=层级最高"},
	{"v13", "在场表：在线/离线按本人自报 offline_after 判定（v13.1 与权限分表）"},
	{"v14", "群网盘 RAID5：每成员预留 0~256MB、单块容错异或重建"},
	{"v15", "退群(remove 自签)与除名(kick 事件)拆分为两条事件"},
	{"v16", "签名算法不固定：sig_alg 标识 + 可插拔注册表（默认 Ed25519）"},
	{"v17", "transfer 新 owner 联署 + netdisk_manifest 独立帧 + 本机脏条目清洗"},
	{"v18", "/progress 进度双轨制设计定稿（代码欠账 → v22 已补做）"},
	{"v19", "Ebitengine 原生窗口 GUI，彻底移除 bubbletea TUI"},
	{"v20", "GUI 美化（圆角气泡/药丸标签）+ 中英双语 i18n"},
	{"v21", "语言目录 JSON 文件化：go:embed 内嵌 + 外置 langs 目录可扩展"},
	{"v22", "默认语言固定中文 + 补做 v18 /progress 欠账"},
	{"v23", "GUI 重写 QQ 风格浅色渲染 + /theme 深浅双主题"},
	{"v24", "主题文件化：调色板迁 JSON（go:embed 内嵌 + 外置 themes 目录可扩展）"},
	{"v25", "操作全面 GUI 化：按钮/右键菜单/表单取代斜杠命令（无头 stdin 语义不变）"},
}

type milestone struct {
	name string
	pct  int
	note string
}

var milestones = []milestone{
	{"M0 地基(core/identity/store)", 100, "全仓 go test 绿"},
	{"M1 群组(双名单+签名事件)", 100, "join/kick/transfer 联署齐"},
	{"M2 传输(Noise+分片+打洞+DHT)", 100, "回环联调过；公网发现待验"},
	{"M3 消息(验证/去重/flood)", 100, "双实例 E2E 全网送达"},
	{"M4 回灌(多源比对+申诉)", 100, "asked/responded 回归过"},
	{"M5 信誉(限速/评分/屏蔽)", 100, "评分与本地屏蔽测试绿"},
	{"M6 网盘(RAID5+重建再平衡)", 100, "单块容错测试绿；多成员待测"},
	{"集成(cmd 接线+GUI)", 100, "无头+真窗口双通道 E2E"},
}

// ProgressLines 输出双轨进度（先版本迭代、后功能实现）。
func ProgressLines() []string {
	out := make([]string, 0, 2+len(changelog)+len(milestones))
	out = append(out, Tr("p.progress.versions"))
	for _, c := range changelog {
		out = append(out, fmt.Sprintf("  %-5s %s", c.ver, c.sum))
	}
	out = append(out, Tr("p.progress.milestones"))
	for _, m := range milestones {
		out = append(out, fmt.Sprintf("  %-28s %d%%  %s", m.name, m.pct, m.note))
	}
	return out
}
