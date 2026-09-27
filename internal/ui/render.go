package ui

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"dmesh/internal/core"
)

// v19 起渲染层不再有终端色码（旧的 TUI 样式库已随界面重写一并移除）：
// 纯文本渲染函数保持不变，GUI 的配色由 viewModel 的 ViewLine.Style
// （见 viewmodel.go）驱动，由 ebiten 绘制层映射成色板。

// FormatAge 把时长压成紧凑展示串：12s / 3m05s / 1h02m / 2d03h。
// 负值按 0 处理（时钟小偏差容忍）。纯函数，table-driven 测试。
func FormatAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := d.Truncate(time.Second)
	switch {
	case s < time.Minute:
		return fmt.Sprintf("%ds", int(s.Seconds()))
	case s < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(s.Minutes()), int(s.Seconds())%60)
	case s < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(s.Hours()), int(s.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%02dh", int(s.Hours())/24, int(s.Hours())%24)
	}
}

// ShortID 返回 "alg:xxxxxxxx"（hex 前 8 位），用于列表与聊天流的身份列。
func ShortID(p core.PubKey) string {
	h := hex.EncodeToString(p.Bytes)
	if len(h) > 8 {
		h = h[:8]
	}
	if p.Alg == "" {
		return h
	}
	return string(p.Alg) + ":" + h
}

// RoleLabel 把角色映射成展示徽章（v20 起随界面语言本地化）。
func RoleLabel(r core.Role) string {
	switch r {
	case core.RoleCreator:
		return Tr("role.creator")
	case core.RoleOwner:
		return Tr("role.owner")
	case core.RoleAdmin:
		return Tr("role.admin")
	case core.RoleMember:
		return Tr("role.member")
	default:
		return string(r)
	}
}

// ---- 成员列表（按在场表渲染 在线/离线/最后活跃，v13.1）----

// MemberRow 是成员列表一行：白名单条目 + 在场表 + 派生的在线判定。
type MemberRow struct {
	Entry    core.MemberEntry
	Presence core.PresenceEntry
	Online   bool
	IsSelf   bool
}

// BuildMemberRows 从 Roster 快照 + 在场表构建成员行，排序：在线优先，
// 组内按最后活跃时间新→旧，再按 ShortID 升序保证稳定。
func BuildMemberRows(r core.Roster, self core.PubKey, now time.Time) []MemberRow {
	members, _, _ := r.Snapshot()
	nowMs := now.UnixMilli()
	rows := make([]MemberRow, 0, len(members))
	for _, e := range members {
		pr := r.Presence(e.Pub)
		rows = append(rows, MemberRow{
			Entry:    e,
			Presence: pr,
			Online:   pr.Online(nowMs),
			IsSelf:   e.Pub.Equal(self),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Online != rows[j].Online {
			return rows[i].Online
		}
		if rows[i].Presence.LastMsgTS != rows[j].Presence.LastMsgTS {
			return rows[i].Presence.LastMsgTS > rows[j].Presence.LastMsgTS
		}
		return ShortID(rows[i].Entry.Pub) < ShortID(rows[j].Entry.Pub)
	})
	return rows
}

// RenderMemberLines 输出纯文本成员行（测试与 GUI 快照共用；配色由
// ViewLine.Style 在 viewModel.Snapshot 侧标注，不再内嵌色码）。
func RenderMemberLines(rows []MemberRow, now time.Time) []string {
	return renderMemberLines(rows, now)
}

// RenderMemberLinesStyled 保留导出契约（v16 时代的带色版本入口）；
// v19 GUI 下与 RenderMemberLines 等价，样式改由 ViewLine.Style 表达。
func RenderMemberLinesStyled(rows []MemberRow, now time.Time) []string {
	return renderMemberLines(rows, now)
}

func renderMemberLines(rows []MemberRow, now time.Time) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		var dot, tail string
		if r.Online {
			dot = "●"
			tail = Tf("mem.active", FormatAge(now.Sub(msTime(r.Presence.LastMsgTS))))
		} else {
			dot = "○"
			if r.Presence.LastMsgTS == 0 {
				tail = Tr("mem.never")
			} else {
				tail = Tf("mem.offline", FormatAge(now.Sub(msTime(r.Presence.LastMsgTS))))
			}
		}
		name := ShortID(r.Entry.Pub)
		if r.IsSelf {
			name += Tr("mem.me")
		}
		out = append(out, fmt.Sprintf("%s %-22s [%s] %-28s %s",
			dot, name, RoleLabel(r.Entry.Role),
			strings.Join(r.Entry.Perms, ","), tail))
	}
	return out
}

// memberLineStyle 把成员行映射成 GUI 样式（语义对应旧终端版的分色）。
func memberLineStyle(r MemberRow) LineStyle {
	switch r.Entry.Role {
	case core.RoleCreator, core.RoleOwner:
		return StyleOwner
	case core.RoleAdmin:
		return StyleAdmin
	}
	if r.IsSelf {
		return StyleSelf
	}
	if r.Online {
		return StyleOnline
	}
	return StyleOffline
}

func msTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// RenderBannedLines 渲染黑名单行（群管面板）。styled 参数保留兼容旧签名，
// v19 起不再内嵌色码（着色由 ViewLine.Style=StyleBad 在快照侧表达）。
func RenderBannedLines(banned []core.BlacklistEntry, now time.Time, styled bool) []string {
	out := make([]string, 0, len(banned))
	sort.SliceStable(banned, func(i, j int) bool { return banned[i].TS > banned[j].TS })
	for _, b := range banned {
		out = append(out, Tf("ban.line", ShortID(b.Pub), FormatAge(now.Sub(msTime(b.TS))), string(b.Proof.Alg)))
	}
	return out
}

// ---- 聊天流 ----

// FormatChatLine 渲染一条入站/出站消息：[15:04:05] alg:xxxxxxxx: text。
// 定向消息加 (→to…) 标记；名单事件不进聊天流（由宿主翻译成 RosterEvent）。
func FormatChatLine(m core.Message) string {
	ts := msTime(m.TSms).Format("15:04:05")
	sender := ShortID(m.Sender)
	dir := ""
	if m.To != nil {
		dir = " →" + ShortID(*m.To)
	}
	return fmt.Sprintf("[%s] %s%s: %s", ts, sender, dir, chatBody(m))
}

// ---- 入群面板 ----

// FormatJoinLine 渲染一条 join_req 队列行（v20：文案随语言，msg_id/wg/mode 结构位不动）。
func FormatJoinLine(req JoinRequest, now time.Time) string {
	wgs := req.ApplicantWG.String()
	if len(wgs) > 8 {
		wgs = wgs[:8]
	}
	seed := Tr("join.seedBad")
	if req.SeedOK {
		seed = Tr("join.seedOK")
	}
	mode := req.Mode
	if mode == "" {
		mode = "?"
	}
	note := ""
	if req.IdentityNote != "" {
		note = Tf("join.note", truncate(req.IdentityNote, 40))
	}
	return Tf("join.line", req.Msg.MsgID, ShortID(req.Msg.Sender), wgs, mode, seed, note,
		ageSuffix(req.Msg.TSms, now))
}

// FormatTransferLine 渲染一条发给本机的 transfer 联署提案行（v17①）：
// 提案是现任 owner/创建者定向送达、尚缺本机 endorse_sig 的 transfer 原文。
func FormatTransferLine(prop TransferProposal, now time.Time) string {
	sig := Tr("xfer.unverified")
	if prop.FromOwner {
		sig = Tr("xfer.owner")
	}
	return Tf("xfer.line", prop.Msg.MsgID, ShortID(prop.Msg.Sender), sig,
		ageSuffix(prop.Msg.TSms, now))
}

func ageSuffix(ms int64, now time.Time) string {
	if ms <= 0 {
		return ""
	}
	return Tf("age.ago", FormatAge(now.Sub(msTime(ms))))
}

// ---- 网盘面板 ----

// RenderNetdiskStatusLines 渲染总览小字（v25：网盘面板顶部非选区）。
func RenderNetdiskStatusLines(s NetdiskStatus) []string {
	out := []string{
		Tf("nd.quota", s.QuotaMB, humanBytes(s.TotalBytes), humanBytes(s.UsedBytes)),
		Tf("nd.contrib", len(s.Contributors), s.OnlineWritable, s.DegradedStripes),
	}
	if s.Note != "" {
		out = append(out, Tf("nd.note", s.Note))
	}
	if s.DegradedStripes > 0 {
		out = append(out, Tr("nd.degraded"))
	}
	if s.QuotaMB == 0 {
		out = append(out, Tr("nd.disabled"))
	}
	return out
}

// RenderNetdiskFileLines 渲染文件列表（与 []NetdiskFile 同序，v25 起逐行可选）。
func RenderNetdiskFileLines(files []NetdiskFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		h := Tr("nd.ok")
		if !f.Healthy {
			h = Tr("nd.degr")
		}
		out = append(out, Tf("nd.fileLine", truncate(f.Name, 28), humanBytes(f.Size), f.Stripes, h))
	}
	return out
}

// RenderNetdiskLines 渲染网盘总览 + 文件列表（纯文本，v20 起文案随语言）。
func RenderNetdiskLines(s NetdiskStatus, files []NetdiskFile) []string {
	out := RenderNetdiskStatusLines(s)
	out = append(out, Tr("nd.files"))
	if len(files) == 0 {
		return append(out, Tr("p.empty"))
	}
	return append(out, RenderNetdiskFileLines(files)...)
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// ---- 通用小工具 ----

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}
