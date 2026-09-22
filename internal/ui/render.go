package ui

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"dmesh/internal/core"

	"github.com/charmbracelet/lipgloss"
)

// ---- lipgloss 样式（仅 View 层使用；纯文本渲染函数保持无色以便测试）----

var (
	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	styleOnline  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleOffline = lipgloss.NewStyle().Faint(true).Foreground(lipgloss.Color("240"))
	styleSelf    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	styleOwner   = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	styleAdmin   = lipgloss.NewStyle().Foreground(lipgloss.Color("207"))
	styleSystem  = lipgloss.NewStyle().Italic(true).Foreground(lipgloss.Color("245"))
	styleStatus  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleBad     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleDim     = lipgloss.NewStyle().Faint(true)
)

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

// RoleLabel 把角色映射成展示徽章。
func RoleLabel(r core.Role) string {
	switch r {
	case core.RoleCreator:
		return "creator"
	case core.RoleOwner:
		return "owner"
	case core.RoleAdmin:
		return "admin"
	case core.RoleMember:
		return "member"
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

// RenderMemberLines 输出纯文本成员行（测试用）。
func RenderMemberLines(rows []MemberRow, now time.Time) []string {
	return renderMemberLines(rows, now, false)
}

// RenderMemberLinesStyled 输出带色成员行（View 用）。
func RenderMemberLinesStyled(rows []MemberRow, now time.Time) []string {
	return renderMemberLines(rows, now, true)
}

func renderMemberLines(rows []MemberRow, now time.Time, styled bool) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		var dot, tail string
		if r.Online {
			dot = "●"
			tail = "active " + FormatAge(now.Sub(msTime(r.Presence.LastMsgTS)))
		} else {
			dot = "○"
			if r.Presence.LastMsgTS == 0 {
				tail = "offline (never seen)"
			} else {
				tail = "offline " + FormatAge(now.Sub(msTime(r.Presence.LastMsgTS)))
			}
		}
		name := ShortID(r.Entry.Pub)
		if r.IsSelf {
			name += " (me)"
		}
		line := fmt.Sprintf("%s %-22s [%s] %-28s %s",
			dot, name, RoleLabel(r.Entry.Role),
			strings.Join(r.Entry.Perms, ","), tail)
		if styled {
			line = styleMemberLine(line, r)
		}
		out = append(out, line)
	}
	return out
}

func styleMemberLine(line string, r MemberRow) string {
	st := styleOnline
	if !r.Online {
		st = styleOffline
	}
	switch r.Entry.Role {
	case core.RoleCreator, core.RoleOwner:
		st = styleOwner
	case core.RoleAdmin:
		st = styleAdmin
	}
	if r.IsSelf {
		st = styleSelf
	}
	return st.Render(line)
}

func msTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// RenderBannedLines 渲染黑名单行（群管面板）。
func RenderBannedLines(banned []core.BlacklistEntry, now time.Time, styled bool) []string {
	out := make([]string, 0, len(banned))
	sort.SliceStable(banned, func(i, j int) bool { return banned[i].TS > banned[j].TS })
	for _, b := range banned {
		line := fmt.Sprintf("x %-22s kicked %s by proof(sig_alg=%s)",
			ShortID(b.Pub), FormatAge(now.Sub(msTime(b.TS))), string(b.Proof.Alg))
		if styled {
			line = styleBad.Render(line)
		}
		out = append(out, line)
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
	body := strings.ToValidUTF8(string(m.Content), "\uFFFD")
	if m.Type != core.TypeText {
		body = "(" + m.Type + ") " + body
	}
	return fmt.Sprintf("[%s] %s%s: %s", ts, sender, dir, body)
}

// ---- 入群面板 ----

// FormatJoinLine 渲染一条 join_req 队列行。
func FormatJoinLine(req JoinRequest, now time.Time) string {
	wgs := req.ApplicantWG.String()
	if len(wgs) > 8 {
		wgs = wgs[:8]
	}
	seed := "seed=unverified"
	if req.SeedOK {
		seed = "seed=OK"
	}
	mode := req.Mode
	if mode == "" {
		mode = "?"
	}
	note := ""
	if req.IdentityNote != "" {
		note = " note=" + truncate(req.IdentityNote, 40)
	}
	return fmt.Sprintf("req %.10s from %s wg=%s mode=%s %s%s%s",
		req.Msg.MsgID, ShortID(req.Msg.Sender), wgs, mode, seed, note,
		ageSuffix(req.Msg.TSms, now))
}

// FormatTransferLine 渲染一条发给本机的 transfer 联署提案行（v17①）：
// 提案是现任 owner/创建者定向送达、尚缺本机 endorse_sig 的 transfer 原文。
func FormatTransferLine(prop TransferProposal, now time.Time) string {
	sig := "signer-unverified!"
	if prop.FromOwner {
		sig = "owner/creator"
	}
	return fmt.Sprintf("xfer %.10s from %s -> me (%s, pending my endorse)%s",
		prop.Msg.MsgID, ShortID(prop.Msg.Sender), sig,
		ageSuffix(prop.Msg.TSms, now))
}

func ageSuffix(ms int64, now time.Time) string {
	if ms <= 0 {
		return ""
	}
	return " (" + FormatAge(now.Sub(msTime(ms))) + " ago)"
}

// ---- 网盘面板 ----

// RenderNetdiskLines 渲染网盘总览 + 文件列表（纯文本）。
func RenderNetdiskLines(s NetdiskStatus, files []NetdiskFile) []string {
	out := []string{
		fmt.Sprintf("quota/member: %d MB   total: %s   used: %s",
			s.QuotaMB, humanBytes(s.TotalBytes), humanBytes(s.UsedBytes)),
		fmt.Sprintf("contributors: %d   online-writable: %d   degraded stripes: %d",
			len(s.Contributors), s.OnlineWritable, s.DegradedStripes),
	}
	if s.Note != "" {
		out = append(out, "note: "+s.Note)
	}
	if s.DegradedStripes > 0 {
		out = append(out, "! RAID5 degraded: single-block loss tolerated, rebuilding preferred; writes may pause")
	}
	if s.QuotaMB == 0 {
		out = append(out, "netdisk disabled (netdisk_mb=0). Owner/creator: /netdisk set <MB> (<=256)")
	}
	out = append(out, "-- files --")
	if len(files) == 0 {
		out = append(out, "  (empty)")
	}
	for _, f := range files {
		h := "ok"
		if !f.Healthy {
			h = "DEGRADED"
		}
		out = append(out, fmt.Sprintf("  %-28s %8s stripes=%d %s",
			truncate(f.Name, 28), humanBytes(f.Size), f.Stripes, h))
	}
	return out
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
