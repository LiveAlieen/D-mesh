// console_test.go：v27 无头命令通道的两侧可达性契约 + 行为断言。
//
// 核心是 TestBothSidesCoverEveryAction：GUI 动作表（allActionIDs）里的每一项，
// 要么无头命令能触发（planFor 产出），要么显式登记为 GUI-only 并写明理由（guiOnly）。
// 新增动作只在一侧接线 ⇒ 本测试红。

package ui

import (
	"encoding/json"
	"strings"
	"testing"

	"dmesh/internal/core"
)

// ---- 契约：一张动作表，两侧都要有归属 ----

func TestBothSidesCoverEveryAction(t *testing.T) {
	// 无头侧：每类命令都必须落到动作或只读回报上，且收集其触发的动作。
	headless := map[ActionID]bool{}
	for _, k := range allCmdKinds {
		p, ok := planFor(sampleCommand(t, k))
		if !ok {
			t.Errorf("命令类别 %v 在无头控制台没有归属（新增命令须在 planFor 接线）", k)
			continue
		}
		if p.action == "" && p.report == "" && k != CmdTheme && k != CmdLang {
			t.Errorf("命令类别 %v 的 plan 既无动作也无回报", k)
		}
		if p.action != "" {
			headless[p.action] = true
		}
	}
	// GUI 侧：每个动作都要在窗口里有落点（顶栏/面板动作条/行菜单/设置浮层）。
	surfaced := guiSurfacedActions(t)

	for _, id := range allActionIDs {
		why, only := guiOnly[id]
		switch {
		case headless[id] && only:
			t.Errorf("动作 %s 同时是无头可达与 GUI-only（理由表该清一项）", id)
		case !headless[id]:
			if !only || strings.TrimSpace(why) == "" {
				t.Errorf("动作 %s 无头不可达，却没在 guiOnly 登记理由", id)
			}
		}
		if !surfaced[id] {
			t.Errorf("动作 %s 在 GUI 任何控件面上都不出现（顶栏/动作条/右键菜单/设置浮层）", id)
		}
	}
	for id := range guiOnly {
		found := false
		for _, known := range allActionIDs {
			if known == id {
				found = true
			}
		}
		if !found {
			t.Errorf("guiOnly 登记了不在 allActionIDs 里的动作 %s", id)
		}
	}
}

// guiSurfacedActions 遍历所有面板与选中行，收集窗口上真正能点到的动作 id。
func guiSurfacedActions(t *testing.T) map[ActionID]bool {
	t.Helper()
	v, app := newTestVM(t)
	out := map[ActionID]bool{}
	collect := func(acts []Action) {
		for _, a := range acts {
			out[a.ID] = true
		}
	}
	collect(v.ToolbarActions())

	// 队列的宿主侧真身：切面板时 vm 会从宿主重拉，事件注入的副本会被覆盖。
	app.joins = []JoinRequest{{Msg: core.Message{MsgID: "jr1", Sender: keyPub(t, 0xdd),
		Kind: core.KindCommand, Body: []byte(`{"join_req":{}}`)}, SeedOK: true}}
	app.transfers = []TransferProposal{{Msg: core.Message{MsgID: "tp1", Sender: app.self,
		Kind: core.KindCommand, Body: []byte(`{"transfer":{}}`)}, FromOwner: true}}
	app.r.banned = []core.BlacklistEntry{{Pub: keyPub(t, 0xcc)}}
	// 聊天行：自己发的那条才有「隐藏本条」。
	v.OnEvent(TextEvent{Msg: core.Message{MsgID: "mine", Sender: app.self, TSms: 1700000000000,
		Kind: core.KindMessage, Body: []byte(`{"text":"hi"}`)}})
	v.OnEvent(AppealEvent{Msg: core.Message{MsgID: "ap1", Sender: keyPub(t, 0xcc),
		Kind: core.KindMessage, Body: []byte(`{"text":"please"}`)}})

	for panel := PanelChat; panel <= PanelProgress; panel++ {
		v.setPanel(panel)
		for sel := 0; sel < 6; sel++ {
			v.sel = sel
			collect(v.PanelActions())
			collect(v.RowActions())
		}
	}
	v.sel = 0
	v.setPanel(PanelChat)
	if d := v.settingsDialog(); d != nil {
		for _, it := range d.items {
			out[ActionID(it.Key)] = true
		}
	}
	return out
}

func sampleCommand(t *testing.T, k CmdKind) Command {
	t.Helper()
	pk := keyPub(t, 0xbb)
	switch k {
	case CmdText:
		return Command{Kind: k, Text: "hi"}
	case CmdHide, CmdApprove, CmdDeny:
		return Command{Kind: k, MsgID: "latest"}
	case CmdKick, CmdUnban, CmdGrantAdmin, CmdRevokeAdmin, CmdTransfer:
		return Command{Kind: k, Target: pk}
	case CmdPerms:
		return Command{Kind: k, Target: pk, Perms: []string{core.PermSpeak}}
	case CmdOfflineAfter:
		return Command{Kind: k, Millis: 60000}
	case CmdSeedCheck, CmdNDUpload:
		return Command{Kind: k, Path: "seed.json"}
	case CmdNDDownload:
		return Command{Kind: k, Name: "a.txt", Path: "out.txt"}
	case CmdNDDelete:
		return Command{Kind: k, Name: "a.txt"}
	case CmdNDSet:
		return Command{Kind: k, MB: 64}
	case CmdLang:
		return Command{Kind: k, Lang: "zh"}
	case CmdTheme:
		return Command{Kind: k, Theme: "dark"}
	case CmdJoinApprove, CmdJoinReject:
		return Command{Kind: k, MsgID: "latest"}
	}
	return Command{Kind: k}
}

// ---- 行为：命令打到宿主上的调用与 GUI 点击完全一致 ----

func newTestConsole(t *testing.T) (*Console, *fakeApp, *fakeND) {
	t.Helper()
	v, app := newTestVM(t)
	c := &Console{vm: v}
	c.vm.errSink = func(note string) { c.err = note }
	return c, app, app.nd.(*fakeND)
}

func TestConsoleActionsHitHost(t *testing.T) {
	c, app, nd := newTestConsole(t)
	target := hexOf(keyPub(t, 0xbb))
	cases := []struct {
		line string
		want string // 宿主调用记录里的子串
	}{
		{"hello there", "SendText:hello there"},
		{"/kick " + target, "Kick:ed25519:" + target},
		{"/unban " + target, "Unban:ed25519:" + target},
		{"/grant-admin " + target, "GrantAdmin:ed25519:" + target},
		{"/revoke-admin " + target, "RevokeAdmin:ed25519:" + target},
		{"/transfer " + target, "Transfer:ed25519:" + target},
		{"/perms " + target + " speak,receive", "SetPerms:ed25519:" + target + "=speak,receive"},
		{"/hide m1", "Hide:m1"},
		{"/remove", "Leave"},
		{"/offline-after 5000", "SetOfflineAfter"},
		{"/netdisk set 64", "SetNetdiskMB"},
		{"/netdisk upload /tmp/x.bin", "Upload:/tmp/x.bin"},
		{"/netdisk download a.txt", "Download:a.txt"},
		{"/netdisk save a.txt /tmp/out.bin", "Download:a.txt→/tmp/out.bin"},
		{"/netdisk delete a.txt", "Delete:a.txt"},
		{"/audit", "Audit"},
	}
	for _, tc := range cases {
		app.calls, nd.calls = nil, nil
		out := c.Run(tc.line)
		if !out.OK {
			t.Errorf("%s: ok=false err=%v", tc.line, out.Err)
			continue
		}
		if out.Kind != "action" {
			t.Errorf("%s: kind=%q，期望 action", tc.line, out.Kind)
		}
		all := strings.Join(append(append([]string{}, app.calls...), nd.calls...), "|")
		if !strings.Contains(all, tc.want) {
			t.Errorf("%s: 宿主未收到 %q（实际 %q）", tc.line, tc.want, all)
		}
	}
}

func TestConsoleReportsErrorsInsteadOfSilentlyNoOp(t *testing.T) {
	c, app, _ := newTestConsole(t)
	if out := c.Run("/kick"); out.OK || out.Kind != "err" || out.Err == "" {
		t.Errorf("缺参数的 /kick 应报错：kind=%q ok=%v err=%v", out.Kind, out.OK, out.Err)
	}
	if out := c.Run("/bogus"); out.OK || out.Kind != "err" {
		t.Errorf("未知命令应报错：%+v", out)
	}
	// 队列里没有该 id ⇒ 定位失败要说清楚，而不是静默什么都不做。
	if out := c.Run("/approve latest"); out.OK || out.Kind != "err" {
		t.Errorf("空收件箱里的 /approve 应报错：%+v", out)
	}
	// 宿主返回 error ⇒ ok=false 且原因来自 exec（不靠猜本地化文本）。
	app.failNext = true
	out := c.Run("/kick " + hexOf(keyPub(t, 0xbb)))
	if out.OK {
		t.Errorf("宿主报错时 ok 应为 false：%+v", out)
	}
	if out.Err == "" {
		t.Error("ok=false 却没带回失败原因")
	}
}

func TestConsoleLocatesQueuesByID(t *testing.T) {
	t.Run("join approve", func(t *testing.T) {
		c, app, _ := newTestConsole(t)
		app.joins = []JoinRequest{
			{Msg: core.Message{MsgID: "jreq-0001", Sender: keyPub(t, 0xdd), Kind: core.KindCommand,
				Body: []byte(`{"join_req":{}}`)}, SeedOK: true},
			{Msg: core.Message{MsgID: "jreq-0002", Sender: keyPub(t, 0xee), Kind: core.KindCommand,
				Body: []byte(`{"join_req":{}}`)}, SeedOK: true},
		}
		if out := c.Run("/join approve jreq-0001"); !out.OK {
			t.Fatalf("ok=false err=%v", out.Err)
		}
		if !app.has("ApproveJoin:jreq-0001") {
			t.Errorf("未批准指定申请：%v", app.calls)
		}
		if out := c.Run("/join reject latest"); !out.OK {
			t.Fatalf("reject: ok=false err=%v", out.Err)
		}
		if !app.has("RejectJoin:jreq-0002") {
			t.Errorf("latest 应命中末条：%v", app.calls)
		}
	})
	t.Run("transfer endorse", func(t *testing.T) {
		c, app, _ := newTestConsole(t)
		mk := func(id string) TransferProposal {
			return TransferProposal{Msg: core.Message{MsgID: id, Sender: keyPub(t, 0xbb),
				Kind: core.KindCommand, Body: []byte(`{"transfer":{}}`)}, FromOwner: true}
		}
		app.transfers = []TransferProposal{mk("prop-1"), mk("prop-2")}
		if out := c.Run("/approve prop-1"); !out.OK {
			t.Fatalf("ok=false err=%v", out.Err)
		}
		if !app.has("ApproveTransfer:prop-1") {
			t.Errorf("未联署指定提案：%v", app.calls)
		}
		if out := c.Run("/deny latest"); !out.OK {
			t.Fatalf("deny: ok=false err=%v", out.Err)
		}
		if !app.has("RejectTransfer:prop-2") {
			t.Errorf("latest 应命中剩下的末条：%v", app.calls)
		}
	})
}

func TestConsoleReadOnlyReports(t *testing.T) {
	c, app, _ := newTestConsole(t)
	if out := c.Run("/progress"); out.Kind != "progress" || len(out.Texts) == 0 {
		t.Errorf("/progress：%+v", out)
	}
	if out := c.Run("/members"); out.Kind != "members" || len(out.Texts) < 2 {
		t.Errorf("/members：%+v", out)
	} else if _, ok := out.Data.([]MemberRow); !ok {
		t.Errorf("/members 的 data 应为成员行数组，实际 %T", out.Data)
	}
	if out := c.Run("/transfers"); out.Kind != "transfers" {
		t.Errorf("/transfers：%+v", out)
	}
	if out := c.Run("/netdisk status"); out.Kind != "ndstatus" {
		t.Errorf("/netdisk status：%+v", out)
	} else if st, ok := out.Data.(NetdiskStatus); !ok || st.QuotaMB != 64 {
		t.Errorf("/netdisk status data：%T %+v", out.Data, out.Data)
	}
	if app.has("SendText") {
		t.Errorf("只读回报不得产生出站动作：%v", app.calls)
	}
}

func TestConsoleStateAndQuit(t *testing.T) {
	c, _, _ := newTestConsole(t)
	prev := string(GetTheme())
	t.Cleanup(func() { SetTheme(prev) })
	if out := c.Run("/theme"); out.Kind != "state" || !strings.Contains(out.Texts[0], "available") {
		t.Errorf("裸 /theme 应回报当前值与可选项：%+v", out)
	}
	if out := c.Run("/theme dark"); !out.OK {
		t.Errorf("/theme dark：ok=false err=%v", out.Err)
	}
	if out := c.Run("/theme nosuch"); out.OK || out.Err == "" {
		t.Errorf("未知主题应报错：%+v", out)
	}
	if out := c.Run("/quit"); !out.Quit {
		t.Errorf("/quit 应置 quit：%+v", out)
	}
}

// ---- 机器可读轨：--json 的每命令一行 ----

func TestConsoleOutJSONShape(t *testing.T) {
	c, _, _ := newTestConsole(t)
	raw, err := json.Marshal(c.Run("/audit"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{`"line":"/audit"`, `"kind":"action"`, `"action":"audit"`, `"ok":true`, `"texts":[`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON 输出缺 %s：%s", want, got)
		}
	}
	if strings.Contains(got, `"err"`) || strings.Contains(got, `"data"`) {
		t.Errorf("成功且无结构化数据的命令不该带空字段：%s", got)
	}
}
