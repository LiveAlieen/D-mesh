package ui

import (
	"encoding/hex"
	"testing"

	"dmesh/internal/core"
)

func TestParseCommandTable(t *testing.T) {
	hexA := "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
	pubA, err := hex.DecodeString(hexA)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		in      string
		want    Command
		wantErr bool
	}{
		{name: "text", in: "hello world", want: Command{Kind: CmdText, Text: "hello world"}},
		{name: "text trimmed", in: "  你好  ", want: Command{Kind: CmdText, Text: "你好"}},
		{name: "empty", in: "   ", wantErr: true},
		{name: "help", in: "/help", want: Command{Kind: CmdHelp}},
		{name: "h alias", in: "/h", want: Command{Kind: CmdHelp}},
		{name: "quit", in: "/quit", want: Command{Kind: CmdQuit}},
		{name: "clear", in: "/clear", want: Command{Kind: CmdClear}},
		{name: "unknown", in: "/frobnicate x", wantErr: true},
		{name: "hide", in: "/hide m123", want: Command{Kind: CmdHide, MsgID: "m123"}},
		{name: "hide missing arg", in: "/hide", wantErr: true},
		{name: "audit", in: "/audit", want: Command{Kind: CmdAudit}},
		{name: "remove", in: "/remove", want: Command{Kind: CmdRemove}},
		{
			name: "kick bare hex defaults ed25519", in: "/kick " + hexA,
			want: Command{Kind: CmdKick, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}},
		},
		{
			name: "kick alg prefixed", in: "/kick sm2:" + hexA,
			want: Command{Kind: CmdKick, Target: core.PubKey{Alg: core.SigAlg("sm2"), Bytes: pubA}},
		},
		{name: "kick bad hex", in: "/kick zz00", wantErr: true},
		{name: "kick missing arg", in: "/kick", wantErr: true},
		{name: "unban", in: "/unban " + hexA, want: Command{Kind: CmdUnban, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}}},
		{
			name: "perms", in: "/perms " + hexA + " speak,receive,carry",
			want: Command{Kind: CmdPerms, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}, Perms: []string{"speak", "receive", "carry"}},
		},
		{name: "perms dedup", in: "/perms " + hexA + " speak,speak,receive", want: Command{Kind: CmdPerms, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}, Perms: []string{"speak", "receive"}}},
		{name: "perms unknown", in: "/perms " + hexA + " speak,fly", wantErr: true},
		{name: "perms missing list", in: "/perms " + hexA, wantErr: true},
		{name: "grant-admin", in: "/grant-admin " + hexA, want: Command{Kind: CmdGrantAdmin, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}}},
		{name: "revoke-admin", in: "/revoke-admin " + hexA, want: Command{Kind: CmdRevokeAdmin, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}}},
		{name: "transfer", in: "/transfer " + hexA, want: Command{Kind: CmdTransfer, Target: core.PubKey{Alg: core.SigEd25519, Bytes: pubA}}},
		{name: "offline-after", in: "/offline-after 120000", want: Command{Kind: CmdOfflineAfter, Millis: 120000}},
		{name: "offline-after zero rejected", in: "/offline-after 0", wantErr: true},
		{name: "offline-after negative rejected", in: "/offline-after -5", wantErr: true},
		{name: "offline-after nan rejected", in: "/offline-after soon", wantErr: true},
		{name: "seedcheck", in: "/seedcheck C:/tmp/group.json", want: Command{Kind: CmdSeedCheck, Path: "C:/tmp/group.json"}},
		{name: "netdisk panel", in: "/netdisk", want: Command{Kind: CmdNetdisk}},
		{name: "nd alias", in: "/nd status", want: Command{Kind: CmdNDStatus}},
		{name: "nd upload", in: "/netdisk upload C:/a b/photo.png", want: Command{Kind: CmdNDUpload, Path: "C:/a b/photo.png"}},
		{name: "nd download keeps spaces", in: "/netdisk download my report.txt", want: Command{Kind: CmdNDDownload, Name: "my report.txt"}},
		{name: "nd delete", in: "/netdisk delete old.bin", want: Command{Kind: CmdNDDelete, Name: "old.bin"}},
		{name: "nd set ok", in: "/netdisk set 64", want: Command{Kind: CmdNDSet, MB: 64}},
		{name: "nd set zero ok", in: "/netdisk set 0", want: Command{Kind: CmdNDSet, MB: 0}},
		{name: "nd set over max rejected", in: "/netdisk set 257", wantErr: true},
		{name: "nd set negative rejected", in: "/netdisk set -1", wantErr: true},
		{name: "nd unknown sub", in: "/netdisk frobnicate", wantErr: true},
		{name: "nd upload missing arg", in: "/netdisk upload", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCommand(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCommand(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCommand(%q) unexpected error: %v", tc.in, err)
			}
			if got.Kind != tc.want.Kind {
				t.Errorf("kind = %v, want %v", got.Kind, tc.want.Kind)
			}
			if got.Text != tc.want.Text || got.MsgID != tc.want.MsgID || got.Path != tc.want.Path || got.Name != tc.want.Name || got.MB != tc.want.MB || got.Millis != tc.want.Millis {
				t.Errorf("args = %+v, want %+v", got, tc.want)
			}
			if !got.Target.Equal(tc.want.Target) {
				t.Errorf("target = %v, want %v", got.Target, tc.want.Target)
			}
			if len(got.Perms) != len(tc.want.Perms) {
				t.Errorf("perms = %v, want %v", got.Perms, tc.want.Perms)
			} else {
				for i := range got.Perms {
					if got.Perms[i] != tc.want.Perms[i] {
						t.Errorf("perms = %v, want %v", got.Perms, tc.want.Perms)
						break
					}
				}
			}
		})
	}
}

func TestParsePubKeyEdge(t *testing.T) {
	if _, err := ParsePubKey("ed25519:"); err == nil {
		t.Fatal("empty hex should error")
	}
	if _, err := ParsePubKey("odd-length-hex?"); err == nil {
		t.Fatal("non-hex should error")
	}
	p, err := ParsePubKey("ff00")
	if err != nil {
		t.Fatal(err)
	}
	if p.Alg != core.SigEd25519 {
		t.Errorf("default alg = %v", p.Alg)
	}
	if len(p.Bytes) != 2 || p.Bytes[0] != 0xff {
		t.Errorf("bytes = %x", p.Bytes)
	}
}

func TestParsePermListRejectsEmptyEntries(t *testing.T) {
	if _, err := ParsePermList("speak,,receive"); err == nil {
		t.Fatal("empty entry should error")
	}
	if _, err := ParsePermList("unban"); err != nil {
		t.Fatalf("valid perm rejected: %v", err)
	}
}
