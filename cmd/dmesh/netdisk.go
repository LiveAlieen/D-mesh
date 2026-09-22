// netdisk.go：M6 群网盘接线——仅当群配置 netdisk_mb>0 时初始化。
// 块收发经 rpc.go 的请求/应答通道桥接（netdisk.Transport 接口），清单走
// nd.manifest 帧一轮去重泛洪；UI 面板走 ui.Netdisk 门面。

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"dmesh/internal/core"
	"dmesh/internal/message"
	"dmesh/internal/netdisk"
	"dmesh/internal/spam"
	"dmesh/internal/ui"
)

const miB = 1 << 20

func (n *node) netdiskDir() string {
	return filepath.Join(n.o.data, "groups", hex.EncodeToString(n.gid[:]))
}

// initNetdisk 打开本机定额目录并装配 Manager（仅 netdisk_mb>0 时调用）。
func (n *node) initNetdisk(mb int) error {
	if mb <= 0 {
		return nil
	}
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	if n.nd != nil {
		return nil
	}
	ds, err := netdisk.OpenDirStore(filepath.Join(n.netdiskDir(), "netdisk_quota"), int64(mb)*miB)
	if err != nil {
		return err
	}
	mgr, err := netdisk.New(netdisk.Options{
		GroupID: n.gid,
		Signer:  n.id,
		Store:   ds,
		Tx:      ndTx{n},
		Now:     n.now,
		OnSuspect: func(pub core.PubKey, err error) {
			n.scores.PenalizePub(pub, spam.EvConflictingData)
			n.log.Printf("netdisk suspect %s: %v", pub, err)
		},
	})
	if err != nil {
		return err
	}
	n.ndStore = ds
	n.nd = mgr
	n.loadManifests()
	n.refreshNetdiskHostsLocked()
	n.log.Printf("netdisk ready: quota %d MB/member, local dir %s", mb, filepath.Join(n.netdiskDir(), "netdisk_quota"))
	return nil
}

// refreshNetdiskHosts 名单变化后重算出配额成员集合（锁安全包装）。
func (n *node) refreshNetdiskHosts() {
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	n.refreshNetdiskHostsLocked()
}

// onNetdiskQuota 处理 netdisk 事件生效后的配额变化（0→开 / 变值重划预留）。
func (n *node) onNetdiskQuota(mb int) {
	if mb > 0 {
		if err := n.initNetdisk(mb); err != nil {
			n.log.Printf("netdisk enable %dMB: %v", mb, err)
			return
		}
	}
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	n.refreshNetdiskHostsLocked()
}

// refreshNetdiskHostsLocked：出配额成员 = 全体白名单成员（群配置要求人人预留
// 同等空间；未落盘者块操作自然失败并被 OnSuspect 差评）。调用方须持 ndMu。
func (n *node) refreshNetdiskHostsLocked() {
	if n.nd == nil {
		return
	}
	mb := n.roster.NetdiskMB()
	members, _, _ := n.roster.Snapshot()
	hs := make([]netdisk.HostInfo, 0, len(members))
	for _, m := range members {
		hs = append(hs, netdisk.HostInfo{Pub: m.Pub, QuotaBytes: int64(mb) * miB})
	}
	if err := n.nd.SetHosts(hs); err != nil {
		n.log.Printf("netdisk SetHosts: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 清单（manifest）登记与一轮去重泛洪
// ---------------------------------------------------------------------------

func (n *node) manifestsDir() string { return filepath.Join(n.netdiskDir(), "manifests") }

func (n *node) loadManifests() {
	fs, err := filepath.Glob(filepath.Join(n.manifestsDir(), "*.json"))
	if err != nil {
		return
	}
	for _, f := range fs {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var mf netdisk.Manifest
		if err := json.Unmarshal(raw, &mf); err != nil || mf.FileID == "" {
			continue
		}
		n.manifests[mf.FileID] = &mf
	}
}

// acceptManifest 复验收录一条清单消息（netdisk 包自带验签 + 哈希核对）。
// from 用于「不回送来源」的一轮泛洪。
func (n *node) acceptManifest(from core.PubKey, msg core.Message) error {
	mf, _, err := netdisk.ManifestFromMessage(msg, n.gid)
	if err != nil {
		n.scores.PenalizePub(from, spam.EvBadSignature)
		return err
	}
	n.ndMu.Lock()
	fresh := n.manifests[mf.FileID] == nil
	if fresh {
		n.manifests[mf.FileID] = mf
		_ = os.MkdirAll(n.manifestsDir(), 0o700)
		if raw, err := json.Marshal(mf); err == nil {
			_ = os.WriteFile(filepath.Join(n.manifestsDir(), mf.FileID+".json"), raw, 0o600)
		}
	}
	seen := n.maniSeen[msg.MsgID]
	n.maniSeen[msg.MsgID] = true
	n.ndMu.Unlock()

	if fresh {
		n.pushEvent(ui.NetdiskEvent{Note: "new file " + mf.Name})
		n.log.Printf("netdisk manifest adopted: %s (%d bytes)", mf.Name, mf.Size)
	}
	// 无许可转发义务：只转一轮（msg_id 去重），不回来源；异步免阻塞应答路径。
	if !seen && !from.IsZero() {
		raw, _ := json.Marshal(msg)
		go func(raw []byte, from core.PubKey) {
			for _, p := range n.nt.PublicNeighbors() {
				if p.Equal(from) || p.Equal(n.self) {
					continue
				}
				frame, err := json.Marshal(rpcFrame{Proto: rpcProto, ID: message.RandomMsgID(), Kind: rpcNDMani, Data: raw})
				if err != nil {
					continue
				}
				_ = n.nt.SendTo(p, frame)
			}
		}(raw, from)
	}
	return nil
}

// broadcastManifest 把清单推给全部在线邻居（尽力而为，失败计数回报）。
func (n *node) broadcastManifest(msg core.Message) int {
	ok := 0
	for _, p := range n.nt.PublicNeighbors() {
		if p.Equal(n.self) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := n.call(ctx, p, rpcNDMani, msg)
		cancel()
		if err == nil {
			ok++
		}
	}
	return ok
}

// ---------------------------------------------------------------------------
// netdisk.Transport 桥（块收发）+ 清单帧
// ---------------------------------------------------------------------------

type ndTx struct{ n *node }

func (t ndTx) Push(to core.PubKey, b *netdisk.Block) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := t.n.call(ctx, to, rpcNDPut, b)
	return err
}

func (t ndTx) Fetch(from core.PubKey, q netdisk.BlockQuery) (*netdisk.Block, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := t.n.call(ctx, from, rpcNDGet, q)
	if err != nil {
		return nil, err
	}
	var b netdisk.Block
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (t ndTx) List(from core.PubKey, fileID string) ([]*netdisk.Block, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := t.n.call(ctx, from, rpcNDList, struct {
		FileID string `json:"file_id"`
	}{FileID: fileID})
	if err != nil {
		return nil, err
	}
	var bs []*netdisk.Block
	if err := json.Unmarshal(data, &bs); err != nil {
		return nil, err
	}
	return bs, nil
}

func (t ndTx) Remove(from core.PubKey, q netdisk.BlockQuery) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := t.n.call(ctx, from, rpcNDDel, q)
	return err
}

// ---------------------------------------------------------------------------
// ui.Netdisk 门面
// ---------------------------------------------------------------------------

type ndFacade struct{ n *node }

func (f ndFacade) Status() (ui.NetdiskStatus, error) {
	n := f.n
	mb := n.roster.NetdiskMB()
	st := ui.NetdiskStatus{QuotaMB: mb}
	if mb == 0 {
		return st, errors.New("netdisk 未启用（netdisk_mb=0）")
	}
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	if n.nd == nil {
		return st, errors.New("netdisk backend 未装配")
	}
	hosts := n.nd.AllHosts()
	st.TotalBytes = int64(len(hosts)) * int64(mb) * miB
	if n.ndStore != nil {
		st.UsedBytes = n.ndStore.Usage()
	}
	onlineWritable := 0
	for _, h := range hosts {
		online := n.isNeighbor(h.Pub)
		if online {
			onlineWritable++
		}
		st.Contributors = append(st.Contributors, ui.NetdiskContributor{
			Pub: h.Pub, QuotaBytes: h.QuotaBytes, ProvidedBytes: h.QuotaBytes, Online: online,
		})
	}
	st.OnlineWritable = onlineWritable
	st.DegradedStripes, st.Note = f.degradedLocked()
	return st, nil
}

// degradedLocked 统计处于「单块降级、待重建」的条带数（多源放置探测，尽力而为）。
func (f ndFacade) degradedLocked() (int, string) {
	n := f.n
	total := 0
	for _, mf := range n.manifests {
		ps, err := n.nd.CollectPlacements(mf)
		if err != nil {
			continue
		}
		total += len(netdisk.MissingByStripe(mf, ps))
	}
	return total, ""
}

func (f ndFacade) List() ([]ui.NetdiskFile, error) {
	n := f.n
	n.ndMu.Lock()
	defer n.ndMu.Unlock()
	out := make([]ui.NetdiskFile, 0, len(n.manifests))
	for _, mf := range n.manifests {
		healthy := true
		if n.nd != nil {
			if ps, err := n.nd.CollectPlacements(mf); err == nil {
				healthy = len(netdisk.MissingByStripe(mf, ps)) == 0
			} else {
				healthy = false
			}
		}
		out = append(out, ui.NetdiskFile{Name: mf.Name, Size: mf.Size, Stripes: mf.Stripes, Healthy: healthy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f ndFacade) Upload(localPath string) error {
	n := f.n
	n.ndMu.Lock()
	mgr := n.nd
	n.ndMu.Unlock()
	if mgr == nil {
		return errors.New("netdisk backend 未装配")
	}
	content, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	mf, err := mgr.Upload(filepath.Base(localPath), content)
	if err != nil {
		return err
	}
	msg, err := mgr.ManifestMessage(mf)
	if err != nil {
		return err
	}
	n.ndMu.Lock()
	n.manifests[mf.FileID] = mf
	raw, _ := json.Marshal(mf)
	_ = os.MkdirAll(n.manifestsDir(), 0o700)
	_ = os.WriteFile(filepath.Join(n.manifestsDir(), mf.FileID+".json"), raw, 0o600)
	n.ndMu.Unlock()
	sent := n.broadcastManifest(msg)
	n.pushEvent(ui.NetdiskEvent{Note: fmt.Sprintf("uploaded %s to %d peers", mf.Name, sent)})
	return nil
}

func (f ndFacade) Download(name, destPath string) error {
	n := f.n
	n.ndMu.Lock()
	mgr := n.nd
	var mf *netdisk.Manifest
	for _, m := range n.manifests {
		if m.Name == name {
			mf = m
			break
		}
	}
	n.ndMu.Unlock()
	if mgr == nil || mf == nil {
		return fmt.Errorf("网盘文件 %q 不存在", name)
	}
	content, err := mgr.Download(mf)
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, content, 0o600)
}

func (f ndFacade) Delete(name string) error {
	n := f.n
	n.ndMu.Lock()
	mgr := n.nd
	var mf *netdisk.Manifest
	for _, m := range n.manifests {
		if m.Name == name {
			mf = m
			break
		}
	}
	if mf != nil {
		delete(n.manifests, mf.FileID)
		_ = os.Remove(filepath.Join(n.manifestsDir(), mf.FileID+".json"))
	}
	n.ndMu.Unlock()
	if mgr == nil || mf == nil {
		return fmt.Errorf("网盘文件 %q 不存在", name)
	}
	n.pushEvent(ui.NetdiskEvent{Note: "deleted " + name})
	return mgr.RemoveFile(mf)
}
