// rpc.go：集成层粘合协议。
//
// backfill.Source 与 netdisk.Transport 两个接口在各包设计里明确「由 cmd/dmesh
// 接线实现」（backfill: "Integration 用 Tunnel + … 实现"；netdisk: "块经 Transport
// 接口由集成层桥接到 gossip/按需拉取通道"）。本文件就是那层桥接：在邻居 Tunnel
// 上跑一个极简请求/应答帧（与聊天帧按 dmesh_rpc 标记解复用，互不干扰），
// 不触碰任何群聊/名单协议语义。

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"dmesh/internal/backfill"
	"dmesh/internal/core"
	"dmesh/internal/message"
	"dmesh/internal/netdisk"
	"dmesh/internal/spam"
	"dmesh/internal/store"
)

const (
	rpcProto   = "dmesh/rpc-v0-integration"
	rpcTimeout = 15 * time.Second
)

// rpc 帧类别。
const (
	rpcSnapshot = "bf.snapshot"
	rpcMsgs     = "bf.msgs"
	rpcMsgIDs   = "bf.msgids"
	rpcByIDs    = "bf.byids"
	rpcNDPut    = "nd.put"
	rpcNDGet    = "nd.get"
	rpcNDList   = "nd.list"
	rpcNDDel    = "nd.del"
	rpcNDMani   = "nd.manifest"
)

type rpcFrame struct {
	Proto string          `json:"dmesh_rpc"`
	ID    string          `json:"id,omitempty"`
	Kind  string          `json:"kind,omitempty"`
	Resp  bool            `json:"resp,omitempty"`
	OK    bool            `json:"ok,omitempty"`
	Err   string          `json:"err,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type rpcReqMsgs struct {
	AfterTS int64 `json:"after_ts"`
}

type rpcReqIDs struct {
	IDs []string `json:"ids"`
}

type rpcRespMsgs struct {
	Messages []core.Message `json:"messages"`
}

type rpcRespIDs struct {
	IDs []string `json:"ids"`
}

// demux 是 neighbor.Receive 入口：rpc 帧先解走；其余帧过 spam 本地闸
// （屏蔽列表 / 每源限速）后进消息层（验证 + 去重 + flood）。
func (n *node) demux(from core.PubKey, data []byte) {
	var f rpcFrame
	if err := json.Unmarshal(data, &f); err == nil && f.Proto == rpcProto {
		n.handleRPCFrame(from, &f)
		return
	}
	if n.blockl.Blocked(from) {
		return
	}
	if !n.chatLim.Allow(from.Key()) {
		n.scores.PenalizePub(from, spam.EvSpam)
		return
	}
	n.engine.Ingest(from, data)
}

// handleRPCFrame：响应帧路由给等待者；请求帧就地应答。
func (n *node) handleRPCFrame(from core.PubKey, f *rpcFrame) {
	if f.Resp {
		n.mu.Lock()
		ch, ok := n.pending[f.ID]
		n.mu.Unlock()
		if ok {
			select {
			case ch <- *f:
			default:
			}
		}
		return
	}
	payload, err := n.serveRPC(from, f.Kind, f.Data)
	resp := rpcFrame{Proto: rpcProto, ID: f.ID, Resp: true, OK: err == nil}
	if err != nil {
		resp.Err = err.Error()
	} else if payload != nil {
		resp.Data, _ = json.Marshal(payload)
	}
	raw, _ := json.Marshal(resp)
	if serr := n.nt.SendTo(from, raw); serr != nil && err == nil {
		n.log.Printf("rpc %s reply to %s failed: %v", f.Kind, from, serr)
	}
}

// serveRPC 应答侧：只读本地状态（名单/存储/网盘目录），逐条独立可验。
func (n *node) serveRPC(from core.PubKey, kind string, data json.RawMessage) (any, error) {
	switch kind {
	case rpcSnapshot:
		members, banned, owner := n.roster.Snapshot()
		return backfill.Snapshot{Members: members, Banned: banned, Owner: owner}, nil

	case rpcMsgs:
		var q rpcReqMsgs
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		msgs, err := n.st.QueryMessages(store.MessageQuery{SinceMS: q.AfterTS})
		if err != nil {
			return nil, err
		}
		return rpcRespMsgs{Messages: msgs}, nil

	case rpcMsgIDs:
		var q rpcReqMsgs
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		msgs, err := n.st.QueryMessages(store.MessageQuery{SinceMS: q.AfterTS})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(msgs))
		for _, m := range msgs {
			ids = append(ids, m.MsgID)
		}
		return rpcRespIDs{IDs: ids}, nil

	case rpcByIDs:
		var q rpcReqIDs
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		out := make([]core.Message, 0, len(q.IDs))
		for _, id := range q.IDs {
			if m, ok, err := n.st.GetMessage(id); err == nil && ok {
				out = append(out, m)
			}
		}
		return rpcRespMsgs{Messages: out}, nil

	case rpcNDPut:
		var b netdisk.Block
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, err
		}
		// 接收侧独立复验（组 id + 内容哈希 + proof），绝不信任传输方。
		if err := netdisk.CheckBlock(&b, n.gid); err != nil {
			n.scores.PenalizePub(from, spam.EvConflictingData)
			return nil, err
		}
		if n.ndStore == nil {
			return nil, errors.New("netdisk disabled here")
		}
		return nil, n.ndStore.Put(&b)

	case rpcNDGet:
		var q netdisk.BlockQuery
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		if n.ndStore == nil {
			return nil, errors.New("netdisk disabled here")
		}
		b, err := n.ndStore.Get(q.FileID, q.Stripe, q.Pos)
		if err != nil {
			return nil, err
		}
		return b, nil

	case rpcNDList:
		var q struct {
			FileID string `json:"file_id"`
		}
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		if n.ndStore == nil {
			return nil, errors.New("netdisk disabled here")
		}
		bs, err := n.ndStore.List(q.FileID)
		if err != nil {
			return nil, err
		}
		return bs, nil

	case rpcNDDel:
		var q netdisk.BlockQuery
		if err := json.Unmarshal(data, &q); err != nil {
			return nil, err
		}
		if n.ndStore == nil {
			return nil, errors.New("netdisk disabled here")
		}
		return nil, n.ndStore.Delete(q.FileID, q.Stripe, q.Pos)

	case rpcNDMani:
		var msg core.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, err
		}
		return nil, n.acceptManifest(from, msg)

	default:
		return nil, fmt.Errorf("unknown rpc kind %q", kind)
	}
}

// call 发起一次请求并等待应答（邻居必须在线；超时/断连返回 error）。
func (n *node) call(ctx context.Context, to core.PubKey, kind string, req any) (json.RawMessage, error) {
	if !n.isNeighbor(to) {
		return nil, fmt.Errorf("peer %s not connected", to)
	}
	var rawReq json.RawMessage
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		rawReq = b
	}
	id := message.RandomMsgID()
	ch := make(chan rpcFrame, 1)
	n.mu.Lock()
	n.pending[id] = ch
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pending, id)
		n.mu.Unlock()
	}()
	frame := rpcFrame{Proto: rpcProto, ID: id, Kind: kind, Data: rawReq}
	raw, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if err := n.nt.SendTo(to, raw); err != nil {
		return nil, err
	}
	t := time.NewTimer(rpcTimeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, fmt.Errorf("rpc %s to %s timeout", kind, to)
	case resp := <-ch:
		if !resp.OK {
			return nil, fmt.Errorf("rpc %s to %s: %s", kind, to, resp.Err)
		}
		return resp.Data, nil
	}
}

// ---------------------------------------------------------------------------
// backfill.Source over rpc
// ---------------------------------------------------------------------------

type bfSource struct {
	n   *node
	pub core.PubKey
}

func (s *bfSource) ID() core.PubKey { return s.pub }

func (s *bfSource) FetchSnapshot(ctx context.Context) (backfill.Snapshot, error) {
	data, err := s.n.call(ctx, s.pub, rpcSnapshot, nil)
	if err != nil {
		return backfill.Snapshot{}, err
	}
	var snap backfill.Snapshot
	err = json.Unmarshal(data, &snap)
	return snap, err
}

func (s *bfSource) FetchMessages(ctx context.Context, q backfill.Query) ([]core.Message, error) {
	data, err := s.n.call(ctx, s.pub, rpcMsgs, rpcReqMsgs{AfterTS: q.AfterTS})
	if err != nil {
		return nil, err
	}
	var out rpcRespMsgs
	err = json.Unmarshal(data, &out)
	return out.Messages, err
}

func (s *bfSource) FetchMsgIDs(ctx context.Context, afterTS int64) ([]string, error) {
	data, err := s.n.call(ctx, s.pub, rpcMsgIDs, rpcReqMsgs{AfterTS: afterTS})
	if err != nil {
		return nil, err
	}
	var out rpcRespIDs
	err = json.Unmarshal(data, &out)
	return out.IDs, err
}

func (s *bfSource) FetchByMsgIDs(ctx context.Context, ids []string) ([]core.Message, error) {
	data, err := s.n.call(ctx, s.pub, rpcByIDs, rpcReqIDs{IDs: ids})
	if err != nil {
		return nil, err
	}
	var out rpcRespMsgs
	err = json.Unmarshal(data, &out)
	return out.Messages, err
}

// bfSources 返回当前活跃（且未被拉黑）邻居的比对源视图。
func (n *node) bfSources() []backfill.Source {
	self := n.self
	out := make([]backfill.Source, 0, 8)
	for _, p := range n.nt.PublicNeighbors() {
		if p.Equal(self) || n.roster.IsBlacklisted(p) {
			continue
		}
		out = append(out, &bfSource{n: n, pub: p})
	}
	return out
}
