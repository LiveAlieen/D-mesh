package backfill

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"dmesh/internal/core"
)

// ---- ed25519 注册（identity 包在线上的职责，测试里自己顶上）----

func TestMain(m *testing.M) {
	core.Register(core.SigEd25519, func(pub core.PubKey, msg, sig []byte) bool {
		if len(pub.Bytes) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
	})
	os.Exit(m.Run())
}

// ---- 确定性身份 ----

type signer struct {
	priv ed25519.PrivateKey
}

func newSigner(name string) *signer {
	sum := sha256.Sum256([]byte("dmesh-backfill-test/" + name))
	return &signer{priv: ed25519.NewKeyFromSeed(sum[:])}
}

func (s *signer) pub() core.PubKey {
	return core.PubKey{Alg: core.SigEd25519, Bytes: []byte(s.priv.Public().(ed25519.PublicKey))}
}

func (s *signer) wg() core.WGPub {
	var w core.WGPub
	sum := sha256.Sum256(append([]byte("wg/"), s.pub().Bytes...))
	copy(w[:], sum[:])
	return w
}

func (s *signer) sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

var testGroupID = sha256.Sum256([]byte("dmesh-backfill-test-group"))

// ---- 消息/事件构造 ----

// makeMsg 构造一条已签名消息：MsgID = sha256(nonce) 的前 16 个 hex 字符，
// 即「同 nonce 同 msg_id、不同 nonce 不同 msg_id」（同 nonce 不同内容 => 同
// msg_id 的冲突版本，用于伪造交叉差异场景）。
func makeMsg(t *testing.T, s *signer, typ string, content any, ts int64, nonce string) core.Message {
	t.Helper()
	return makeMsgTo(t, s, typ, content, ts, nonce, nil)
}

// makeMsgTo 构造一条已签名消息，to 非 nil 时写入定向字段 To。
//
// To 必须在签名之前写入：MessageSigPayload 的原文含 to（PLAN 的定向申诉消息
// 必须被签名绑定），签后再改 To 就等于伪造了一条坏签名。
func makeMsgTo(t *testing.T, s *signer, typ string, content any, ts int64, nonce string, to *core.PubKey) core.Message {
	t.Helper()
	var cb []byte
	if content != nil {
		var err error
		cb, err = json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
	}
	id := sha256.Sum256([]byte(nonce))
	m := core.Message{
		MsgID:   hex.EncodeToString(id[:])[:16],
		GroupID: testGroupID,
		Sender:  s.pub(),
		TSms:    ts,
		Type:    typ,
		Content: cb,
		To:      to,
		Alg:     core.SigEd25519,
	}
	payload, err := core.MessageSigPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Sig = s.sign(payload)
	return m
}

func makeText(t *testing.T, s *signer, body string, ts int64, nonce string) core.Message {
	t.Helper()
	return makeMsg(t, s, core.TypeText, body, ts, nonce)
}

type joinContent struct {
	Pub   core.PubKey `json:"pub"`
	WG    core.WGPub  `json:"wg_pub"`
	Perms []string    `json:"perms"`
}

type targetContent struct {
	Pub core.PubKey `json:"pub"`
}

func makeJoin(t *testing.T, carrier *signer, target *signer, perms []string, ts int64) core.Message {
	t.Helper()
	return makeMsg(t, carrier, core.TypeJoin, joinContent{Pub: target.pub(), WG: target.wg(), Perms: perms}, ts, "join/"+target.pub().String()+fmt.Sprint(ts))
}

func makeKick(t *testing.T, kicker *signer, target core.PubKey, ts int64) core.Message {
	t.Helper()
	return makeMsg(t, kicker, core.TypeKick, targetContent{Pub: target}, ts, "kick/"+target.String()+fmt.Sprint(ts))
}

func proofOf(t *testing.T, m core.Message) core.Proof {
	t.Helper()
	pr, err := core.ProofOf(m)
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

func memberEntryFromJoin(t *testing.T, joinMsg core.Message, jc joinContent) core.MemberEntry {
	t.Helper()
	return core.MemberEntry{
		Pub:   jc.Pub,
		WG:    jc.WG,
		Role:  core.RoleMember,
		Perms: jc.Perms,
		Proof: proofOf(t, joinMsg),
		TS:    joinMsg.TSms,
	}
}

func banEntryFromKick(t *testing.T, kickMsg core.Message, target core.PubKey) core.BlacklistEntry {
	t.Helper()
	return core.BlacklistEntry{Pub: target, Proof: proofOf(t, kickMsg), TS: kickMsg.TSms}
}

// ---- testRoster：core.Roster 的内存实现（验证语义贴近 group 包约定）----

type testRoster struct {
	mu       sync.RWMutex
	members  map[string]core.MemberEntry
	bans     map[string]core.BlacklistEntry
	presence map[string]core.PresenceEntry
}

func newTestRoster() *testRoster {
	return &testRoster{
		members:  map[string]core.MemberEntry{},
		bans:     map[string]core.BlacklistEntry{},
		presence: map[string]core.PresenceEntry{},
	}
}

func (r *testRoster) addDirect(e core.MemberEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.members[e.Pub.Key()] = e
}

func (r *testRoster) addBanDirect(be core.BlacklistEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bans[be.Pub.Key()] = be
}

func (r *testRoster) IsBlacklisted(p core.PubKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.bans[p.Key()]
	return ok
}

func (r *testRoster) Member(p core.PubKey) (core.MemberEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.members[p.Key()]
	return e, ok
}

func (r *testRoster) TierOf(p core.PubKey) int {
	e, ok := r.Member(p)
	if !ok {
		return core.TierNonMember
	}
	return core.TierOfRole(e.Role)
}

func (r *testRoster) HasPerm(p core.PubKey, perm string) bool {
	e, ok := r.Member(p)
	if !ok {
		return false
	}
	for _, q := range e.Perms {
		if q == perm {
			return true
		}
	}
	return false
}

func (r *testRoster) Presence(p core.PubKey) core.PresenceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.presence[p.Key()]
}

func (r *testRoster) Snapshot() ([]core.MemberEntry, []core.BlacklistEntry, core.PubKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ms := make([]core.MemberEntry, 0, len(r.members))
	for _, e := range r.members {
		ms = append(ms, e)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Pub.Key() < ms[j].Pub.Key() })
	bs := make([]core.BlacklistEntry, 0, len(r.bans))
	for _, e := range r.bans {
		bs = append(bs, e)
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].Pub.Key() < bs[j].Pub.Key() })
	return ms, bs, core.PubKey{}
}

func (r *testRoster) ApplyEvent(m core.Message) error {
	payload, err := core.MessageSigPayload(m)
	if err != nil {
		return err
	}
	if err := core.Verify(m.Sender, payload, m.Sig); err != nil {
		return err
	}
	switch m.Type {
	case core.TypeJoin:
		var jc joinContent
		if err := json.Unmarshal(m.Content, &jc); err != nil {
			return fmt.Errorf("%w: join content", core.ErrMalformed)
		}
		if m.Sender.Equal(jc.Pub) {
			return errors.New("join must be signed by a carrier, self-signed invalid")
		}
		if r.IsBlacklisted(jc.Pub) {
			return errors.New("target blacklisted: join rejected until unban")
		}
		if !r.HasPerm(m.Sender, core.PermCarry) {
			return fmt.Errorf("%w: carrier without carry perm", core.ErrNotPermitted)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.members[jc.Pub.Key()] = core.MemberEntry{
			Pub: jc.Pub, WG: jc.WG, Role: core.RoleMember, Perms: jc.Perms,
			Proof: proofOfNoErr(m), TS: m.TSms,
		}
		return nil
	case core.TypeKick:
		var tc targetContent
		if err := json.Unmarshal(m.Content, &tc); err != nil {
			return fmt.Errorf("%w: kick content", core.ErrMalformed)
		}
		if !r.HasPerm(m.Sender, core.PermKick) {
			return fmt.Errorf("%w: kicker without kick perm", core.ErrNotPermitted)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.members, tc.Pub.Key())
		r.bans[tc.Pub.Key()] = core.BlacklistEntry{Pub: tc.Pub, Proof: proofOfNoErr(m), TS: m.TSms}
		return nil
	case core.TypeUnban:
		var tc targetContent
		if err := json.Unmarshal(m.Content, &tc); err != nil {
			return fmt.Errorf("%w: unban content", core.ErrMalformed)
		}
		if !r.HasPerm(m.Sender, core.PermUnban) && !r.HasPerm(m.Sender, core.PermKick) {
			return fmt.Errorf("%w: unbanner without unban perm", core.ErrNotPermitted)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.bans, tc.Pub.Key())
		return nil
	case core.TypeRemove:
		var tc targetContent
		if err := json.Unmarshal(m.Content, &tc); err != nil {
			return fmt.Errorf("%w: remove content", core.ErrMalformed)
		}
		if !m.Sender.Equal(tc.Pub) {
			return errors.New("remove is only valid self-signed (never escalates)")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.members, tc.Pub.Key())
		return nil
	case core.TypePresence:
		var pc struct {
			Pub          core.PubKey `json:"pub"`
			LastMsgTS    int64       `json:"last_msg_ts"`
			OfflineAfter int64       `json:"offline_after"`
		}
		if err := json.Unmarshal(m.Content, &pc); err != nil {
			return fmt.Errorf("%w: presence content", core.ErrMalformed)
		}
		if !m.Sender.Equal(pc.Pub) {
			return errors.New("presence only self-signed")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		cur := r.presence[pc.Pub.Key()]
		if pc.LastMsgTS > cur.LastMsgTS {
			cur.LastMsgTS = pc.LastMsgTS
		}
		if pc.OfflineAfter > 0 {
			cur.OfflineAfter = pc.OfflineAfter
		}
		cur.Pub = pc.Pub
		r.presence[pc.Pub.Key()] = cur
		return nil
	default:
		return nil
	}
}

func proofOfNoErr(m core.Message) core.Proof {
	pr, err := core.ProofOf(m)
	if err != nil {
		panic(err)
	}
	return pr
}

// ---- memStore ----

type memStore struct {
	mu       sync.Mutex
	msgs     map[string]core.Message
	rejected map[string]string
	maxTS    int64
}

func newMemStore() *memStore {
	return &memStore{msgs: map[string]core.Message{}, rejected: map[string]string{}}
}

func (s *memStore) MaxTS() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxTS
}

func (s *memStore) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.msgs[id]
	return ok
}

func (s *memStore) Get(id string) (core.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.msgs[id]
	return m, ok
}

func (s *memStore) Append(m core.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs[m.MsgID] = m
	if m.TSms > s.maxTS {
		s.maxTS = m.TSms
	}
	return nil
}

func (s *memStore) MsgIDs(after int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, m := range s.msgs {
		if m.TSms >= after {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (s *memStore) Reject(msgID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.msgs[msgID]; !ok {
		return errors.New("unknown msg id")
	}
	delete(s.msgs, msgID)
	s.rejected[msgID] = reason
	return nil
}

func (s *memStore) rejectedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id := range s.rejected {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *memStore) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id := range s.msgs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ---- memSource：内存邻居数据源 ----

type memSource struct {
	id       core.PubKey
	snap     Snapshot
	msgs     []core.Message
	failSnap bool
	failMsgs bool
}

func (m *memSource) ID() core.PubKey { return m.id }

func (m *memSource) FetchSnapshot(context.Context) (Snapshot, error) {
	if m.failSnap {
		return Snapshot{}, errors.New("unreachable")
	}
	return m.snap, nil
}

func (m *memSource) FetchMessages(_ context.Context, q Query) ([]core.Message, error) {
	if m.failMsgs {
		return nil, errors.New("unreachable")
	}
	var out []core.Message
	for _, msg := range m.msgs {
		if msg.TSms >= q.AfterTS {
			out = append(out, msg)
		}
	}
	return out, nil
}

func (m *memSource) FetchMsgIDs(_ context.Context, after int64) ([]string, error) {
	var out []string
	for _, msg := range m.msgs {
		if msg.TSms >= after {
			out = append(out, msg.MsgID)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memSource) FetchByMsgIDs(_ context.Context, ids []string) ([]core.Message, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []core.Message
	for _, msg := range m.msgs {
		if want[msg.MsgID] {
			out = append(out, msg)
		}
	}
	return out, nil
}

// ---- 差评追踪 ----

type penRecord struct {
	peer   string
	reason DropReason
}

type penTracker struct {
	mu  sync.Mutex
	n   map[string]int
	ok  map[string]bool // 零值公钥：只记 reason 不记 peer
	all []penRecord
}

func newPenTracker() *penTracker {
	return &penTracker{n: map[string]int{}, ok: map[string]bool{}}
}

func (p *penTracker) penalize(peer core.PubKey, reason DropReason, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.all = append(p.all, penRecord{peer: peer.Key(), reason: reason})
	if !peer.IsZero() {
		p.n[peer.Key()]++
	}
}

func (p *penTracker) count(peer core.PubKey) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n[peer.Key()]
}

func (p *penTracker) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all)
}

func (p *penTracker) has(peer core.PubKey, reason DropReason) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.all {
		if r.peer == peer.Key() && r.reason == reason {
			return true
		}
	}
	return false
}

// ---- 断言辅助 ----

func acceptIDs(cr *CrossResult) []string {
	var out []string
	for _, m := range cr.Accepted {
		out = append(out, m.MsgID)
	}
	sort.Strings(out)
	return out
}

func mustContain(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, nd := range needles {
		if !strings.Contains(haystack, nd) {
			t.Fatalf("expected %q in %q", nd, haystack)
		}
	}
}
