package message

import (
	"crypto/rand"
	"os"
	"sync"
	"testing"
	"time"

	"dmesh/internal/core"

	"golang.org/x/crypto/ed25519"
)

// TestMain 注册真实 ed25519 验签实现到 core 注册表（本包单测自足，
// 不依赖 identity 包；identity 上线后由它注册同一实现）。
func TestMain(m *testing.M) {
	core.Register(core.SigEd25519, func(pub core.PubKey, msg, sig []byte) bool {
		return len(pub.Bytes) == ed25519.PublicKeySize &&
			ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
	})
	os.Exit(m.Run())
}

// ---------- 测试签名器 ----------

type testSigner struct {
	priv ed25519.PrivateKey
	pub  core.PubKey
}

func newTestSigner() *testSigner {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &testSigner{priv: sk, pub: core.PubKey{Alg: core.SigEd25519, Bytes: pk}}
}

func (s *testSigner) Alg() core.SigAlg { return core.SigEd25519 }
func (s *testSigner) Pub() core.PubKey { return s.pub }
func (s *testSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// ---------- 假名单（core.Roster 契约的内存实现） ----------

type fakeRoster struct {
	mu       sync.Mutex
	members  map[string]core.MemberEntry
	black    map[string]bool
	presence map[string]core.PresenceEntry
	applyErr map[string]error // type -> 强制 ApplyEvent 失败
	applied  []core.Message
}

func newFakeRoster() *fakeRoster {
	return &fakeRoster{
		members:  map[string]core.MemberEntry{},
		black:    map[string]bool{},
		presence: map[string]core.PresenceEntry{},
		applyErr: map[string]error{},
	}
}

func (r *fakeRoster) addMember(pub core.PubKey, role core.Role, perms ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.members[pub.Key()] = core.MemberEntry{Pub: pub, Role: role, Perms: perms}
}

func (r *fakeRoster) blacklist(pub core.PubKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.black[pub.Key()] = true
}

func (r *fakeRoster) setPresence(pub core.PubKey, lastMS int64, offlineAfter int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.presence[pub.Key()] = core.PresenceEntry{Pub: pub, LastMsgTS: lastMS, OfflineAfter: offlineAfter}
}

func (r *fakeRoster) IsBlacklisted(p core.PubKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.black[p.Key()]
}

func (r *fakeRoster) Member(p core.PubKey) (core.MemberEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.members[p.Key()]
	return m, ok
}

func (r *fakeRoster) ApplyEvent(m core.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err, ok := r.applyErr[m.Type]; ok {
		return err
	}
	r.applied = append(r.applied, m)
	return nil
}

func (r *fakeRoster) TierOf(p core.PubKey) int {
	m, ok := r.Member(p)
	if !ok {
		return core.TierNonMember
	}
	return core.TierOfRole(m.Role)
}

func (r *fakeRoster) HasPerm(p core.PubKey, perm string) bool {
	m, ok := r.Member(p)
	if !ok {
		return false
	}
	for _, x := range m.Perms {
		if x == perm {
			return true
		}
	}
	return false
}

func (r *fakeRoster) Presence(p core.PubKey) core.PresenceEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.presence[p.Key()]
}

func (r *fakeRoster) Snapshot() ([]core.MemberEntry, []core.BlacklistEntry, core.PubKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ms []core.MemberEntry
	for _, m := range r.members {
		ms = append(ms, m)
	}
	return ms, nil, core.PubKey{}
}

// ---------- 假传输 / 假邻居 ----------

type fakeTransport struct {
	mu   sync.Mutex
	sent map[string][]string // peer key -> 收到的帧（msg_id 无法直接反映，存 hex 前缀即可）
	fail map[string]bool
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{sent: map[string][]string{}, fail: map[string]bool{}}
}

func (t *fakeTransport) Send(to core.PubKey, frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail[to.Key()] {
		return errSendFailed
	}
	t.sent[to.Key()] = append(t.sent[to.Key()], string(frame))
	return nil
}

func (t *fakeTransport) countTo(p core.PubKey) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sent[p.Key()])
}

func (t *fakeTransport) total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, v := range t.sent {
		n += len(v)
	}
	return n
}

var errSendFailed = core.ErrMalformed // 复用契约错误当哨兵即可（测试内不关心语义）

type fakePeers struct {
	peers []core.PubKey
}

func (p fakePeers) Peers() []core.PubKey { return p.peers }

// ---------- 通用工具 ----------

var testGroupID = [32]byte{1, 2, 3, 4, 5}

// fixedClock 返回可拨表的时钟。
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustText(t *testing.T, s core.Signer, tsMS int64, body string, msgID string) core.Message {
	t.Helper()
	m, err := NewMessage(s, testGroupID, &core.Message{
		Type:    core.TypeText,
		TSms:    tsMS,
		Content: []byte(body),
		MsgID:   msgID,
	}, nil)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	return m
}

func frameOf(t *testing.T, m core.Message) []byte {
	t.Helper()
	f, err := EncodeFrame(m)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	return f
}
