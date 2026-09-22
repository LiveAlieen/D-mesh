package netdisk

import (
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/ed25519"

	"dmesh/internal/core"
)

// ---------- 测试身份：注册真 ed25519 验签（模拟 identity 包的接线） ----------

func TestMain(m *testing.M) {
	core.Register(core.SigEd25519, func(pub core.PubKey, msg, sig []byte) bool {
		if len(pub.Bytes) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub.Bytes), msg, sig)
	})
	m.Run()
}

// tsigner 是测试用的 core.Signer（生产由 identity 包提供）。
type tsigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	name string
}

func newSigner(t *testing.T, name string) *tsigner {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	// 名字混入种子：同名可复现，不同名必不同。
	for i := 0; i < len(name); i++ {
		seed[i%32] ^= name[i]
	}
	priv := ed25519.NewKeyFromSeed(seed[:32])
	return &tsigner{pub: priv.Public().(ed25519.PublicKey), priv: priv, name: name}
}

func (s *tsigner) Alg() core.SigAlg                { return core.SigEd25519 }
func (s *tsigner) Pub() core.PubKey                { return core.PubKey{Alg: core.SigEd25519, Bytes: []byte(s.pub)} }
func (s *tsigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }

func pubs(ss ...*tsigner) []core.PubKey {
	out := make([]core.PubKey, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Pub())
	}
	return out
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ---------- simNet：纯内存的「成员间传输网络」，可模拟离线/篡改 ----------

type simHost struct {
	pub    core.PubKey
	store  *MemStore
	online bool
	bad    bool // true = 交出被篡改的块（作恶源）
}

type simNet struct {
	t     *testing.T
	hosts map[string]*simHost // key: pub.Key()
}

func newSimNet(t *testing.T) *simNet {
	return &simNet{t: t, hosts: map[string]*simHost{}}
}

func (n *simNet) add(s *tsigner, quota int64) *simHost {
	h := &simHost{pub: s.Pub(), store: NewMemStore(quota), online: true}
	n.hosts[h.pub.Key()] = h
	return h
}

func (n *simNet) host(pub core.PubKey) (*simHost, error) {
	h, ok := n.hosts[pub.Key()]
	if !ok || !h.online {
		return nil, fmt.Errorf("%w: %s", ErrHostUnreachable, pub)
	}
	return h, nil
}

func (n *simNet) Push(to core.PubKey, b *Block) error {
	h, err := n.host(to)
	if err != nil {
		return err
	}
	return h.store.Put(b)
}

func (n *simNet) Fetch(from core.PubKey, q BlockQuery) (*Block, error) {
	h, err := n.host(from)
	if err != nil {
		return nil, err
	}
	b, err := h.store.Get(q.FileID, q.Stripe, q.Pos)
	if err != nil {
		return nil, err
	}
	if h.bad {
		b = corruptCopy(b)
	}
	return b, nil
}

func (n *simNet) List(from core.PubKey, fileID string) ([]*Block, error) {
	h, err := n.host(from)
	if err != nil {
		return nil, err
	}
	bs, err := h.store.List(fileID)
	if err != nil {
		return nil, err
	}
	if h.bad {
		out := make([]*Block, 0, len(bs))
		for _, b := range bs {
			out = append(out, corruptCopy(b))
		}
		return out, nil
	}
	return bs, nil
}

func (n *simNet) Remove(from core.PubKey, q BlockQuery) error {
	h, err := n.host(from)
	if err != nil {
		return err
	}
	return h.store.Delete(q.FileID, q.Stripe, q.Pos)
}

func corruptCopy(b *Block) *Block {
	cp := *b
	cp.Data = append([]byte(nil), b.Data...)
	if len(cp.Data) > 0 {
		cp.Data[0] ^= 0xa5
	}
	return &cp
}

// hostsInfo 把若干 signer 变成配额视图（quota 相同）。
func hostsInfo(quota int64, ss ...*tsigner) []HostInfo {
	out := make([]HostInfo, 0, len(ss))
	for _, s := range ss {
		out = append(out, HostInfo{Pub: s.Pub(), QuotaBytes: quota})
	}
	return out
}

// newMgr 建一台接好线的成员（共享该成员在 simNet 上的定额目录）。
func newMgr(t *testing.T, groupID [32]byte, s *tsigner, tx Transport, store BlockStore) *Manager {
	t.Helper()
	m, err := New(Options{
		GroupID:   groupID,
		Signer:    s,
		Store:     store,
		Tx:        tx,
		BlockSize: 16, // 小块让测试跑得快
	})
	mustOK(t, err)
	return m
}

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
