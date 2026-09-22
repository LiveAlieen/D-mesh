package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"

	"dmesh/internal/core"
)

// 密钥文件里的 sig_alg 字段值。当前仅 ed25519；加载时未注册/未知的 alg 一律拒绝。
const (
	fileSigAlgEd25519 = string(core.SigEd25519)

	keyFilePerm = 0o600
	dirPerm     = 0o700
)

// identityFile 是身份密钥（签名 + 传输）的磁盘表示（JSON，hex/base64 字段）。
type identityFile struct {
	SigAlg string `json:"sig_alg"`
	Pub    string `json:"pub"`  // hex, 32B ed25519 公钥
	Priv   string `json:"priv"` // hex, 64B ed25519 私钥
	WGPub  string `json:"wg_pub"`
	WGPriv string `json:"wg_priv"`
}

type keyPairFile struct {
	SigAlg string `json:"sig_alg"`
	Pub    string `json:"pub"`
	Priv   string `json:"priv"`
}

// SaveIdentity 把身份密钥写入 path（父目录自动创建，权限 0600）。
func SaveIdentity(path string, id *Identity) error {
	if id == nil || id.KeyPair == nil {
		return fmt.Errorf("%w: nil identity", core.ErrMalformed)
	}
	f := identityFile{
		SigAlg: fileSigAlgEd25519,
		Pub:    hex.EncodeToString(id.Pub().Bytes),
		Priv:   hex.EncodeToString(id.Private()),
		WGPub:  base64.StdEncoding.EncodeToString(id.wgPub[:]),
		WGPriv: hex.EncodeToString(id.wgPriv[:]),
	}
	return writeJSONFile(path, f)
}

// LoadIdentity 从 path 读取并校验身份密钥文件。
func LoadIdentity(path string) (*Identity, error) {
	var f identityFile
	if err := readJSONFile(path, &f); err != nil {
		return nil, err
	}
	kp, err := loadKeyPair(f.SigAlg, f.Pub, f.Priv)
	if err != nil {
		return nil, err
	}
	wgPriv, err := decodeHexFixed("wg_priv", f.WGPriv, curve25519.ScalarSize)
	if err != nil {
		return nil, err
	}
	// wg_pub 上线格式是 base64（core.WGPub 的 JSON 约定）；文件里兼容 hex 与 base64。
	wgPub, err := decodeWGPubField(f.WGPub)
	if err != nil {
		return nil, err
	}
	var id [32]byte
	copy(id[:], wgPriv)
	// 自洽性检查：私钥派生的公钥必须与文件记录一致。
	derived, err := curve25519.X25519(id[:], curve25519.Basepoint)
	if err != nil || !bytes.Equal(derived, wgPub[:]) {
		return nil, fmt.Errorf("%w: identity file wg_priv/wg_pub mismatch", core.ErrMalformed)
	}
	return &Identity{KeyPair: kp, wgPriv: id, wgPub: wgPub}, nil
}

// LoadOrCreateIdentity 读取 path 上的身份；不存在则新生成并保存。
func LoadOrCreateIdentity(path string) (*Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return LoadIdentity(path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	id, err := NewIdentity()
	if err != nil {
		return nil, err
	}
	if err := SaveIdentity(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

// SaveKeyPair 单独持久化一把签名密钥（群密钥备份等场景，无传输密钥字段）。
func SaveKeyPair(path string, k *KeyPair) error {
	if k == nil {
		return fmt.Errorf("%w: nil keypair", core.ErrMalformed)
	}
	return writeJSONFile(path, keyPairFile{
		SigAlg: fileSigAlgEd25519,
		Pub:    hex.EncodeToString(k.Pub().Bytes),
		Priv:   hex.EncodeToString(k.Private()),
	})
}

// LoadKeyPair 读取单把签名密钥。
func LoadKeyPair(path string) (*KeyPair, error) {
	var f keyPairFile
	if err := readJSONFile(path, &f); err != nil {
		return nil, err
	}
	return loadKeyPair(f.SigAlg, f.Pub, f.Priv)
}

func loadKeyPair(alg, pubHex, privHex string) (*KeyPair, error) {
	if alg != fileSigAlgEd25519 {
		return nil, fmt.Errorf("%w: %q", core.ErrUnknownAlg, alg)
	}
	priv, err := decodeHexFixed("priv", privHex, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	pub, err := decodeHexFixed("pub", pubHex, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	kp := keyPairFromPrivate(ed25519.PrivateKey(priv))
	if !kp.Pub().Equal(core.PubKey{Alg: core.SigEd25519, Bytes: pub}) {
		return nil, fmt.Errorf("%w: keypair pub/priv mismatch", core.ErrMalformed)
	}
	return kp, nil
}

func writeJSONFile(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), keyFilePerm)
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %s: %v", core.ErrMalformed, path, err)
	}
	return nil
}

func decodeHexFixed(field, s string, n int) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: field %q not hex: %v", core.ErrMalformed, field, err)
	}
	if len(raw) != n {
		return nil, fmt.Errorf("%w: field %q length %d, want %d", core.ErrMalformed, field, len(raw), n)
	}
	return raw, nil
}

func decodeWGPubField(s string) (core.WGPub, error) {
	var w core.WGPub
	if isHex(s) {
		raw, err := hex.DecodeString(s)
		if err == nil && len(raw) == len(w) {
			copy(w[:], raw)
			return w, nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != len(w) {
		return w, fmt.Errorf("%w: identity file wg_pub not hex/base64 of %d bytes", core.ErrMalformed, len(w))
	}
	copy(w[:], raw)
	return w, nil
}

func isHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
