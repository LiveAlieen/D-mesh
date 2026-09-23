// Package deps 不做任何事：它只用空导入把全工程的第三方依赖钉在 go.mod / go.sum 里。
//
// Foundation 阶段先建好它，后续并行模块代理就无需各自 go get（避免 go.mod 竞争）；
// 新增第三方库请只改本文件并重新 go mod tidy。业务包不要 import 本包。
package deps

import (
	// 发现层：公共 DHT + PEX 收集 swarm peer（anacrolix/torrent 加载种子/磁力链）。
	_ "github.com/anacrolix/dht/v2"
	_ "github.com/anacrolix/torrent"

	// 传输层：Noise IK/XX 式握手（静态密钥 = 对端 wg_pub）。
	_ "github.com/flynn/noise"

	// 签名与密钥：默认 Ed25519（core.SigEd25519）、X25519 传输密钥、
	// Noise 信道与备份加密用的 AEAD、box（curve25519+chacha20poly1305）。
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/crypto/curve25519"
	_ "golang.org/x/crypto/ed25519"
	_ "golang.org/x/crypto/nacl/box"

	// 存储层：SQLite 索引/去重/隐藏标记/双名单条目（纯 Go，无 CGO）。
	_ "modernc.org/sqlite"

	// UI 层：Ebitengine 原生窗口 GUI（v19，纯 Go 无 cgo）+ 剪贴板粘贴。
	_ "github.com/atotto/clipboard"
	_ "github.com/hajimehoshi/ebiten/v2"
)
