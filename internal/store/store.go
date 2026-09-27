// Package store 实现 D-Mesh 的本地持久层：
//
//   - 追加式 JSONL（<dir>/messages.jsonl）= 消息与名单事件的真相源；
//   - SQLite（<dir>/index.db，modernc.org/sqlite 纯 Go 驱动）= 可重建索引：
//     msg_id 去重、hide 软删除标记、白名单/黑名单条目+proof、在场表、
//     owner 指针、群配置缓存。
//
// 设计要点（PLAN.md v16 · 技术选型「存储」）：
//
//  1. JSONL 是唯一真相源：Open 时自动从 JSONL 全量重建消息索引与 hide 标记，
//     SQLite 文件损坏/被删不丢数据（删掉 index.db 重开即可完全恢复）。
//  2. AppendMessage 幂等：同一 msg_id 第二次写入返回 (false, nil)，天然去重
//     （flood 防风暴、回灌多源合并、事件重放全部依赖这一点）。
//  3. 名单条目（members/blacklist/presence/owner/group_config）是 group 包
//     ApplyEvent 之后的「已验证状态」持久化，本包不重复验签——协议判定归
//     group，持久与恢复归 store。这些表不参与 JSONL 重建（重建只恢复消息
//     索引与 hide 标记），由 group 包在启动时从本包读出后继续增量应用。
//  4. 所有写接口对并发调用安全（内部串行化；SQLite 连接池限制为 1）。
//
// hide 原文约定：name=hide 的消息 body 载荷按两种形式解析目标 msg_id——
// JSON 对象（键 target_msg_id / msg_id / target 任一）或裸字符串；
// 两种历史格式都能被重建流程识别。
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，无 cgo
)

const (
	jsonlName = "messages.jsonl"
	dbName    = "index.db"

	metaGroupConfig = "group_config"
	metaOwner       = "owner"
)

// Store 是一个群目录的持久层句柄（一目录 = 一群）。零值不可用，必须 Open。
type Store struct {
	mu     sync.Mutex
	dir    string
	jsonl  *os.File
	db     *sql.DB
	closed bool
}

// Open 打开（不存在则创建）dir 下的存储：初始化 schema、截断 JSONL 末尾
// 残缺行、并从 JSONL 全量重建消息索引与 hide 标记。调用方负责 Close。
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("store: Open with empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	s := &Store{dir: dir}

	jsonlPath := filepath.Join(dir, jsonlName)
	if err := truncateTail(jsonlPath); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open jsonl: %w", err)
	}
	s.jsonl = f

	dbPath := filepath.Join(dir, dbName)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(10000)")
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // modernc/sqlite：单写者，串行化避免锁竞争
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		_ = f.Close()
		return nil, fmt.Errorf("store: wal: %w", err)
	}
	if err := createSchema(db); err != nil {
		_ = db.Close()
		_ = f.Close()
		return nil, err
	}
	s.db = db

	if err := s.rebuildIndex(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("store: rebuild: %w", err)
	}
	return s, nil
}

// Close 释放文件句柄与数据库连接；重复 Close 安全。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []string
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.jsonl != nil {
		if err := s.jsonl.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("store: close: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Dir 返回本 Store 所在目录。
func (s *Store) Dir() string { return s.dir }

const schemaDDL = `
CREATE TABLE IF NOT EXISTS messages (
	msg_id   TEXT PRIMARY KEY,
	sender   TEXT NOT NULL,
	ts_ms    INTEGER NOT NULL,
	name     TEXT NOT NULL,            -- 具体消息名（body 单键：text/hide/join/…）
	data     BLOB NOT NULL            -- CanonicalJSON(core.Message)，与 JSONL 行同字节
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts_ms);
CREATE TABLE IF NOT EXISTS hidden (
	msg_id TEXT PRIMARY KEY           -- hide 软删除标记（真相仍在 JSONL）
);
CREATE TABLE IF NOT EXISTS members (
	pub  TEXT PRIMARY KEY,            -- core.PubKey.String()
	data BLOB NOT NULL,               -- JSON(core.MemberEntry)，含 proof
	ts   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blacklist (
	pub  TEXT PRIMARY KEY,
	data BLOB NOT NULL,               -- JSON(core.BlacklistEntry)，含封禁 proof
	ts   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS presence (
	pub           TEXT PRIMARY KEY,
	data          BLOB NOT NULL,      -- JSON(core.PresenceEntry)
	ts            INTEGER NOT NULL,   -- = last_msg_ts，统一排序列
	last_msg_ts   INTEGER NOT NULL,
	offline_after INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v BLOB NOT NULL
);
`

func createSchema(db *sql.DB) error {
	if _, err := db.Exec(schemaDDL); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	return nil
}
