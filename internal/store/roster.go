package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"dmesh/internal/core"
)

// ---------------------------------------------------------------------------
// 白名单（成员条目 + proof）
// ---------------------------------------------------------------------------

// PutMember 幂等写入/覆盖一条白名单条目（按 PubKey 主键 upsert）。
// 调用前提：group 包已完成验签与层级判定，这里只管持久化。
func (s *Store) PutMember(e core.MemberEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return putEntry(s.db, "members", e.Pub.String(), e, e.TS)
}

// DeleteMember 删除白名单条目（remove 退群 / kick 除名时由 group 包调用）。
// 条目不存在时静默成功（幂等）。
func (s *Store) DeleteMember(p core.PubKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, err := s.db.Exec(`DELETE FROM members WHERE pub=?`, p.String()); err != nil {
		return fmt.Errorf("store: delete member: %w", err)
	}
	return nil
}

// Member 按公钥查白名单条目。
func (s *Store) Member(p core.PubKey) (core.MemberEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.MemberEntry{}, false, ErrClosed
	}
	var e core.MemberEntry
	found, err := getEntry(s.db, "members", p.String(), &e)
	return e, found, err
}

// Members 返回全部白名单条目（按 ts 升序，便于按事件时间回放展示）。
func (s *Store) Members() ([]core.MemberEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var out []core.MemberEntry
	if err := scanEntries(s.db, "members", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// 黑名单（封禁条目 + proof）
// ---------------------------------------------------------------------------

// PutBlacklist 幂等写入/覆盖一条黑名单条目（含 kick 事件 proof）。
func (s *Store) PutBlacklist(e core.BlacklistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return putEntry(s.db, "blacklist", e.Pub.String(), e, e.TS)
}

// DeleteBlacklist 删除黑名单条目（unban 生效时调用）。幂等。
func (s *Store) DeleteBlacklist(p core.PubKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, err := s.db.Exec(`DELETE FROM blacklist WHERE pub=?`, p.String()); err != nil {
		return fmt.Errorf("store: delete blacklist: %w", err)
	}
	return nil
}

// Blacklisted 报告公钥是否在黑名单（准入判定的持久化查询）。
func (s *Store) Blacklisted(p core.PubKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	return exists(s.db, `SELECT 1 FROM blacklist WHERE pub=?`, p.String())
}

// BlacklistEntry 按公钥查黑名单条目。
func (s *Store) BlacklistEntry(p core.PubKey) (core.BlacklistEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.BlacklistEntry{}, false, ErrClosed
	}
	var e core.BlacklistEntry
	found, err := getEntry(s.db, "blacklist", p.String(), &e)
	return e, found, err
}

// Blacklist 返回全部黑名单条目（ts 升序）。
func (s *Store) Blacklist() ([]core.BlacklistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var out []core.BlacklistEntry
	if err := scanEntries(s.db, "blacklist", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// 在场表（v13/v13.1：与权限分表，max 合并）
// ---------------------------------------------------------------------------

// UpsertPresence 以 max 合并规则更新在场表：仅当新报告的 LastMsgTS >= 已存
// 记录时才覆盖（旧值不覆盖新值；offline_after 随更新的自报记录一起替换）。
// 返回值 applied=false 表示这是一条过期报告，被静默丢弃。
// 本人自签校验由 group 包负责，本方法只保证合并语义。
func (s *Store) UpsertPresence(e core.PresenceEntry) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	off := e.OfflineAfter
	if off <= 0 {
		off = core.DefaultOfflineAfterMS // 未自报者落到默认阈值，入库即归一化
	}
	e.OfflineAfter = off
	raw, err := json.Marshal(e)
	if err != nil {
		return false, fmt.Errorf("store: encode presence: %w", err)
	}
	res, err := s.db.Exec(`
		INSERT INTO presence(pub, data, ts, last_msg_ts, offline_after) VALUES(?,?,?,?,?)
		ON CONFLICT(pub) DO UPDATE SET
			data          = excluded.data,
			ts            = excluded.ts,
			last_msg_ts   = excluded.last_msg_ts,
			offline_after = excluded.offline_after
		WHERE excluded.last_msg_ts >= presence.last_msg_ts`,
		e.Pub.String(), raw, e.LastMsgTS, e.LastMsgTS, off)
	if err != nil {
		return false, fmt.Errorf("store: upsert presence: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: upsert presence result: %w", err)
	}
	return n > 0, nil
}

// PresenceFor 查单个在场记录；无记录返回 (零值, false, nil)。
func (s *Store) PresenceFor(p core.PubKey) (core.PresenceEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.PresenceEntry{}, false, ErrClosed
	}
	var e core.PresenceEntry
	found, err := getEntry(s.db, "presence", p.String(), &e)
	return e, found, err
}

// Presences 返回全部在场记录（供 UI 成员列表渲染在线/离线/最后活跃）。
func (s *Store) Presences() ([]core.PresenceEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var out []core.PresenceEntry
	if err := scanEntries(s.db, "presence", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// owner 指针与群配置
// ---------------------------------------------------------------------------

// SetOwner 持久化当前 owner 指针（transfer 生效后由 group 包调用）。
func (s *Store) SetOwner(p core.PubKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return putMeta(s.db, metaOwner, p)
}

// Owner 读 owner 指针；未设置返回 (零值, false, nil)。
func (s *Store) Owner() (core.PubKey, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.PubKey{}, false, ErrClosed
	}
	var p core.PubKey
	found, err := getMeta(s.db, metaOwner, &p)
	return p, found, err
}

// PutGroupConfig 持久化创世配置（种子），并返回其 group_id
// （core.GroupIDOf 计算；CreatorSig 必须已在 cfg 中，group_id 计算自动忽略它）。
func (s *Store) PutGroupConfig(cfg core.GroupConfig) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return [32]byte{}, ErrClosed
	}
	id, err := core.GroupIDOf(cfg)
	if err != nil {
		return [32]byte{}, fmt.Errorf("store: group id: %w", err)
	}
	if err := putMeta(s.db, metaGroupConfig, cfg); err != nil {
		return [32]byte{}, err
	}
	return id, nil
}

// GroupConfig 读回群配置与其 group_id；未设置返回 found=false。
func (s *Store) GroupConfig() (core.GroupConfig, [32]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.GroupConfig{}, [32]byte{}, false, ErrClosed
	}
	var cfg core.GroupConfig
	found, err := getMeta(s.db, metaGroupConfig, &cfg)
	if err != nil || !found {
		return core.GroupConfig{}, [32]byte{}, found, err
	}
	id, err := core.GroupIDOf(cfg)
	if err != nil {
		return core.GroupConfig{}, [32]byte{}, false, fmt.Errorf("store: group id: %w", err)
	}
	return cfg, id, true, nil
}

// RosterSnapshot 一次读出双名单副本 + owner 指针，满足副本应答/一致性核查
// 与 core.Roster.Snapshot 的数据需求。
func (s *Store) RosterSnapshot() (members []core.MemberEntry, banned []core.BlacklistEntry, owner core.PubKey, err error) {
	members, err = s.Members()
	if err != nil {
		return nil, nil, core.PubKey{}, err
	}
	banned, err = s.Blacklist()
	if err != nil {
		return nil, nil, core.PubKey{}, err
	}
	owner, _, err = s.Owner()
	if err != nil {
		return nil, nil, core.PubKey{}, err
	}
	return members, banned, owner, nil
}

// ---------------------------------------------------------------------------
// 通用表读写（data 列 = 条目 JSON，pub/k 列 = 键）
// ---------------------------------------------------------------------------

func putEntry(db *sql.DB, table, key string, val any, ts int64) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("store: encode %s entry: %w", table, err)
	}
	_, err = db.Exec(
		`INSERT INTO `+table+`(pub, data, ts) VALUES(?,?,?)
		 ON CONFLICT(pub) DO UPDATE SET data=excluded.data, ts=excluded.ts`,
		key, raw, ts)
	if err != nil {
		return fmt.Errorf("store: put %s entry: %w", table, err)
	}
	return nil
}

func getEntry(db *sql.DB, table, key string, dst any) (bool, error) {
	var raw []byte
	err := db.QueryRow(`SELECT data FROM `+table+` WHERE pub=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: get %s entry: %w", table, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("store: decode %s entry: %w", table, err)
	}
	return true, nil
}

func scanEntries[T any](db *sql.DB, table string, out *[]T) error {
	rows, err := db.Query(`SELECT data FROM ` + table + ` ORDER BY ts ASC, pub ASC`)
	if err != nil {
		return fmt.Errorf("store: scan %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("store: scan %s row: %w", table, err)
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("store: decode %s row: %w", table, err)
		}
		*out = append(*out, v)
	}
	return rows.Err()
}

func putMeta(db *sql.DB, key string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("store: encode meta %s: %w", key, err)
	}
	_, err = db.Exec(`INSERT INTO meta(k, v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, raw)
	if err != nil {
		return fmt.Errorf("store: put meta %s: %w", key, err)
	}
	return nil
}

func getMeta(db *sql.DB, key string, dst any) (bool, error) {
	var raw []byte
	err := db.QueryRow(`SELECT v FROM meta WHERE k=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: get meta %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("store: decode meta %s: %w", key, err)
	}
	return true, nil
}
