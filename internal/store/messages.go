package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"dmesh/internal/core"
)

// ErrClosed 表示 Store 已关闭。
var ErrClosed = errors.New("store: closed")

// AppendMessage 幂等地追加一条消息或名单事件：先 INSERT OR IGNORE 进索引，
// 仅当 msg_id 是新的才把同一份 CanonicalJSON 字节追加进 JSONL 并 fsync。
//
//	返回值 appended=false 且 err=nil  → msg_id 已存在（重复 flood/回灌），静默去重；
//	返回值 err!=nil                   → 未写入任何东西（含 JSONL 写失败时的回滚）。
//
// type=hide 的事件在落库后自动对被指向的 target msg_id 打软删除标记。
func (s *Store) AppendMessage(m core.Message) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if m.MsgID == "" {
		return false, fmt.Errorf("%w: empty msg_id", core.ErrMalformed)
	}
	raw, err := core.CanonicalJSON(m)
	if err != nil {
		return false, fmt.Errorf("store: encode message: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO messages(msg_id, sender, ts_ms, type, data) VALUES(?,?,?,?,?)`,
		m.MsgID, m.Sender.String(), m.TSms, m.Type, raw)
	if err != nil {
		return false, fmt.Errorf("store: insert message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: insert result: %w", err)
	}
	if n == 0 {
		return false, nil // 去重命中：真相源不重复写
	}
	if _, err := s.jsonl.Write(append(raw, '\n')); err != nil {
		s.rollbackMsg(m.MsgID)
		return false, fmt.Errorf("store: append jsonl: %w", err)
	}
	if err := s.jsonl.Sync(); err != nil {
		s.rollbackMsg(m.MsgID)
		return false, fmt.Errorf("store: sync jsonl: %w", err)
	}
	if m.Type == core.TypeHide {
		for _, target := range hideTargets(m.Content) {
			if _, err := s.db.Exec(`INSERT OR IGNORE INTO hidden(msg_id) VALUES(?)`, target); err != nil {
				return false, fmt.Errorf("store: mark hidden: %w", err)
			}
		}
	}
	return true, nil
}

func (s *Store) rollbackMsg(msgID string) {
	_, _ = s.db.Exec(`DELETE FROM messages WHERE msg_id=?`, msgID)
}

// rebuildIndex 从 JSONL（真相源）全量重建 messages 与 hidden 两张表。
// members/blacklist/presence/meta 是 group 包持久化的已验证状态，不在此重建。
func (s *Store) rebuildIndex() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM messages; DELETE FROM hidden;`); err != nil {
		return fmt.Errorf("store: clear index: %w", err)
	}
	skipped := 0
	_, err := scanLines(s.jsonlPath(), func(raw []byte) error {
		var m core.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			skipped++
			return nil // 坏行跳过：JSONL 是追加式真相源，残缺由多源比对兜底
		}
		if m.MsgID == "" {
			skipped++
			return nil
		}
		if _, err := s.db.Exec(
			`INSERT OR IGNORE INTO messages(msg_id, sender, ts_ms, type, data) VALUES(?,?,?,?,?)`,
			m.MsgID, m.Sender.String(), m.TSms, m.Type, raw); err != nil {
			return fmt.Errorf("store: reindex %s: %w", m.MsgID, err)
		}
		if m.Type == core.TypeHide {
			for _, target := range hideTargets(m.Content) {
				if _, err := s.db.Exec(`INSERT OR IGNORE INTO hidden(msg_id) VALUES(?)`, target); err != nil {
					return fmt.Errorf("store: reindex hidden: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if os.Getenv("DMESH_STORE_VERBOSE") != "" && skipped > 0 {
		fmt.Fprintf(os.Stderr, "store: rebuilt index, skipped %d malformed jsonl lines\n", skipped)
	}
	return nil
}

// hideTargets 解析 hide 消息 Content 指向的目标 msg_id（可为 0/1/多个）。
// 兼容两种格式：JSON 对象（target_msg_id|msg_id|target 键）与裸字符串。
func hideTargets(content []byte) []string {
	s := strings.TrimSpace(string(content))
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(s), &obj); err == nil {
			var out []string
			for _, k := range []string{"target_msg_id", "msg_id", "target", "target_ids"} {
				switch v := obj[k].(type) {
				case string:
					if v != "" {
						out = append(out, v)
					}
				case []any:
					for _, e := range v {
						if es, ok := e.(string); ok && es != "" {
							out = append(out, es)
						}
					}
				}
			}
			return out
		}
		return nil
	}
	return []string{s}
}

// HasMessage 报告 msg_id 是否已入库（去重缓存的持久化等价物）。
func (s *Store) HasMessage(msgID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	return exists(s.db, `SELECT 1 FROM messages WHERE msg_id=?`, msgID)
}

// GetMessage 按 msg_id 取回完整消息（含被 hide 的）。
func (s *Store) GetMessage(msgID string) (core.Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return core.Message{}, false, ErrClosed
	}
	var raw []byte
	err := s.db.QueryRow(`SELECT data FROM messages WHERE msg_id=?`, msgID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Message{}, false, nil
	}
	if err != nil {
		return core.Message{}, false, fmt.Errorf("store: get message: %w", err)
	}
	var m core.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return core.Message{}, false, fmt.Errorf("store: decode message %s: %w", msgID, err)
	}
	return m, true, nil
}

// MarkHidden 给目标 msg_id 打软删除标记（幂等；不要求目标已入库，
// 乱序到达的 hide 也能正确记账）。绝不作用于 hide 本身由协议层保证。
func (s *Store) MarkHidden(targetMsgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if targetMsgID == "" {
		return fmt.Errorf("%w: empty hide target", core.ErrMalformed)
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO hidden(msg_id) VALUES(?)`, targetMsgID)
	if err != nil {
		return fmt.Errorf("store: mark hidden: %w", err)
	}
	return nil
}

// IsHidden 报告目标是否被软删除。
func (s *Store) IsHidden(targetMsgID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	return exists(s.db, `SELECT 1 FROM hidden WHERE msg_id=?`, targetMsgID)
}

// MessageQuery 是消息查询过滤器；零值 = 全量按插入序升序。
type MessageQuery struct {
	Types         []string     // 空 = 所有类型（含名单事件）
	ExcludeTypes  []string     // 例如只要聊天流：ExcludeTypes=[除 text 外的事件类型]
	Sender        *core.PubKey // nil = 不限发送者
	SinceMS       int64        // ts_ms >= SinceMS（0 = 不限）
	UntilMS       int64        // ts_ms <= UntilMS（0 = 不限）
	IncludeHidden bool         // false = 过滤掉被 hide 的（默认软删除不显示）
	AfterRowID    int64        // 增量游标：只取插入序 > 该值的行（回灌/审计用）
	Limit         int          // 0 = 不限
}

// QueryMessages 按过滤条件返回消息，按插入序（rowid）排序。
func (s *Store) QueryMessages(q MessageQuery) ([]core.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var (
		where []string
		args  []any
	)
	if len(q.Types) > 0 {
		where = append(where, "type IN ("+placeholders(len(q.Types))+")")
		for _, t := range q.Types {
			args = append(args, t)
		}
	}
	if len(q.ExcludeTypes) > 0 {
		where = append(where, "type NOT IN ("+placeholders(len(q.ExcludeTypes))+")")
		for _, t := range q.ExcludeTypes {
			args = append(args, t)
		}
	}
	if q.Sender != nil {
		where = append(where, "sender = ?")
		args = append(args, q.Sender.String())
	}
	if q.SinceMS > 0 {
		where = append(where, "ts_ms >= ?")
		args = append(args, q.SinceMS)
	}
	if q.UntilMS > 0 {
		where = append(where, "ts_ms <= ?")
		args = append(args, q.UntilMS)
	}
	if !q.IncludeHidden {
		where = append(where, "msg_id NOT IN (SELECT msg_id FROM hidden)")
	}
	if q.AfterRowID > 0 {
		where = append(where, "rowid > ?")
		args = append(args, q.AfterRowID)
	}
	stmt := `SELECT data FROM messages`
	if len(where) > 0 {
		stmt += ` WHERE ` + strings.Join(where, " AND ")
	}
	stmt += ` ORDER BY rowid ASC`
	if q.Limit > 0 {
		stmt += ` LIMIT ?`
		args = append(args, q.Limit)
	}
	rows, err := s.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query: %w", err)
	}
	defer rows.Close()
	var out []core.Message
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("store: query scan: %w", err)
		}
		var m core.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("store: query decode: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query iter: %w", err)
	}
	return out, nil
}

// CountMessages 返回入库消息总数（含被 hide 的）。
func (s *Store) CountMessages() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count: %w", err)
	}
	return n, nil
}

// MaxMsgTS 返回本机已存消息的最大 ts_ms（回灌时向邻居上报的缺口游标），
// 无消息时返回 0。
func (s *Store) MaxMsgTS() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(ts_ms) FROM messages`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: max ts: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return v.Int64, nil
}

// LastRowID 返回当前插入序游标，配合 MessageQuery.AfterRowID 做增量遍历。
func (s *Store) LastRowID() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(rowid) FROM messages`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: last rowid: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return v.Int64, nil
}

// AllMsgIDs 返回全部 msg_id（含被 hide 的，插入序升序）——
// /audit 多源 msg_id 集合比对与回灌差异计算的入口。
func (s *Store) AllMsgIDs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	rows, err := s.db.Query(`SELECT msg_id FROM messages ORDER BY rowid ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: msg ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: msg ids scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func exists(db *sql.DB, query string, args ...any) (bool, error) {
	var one int
	err := db.QueryRow(query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: exists: %w", err)
	}
	return true, nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
