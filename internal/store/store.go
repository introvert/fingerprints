// Package store persists fingerprint reports in SQLite so they can be read
// back later by id / permalink and searched by hash (history).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a record id does not exist.
var ErrNotFound = errors.New("store: not found")

// Summary is the indexed metadata of a stored fingerprint.
type Summary struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	Label        string    `json:"label,omitempty"`
	JA3          string    `json:"ja3_hash,omitempty"`
	JA4          string    `json:"ja4,omitempty"`
	HTTP2        string    `json:"http2_hash,omitempty"`
	BrowserHash  string    `json:"browser_hash,omitempty"`
	CombinedHash string    `json:"combined_hash,omitempty"`
	VisitorID    string    `json:"visitor_id,omitempty"`
}

// Record is a stored fingerprint: summary plus the full JSON report.
type Record struct {
	Summary
	Report json.RawMessage `json:"report"`
}

// Store is a SQLite backed fingerprint store.
type Store struct{ db *sql.DB }

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS fingerprints (
  id            TEXT PRIMARY KEY,
  created_at    INTEGER NOT NULL,
  ip            TEXT NOT NULL DEFAULT '',
  user_agent    TEXT NOT NULL DEFAULT '',
  label         TEXT NOT NULL DEFAULT '',
  ja3_hash      TEXT NOT NULL DEFAULT '',
  ja4           TEXT NOT NULL DEFAULT '',
  http2_hash    TEXT NOT NULL DEFAULT '',
  browser_hash  TEXT NOT NULL DEFAULT '',
  combined_hash TEXT NOT NULL DEFAULT '',
  visitor_id    TEXT NOT NULL DEFAULT '',
  report        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS fp_created  ON fingerprints(created_at);
CREATE INDEX IF NOT EXISTS fp_ja4      ON fingerprints(ja4);
CREATE INDEX IF NOT EXISTS fp_ja3      ON fingerprints(ja3_hash);
CREATE INDEX IF NOT EXISTS fp_browser  ON fingerprints(browser_hash);
CREATE INDEX IF NOT EXISTS fp_combined ON fingerprints(combined_hash);
CREATE INDEX IF NOT EXISTS fp_visitor  ON fingerprints(visitor_id);
CREATE INDEX IF NOT EXISTS fp_ip       ON fingerprints(ip);
`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const idAlphabet = "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

// NewID returns a random, URL safe, unambiguous id (12 chars, ~70 bits).
func NewID() string {
	b := make([]byte, 12)
	rand.Read(b)
	for i := range b {
		b[i] = idAlphabet[int(b[i])%len(idAlphabet)]
	}
	return string(b)
}

// Insert stores a record. If rec.ID is empty a new id is generated.
func (s *Store) Insert(ctx context.Context, rec *Record) error {
	if rec.ID == "" {
		rec.ID = NewID()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO fingerprints
 (id, created_at, ip, user_agent, label, ja3_hash, ja4, http2_hash, browser_hash, combined_hash, visitor_id, report)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.ID, rec.CreatedAt.UnixMilli(), rec.IP, rec.UserAgent, rec.Label, rec.JA3, rec.JA4, rec.HTTP2,
		rec.BrowserHash, rec.CombinedHash, rec.VisitorID, []byte(rec.Report))
	return err
}

const cols = `id, created_at, ip, user_agent, label, ja3_hash, ja4, http2_hash, browser_hash, combined_hash, visitor_id`

func scanSummary(sc interface{ Scan(...any) error }, extra ...any) (Summary, error) {
	var sm Summary
	var ms int64
	dst := append([]any{&sm.ID, &ms, &sm.IP, &sm.UserAgent, &sm.Label, &sm.JA3, &sm.JA4, &sm.HTTP2, &sm.BrowserHash, &sm.CombinedHash, &sm.VisitorID}, extra...)
	if err := sc.Scan(dst...); err != nil {
		return sm, err
	}
	sm.CreatedAt = time.UnixMilli(ms).UTC()
	return sm, nil
}

// Get loads a record by id.
func (s *Store) Get(ctx context.Context, id string) (*Record, error) {
	var rep []byte
	row := s.db.QueryRowContext(ctx, `SELECT `+cols+`, report FROM fingerprints WHERE id = ?`, id)
	sm, err := scanSummary(row, &rep)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Record{Summary: sm, Report: rep}, nil
}

// Delete removes a record.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM fingerprints WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Filter selects records for List. Empty fields are ignored.
type Filter struct {
	JA3, JA4, HTTP2, BrowserHash, CombinedHash, VisitorID, IP, Label string
	Before                                                           time.Time
	Limit                                                            int
}

// List returns summaries matching f, newest first.
func (s *Store) List(ctx context.Context, f Filter) ([]Summary, error) {
	var where []string
	var args []any
	add := func(col, v string) {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	add("ja3_hash", f.JA3)
	add("ja4", f.JA4)
	add("http2_hash", f.HTTP2)
	add("browser_hash", f.BrowserHash)
	add("combined_hash", f.CombinedHash)
	add("visitor_id", f.VisitorID)
	add("ip", f.IP)
	add("label", f.Label)
	if !f.Before.IsZero() {
		where = append(where, "created_at < ?")
		args = append(args, f.Before.UnixMilli())
	}
	q := `SELECT ` + cols + ` FROM fingerprints`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d", f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Summary{}
	for rows.Next() {
		sm, err := scanSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

// Related returns other records sharing any strong identifier with rec.
func (s *Store) Related(ctx context.Context, rec *Summary, limit int) (map[string][]Summary, error) {
	out := map[string][]Summary{}
	for _, k := range []struct{ name, col, v string }{
		{"combined_hash", "combined_hash", rec.CombinedHash},
		{"browser_hash", "browser_hash", rec.BrowserHash},
		{"visitor_id", "visitor_id", rec.VisitorID},
		{"ja4", "ja4", rec.JA4},
	} {
		if k.v == "" {
			continue
		}
		rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM fingerprints WHERE `+k.col+` = ? AND id != ? ORDER BY created_at DESC LIMIT ?`, k.v, rec.ID, limit)
		if err != nil {
			return nil, err
		}
		list := []Summary{}
		for rows.Next() {
			sm, err := scanSummary(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			list = append(list, sm)
		}
		rows.Close()
		out[k.name] = list
	}
	return out, nil
}

// Count returns the number of stored records.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fingerprints`).Scan(&n)
	return n, err
}
