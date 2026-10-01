package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Knowledge: the server diary (journal), learned facts per server and the
// learned dependency graph. The database is the source of truth; the
// Obsidian vault is rendered from it.

const schemaKnowledge = `
CREATE TABLE IF NOT EXISTS journal (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	server_id TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	author TEXT NOT NULL DEFAULT 'ServerBrain'
);
CREATE INDEX IF NOT EXISTS journal_ts ON journal(ts);
CREATE INDEX IF NOT EXISTS journal_server_ts ON journal(server_id, ts);
CREATE TABLE IF NOT EXISTS facts (
	server_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (server_id, key)
);
CREATE TABLE IF NOT EXISTS dependencies (
	src_id TEXT NOT NULL,
	dst_id TEXT NOT NULL,
	port INTEGER NOT NULL,
	process TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	PRIMARY KEY (src_id, dst_id, port)
);
`

// Journal categories.
const (
	CatInventory    = "inventar"
	CatAvailability = "verfuegbarkeit"
	CatService      = "dienst"
	CatSoftware     = "software"
	CatRole         = "rolle"
	CatResource     = "ressource"
	CatEvent        = "ereignis"
	CatSystem       = "system"
	CatNetwork      = "netzwerk"
	CatAction       = "aktion"
	CatConsole      = "konsole"
	CatNote         = "notiz"
	CatAI           = "ki"
	CatAutopilot    = "autopilot"
)

// Journal severities.
const (
	SevInfo = "info"
	SevOK   = "ok"
	SevWarn = "warn"
	SevCrit = "crit"
)

type JournalEntry struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	ServerID string    `json:"server_id"`
	Hostname string    `json:"hostname,omitempty"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	Author   string    `json:"author"`
}

func (s *Store) AddJournal(ctx context.Context, e JournalEntry) (int64, error) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Author == "" {
		e.Author = "ServerBrain"
	}
	if e.Severity == "" {
		e.Severity = SevInfo
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO journal(ts,server_id,category,severity,title,detail,author) VALUES(?,?,?,?,?,?,?)`,
		unix(e.TS), e.ServerID, e.Category, e.Severity, e.Title, e.Detail, e.Author)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type JournalFilter struct {
	ServerID string
	Since    time.Time
	Until    time.Time
	Limit    int
}

func (s *Store) ListJournal(ctx context.Context, f JournalFilter) ([]JournalEntry, error) {
	q := `SELECT j.id,j.ts,j.server_id,COALESCE(s.hostname,''),j.category,j.severity,j.title,j.detail,j.author
	      FROM journal j LEFT JOIN servers s ON s.id=j.server_id WHERE j.ts>=?`
	args := []any{unix(f.Since)}
	if !f.Until.IsZero() {
		q += ` AND j.ts<?`
		args = append(args, unix(f.Until))
	}
	if f.ServerID != "" {
		q += ` AND j.server_id=?`
		args = append(args, f.ServerID)
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	q += ` ORDER BY j.ts DESC, j.id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JournalEntry{}
	for rows.Next() {
		var e JournalEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.ServerID, &e.Hostname, &e.Category, &e.Severity, &e.Title, &e.Detail, &e.Author); err != nil {
			return nil, err
		}
		e.TS = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// JournalDays returns the distinct UTC-agnostic local days (YYYY-MM-DD in
// loc) that have entries since t.
func (s *Store) JournalDays(ctx context.Context, since time.Time, loc *time.Location) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts FROM journal WHERE ts>=? ORDER BY ts`, unix(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		d := fromUnix(ts).In(loc).Format("2006-01-02")
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// ---------- facts ----------

type Fact struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetFact returns the value of a fact, or ErrNotFound.
func (s *Store) GetFact(ctx context.Context, serverID, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM facts WHERE server_id=? AND key=?`, serverID, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetFact stores a fact and reports whether it was new.
func (s *Store) SetFact(ctx context.Context, serverID, key, value string) (bool, error) {
	now := unix(time.Now())
	res, err := s.db.ExecContext(ctx, `INSERT INTO facts(server_id,key,value,first_seen,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(server_id,key) DO NOTHING`, serverID, key, value, now, now)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE facts SET value=?, updated_at=? WHERE server_id=? AND key=?`, value, now, serverID, key)
	return false, err
}

func (s *Store) DeleteFact(ctx context.Context, serverID, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM facts WHERE server_id=? AND key=?`, serverID, key)
	return err
}

// Facts lists facts of a server whose key starts with prefix.
func (s *Store) Facts(ctx context.Context, serverID, prefix string) ([]Fact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value,first_seen,updated_at FROM facts WHERE server_id=? AND key LIKE ? ORDER BY key`, serverID, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Fact{}
	for rows.Next() {
		var f Fact
		var first, upd int64
		if err := rows.Scan(&f.Key, &f.Value, &first, &upd); err != nil {
			return nil, err
		}
		f.FirstSeen, f.UpdatedAt = fromUnix(first), fromUnix(upd)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---------- dependencies ----------

type Dependency struct {
	SrcID     string    `json:"src_id"`
	SrcHost   string    `json:"src_host"`
	DstID     string    `json:"dst_id"`
	DstHost   string    `json:"dst_host"`
	Port      int       `json:"port"`
	Process   string    `json:"process"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// TouchDependency records that src talks to dst:port and reports whether the
// edge is new.
func (s *Store) TouchDependency(ctx context.Context, src, dst string, port int, process string) (bool, error) {
	now := unix(time.Now())
	res, err := s.db.ExecContext(ctx, `INSERT INTO dependencies(src_id,dst_id,port,process,first_seen,last_seen) VALUES(?,?,?,?,?,?)
		ON CONFLICT(src_id,dst_id,port) DO NOTHING`, src, dst, port, process, now, now)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE dependencies SET last_seen=?, process=CASE WHEN ?<>'' THEN ? ELSE process END WHERE src_id=? AND dst_id=? AND port=?`,
		now, process, process, src, dst, port)
	return false, err
}

// Dependencies returns all edges touching serverID (or all if empty).
func (s *Store) Dependencies(ctx context.Context, serverID string) ([]Dependency, error) {
	q := `SELECT d.src_id,COALESCE(a.hostname,''),d.dst_id,COALESCE(b.hostname,''),d.port,d.process,d.first_seen,d.last_seen
	      FROM dependencies d LEFT JOIN servers a ON a.id=d.src_id LEFT JOIN servers b ON b.id=d.dst_id`
	var args []any
	if serverID != "" {
		q += ` WHERE d.src_id=? OR d.dst_id=?`
		args = append(args, serverID, serverID)
	}
	q += ` ORDER BY 2, 4, d.port`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Dependency{}
	for rows.Next() {
		var d Dependency
		var first, last int64
		if err := rows.Scan(&d.SrcID, &d.SrcHost, &d.DstID, &d.DstHost, &d.Port, &d.Process, &first, &last); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen = fromUnix(first), fromUnix(last)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ErrorSignatures counts error/critical events per source+event id for a
// server since t (the "known problems" of a server).
type ErrorSignature struct {
	Source  string    `json:"source"`
	EventID int       `json:"event_id"`
	Level   string    `json:"level"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
	Message string    `json:"message"`
}

func (s *Store) ErrorSignatures(ctx context.Context, serverID string, since time.Time, limit int) ([]ErrorSignature, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source,event_id,MIN(level),COUNT(*),MAX(ts),
		(SELECT message FROM events e2 WHERE e2.server_id=e.server_id AND e2.source=e.source AND e2.event_id=e.event_id ORDER BY ts DESC LIMIT 1)
		FROM events e WHERE server_id=? AND ts>=? AND level IN ('Error','Critical')
		GROUP BY source,event_id ORDER BY COUNT(*) DESC LIMIT ?`, serverID, unix(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ErrorSignature{}
	for rows.Next() {
		var e ErrorSignature
		var last int64
		if err := rows.Scan(&e.Source, &e.EventID, &e.Level, &e.Count, &last, &e.Message); err != nil {
			return nil, err
		}
		e.Last = fromUnix(last)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Baseline is the average resource usage of a server over a window.
type Baseline struct {
	Samples int     `json:"samples"`
	CPUAvg  float64 `json:"cpu_avg"`
	CPUMax  float64 `json:"cpu_max"`
	MemAvg  float64 `json:"mem_avg_pct"`
	DiskMax float64 `json:"disk_max_pct"`
}

func (s *Store) Baseline(ctx context.Context, serverID string, since time.Time) (Baseline, error) {
	var b Baseline
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(AVG(cpu),0),COALESCE(MAX(cpu),0),
		COALESCE(AVG(CASE WHEN mem_total>0 THEN 100.0*mem_used/mem_total END),0),COALESCE(MAX(disk_used_pct),0)
		FROM metrics WHERE server_id=? AND ts>=?`, serverID, unix(since)).Scan(&b.Samples, &b.CPUAvg, &b.CPUMax, &b.MemAvg, &b.DiskMax)
	return b, err
}
