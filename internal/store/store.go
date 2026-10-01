// Package store persists the control plane state in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	role TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT 'human',
	token_hash TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	token_hash TEXT PRIMARY KEY,
	created_by TEXT NOT NULL,
	tags TEXT NOT NULL DEFAULT '[]',
	uses_left INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
	id TEXT PRIMARY KEY,
	hostname TEXT NOT NULL,
	os TEXT NOT NULL DEFAULT '',
	os_version TEXT NOT NULL DEFAULT '',
	agent_version TEXT NOT NULL DEFAULT '',
	remote_addr TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '[]',
	secret_hash TEXT NOT NULL UNIQUE,
	enrolled_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL DEFAULT 0,
	capabilities TEXT NOT NULL DEFAULT '[]',
	snapshot TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS metrics (
	server_id TEXT NOT NULL,
	ts INTEGER NOT NULL,
	cpu REAL NOT NULL,
	mem_used INTEGER NOT NULL,
	mem_total INTEGER NOT NULL,
	disk_used_pct REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_server_ts ON metrics(server_id, ts);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id TEXT NOT NULL,
	ts INTEGER NOT NULL,
	log TEXT NOT NULL,
	level TEXT NOT NULL,
	source TEXT NOT NULL,
	event_id INTEGER NOT NULL,
	message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_server_ts ON events(server_id, ts);
CREATE TABLE IF NOT EXISTS commands (
	id TEXT PRIMARY KEY,
	server_id TEXT NOT NULL,
	action TEXT NOT NULL,
	params TEXT NOT NULL,
	preview TEXT NOT NULL,
	risk TEXT NOT NULL,
	status TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	actor_type TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	policy_rule TEXT NOT NULL DEFAULT '',
	decided_by TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS commands_server_status ON commands(server_id, status);
CREATE TABLE IF NOT EXISTS audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	actor TEXT NOT NULL,
	actor_type TEXT NOT NULL,
	event TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
`

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; serializing keeps things simple and safe.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ---------- helpers ----------

// NewToken returns a random URL-safe secret with the given prefix.
func NewToken(prefix string) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}

// NewID returns a random identifier.
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HashToken hashes a high-entropy secret for storage.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func unix(t time.Time) int64 { return t.UnixMilli() }

func fromUnix(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// ---------- users ----------

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Kind      string    `json:"kind"` // human or ai
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser creates a user and returns its API token (shown only once).
func (s *Store) CreateUser(ctx context.Context, name, role, kind string) (*User, string, error) {
	token := NewToken("sbu_")
	u := &User{ID: NewID(), Name: name, Role: role, Kind: kind, CreatedAt: time.Now().UTC()}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,name,role,kind,token_hash,created_at) VALUES(?,?,?,?,?,?)`,
		u.ID, u.Name, u.Role, u.Kind, HashToken(token), unix(u.CreatedAt))
	if err != nil {
		return nil, "", err
	}
	return u, token, nil
}

func (s *Store) UserByToken(ctx context.Context, token string) (*User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id,name,role,kind,created_at FROM users WHERE token_hash=?`, HashToken(token)).
		Scan(&u.ID, &u.Name, &u.Role, &u.Kind, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	u.CreatedAt = fromUnix(created)
	return &u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,role,kind,created_at FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &u.Role, &u.Kind, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = fromUnix(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------- enrollment ----------

func (s *Store) CreateEnrollmentToken(ctx context.Context, createdBy string, tags []string, uses int, ttl time.Duration) (string, time.Time, error) {
	token := NewToken("sbe_")
	now := time.Now().UTC()
	exp := now.Add(ttl)
	if tags == nil {
		tags = []string{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(token_hash,created_by,tags,uses_left,expires_at,created_at) VALUES(?,?,?,?,?,?)`,
		HashToken(token), createdBy, mustJSON(tags), uses, unix(exp), unix(now))
	return token, exp, err
}

// Enroll consumes an enrollment token and registers a new server. It returns
// the server ID and the agent secret.
func (s *Store) Enroll(ctx context.Context, token string, sys protocol.SystemInfo, agentVersion, remoteAddr string) (string, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	var uses int
	var exp int64
	var tags string
	err = tx.QueryRowContext(ctx, `SELECT uses_left,expires_at,tags FROM enrollment_tokens WHERE token_hash=?`, HashToken(token)).Scan(&uses, &exp, &tags)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (uses <= 0 || time.Now().After(fromUnix(exp)))) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET uses_left=uses_left-1 WHERE token_hash=?`, HashToken(token)); err != nil {
		return "", "", err
	}
	id := NewID()
	secret := NewToken("sba_")
	_, err = tx.ExecContext(ctx, `INSERT INTO servers(id,hostname,os,os_version,agent_version,remote_addr,tags,secret_hash,enrolled_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		id, sys.Hostname, sys.OS, sys.OSVersion, agentVersion, remoteAddr, tags, HashToken(secret), unix(time.Now()))
	if err != nil {
		return "", "", err
	}
	return id, secret, tx.Commit()
}

// ---------- servers ----------

type Server struct {
	ID           string              `json:"id"`
	Hostname     string              `json:"hostname"`
	OS           string              `json:"os"`
	OSVersion    string              `json:"os_version"`
	AgentVersion string              `json:"agent_version"`
	RemoteAddr   string              `json:"remote_addr"`
	Tags         []string            `json:"tags"`
	EnrolledAt   time.Time           `json:"enrolled_at"`
	LastSeen     time.Time           `json:"last_seen"`
	Capabilities []string            `json:"capabilities"`
	Snapshot     *protocol.Heartbeat `json:"snapshot,omitempty"`
}

const serverCols = `id,hostname,os,os_version,agent_version,remote_addr,tags,enrolled_at,last_seen,capabilities,snapshot`

func scanServer(sc interface{ Scan(...any) error }, withSnapshot bool) (*Server, error) {
	var srv Server
	var tags, caps, snap string
	var enrolled, seen int64
	if err := sc.Scan(&srv.ID, &srv.Hostname, &srv.OS, &srv.OSVersion, &srv.AgentVersion, &srv.RemoteAddr, &tags, &enrolled, &seen, &caps, &snap); err != nil {
		return nil, err
	}
	srv.EnrolledAt, srv.LastSeen = fromUnix(enrolled), fromUnix(seen)
	_ = json.Unmarshal([]byte(tags), &srv.Tags)
	_ = json.Unmarshal([]byte(caps), &srv.Capabilities)
	if srv.Tags == nil {
		srv.Tags = []string{}
	}
	if srv.Capabilities == nil {
		srv.Capabilities = []string{}
	}
	var hb protocol.Heartbeat
	if err := json.Unmarshal([]byte(snap), &hb); err == nil {
		if !withSnapshot {
			// Keep metrics for list views but drop bulky inventory.
			hb.Services, hb.Events = nil, nil
		}
		srv.Snapshot = &hb
	}
	return &srv, nil
}

func (s *Store) ServerBySecret(ctx context.Context, secret string) (*Server, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE secret_hash=?`, HashToken(secret))
	srv, err := scanServer(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

func (s *Store) GetServer(ctx context.Context, id string) (*Server, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE id=?`, id)
	srv, err := scanServer(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// ListServers lists all servers. With full=false the bulky service
// inventory is omitted from the snapshots.
func (s *Store) ListServers(ctx context.Context, full bool) ([]*Server, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+serverCols+` FROM servers ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Server{}
	for rows.Next() {
		srv, err := scanServer(rows, full)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

func (s *Store) SetServerTags(ctx context.Context, id string, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE servers SET tags=? WHERE id=?`, mustJSON(tags), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteServer(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM metrics WHERE server_id=?`, `DELETE FROM events WHERE server_id=?`,
		`UPDATE commands SET status='cancelled' WHERE server_id=? AND status IN ('pending_approval','queued')`, `DELETE FROM servers WHERE id=?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RecordHeartbeat stores the latest snapshot plus metric and event history.
func (s *Store) RecordHeartbeat(ctx context.Context, id, remoteAddr string, hb *protocol.Heartbeat) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	events := hb.Events
	hb.Events = nil // events are stored in their own table
	if hb.Capabilities == nil {
		hb.Capabilities = []string{}
	}
	_, err = tx.ExecContext(ctx, `UPDATE servers SET hostname=?,os=?,os_version=?,agent_version=?,remote_addr=?,last_seen=?,capabilities=?,snapshot=? WHERE id=?`,
		hb.System.Hostname, hb.System.OS, hb.System.OSVersion, hb.AgentVersion, remoteAddr, unix(now), mustJSON(hb.Capabilities), mustJSON(hb), id)
	if err != nil {
		return err
	}
	var maxDisk float64
	for _, d := range hb.Metrics.Disks {
		if d.Total > 0 {
			if p := 100 * float64(d.Total-d.Free) / float64(d.Total); p > maxDisk {
				maxDisk = p
			}
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO metrics(server_id,ts,cpu,mem_used,mem_total,disk_used_pct) VALUES(?,?,?,?,?,?)`,
		id, unix(now), hb.Metrics.CPUPercent, hb.Metrics.MemUsed, hb.Metrics.MemTotal, maxDisk)
	if err != nil {
		return err
	}
	for _, e := range events {
		msg := e.Message
		if len(msg) > 4000 {
			msg = msg[:4000]
		}
		ts := e.Time
		if ts.IsZero() {
			ts = now
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(server_id,ts,log,level,source,event_id,message) VALUES(?,?,?,?,?,?,?)`,
			id, unix(ts), e.Log, e.Level, e.Source, e.EventID, msg); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type MetricPoint struct {
	TS          time.Time `json:"ts"`
	CPU         float64   `json:"cpu"`
	MemUsed     uint64    `json:"mem_used"`
	MemTotal    uint64    `json:"mem_total"`
	DiskUsedPct float64   `json:"disk_used_pct"`
}

func (s *Store) Metrics(ctx context.Context, serverID string, since time.Time) ([]MetricPoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts,cpu,mem_used,mem_total,disk_used_pct FROM metrics WHERE server_id=? AND ts>=? ORDER BY ts`, serverID, unix(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MetricPoint{}
	for rows.Next() {
		var p MetricPoint
		var ts int64
		if err := rows.Scan(&ts, &p.CPU, &p.MemUsed, &p.MemTotal, &p.DiskUsedPct); err != nil {
			return nil, err
		}
		p.TS = fromUnix(ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

type StoredEvent struct {
	protocol.Event
	ID       int64  `json:"id"`
	ServerID string `json:"server_id"`
}

func (s *Store) Events(ctx context.Context, serverID string, since time.Time, limit int) ([]StoredEvent, error) {
	q := `SELECT id,server_id,ts,log,level,source,event_id,message FROM events WHERE ts>=?`
	args := []any{unix(since)}
	if serverID != "" {
		q += ` AND server_id=?`
		args = append(args, serverID)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredEvent{}
	for rows.Next() {
		var e StoredEvent
		var ts int64
		if err := rows.Scan(&e.ID, &e.ServerID, &ts, &e.Log, &e.Level, &e.Source, &e.EventID, &e.Message); err != nil {
			return nil, err
		}
		e.Time = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrorCounts returns the number of Error/Critical events per server since t.
func (s *Store) ErrorCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT server_id, COUNT(*) FROM events WHERE ts>=? AND level IN ('Error','Critical') GROUP BY server_id`, unix(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ---------- commands ----------

// Command statuses.
const (
	StatusPendingApproval = "pending_approval"
	StatusQueued          = "queued"
	StatusDispatched      = "dispatched"
	StatusSucceeded       = "succeeded"
	StatusFailed          = "failed"
	StatusRejected        = "rejected"
	StatusExpired         = "expired"
	StatusCancelled       = "cancelled"
)

type Command struct {
	ID          string                  `json:"id"`
	ServerID    string                  `json:"server_id"`
	Hostname    string                  `json:"hostname,omitempty"`
	Action      string                  `json:"action"`
	Params      map[string]string       `json:"params"`
	Preview     string                  `json:"preview"`
	Risk        string                  `json:"risk"`
	Status      string                  `json:"status"`
	RequestedBy string                  `json:"requested_by"`
	ActorType   string                  `json:"actor_type"`
	Reason      string                  `json:"reason"`
	PolicyRule  string                  `json:"policy_rule"`
	DecidedBy   string                  `json:"decided_by,omitempty"`
	Result      *protocol.CommandResult `json:"result,omitempty"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

func (s *Store) CreateCommand(ctx context.Context, c *Command) error {
	now := time.Now().UTC()
	c.ID, c.CreatedAt, c.UpdatedAt = NewID(), now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO commands(id,server_id,action,params,preview,risk,status,requested_by,actor_type,reason,policy_rule,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.ServerID, c.Action, mustJSON(c.Params), c.Preview, c.Risk, c.Status, c.RequestedBy, c.ActorType, c.Reason, c.PolicyRule, unix(now), unix(now))
	return err
}

const commandCols = `c.id,c.server_id,COALESCE(s.hostname,''),c.action,c.params,c.preview,c.risk,c.status,c.requested_by,c.actor_type,c.reason,c.policy_rule,c.decided_by,c.result,c.created_at,c.updated_at`

func scanCommand(sc interface{ Scan(...any) error }) (*Command, error) {
	var c Command
	var params, result string
	var created, updated int64
	if err := sc.Scan(&c.ID, &c.ServerID, &c.Hostname, &c.Action, &params, &c.Preview, &c.Risk, &c.Status, &c.RequestedBy, &c.ActorType, &c.Reason, &c.PolicyRule, &c.DecidedBy, &result, &created, &updated); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(params), &c.Params)
	if result != "" {
		var r protocol.CommandResult
		if json.Unmarshal([]byte(result), &r) == nil {
			c.Result = &r
		}
	}
	c.CreatedAt, c.UpdatedAt = fromUnix(created), fromUnix(updated)
	return &c, nil
}

func (s *Store) GetCommand(ctx context.Context, id string) (*Command, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+commandCols+` FROM commands c LEFT JOIN servers s ON s.id=c.server_id WHERE c.id=?`, id)
	c, err := scanCommand(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

type CommandFilter struct {
	ServerID string
	Status   string
	Limit    int
}

func (s *Store) ListCommands(ctx context.Context, f CommandFilter) ([]*Command, error) {
	q := `SELECT ` + commandCols + ` FROM commands c LEFT JOIN servers s ON s.id=c.server_id WHERE 1=1`
	var args []any
	if f.ServerID != "" {
		q += ` AND c.server_id=?`
		args = append(args, f.ServerID)
	}
	if f.Status != "" {
		q += ` AND c.status=?`
		args = append(args, f.Status)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q += ` ORDER BY c.created_at DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Command{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TransitionCommand moves a command from one status to another atomically.
// It returns ErrNotFound if the command is not in the expected state.
func (s *Store) TransitionCommand(ctx context.Context, id, from, to, decidedBy string) error {
	q := `UPDATE commands SET status=?, updated_at=?`
	args := []any{to, unix(time.Now())}
	if decidedBy != "" {
		q += `, decided_by=?`
		args = append(args, decidedBy)
	}
	q += ` WHERE id=? AND status=?`
	args = append(args, id, from)
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimQueued marks all queued commands for a server as dispatched and
// returns them.
func (s *Store) ClaimQueued(ctx context.Context, serverID string) ([]protocol.Command, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,action,params FROM commands WHERE server_id=? AND status=? ORDER BY created_at LIMIT 20`, serverID, StatusQueued)
	if err != nil {
		return nil, err
	}
	var out []protocol.Command
	for rows.Next() {
		var c protocol.Command
		var params string
		if err := rows.Scan(&c.ID, &c.Action, &params); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(params), &c.Params)
		out = append(out, c)
	}
	rows.Close()
	now := unix(time.Now())
	for _, c := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE commands SET status=?, updated_at=? WHERE id=?`, StatusDispatched, now, c.ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

// CompleteCommand stores the agent's result for a dispatched command that
// belongs to the given server.
func (s *Store) CompleteCommand(ctx context.Context, serverID, id string, r *protocol.CommandResult) (*Command, error) {
	status := StatusFailed
	if r.Success {
		status = StatusSucceeded
	}
	res, err := s.db.ExecContext(ctx, `UPDATE commands SET status=?, result=?, updated_at=? WHERE id=? AND server_id=? AND status=?`,
		status, mustJSON(r), unix(time.Now()), id, serverID, StatusDispatched)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetCommand(ctx, id)
}

// ExpireStale expires commands that waited too long for approval or
// dispatch, and fails dispatched commands whose agent never answered.
func (s *Store) ExpireStale(ctx context.Context, pendingTTL, dispatchTTL time.Duration) (int64, error) {
	now := time.Now()
	var total int64
	res, err := s.db.ExecContext(ctx, `UPDATE commands SET status=?, updated_at=? WHERE status IN (?,?) AND created_at<?`,
		StatusExpired, unix(now), StatusPendingApproval, StatusQueued, unix(now.Add(-pendingTTL)))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	total += n
	res, err = s.db.ExecContext(ctx, `UPDATE commands SET status=?, result=?, updated_at=? WHERE status=? AND updated_at<?`,
		StatusFailed, mustJSON(protocol.CommandResult{Error: "agent did not report a result in time"}), unix(now), StatusDispatched, unix(now.Add(-dispatchTTL)))
	if err != nil {
		return total, err
	}
	n, _ = res.RowsAffected()
	return total + n, nil
}

// Prune removes telemetry older than the retention windows.
func (s *Store) Prune(ctx context.Context, metricsKeep, eventsKeep time.Duration) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM metrics WHERE ts<?`, unix(now.Add(-metricsKeep))); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts<?`, unix(now.Add(-eventsKeep)))
	return err
}

// ---------- audit ----------

type AuditEntry struct {
	ID        int64          `json:"id"`
	TS        time.Time      `json:"ts"`
	Actor     string         `json:"actor"`
	ActorType string         `json:"actor_type"`
	Event     string         `json:"event"`
	Target    string         `json:"target"`
	Details   map[string]any `json:"details"`
}

func (s *Store) Audit(ctx context.Context, actor, actorType, event, target string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit(ts,actor,actor_type,event,target,details) VALUES(?,?,?,?,?,?)`,
		unix(time.Now()), actor, actorType, event, target, mustJSON(details))
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,ts,actor,actor_type,event,target,details FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		var ts int64
		var details string
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.ActorType, &a.Event, &a.Target, &details); err != nil {
			return nil, err
		}
		a.TS = fromUnix(ts)
		_ = json.Unmarshal([]byte(details), &a.Details)
		out = append(out, a)
	}
	return out, rows.Err()
}
