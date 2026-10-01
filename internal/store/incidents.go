package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Incidents: a detected problem on a server, its analysis, a prepared
// solution (a plan of catalog actions) and the outcome after a person
// confirmed it.

const schemaIncidents = `
CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	server_id TEXT NOT NULL,
	key TEXT NOT NULL,
	kind TEXT NOT NULL,
	title TEXT NOT NULL,
	trigger TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL,
	status TEXT NOT NULL,
	occurrences INTEGER NOT NULL DEFAULT 1,
	diagnosis TEXT NOT NULL DEFAULT '',
	plan TEXT NOT NULL DEFAULT '[]',
	analysis_by TEXT NOT NULL DEFAULT '',
	run_id TEXT NOT NULL DEFAULT '',
	decided_by TEXT NOT NULL DEFAULT '',
	resolution TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	resolved_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_server_key ON incidents(server_id, key);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents(status);
`

// Incident statuses.
const (
	IncNew       = "new"       // detected, not analysed yet (e.g. rate-limited)
	IncAutopilot = "autopilot" // the autopilot is handling it first
	IncAnalyzing = "analyzing" // AI analysis running
	IncProposed  = "proposed"  // a solution is prepared and awaits confirmation
	IncManual    = "manual"    // analysed; no automatic solution, needs a person
	IncExecuting = "executing" // confirmed solution is being carried out
	IncFailed    = "failed"    // a step failed or the problem persists
	IncResolved  = "resolved"  // problem gone (verified, autopilot or by itself)
	IncDismissed = "dismissed" // closed by a person without action
)

// OpenIncidentStatuses are the statuses of incidents that still need work.
var OpenIncidentStatuses = []string{IncNew, IncAutopilot, IncAnalyzing, IncProposed, IncManual, IncExecuting, IncFailed}

// PlanStep is one action of a prepared solution.
type PlanStep struct {
	Action    string            `json:"action"`
	Params    map[string]string `json:"params"`
	Reason    string            `json:"reason"`
	Risk      string            `json:"risk"`
	ReadOnly  bool              `json:"read_only"`
	Preview   string            `json:"preview"`
	Status    string            `json:"status,omitempty"` // pending, waiting_approval, succeeded, failed, blocked, skipped
	CommandID string            `json:"command_id,omitempty"`
	Output    string            `json:"output,omitempty"`
}

type Incident struct {
	ID          string     `json:"id"`
	ServerID    string     `json:"server_id"`
	Hostname    string     `json:"hostname"`
	Key         string     `json:"key"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title"`
	Trigger     string     `json:"trigger"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Occurrences int        `json:"occurrences"`
	Diagnosis   string     `json:"diagnosis"`
	Plan        []PlanStep `json:"plan"`
	AnalysisBy  string     `json:"analysis_by"` // "KI", "Regel" ...
	RunID       string     `json:"run_id,omitempty"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Resolution  string     `json:"resolution,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ResolvedAt  time.Time  `json:"resolved_at,omitempty"`
}

// IsOpen reports whether the incident still needs work.
func (i *Incident) IsOpen() bool {
	for _, s := range OpenIncidentStatuses {
		if i.Status == s {
			return true
		}
	}
	return false
}

func (s *Store) CreateIncident(ctx context.Context, inc *Incident) error {
	now := time.Now().UTC()
	inc.ID, inc.CreatedAt, inc.UpdatedAt = NewID(), now, now
	if inc.Plan == nil {
		inc.Plan = []PlanStep{}
	}
	if inc.Occurrences == 0 {
		inc.Occurrences = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO incidents(id,server_id,key,kind,title,trigger,severity,status,occurrences,diagnosis,plan,analysis_by,run_id,decided_by,resolution,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		inc.ID, inc.ServerID, inc.Key, inc.Kind, inc.Title, inc.Trigger, inc.Severity, inc.Status, inc.Occurrences, inc.Diagnosis, mustJSON(inc.Plan),
		inc.AnalysisBy, inc.RunID, inc.DecidedBy, inc.Resolution, unix(now), unix(now))
	return err
}

// SaveIncident writes all mutable fields.
func (s *Store) SaveIncident(ctx context.Context, inc *Incident) error {
	inc.UpdatedAt = time.Now().UTC()
	if inc.Plan == nil {
		inc.Plan = []PlanStep{}
	}
	_, err := s.db.ExecContext(ctx, `UPDATE incidents SET title=?,trigger=?,severity=?,status=?,occurrences=?,diagnosis=?,plan=?,analysis_by=?,run_id=?,decided_by=?,resolution=?,updated_at=?,resolved_at=? WHERE id=?`,
		inc.Title, inc.Trigger, inc.Severity, inc.Status, inc.Occurrences, inc.Diagnosis, mustJSON(inc.Plan), inc.AnalysisBy, inc.RunID, inc.DecidedBy, inc.Resolution,
		unix(inc.UpdatedAt), unix(inc.ResolvedAt), inc.ID)
	return err
}

const incidentCols = `i.id,i.server_id,COALESCE(s.hostname,''),i.key,i.kind,i.title,i.trigger,i.severity,i.status,i.occurrences,i.diagnosis,i.plan,i.analysis_by,i.run_id,i.decided_by,i.resolution,i.created_at,i.updated_at,i.resolved_at`

func scanIncident(sc interface{ Scan(...any) error }) (*Incident, error) {
	var inc Incident
	var plan string
	var created, updated, resolved int64
	if err := sc.Scan(&inc.ID, &inc.ServerID, &inc.Hostname, &inc.Key, &inc.Kind, &inc.Title, &inc.Trigger, &inc.Severity, &inc.Status, &inc.Occurrences,
		&inc.Diagnosis, &plan, &inc.AnalysisBy, &inc.RunID, &inc.DecidedBy, &inc.Resolution, &created, &updated, &resolved); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(plan), &inc.Plan)
	if inc.Plan == nil {
		inc.Plan = []PlanStep{}
	}
	inc.CreatedAt, inc.UpdatedAt, inc.ResolvedAt = fromUnix(created), fromUnix(updated), fromUnix(resolved)
	return &inc, nil
}

func (s *Store) GetIncident(ctx context.Context, id string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN servers s ON s.id=i.server_id WHERE i.id=?`, id)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return inc, err
}

// OpenIncidentByKey returns the open incident for a server and problem key.
func (s *Store) OpenIncidentByKey(ctx context.Context, serverID, key string) (*Incident, error) {
	q := `SELECT ` + incidentCols + ` FROM incidents i LEFT JOIN servers s ON s.id=i.server_id
	      WHERE i.server_id=? AND i.key=? AND i.status IN ('new','autopilot','analyzing','proposed','manual','executing','failed') ORDER BY i.created_at DESC LIMIT 1`
	inc, err := scanIncident(s.db.QueryRowContext(ctx, q, serverID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return inc, err
}

type IncidentFilter struct {
	ServerID string
	Open     bool
	Status   string
	Limit    int
}

func (s *Store) ListIncidents(ctx context.Context, f IncidentFilter) ([]*Incident, error) {
	q := `SELECT ` + incidentCols + ` FROM incidents i LEFT JOIN servers s ON s.id=i.server_id WHERE 1=1`
	var args []any
	if f.ServerID != "" {
		q += ` AND i.server_id=?`
		args = append(args, f.ServerID)
	}
	if f.Open {
		q += ` AND i.status IN ('new','autopilot','analyzing','proposed','manual','executing','failed')`
	}
	if f.Status != "" {
		q += ` AND i.status=?`
		args = append(args, f.Status)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q += ` ORDER BY i.updated_at DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Incident{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}
