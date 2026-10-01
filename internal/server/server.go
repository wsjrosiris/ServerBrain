// Package server implements the ServerBrain control plane: the agent API
// (enrollment, heartbeats, command long-polling), the operator API with
// RBAC, policy-checked actions with approvals, and the audit log.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/server/web"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

type Config struct {
	HeartbeatInterval time.Duration
	// LongPollTimeout bounds how long an agent's command poll is held open.
	LongPollTimeout time.Duration
	// RequireClientCert enforces mTLS on agent endpoints (the TLS listener
	// must be configured to request client certificates).
	RequireClientCert bool
	// TrustProxy uses X-Forwarded-For for the recorded agent address.
	TrustProxy       bool
	PendingTTL       time.Duration
	DispatchTTL      time.Duration
	MetricsRetention time.Duration
	EventsRetention  time.Duration
}

func (c *Config) defaults() {
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 30 * time.Second
	}
	if c.LongPollTimeout == 0 {
		c.LongPollTimeout = 25 * time.Second
	}
	if c.PendingTTL == 0 {
		c.PendingTTL = 24 * time.Hour
	}
	if c.DispatchTTL == 0 {
		c.DispatchTTL = 45 * time.Minute
	}
	if c.MetricsRetention == 0 {
		c.MetricsRetention = 7 * 24 * time.Hour
	}
	if c.EventsRetention == 0 {
		c.EventsRetention = 30 * 24 * time.Hour
	}
}

type Server struct {
	cfg    Config
	store  *store.Store
	policy *policy.Policy
	log    *slog.Logger

	mu      sync.Mutex
	waiters map[string]chan struct{} // serverID -> wake-up signal for long polls
}

func New(cfg Config, st *store.Store, pol *policy.Policy, log *slog.Logger) *Server {
	cfg.defaults()
	return &Server{cfg: cfg, store: st, policy: pol, log: log, waiters: map[string]chan struct{}{}}
}

// Handler returns the HTTP handler for the whole control plane.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agent API (agent-initiated, outbound from the managed server).
	mux.HandleFunc("POST /api/agent/enroll", s.agentOnly(s.handleEnroll))
	mux.HandleFunc("POST /api/agent/heartbeat", s.agentOnly(s.agentAuth(s.handleHeartbeat)))
	mux.HandleFunc("GET /api/agent/commands", s.agentOnly(s.agentAuth(s.handlePoll)))
	mux.HandleFunc("POST /api/agent/commands/{id}/result", s.agentOnly(s.agentAuth(s.handleResult)))

	// Operator API.
	mux.HandleFunc("GET /api/me", s.userAuth(policy.RoleViewer, s.handleMe))
	mux.HandleFunc("GET /api/servers", s.userAuth(policy.RoleViewer, s.handleListServers))
	mux.HandleFunc("GET /api/servers/{id}", s.userAuth(policy.RoleViewer, s.handleGetServer))
	mux.HandleFunc("PUT /api/servers/{id}/tags", s.userAuth(policy.RoleAdmin, s.handleSetTags))
	mux.HandleFunc("DELETE /api/servers/{id}", s.userAuth(policy.RoleAdmin, s.handleDeleteServer))
	mux.HandleFunc("GET /api/servers/{id}/metrics", s.userAuth(policy.RoleViewer, s.handleMetrics))
	mux.HandleFunc("GET /api/servers/{id}/events", s.userAuth(policy.RoleViewer, s.handleServerEvents))
	mux.HandleFunc("POST /api/servers/{id}/actions", s.userAuth(policy.RoleViewer, s.handleRequestAction))
	mux.HandleFunc("POST /api/servers/{id}/actions/preview", s.userAuth(policy.RoleViewer, s.handlePreviewAction))
	mux.HandleFunc("GET /api/events", s.userAuth(policy.RoleViewer, s.handleEvents))
	mux.HandleFunc("GET /api/alerts", s.userAuth(policy.RoleViewer, s.handleAlerts))
	mux.HandleFunc("GET /api/actions", s.userAuth(policy.RoleViewer, s.handleCatalog))
	mux.HandleFunc("GET /api/ai/tools", s.userAuth(policy.RoleViewer, s.handleAITools))
	mux.HandleFunc("GET /api/commands", s.userAuth(policy.RoleViewer, s.handleListCommands))
	mux.HandleFunc("GET /api/commands/{id}", s.userAuth(policy.RoleViewer, s.handleGetCommand))
	mux.HandleFunc("POST /api/commands/{id}/approve", s.userAuth(policy.RoleAdmin, s.handleDecide(true)))
	mux.HandleFunc("POST /api/commands/{id}/reject", s.userAuth(policy.RoleAdmin, s.handleDecide(false)))
	mux.HandleFunc("POST /api/commands/{id}/cancel", s.userAuth(policy.RoleOperator, s.handleCancel))
	mux.HandleFunc("GET /api/audit", s.userAuth(policy.RoleAdmin, s.handleAudit))
	mux.HandleFunc("GET /api/policy", s.userAuth(policy.RoleViewer, s.handlePolicy))
	mux.HandleFunc("POST /api/enrollment-tokens", s.userAuth(policy.RoleAdmin, s.handleCreateEnrollmentToken))
	mux.HandleFunc("GET /api/users", s.userAuth(policy.RoleAdmin, s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.userAuth(policy.RoleAdmin, s.handleCreateUser))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	static, _ := fs.Sub(web.Static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(static)))

	return securityHeaders(mux)
}

// Run executes background maintenance until ctx is done.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := s.store.ExpireStale(ctx, s.cfg.PendingTTL, s.cfg.DispatchTTL); err != nil {
			s.log.Error("expire commands", "err", err)
		} else if n > 0 {
			s.log.Info("expired stale commands", "count", n)
			_ = s.store.Audit(ctx, "system", "system", "command.expired", "", map[string]any{"count": n})
		}
		if i%60 == 0 {
			if err := s.store.Prune(ctx, s.cfg.MetricsRetention, s.cfg.EventsRetention); err != nil {
				s.log.Error("prune telemetry", "err", err)
			}
		}
	}
}

// ---------- plumbing ----------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	return dec.Decode(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) remoteAddr(r *http.Request) string {
	if s.cfg.TrustProxy {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			return strings.TrimSpace(strings.Split(f, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) internalErr(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) agentOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.RequireClientCert && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
			writeErr(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		next(w, r)
	}
}

type ctxKey int

const (
	ctxServer ctxKey = iota
	ctxUser
)

func (s *Server) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing agent credentials")
			return
		}
		srv, err := s.store.ServerBySecret(r.Context(), tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unknown agent")
			return
		}
		if id := r.Header.Get("X-Agent-ID"); id != "" && subtle.ConstantTimeCompare([]byte(id), []byte(srv.ID)) != 1 {
			writeErr(w, http.StatusUnauthorized, "agent id mismatch")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxServer, srv)))
	}
}

var roleRank = map[string]int{policy.RoleViewer: 1, policy.RoleOperator: 2, policy.RoleAdmin: 3}

func (s *Server) userAuth(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing token")
			return
		}
		u, err := s.store.UserByToken(r.Context(), tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if roleRank[u.Role] < roleRank[minRole] {
			writeErr(w, http.StatusForbidden, "requires role "+minRole)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxUser, u)))
	}
}

func userFrom(r *http.Request) *store.User     { return r.Context().Value(ctxUser).(*store.User) }
func serverFrom(r *http.Request) *store.Server { return r.Context().Value(ctxServer).(*store.Server) }

func (s *Server) wake(serverID string) {
	s.mu.Lock()
	if ch, ok := s.waiters[serverID]; ok {
		close(ch)
		delete(s.waiters, serverID)
	}
	s.mu.Unlock()
}

func (s *Server) waitChan(serverID string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.waiters[serverID]
	if !ok {
		ch = make(chan struct{})
		s.waiters[serverID] = ch
	}
	return ch
}

// ---------- agent handlers ----------

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if err := readJSON(r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.System.Hostname == "" || req.EnrollmentToken == "" {
		writeErr(w, http.StatusBadRequest, "hostname and enrollment_token are required")
		return
	}
	id, secret, err := s.store.Enroll(r.Context(), req.EnrollmentToken, req.System, req.AgentVersion, s.remoteAddr(r))
	if errors.Is(err, store.ErrNotFound) {
		_ = s.store.Audit(r.Context(), req.System.Hostname, "agent", "agent.enroll_denied", s.remoteAddr(r), nil)
		writeErr(w, http.StatusUnauthorized, "invalid or expired enrollment token")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	_ = s.store.Audit(r.Context(), req.System.Hostname, "agent", "agent.enrolled", id,
		map[string]any{"remote_addr": s.remoteAddr(r), "os": req.System.OS, "os_version": req.System.OSVersion})
	s.log.Info("agent enrolled", "server", id, "hostname", req.System.Hostname)
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{AgentID: id, AgentSecret: secret})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	srv := serverFrom(r)
	var hb protocol.Heartbeat
	if err := readJSON(r, 8<<20, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid heartbeat")
		return
	}
	if hb.System.Hostname == "" {
		hb.System.Hostname = srv.Hostname
	}
	if err := s.store.RecordHeartbeat(r.Context(), srv.ID, s.remoteAddr(r), &hb); err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{IntervalSeconds: int(s.cfg.HeartbeatInterval / time.Second)})
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	srv := serverFrom(r)
	deadline := time.NewTimer(s.cfg.LongPollTimeout)
	defer deadline.Stop()
	for {
		// Register for wake-ups before checking, so no command is missed.
		ch := s.waitChan(srv.ID)
		cmds, err := s.store.ClaimQueued(r.Context(), srv.ID)
		if err != nil {
			s.internalErr(w, err)
			return
		}
		if len(cmds) > 0 {
			for _, c := range cmds {
				_ = s.store.Audit(r.Context(), srv.Hostname, "agent", "command.dispatched", c.ID, map[string]any{"action": c.Action})
			}
			writeJSON(w, http.StatusOK, cmds)
			return
		}
		select {
		case <-ch:
		case <-deadline.C:
			writeJSON(w, http.StatusOK, []protocol.Command{})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	srv := serverFrom(r)
	var res protocol.CommandResult
	if err := readJSON(r, 2<<20, &res); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid result")
		return
	}
	cmd, err := s.store.CompleteCommand(r.Context(), srv.ID, r.PathValue("id"), &res)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such dispatched command")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	_ = s.store.Audit(r.Context(), srv.Hostname, "agent", "command."+cmd.Status, cmd.ID,
		map[string]any{"action": cmd.Action, "exit_code": res.ExitCode, "error": res.Error})
	writeJSON(w, http.StatusOK, map[string]string{"status": cmd.Status})
}

// ---------- operator handlers ----------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r))
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListServers(r.Context(), false)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	type item struct {
		*store.Server
		Online bool `json:"online"`
	}
	out := make([]item, 0, len(list))
	for _, srv := range list {
		out = append(out, item{srv, s.online(srv)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) online(srv *store.Server) bool {
	return time.Since(srv.LastSeen) < 3*s.cfg.HeartbeatInterval
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	srv, err := s.store.GetServer(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		*store.Server
		Online bool `json:"online"`
	}{srv, s.online(srv)})
}

func (s *Server) handleSetTags(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := readJSON(r, 16<<10, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	id := r.PathValue("id")
	if err := s.store.SetServerTags(r.Context(), id, body.Tags); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	} else if err != nil {
		s.internalErr(w, err)
		return
	}
	u := userFrom(r)
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "server.tags_changed", id, map[string]any{"tags": body.Tags})
	writeJSON(w, http.StatusOK, map[string]any{"tags": body.Tags})
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteServer(r.Context(), id); err != nil {
		s.internalErr(w, err)
		return
	}
	u := userFrom(r)
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "server.deleted", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func sinceParam(r *http.Request, def time.Duration) time.Time {
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h > 0 && h <= 24*90 {
		return time.Now().Add(-time.Duration(h) * time.Hour)
	}
	return time.Now().Add(-def)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	pts, err := s.store.Metrics(r.Context(), r.PathValue("id"), sinceParam(r, 6*time.Hour))
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pts)
}

func (s *Server) handleServerEvents(w http.ResponseWriter, r *http.Request) {
	evs, err := s.store.Events(r.Context(), r.PathValue("id"), sinceParam(r, 24*time.Hour), 500)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	evs, err := s.store.Events(r.Context(), "", sinceParam(r, 24*time.Hour), 500)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, actions.All())
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.policy)
}

type actionRequest struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
	Reason string         `json:"reason"`
}

type evaluated struct {
	srv      *store.Server
	def      *actions.Def
	params   map[string]string
	preview  string
	decision policy.Decision
}

// evaluate validates an action request against the catalog, the target's
// advertised capabilities and the policy.
func (s *Server) evaluate(r *http.Request, req actionRequest) (*evaluated, int, error) {
	srv, err := s.store.GetServer(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusNotFound, errors.New("server not found")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	def, ok := actions.Get(req.Action)
	if !ok {
		return nil, http.StatusBadRequest, fmt.Errorf("unknown action %q", req.Action)
	}
	hasCap := false
	for _, c := range srv.Capabilities {
		hasCap = hasCap || c == def.Name
	}
	if !hasCap {
		return nil, http.StatusConflict, fmt.Errorf("server %s does not offer capability %q", srv.Hostname, def.Name)
	}
	params, err := def.Validate(req.Params)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	u := userFrom(r)
	dec := s.policy.Evaluate(policy.Request{Action: def, Hostname: srv.Hostname, Tags: srv.Tags, ActorType: u.Kind, Role: u.Role})
	if u.Role == policy.RoleViewer && !def.ReadOnly {
		dec = policy.Decision{Effect: policy.Block, Rule: "rbac", Reason: "viewers may only run read-only actions"}
	}
	return &evaluated{srv: srv, def: def, params: params, preview: def.Preview(srv.OS, params), decision: dec}, 0, nil
}

func (s *Server) handlePreviewAction(w http.ResponseWriter, r *http.Request) {
	var req actionRequest
	if err := readJSON(r, 128<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ev, status, err := s.evaluate(r, req)
	if err != nil {
		if status == http.StatusInternalServerError {
			s.internalErr(w, err)
			return
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": ev.def, "params": ev.params, "preview": ev.preview, "decision": ev.decision,
	})
}

func (s *Server) handleRequestAction(w http.ResponseWriter, r *http.Request) {
	var req actionRequest
	if err := readJSON(r, 128<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	u := userFrom(r)
	ev, status, err := s.evaluate(r, req)
	if err != nil {
		if status == http.StatusInternalServerError {
			s.internalErr(w, err)
			return
		}
		writeErr(w, status, err.Error())
		return
	}
	details := map[string]any{"action": ev.def.Name, "params": ev.params, "reason": req.Reason, "rule": ev.decision.Rule, "effect": ev.decision.Effect}
	if ev.decision.Effect == policy.Block {
		_ = s.store.Audit(r.Context(), u.Name, u.Kind, "action.blocked", ev.srv.ID, details)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "blocked by policy", "decision": ev.decision})
		return
	}
	cmd := &store.Command{
		ServerID: ev.srv.ID, Action: ev.def.Name, Params: ev.params, Preview: ev.preview, Risk: string(ev.def.Risk),
		RequestedBy: u.Name, ActorType: u.Kind, Reason: req.Reason, PolicyRule: ev.decision.Rule,
		Status: store.StatusQueued,
	}
	if ev.decision.Effect == policy.Approve {
		cmd.Status = store.StatusPendingApproval
	}
	if err := s.store.CreateCommand(r.Context(), cmd); err != nil {
		s.internalErr(w, err)
		return
	}
	details["command"] = cmd.ID
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "action.requested", ev.srv.ID, details)
	if cmd.Status == store.StatusQueued {
		s.wake(ev.srv.ID)
	}
	cmd.Hostname = ev.srv.Hostname
	writeJSON(w, http.StatusAccepted, map[string]any{"command": cmd, "decision": ev.decision})
}

func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := s.store.ListCommands(r.Context(), store.CommandFilter{ServerID: q.Get("server"), Status: q.Get("status"), Limit: limit})
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetCommand(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCommand(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "command not found")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u.Kind == policy.ActorAI {
			writeErr(w, http.StatusForbidden, "AI accounts cannot approve actions")
			return
		}
		c, err := s.store.GetCommand(r.Context(), r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "command not found")
			return
		}
		if err != nil {
			s.internalErr(w, err)
			return
		}
		if approve && !s.policy.AllowSelfApproval && c.RequestedBy == u.Name {
			writeErr(w, http.StatusForbidden, "four-eyes principle: you cannot approve your own request")
			return
		}
		to, event := store.StatusRejected, "action.rejected"
		if approve {
			to, event = store.StatusQueued, "action.approved"
		}
		if err := s.store.TransitionCommand(r.Context(), c.ID, store.StatusPendingApproval, to, u.Name); errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusConflict, "command is not pending approval")
			return
		} else if err != nil {
			s.internalErr(w, err)
			return
		}
		_ = s.store.Audit(r.Context(), u.Name, u.Kind, event, c.ServerID, map[string]any{"command": c.ID, "action": c.Action, "requested_by": c.RequestedBy})
		if approve {
			s.wake(c.ServerID)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": to})
	}
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	c, err := s.store.GetCommand(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "command not found")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	if c.RequestedBy != u.Name && u.Role != policy.RoleAdmin {
		writeErr(w, http.StatusForbidden, "only the requester or an admin can cancel")
		return
	}
	err = s.store.TransitionCommand(r.Context(), c.ID, store.StatusPendingApproval, store.StatusCancelled, u.Name)
	if errors.Is(err, store.ErrNotFound) {
		err = s.store.TransitionCommand(r.Context(), c.ID, store.StatusQueued, store.StatusCancelled, u.Name)
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, "command can no longer be cancelled")
		return
	} else if err != nil {
		s.internalErr(w, err)
		return
	}
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "action.cancelled", c.ServerID, map[string]any{"command": c.ID, "action": c.Action})
	writeJSON(w, http.StatusOK, map[string]string{"status": store.StatusCancelled})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tags     []string `json:"tags"`
		Uses     int      `json:"uses"`
		TTLHours int      `json:"ttl_hours"`
	}
	if err := readJSON(r, 16<<10, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.Uses <= 0 {
		body.Uses = 1
	}
	if body.TTLHours <= 0 {
		body.TTLHours = 24
	}
	u := userFrom(r)
	tok, exp, err := s.store.CreateEnrollmentToken(r.Context(), u.Name, body.Tags, body.Uses, time.Duration(body.TTLHours)*time.Hour)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "enrollment_token.created", "", map[string]any{"uses": body.Uses, "tags": body.Tags, "expires_at": exp})
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": exp, "uses": body.Uses})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
		Kind string `json:"kind"`
	}
	if err := readJSON(r, 16<<10, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.Kind == "" {
		body.Kind = policy.ActorHuman
	}
	if _, ok := roleRank[body.Role]; !ok || body.Name == "" || (body.Kind != policy.ActorHuman && body.Kind != policy.ActorAI) {
		writeErr(w, http.StatusBadRequest, "name, role (viewer|operator|admin) and kind (human|ai) are required")
		return
	}
	if body.Kind == policy.ActorAI && body.Role == policy.RoleAdmin {
		writeErr(w, http.StatusBadRequest, "AI accounts cannot be admins")
		return
	}
	nu, tok, err := s.store.CreateUser(r.Context(), body.Name, body.Role, body.Kind)
	if err != nil {
		writeErr(w, http.StatusConflict, "could not create user (name taken?)")
		return
	}
	u := userFrom(r)
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "user.created", nu.ID, map[string]any{"name": nu.Name, "role": nu.Role, "kind": nu.Kind})
	writeJSON(w, http.StatusCreated, map[string]any{"user": nu, "token": tok})
}
