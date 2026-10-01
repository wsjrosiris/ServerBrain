package server

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Interactive console sessions.
//
// The browser never talks to a server. Every keystroke batch travels
//   console → control plane (policy, audit) → agent long-poll → persistent
//   shell process on the server → output stream → control plane → console
// so the agent's outbound connection is the only path onto the machine.
//
// Sessions live in memory: a control plane restart ends them (the agent
// learns this on its next input and reports the session as gone). Every
// input is written to the persistent audit log.

const (
	sessionPending = "pending_approval"
	sessionOpening = "opening"
	sessionOpen    = "open"
	sessionClosed  = "closed"
	sessionFailed  = "failed"
	sessionReject  = "rejected"

	sessionIdleTimeout    = 30 * time.Minute
	sessionPendingTimeout = time.Hour
	sessionKeepClosed     = time.Hour
	sessionMaxBuffer      = 2 << 20
	maxSessionInput       = 64 << 10
)

// Chunk is one entry of a session transcript as seen by the console.
type Chunk struct {
	Index int       `json:"index"`
	Kind  string    `json:"kind"` // input, output, ready, status, error, closed
	Text  string    `json:"text,omitempty"`
	OK    bool      `json:"ok,omitempty"`
	Cwd   string    `json:"cwd,omitempty"`
	By    string    `json:"by,omitempty"`
	Time  time.Time `json:"time"`
}

type Session struct {
	ID         string    `json:"id"`
	ServerID   string    `json:"server_id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	Owner      string    `json:"owner"`
	Reason     string    `json:"reason"`
	PolicyRule string    `json:"policy_rule"`
	DecidedBy  string    `json:"decided_by,omitempty"`
	Status     string    `json:"status"`
	Busy       bool      `json:"busy"`
	Cwd        string    `json:"cwd"`
	CreatedAt  time.Time `json:"created_at"`
	LastActive time.Time `json:"last_active"`

	chunks  []Chunk
	base    int // index of chunks[0]
	size    int
	lastSeq int
	notify  chan struct{}

	// diary bookkeeping
	opened     bool
	journaled  bool
	inputs     []string
	inputCount int
}

func (s *Session) next() int { return s.base + len(s.chunks) }

type sessionHub struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ops      map[string][]protocol.SessionOp // serverID -> pending ops
}

func newSessionHub() *sessionHub {
	return &sessionHub{sessions: map[string]*Session{}, ops: map[string][]protocol.SessionOp{}}
}

// append adds a transcript chunk and wakes console long-polls. Caller holds mu.
func (h *sessionHub) append(s *Session, c Chunk) {
	c.Index, c.Time = s.next(), time.Now().UTC()
	s.chunks = append(s.chunks, c)
	s.size += len(c.Text)
	for s.size > sessionMaxBuffer && len(s.chunks) > 1 {
		s.size -= len(s.chunks[0].Text)
		s.chunks = s.chunks[1:]
		s.base++
	}
	close(s.notify)
	s.notify = make(chan struct{})
}

// enqueue queues an op for the agent. Caller holds mu; call s.wake after.
func (h *sessionHub) enqueue(serverID string, op protocol.SessionOp) {
	h.ops[serverID] = append(h.ops[serverID], op)
}

func (s *Server) sessionView(sess *Session) Session {
	v := *sess
	v.chunks, v.notify = nil, nil
	return v
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request, ownerOnly bool) *Session {
	u := userFrom(r)
	s.sessions.mu.Lock()
	sess := s.sessions.sessions[r.PathValue("sid")]
	s.sessions.mu.Unlock()
	if sess == nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return nil
	}
	if sess.Owner != u.Name && (ownerOnly || u.Role != policy.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "not your session")
		return nil
	}
	return sess
}

// POST /api/servers/{id}/sessions
func (s *Server) handleOpenSession(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Kind == policy.ActorAI {
		writeErr(w, http.StatusForbidden, "AI accounts cannot open interactive sessions; use actions so every step is policy-checked")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = readJSON(r, 16<<10, &body)
	// Opening a console is authorized exactly like running shell.run.
	ev, status, err := s.evaluate(r, actionRequest{Action: "shell.run", Params: map[string]any{"script": "(interactive session)"}})
	if err != nil {
		if status == http.StatusInternalServerError {
			s.internalErr(w, err)
			return
		}
		writeErr(w, status, err.Error())
		return
	}
	details := map[string]any{"reason": body.Reason, "rule": ev.decision.Rule, "effect": ev.decision.Effect}
	if ev.decision.Effect == policy.Block {
		_ = s.store.Audit(r.Context(), u.Name, u.Kind, "session.blocked", ev.srv.ID, details)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "blocked by policy", "decision": ev.decision})
		return
	}
	now := time.Now().UTC()
	sess := &Session{
		ID: store.NewID(), ServerID: ev.srv.ID, Hostname: ev.srv.Hostname, OS: ev.srv.OS, Owner: u.Name,
		Reason: body.Reason, PolicyRule: ev.decision.Rule, Status: sessionOpening, CreatedAt: now, LastActive: now,
		notify: make(chan struct{}),
	}
	h := s.sessions
	h.mu.Lock()
	h.sessions[sess.ID] = sess
	if ev.decision.Effect == policy.Approve {
		sess.Status = sessionPending
		h.append(sess, Chunk{Kind: "status", Text: "Waiting for approval by an admin"})
	} else {
		sess.Busy = true
		h.append(sess, Chunk{Kind: "status", Text: "Connecting to the agent on " + sess.Hostname + " ..."})
		h.enqueue(sess.ServerID, protocol.SessionOp{SessionID: sess.ID, Type: protocol.SessionOpen})
	}
	view := s.sessionView(sess)
	h.mu.Unlock()
	details["session"] = sess.ID
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "session.requested", sess.ServerID, details)
	s.wake(sess.ServerID)
	writeJSON(w, http.StatusCreated, map[string]any{"session": view, "decision": ev.decision})
}

// GET /api/sessions?server=&status=
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	q := r.URL.Query()
	s.sessions.mu.Lock()
	out := []Session{}
	for _, sess := range s.sessions.sessions {
		if sess.Owner != u.Name && u.Role != policy.RoleAdmin {
			continue
		}
		if (q.Get("server") != "" && sess.ServerID != q.Get("server")) || (q.Get("status") != "" && sess.Status != q.Get("status")) {
			continue
		}
		out = append(out, s.sessionView(sess))
	}
	s.sessions.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// GET /api/sessions/{sid}/output?after=N  (long-poll)
func (s *Server) handleSessionOutput(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r, false)
	if sess == nil {
		return
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	deadline := time.NewTimer(s.cfg.LongPollTimeout)
	defer deadline.Stop()
	for {
		s.sessions.mu.Lock()
		after = min(after, sess.next()) // a client ahead of us restarts from the end
		start := max(after, sess.base)
		chunks := append([]Chunk(nil), sess.chunks[start-sess.base:]...)
		truncated := after < sess.base
		view := s.sessionView(sess)
		notify := sess.notify
		s.sessions.mu.Unlock()
		done := view.Status == sessionClosed || view.Status == sessionFailed || view.Status == sessionReject
		if len(chunks) > 0 || done {
			writeJSON(w, http.StatusOK, map[string]any{"session": view, "chunks": chunks, "next": start + len(chunks), "truncated": truncated})
			return
		}
		select {
		case <-notify:
		case <-deadline.C:
			writeJSON(w, http.StatusOK, map[string]any{"session": view, "chunks": []Chunk{}, "next": after})
			return
		case <-r.Context().Done():
			return
		}
	}
}

// POST /api/sessions/{sid}/input {code}
func (s *Server) handleSessionInput(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	sess := s.getSession(w, r, true)
	if sess == nil {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, maxSessionInput+1024, &body); err != nil || len(body.Code) > maxSessionInput {
		writeErr(w, http.StatusBadRequest, "invalid input")
		return
	}
	h := s.sessions
	h.mu.Lock()
	if sess.Status != sessionOpen {
		st := sess.Status
		h.mu.Unlock()
		writeErr(w, http.StatusConflict, "session is "+st)
		return
	}
	sess.Busy, sess.LastActive = true, time.Now().UTC()
	sess.inputCount++
	if len(sess.inputs) < 100 {
		in := strings.TrimSpace(body.Code)
		if len(in) > 300 {
			in = in[:300] + "…"
		}
		if in != "" {
			sess.inputs = append(sess.inputs, in)
		}
	}
	h.append(sess, Chunk{Kind: "input", Text: body.Code, Cwd: sess.Cwd, By: u.Name})
	h.enqueue(sess.ServerID, protocol.SessionOp{SessionID: sess.ID, Type: protocol.SessionInput, Code: body.Code})
	h.mu.Unlock()
	code := body.Code
	if len(code) > 8192 {
		code = code[:8192] + "...(truncated)"
	}
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "session.input", sess.ServerID, map[string]any{"session": sess.ID, "code": code, "cwd": sess.Cwd})
	s.wake(sess.ServerID)
	w.WriteHeader(http.StatusAccepted)
}

// POST /api/sessions/{sid}/reset
func (s *Server) handleSessionReset(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	sess := s.getSession(w, r, true)
	if sess == nil {
		return
	}
	h := s.sessions
	h.mu.Lock()
	if sess.Status != sessionOpen {
		h.mu.Unlock()
		writeErr(w, http.StatusConflict, "session is not open")
		return
	}
	sess.Busy = true
	h.append(sess, Chunk{Kind: "status", Text: "Restarting shell ..."})
	h.enqueue(sess.ServerID, protocol.SessionOp{SessionID: sess.ID, Type: protocol.SessionReset})
	h.mu.Unlock()
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "session.reset", sess.ServerID, map[string]any{"session": sess.ID})
	s.wake(sess.ServerID)
	w.WriteHeader(http.StatusAccepted)
}

// DELETE /api/sessions/{sid}
func (s *Server) handleSessionClose(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	sess := s.getSession(w, r, false)
	if sess == nil {
		return
	}
	s.closeSession(r.Context(), sess, u.Name, u.Kind, "Session closed by "+u.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) closeSession(ctx context.Context, sess *Session, actor, actorType, msg string) {
	h := s.sessions
	h.mu.Lock()
	if sess.Status == sessionClosed || sess.Status == sessionFailed || sess.Status == sessionReject {
		h.mu.Unlock()
		return
	}
	notifyAgent := sess.Status == sessionOpen || sess.Status == sessionOpening
	sess.Status, sess.Busy, sess.LastActive = sessionClosed, false, time.Now().UTC()
	h.append(sess, Chunk{Kind: "closed", Text: msg})
	if notifyAgent {
		h.enqueue(sess.ServerID, protocol.SessionOp{SessionID: sess.ID, Type: protocol.SessionClose})
	}
	h.mu.Unlock()
	_ = s.store.Audit(ctx, actor, actorType, "session.closed", sess.ServerID, map[string]any{"session": sess.ID, "message": msg})
	s.journalSession(ctx, sess)
	if notifyAgent {
		s.wake(sess.ServerID)
	}
}

// POST /api/sessions/{sid}/approve|reject
func (s *Server) handleSessionDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u.Kind == policy.ActorAI {
			writeErr(w, http.StatusForbidden, "AI accounts cannot approve")
			return
		}
		sess := s.getSession(w, r, false)
		if sess == nil {
			return
		}
		if approve && !s.policy.AllowSelfApproval && sess.Owner == u.Name {
			writeErr(w, http.StatusForbidden, "four-eyes principle: you cannot approve your own request")
			return
		}
		h := s.sessions
		h.mu.Lock()
		if sess.Status != sessionPending {
			h.mu.Unlock()
			writeErr(w, http.StatusConflict, "session is not pending approval")
			return
		}
		sess.DecidedBy, sess.LastActive = u.Name, time.Now().UTC()
		event := "session.rejected"
		if approve {
			event = "session.approved"
			sess.Status, sess.Busy = sessionOpening, true
			h.append(sess, Chunk{Kind: "status", Text: "Approved by " + u.Name + ". Connecting to the agent on " + sess.Hostname + " ..."})
			h.enqueue(sess.ServerID, protocol.SessionOp{SessionID: sess.ID, Type: protocol.SessionOpen})
		} else {
			sess.Status = sessionReject
			h.append(sess, Chunk{Kind: "closed", Text: "Rejected by " + u.Name})
		}
		status := sess.Status
		h.mu.Unlock()
		_ = s.store.Audit(r.Context(), u.Name, u.Kind, event, sess.ServerID, map[string]any{"session": sess.ID, "owner": sess.Owner})
		if approve {
			s.wake(sess.ServerID)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

// ---------- agent side ----------

// GET /api/agent/sessions  (long-poll)
func (s *Server) handleAgentSessionPoll(w http.ResponseWriter, r *http.Request) {
	srv := serverFrom(r)
	deadline := time.NewTimer(s.cfg.LongPollTimeout)
	defer deadline.Stop()
	for {
		ch := s.waitChan(srv.ID)
		h := s.sessions
		h.mu.Lock()
		ops := h.ops[srv.ID]
		delete(h.ops, srv.ID)
		h.mu.Unlock()
		if len(ops) > 0 {
			writeJSON(w, http.StatusOK, ops)
			return
		}
		select {
		case <-ch:
		case <-deadline.C:
			writeJSON(w, http.StatusOK, []protocol.SessionOp{})
			return
		case <-r.Context().Done():
			return
		}
	}
}

// POST /api/agent/sessions/{sid}/output
func (s *Server) handleAgentSessionOutput(w http.ResponseWriter, r *http.Request) {
	srv := serverFrom(r)
	var batch []protocol.SessionOutput
	if err := readJSON(r, 4<<20, &batch); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid output")
		return
	}
	h := s.sessions
	h.mu.Lock()
	sess := h.sessions[r.PathValue("sid")]
	if sess == nil || sess.ServerID != srv.ID {
		h.mu.Unlock()
		writeErr(w, http.StatusNotFound, "unknown session")
		return
	}
	var audit []map[string]any
	for _, o := range batch {
		if o.Seq <= sess.lastSeq {
			continue // retransmission
		}
		sess.lastSeq = o.Seq
		if sess.Status == sessionClosed || sess.Status == sessionFailed || sess.Status == sessionReject {
			continue
		}
		sess.LastActive = time.Now().UTC()
		switch o.Kind {
		case protocol.OutputText:
			h.append(sess, Chunk{Kind: "output", Text: o.Text})
		case protocol.OutputReady:
			if sess.Status == sessionOpening {
				sess.Status, sess.opened = sessionOpen, true
				audit = append(audit, map[string]any{"event": "session.opened"})
			}
			sess.Busy, sess.Cwd = false, o.Cwd
			h.append(sess, Chunk{Kind: "ready", OK: o.OK, Cwd: o.Cwd})
		case protocol.OutputError:
			sess.Status, sess.Busy = sessionFailed, false
			h.append(sess, Chunk{Kind: "error", Text: o.Text})
			audit = append(audit, map[string]any{"event": "session.failed", "error": o.Text})
		case protocol.OutputClosed:
			sess.Status, sess.Busy = sessionClosed, false
			msg := o.Text
			if msg == "" {
				msg = "Shell exited on " + sess.Hostname
			}
			h.append(sess, Chunk{Kind: "closed", Text: msg})
			audit = append(audit, map[string]any{"event": "session.closed", "message": msg})
		}
	}
	sid := sess.ID
	ended := sess.Status == sessionClosed || sess.Status == sessionFailed
	h.mu.Unlock()
	if ended {
		s.journalSession(r.Context(), sess)
	}
	for _, a := range audit {
		ev := a["event"].(string)
		delete(a, "event")
		a["session"] = sid
		_ = s.store.Audit(r.Context(), srv.Hostname, "agent", ev, srv.ID, a)
	}
	w.WriteHeader(http.StatusNoContent)
}

// maintainSessions closes idle sessions and forgets old ones.
func (s *Server) maintainSessions(ctx context.Context) {
	h := s.sessions
	var idle, stale []*Session
	h.mu.Lock()
	for id, sess := range h.sessions {
		age := time.Since(sess.LastActive)
		switch sess.Status {
		case sessionOpen, sessionOpening:
			if age > sessionIdleTimeout {
				idle = append(idle, sess)
			}
		case sessionPending:
			if age > sessionPendingTimeout {
				stale = append(stale, sess)
			}
		default:
			if age > sessionKeepClosed {
				delete(h.sessions, id)
			}
		}
	}
	h.mu.Unlock()
	for _, sess := range idle {
		s.closeSession(ctx, sess, "system", "system", "Closed after 30 minutes of inactivity")
	}
	for _, sess := range stale {
		s.closeSession(ctx, sess, "system", "system", "Approval request expired")
	}
}
