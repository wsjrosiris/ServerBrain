package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/knowledge"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// ---------- diary entries for actions and sessions ----------

func paramSummary(p map[string]string) string {
	var keys []string
	for k := range p {
		if k != "script" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + p[k]
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func actorSuffix(t string) string {
	if t == policy.ActorAI {
		return " (KI)"
	}
	return ""
}

func reasonSuffix(r string) string {
	if strings.TrimSpace(r) == "" {
		return ""
	}
	return " · Grund: " + r
}

func fence(s string, maxLines int) string {
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
	if len(lines) > maxLines {
		lines = append(lines[:maxLines], fmt.Sprintf("… (%d weitere Zeilen)", len(lines)-maxLines))
	}
	for i, l := range lines {
		if len(l) > 300 {
			lines[i] = l[:300] + "…"
		}
	}
	return "```\n" + strings.ReplaceAll(strings.Join(lines, "\n"), "```", "'''") + "\n```"
}

func (s *Server) journalCommand(ctx context.Context, c *store.Command) {
	title := "Aktion ausgeführt: " + c.Action + paramSummary(c.Params)
	sev := store.SevOK
	if c.Status != store.StatusSucceeded {
		title = "Aktion fehlgeschlagen: " + c.Action + paramSummary(c.Params)
		sev = store.SevCrit
	}
	detail := "Angefordert von " + c.RequestedBy + actorSuffix(c.ActorType) + reasonSuffix(c.Reason)
	if c.DecidedBy != "" {
		detail += " · freigegeben von " + c.DecidedBy
	}
	if script := c.Params["script"]; script != "" {
		detail += "\nSkript:\n" + fence(script, 15)
	}
	if r := c.Result; r != nil {
		if r.Error != "" {
			detail += "\nFehler: " + r.Error
		}
		if strings.TrimSpace(r.Output) != "" {
			detail += "\nAusgabe:\n" + fence(r.Output, 20)
		}
	}
	_ = s.learner.Note(ctx, c.ServerID, store.CatAction, sev, title, detail, c.RequestedBy)
}

// journalSession writes one diary entry per console session once it ends:
// who worked on the server, why, and which commands were typed.
func (s *Server) journalSession(ctx context.Context, sess *Session) {
	h := s.sessions
	h.mu.Lock()
	if sess.journaled || !sess.opened {
		h.mu.Unlock()
		return
	}
	sess.journaled = true
	inputs := append([]string(nil), sess.inputs...)
	dropped := sess.inputCount - len(inputs)
	h.mu.Unlock()

	dur := time.Since(sess.CreatedAt).Round(time.Minute)
	title := fmt.Sprintf("Konsolensitzung: %d Befehl(e)", sess.inputCount)
	detail := fmt.Sprintf("Sitzung von %s, Dauer %s%s", sess.Owner, strings.TrimSuffix(dur.String(), "0s"), reasonSuffix(sess.Reason))
	if sess.DecidedBy != "" {
		detail += " · freigegeben von " + sess.DecidedBy
	}
	if len(inputs) > 0 {
		detail += "\n" + fence(strings.Join(inputs, "\n"), 40)
		if dropped > 0 {
			detail += fmt.Sprintf("\n… %d weitere Befehle im Audit-Log", dropped)
		}
	}
	_ = s.learner.Note(ctx, sess.ServerID, store.CatConsole, store.SevInfo, title, detail, sess.Owner)
}

// ---------- API ----------

// GET /api/journal?server=&days=7&limit=
func (s *Server) handleJournal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > 3650 {
		days = 7
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := s.store.ListJournal(r.Context(), store.JournalFilter{ServerID: q.Get("server"), Since: time.Now().AddDate(0, 0, -days), Limit: limit})
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// POST /api/journal and /api/servers/{id}/journal {title, detail}
func (s *Server) handleAddJournal(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var body struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := readJSON(r, 64<<10, &body); err != nil || strings.TrimSpace(body.Title) == "" || len(body.Title) > 300 {
		writeErr(w, http.StatusBadRequest, "title (max 300 characters) is required")
		return
	}
	id := r.PathValue("id")
	if id != "" {
		if _, err := s.store.GetServer(r.Context(), id); errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "server not found")
			return
		}
	}
	if err := s.learner.Note(r.Context(), id, store.CatNote, store.SevInfo, strings.TrimSpace(body.Title), body.Detail, u.Name); err != nil {
		s.internalErr(w, err)
		return
	}
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "journal.note", id, map[string]any{"title": body.Title})
	w.WriteHeader(http.StatusCreated)
}

type roleInfo struct {
	Name  string    `json:"name"`
	Via   string    `json:"via"`
	Since time.Time `json:"since"`
}

type serverKnowledge struct {
	Roles         []roleInfo             `json:"roles"`
	Dependencies  []store.Dependency     `json:"dependencies"`
	Baseline      store.Baseline         `json:"baseline"`
	ErrorPatterns []store.ErrorSignature `json:"error_patterns"`
	ManualNotes   string                 `json:"manual_notes"`
	VaultEnabled  bool                   `json:"vault_enabled"`
	NotePath      string                 `json:"note_path,omitempty"`
}

func (s *Server) knowledgeFor(r *http.Request, id string) (*serverKnowledge, error) {
	ctx := r.Context()
	k := &serverKnowledge{VaultEnabled: s.vault != nil, Roles: []roleInfo{}}
	facts, err := s.store.Facts(ctx, id, "role:")
	if err != nil {
		return nil, err
	}
	for _, f := range facts {
		name, via, _ := strings.Cut(f.Value, "|")
		k.Roles = append(k.Roles, roleInfo{Name: name, Via: via, Since: f.FirstSeen})
	}
	if k.Dependencies, err = s.store.Dependencies(ctx, id); err != nil {
		return nil, err
	}
	if k.Baseline, err = s.store.Baseline(ctx, id, time.Now().AddDate(0, 0, -7)); err != nil {
		return nil, err
	}
	if k.ErrorPatterns, err = s.store.ErrorSignatures(ctx, id, time.Now().AddDate(0, 0, -30), 10); err != nil {
		return nil, err
	}
	if s.vault != nil {
		k.ManualNotes, k.NotePath = s.vault.ManualNotes(id)
	}
	return k, nil
}

// GET /api/servers/{id}/knowledge
func (s *Server) handleServerKnowledge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetServer(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}
	k, err := s.knowledgeFor(r, id)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// GET /api/dependencies
func (s *Server) handleDependencies(w http.ResponseWriter, r *http.Request) {
	deps, err := s.store.Dependencies(r.Context(), "")
	if err != nil {
		s.internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, deps)
}

// GET /api/knowledge/context?server=ID&days=14
//
// Returns a compact Markdown briefing for an LLM: what ServerBrain has
// learned about a server (roles, dependencies, baseline, known errors), the
// notes people wrote in Obsidian, and the recent server diary. This is the
// "second brain" an AI assistant reads before it diagnoses anything.
func (s *Server) handleKnowledgeContext(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("server")
	srv, err := s.store.GetServer(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}
	if err != nil {
		s.internalErr(w, err)
		return
	}
	k, err := s.knowledgeFor(r, id)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 14
	}
	diary, err := s.store.ListJournal(r.Context(), store.JournalFilter{ServerID: id, Since: time.Now().AddDate(0, 0, -days), Limit: 60})
	if err != nil {
		s.internalErr(w, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Server %s\n\n", srv.Hostname)
	if hb := srv.Snapshot; hb != nil {
		fmt.Fprintf(&b, "- Betriebssystem: %s\n- Domäne: %s\n- IP: %s\n- CPUs: %d, RAM: %s\n- Status: %s (zuletzt gesehen %s)\n",
			hb.System.OSVersion, hb.System.Domain, strings.Join(hb.System.IPs, ", "), hb.System.CPUs, knowledge.GB(hb.Metrics.MemTotal),
			map[bool]string{true: "online", false: "offline"}[s.online(srv)], srv.LastSeen.Format(time.RFC3339))
		for _, d := range hb.Metrics.Disks {
			if d.Total > 0 {
				fmt.Fprintf(&b, "- Datenträger %s: %.0f %% belegt, %s frei\n", d.Name, 100*float64(d.Total-d.Free)/float64(d.Total), knowledge.GB(d.Free))
			}
		}
	}
	if len(srv.Tags) > 0 {
		fmt.Fprintf(&b, "- Tags: %s\n", strings.Join(srv.Tags, ", "))
	}
	b.WriteString("\n## Rollen\n")
	for _, ro := range k.Roles {
		fmt.Fprintf(&b, "- %s (erkannt über %s)\n", ro.Name, ro.Via)
	}
	b.WriteString("\n## Abhängigkeiten\n")
	for _, d := range k.Dependencies {
		fmt.Fprintf(&b, "- %s → %s Port %s %s\n", d.SrcHost, d.DstHost, knowledge.PortName(d.Port), d.Process)
	}
	if k.Baseline.Samples > 0 {
		fmt.Fprintf(&b, "\n## Normale Auslastung (7 Tage)\nCPU Ø %.0f %% (max %.0f %%), RAM Ø %.0f %%, Datenträger max %.0f %%\n", k.Baseline.CPUAvg, k.Baseline.CPUMax, k.Baseline.MemAvg, k.Baseline.DiskMax)
	}
	if len(k.ErrorPatterns) > 0 {
		b.WriteString("\n## Bekannte Fehlerbilder (30 Tage)\n")
		for _, e := range k.ErrorPatterns {
			fmt.Fprintf(&b, "- %s ID %d: %d×, zuletzt %s\n", e.Source, e.EventID, e.Count, e.Last.Format(time.RFC3339))
		}
	}
	if k.ManualNotes != "" {
		b.WriteString("\n## Notizen der Administratoren (Obsidian)\n" + k.ManualNotes + "\n")
	}
	if len(diary) > 0 {
		fmt.Fprintf(&b, "\n## Servertagebuch (letzte %d Tage, neueste zuerst)\n", days)
		for _, e := range diary {
			fmt.Fprintf(&b, "- %s [%s/%s] %s", e.TS.Format("2006-01-02 15:04"), e.Category, e.Severity, e.Title)
			if e.Author != "ServerBrain" {
				b.WriteString(" — " + e.Author)
			}
			b.WriteString("\n")
		}
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write([]byte(b.String()))
}
