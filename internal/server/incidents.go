package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/knowledge"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Incident workflow:
//
//	error detected (learner signal)
//	  → incident (deduplicated per server and problem)
//	  → autopilot first, where a safe playbook exists
//	  → analysis (AI, read-only; or a rule-based default)
//	  → prepared solution: a validated plan of catalog actions
//	  → a person confirms → executed through the policy as that person
//	  → verification that the problem is really gone
//
// Every transition is written to the server diary (and so to Obsidian).

const (
	maxPlanSteps      = 8
	approvalWaitPlan  = time.Hour
	correlationWindow = 10 * time.Minute
)

var incidentMu sync.Mutex // serializes read-modify-write of incidents

// incidentKey maps a signal to the problem it describes.
func incidentKey(sig knowledge.Signal) (key, kind, severity string, ok bool) {
	switch sig.Kind {
	case knowledge.SignalServiceStopped:
		return "svc:" + strings.ToLower(sig.Service), sig.Kind, store.SevCrit, true
	case knowledge.SignalDiskCritical:
		return "disk:" + sig.Disk, sig.Kind, store.SevCrit, true
	case knowledge.SignalCriticalEvent:
		return fmt.Sprintf("crit:%s|%d", sig.Source, sig.EventID), sig.Kind, store.SevCrit, true
	case knowledge.SignalNewError:
		return fmt.Sprintf("err:%s|%d", sig.Source, sig.EventID), "error", store.SevWarn, true
	case knowledge.SignalOffline:
		return "offline", sig.Kind, store.SevCrit, true
	}
	return "", "", "", false
}

func (s *Server) incidentNote(ctx context.Context, inc *store.Incident, sev, title, detail, author string) {
	if author == "" {
		author = "ServerBrain"
	}
	_ = s.learner.Note(ctx, inc.ServerID, store.CatIncident, sev, title, detail, author)
}

// onSignal routes learner signals into the incident workflow.
func (s *Server) onSignal(sig knowledge.Signal) {
	ctx := context.Background()
	switch sig.Kind {
	case knowledge.SignalServiceRunning:
		s.resolveIncident(ctx, sig.ServerID, "svc:"+strings.ToLower(sig.Service), "Der Dienst läuft wieder.")
		return
	case knowledge.SignalDiskRecovered:
		s.resolveIncident(ctx, sig.ServerID, "disk:"+sig.Disk, "Der Datenträger ist wieder unter der Warnschwelle.")
		return
	case knowledge.SignalOnline:
		s.resolveIncident(ctx, sig.ServerID, "offline", "Der Server meldet sich wieder.")
		return
	}
	inc, isNew := s.openIncident(ctx, sig)
	if inc == nil || !isNew {
		return
	}
	ap := s.autopilot
	switch sig.Kind {
	case knowledge.SignalServiceStopped:
		if ap != nil {
			s.setIncidentStatus(ctx, inc.ID, store.IncAutopilot, "")
			ap.spawn(sig.ServerID+"|svc|"+strings.ToLower(sig.Service), func() { ap.restartService(sig) })
			return
		}
	case knowledge.SignalDiskCritical:
		if ap != nil {
			s.setIncidentStatus(ctx, inc.ID, store.IncAutopilot, "")
			ap.spawn(sig.ServerID+"|disk|"+sig.Disk, func() { ap.inspectDisk(sig) })
			return
		}
	case knowledge.SignalOffline:
		inc.Diagnosis = "Der ServerBrain-Agent meldet sich nicht mehr. Mögliche Ursachen: Server ausgeschaltet oder abgestürzt, Netzwerkproblem, Agent-Dienst gestoppt. Da der Server nicht erreichbar ist, kann keine Lösung über den Agenten vorbereitet werden."
		s.setIncidentStatus(ctx, inc.ID, store.IncManual, inc.Diagnosis)
		return
	}
	s.analyzeIncident(ctx, inc.ID, false)
}

// openIncident creates an incident or counts another occurrence of an open one.
func (s *Server) openIncident(ctx context.Context, sig knowledge.Signal) (*store.Incident, bool) {
	key, kind, sev, ok := incidentKey(sig)
	if !ok {
		return nil, false
	}
	incidentMu.Lock()
	defer incidentMu.Unlock()
	if inc, err := s.store.OpenIncidentByKey(ctx, sig.ServerID, key); err == nil {
		inc.Occurrences++
		_ = s.store.SaveIncident(ctx, inc)
		return inc, false
	}
	// Error events right after another problem on the same server are
	// usually symptoms of it: attach them instead of opening a new incident.
	if sig.Kind == knowledge.SignalNewError || sig.Kind == knowledge.SignalCriticalEvent {
		if open, err := s.store.ListIncidents(ctx, store.IncidentFilter{ServerID: sig.ServerID, Open: true, Limit: 20}); err == nil {
			for _, inc := range open {
				if time.Since(inc.CreatedAt) < correlationWindow && inc.Status != store.IncExecuting {
					inc.Trigger = strings.TrimSpace(inc.Trigger + "\nBegleitendes Symptom: " + sig.Title + " – " + firstLines(sig.Detail, 1))
					_ = s.store.SaveIncident(ctx, inc)
					return inc, false
				}
			}
		}
	}
	inc := &store.Incident{ServerID: sig.ServerID, Key: key, Kind: kind, Title: sig.Title, Trigger: sig.Detail, Severity: sev, Status: store.IncNew}
	if err := s.store.CreateIncident(ctx, inc); err != nil {
		s.log.Error("create incident", "err", err)
		return nil, false
	}
	inc.Hostname = sig.Hostname
	s.incidentNote(ctx, inc, sev, "Vorfall erkannt: "+inc.Title, "Der Vorfall wird analysiert; eine vorbereitete Lösung erscheint in der Konsole unter „Vorfälle“.", "")
	return inc, true
}

func (s *Server) setIncidentStatus(ctx context.Context, id, status, diagnosis string) {
	incidentMu.Lock()
	defer incidentMu.Unlock()
	inc, err := s.store.GetIncident(ctx, id)
	if err != nil {
		return
	}
	inc.Status = status
	if diagnosis != "" {
		inc.Diagnosis = diagnosis
	}
	_ = s.store.SaveIncident(ctx, inc)
}

// resolveIncident closes an open incident whose problem disappeared.
func (s *Server) resolveIncident(ctx context.Context, serverID, key, why string) {
	incidentMu.Lock()
	inc, err := s.store.OpenIncidentByKey(ctx, serverID, key)
	if err != nil || inc.Status == store.IncExecuting {
		incidentMu.Unlock()
		return // the executor verifies its own work
	}
	resolution := why
	if inc.Status == store.IncAutopilot {
		resolution = "Vom Autopilot behoben. " + why
	}
	inc.Status, inc.Resolution, inc.ResolvedAt = store.IncResolved, resolution, time.Now().UTC()
	_ = s.store.SaveIncident(ctx, inc)
	incidentMu.Unlock()
	s.incidentNote(ctx, inc, store.SevOK, "Vorfall behoben: "+inc.Title, resolution, "")
}

// escalateIncident hands an incident from the autopilot to the analysis.
func (s *Server) escalateIncident(serverID, key, note string) {
	ctx := context.Background()
	incidentMu.Lock()
	inc, err := s.store.OpenIncidentByKey(ctx, serverID, key)
	if err == nil && note != "" {
		inc.Trigger = strings.TrimSpace(inc.Trigger + "\n" + note)
		_ = s.store.SaveIncident(ctx, inc)
	}
	incidentMu.Unlock()
	if err == nil {
		s.analyzeIncident(ctx, inc.ID, false)
	}
}

// analyzeIncident prepares a solution: with the AI when configured (rate
// limited unless forced), otherwise with a rule-based default.
func (s *Server) analyzeIncident(ctx context.Context, id string, force bool) error {
	incidentMu.Lock()
	inc, err := s.store.GetIncident(ctx, id)
	if err != nil {
		incidentMu.Unlock()
		return err
	}
	if !inc.IsOpen() || inc.Status == store.IncExecuting || inc.Status == store.IncAnalyzing {
		incidentMu.Unlock()
		return fmt.Errorf("incident is %s", inc.Status)
	}
	srv, err := s.store.GetServer(ctx, inc.ServerID)
	if err != nil {
		incidentMu.Unlock()
		return err
	}
	useAI := s.ai != nil && (force || s.cfg.AutoAnalysis)
	if useAI && !force {
		interval := s.cfg.AutoAnalysisInterval
		if interval == 0 {
			interval = 30 * time.Minute
		}
		s.assistant.mu.Lock()
		if last, ok := s.assistant.lastAuto[inc.ServerID]; ok && time.Since(last) < interval {
			useAI = false // rate limited: fall back to the rule, or wait for a person
		} else {
			s.assistant.lastAuto[inc.ServerID] = time.Now()
		}
		s.assistant.mu.Unlock()
	}
	if !useAI {
		diagnosis, plan := s.defaultPlan(inc, srv)
		inc.Diagnosis, inc.Plan, inc.AnalysisBy = diagnosis, plan, "Regel"
		inc.Status = store.IncManual
		if len(plan) > 0 {
			inc.Status = store.IncProposed
		} else if s.ai != nil {
			inc.Status = store.IncNew // AI analysis possible on request
		}
		_ = s.store.SaveIncident(ctx, inc)
		incidentMu.Unlock()
		if len(plan) > 0 {
			s.incidentNote(ctx, inc, store.SevInfo, "Lösung vorbereitet: "+inc.Title, planSummary(inc), "")
		}
		return nil
	}
	inc.Status, inc.AnalysisBy, inc.Plan, inc.Diagnosis = store.IncAnalyzing, "KI", []store.PlanStep{}, ""
	_ = s.store.SaveIncident(ctx, inc)
	incidentMu.Unlock()

	q := fmt.Sprintf(`Automatische Analyse eines Vorfalls: %s
%s

Aufgabe:
1. Ermittle die Ursache mit den Tools. Du arbeitest unbeaufsichtigt und darfst nur read-only Diagnose-Aktionen ausführen.
2. Rufe am Ende genau einmal propose_solution auf: diagnosis = kurze Markdown-Diagnose (Ursachenkette und Belege), steps = die Aktionen aus list_actions, die ein Administrator nach Bestätigung ausführen lassen kann, in Ausführungsreihenfolge und so wenig invasiv wie möglich. Löst keine Katalog-Aktion das Problem, übergib leere steps und beschreibe die manuelle Lösung in diagnosis.
3. Antworte danach mit einer kurzen Zusammenfassung.`, inc.Title, inc.Trigger)
	run := s.startIncidentRun(srv, inc.ID, q)
	incidentMu.Lock()
	if cur, err := s.store.GetIncident(ctx, inc.ID); err == nil {
		cur.RunID = run.ID
		_ = s.store.SaveIncident(ctx, cur)
	}
	incidentMu.Unlock()
	return nil
}

// defaultPlan is the rule-based solution used without (or instead of) AI.
func (s *Server) defaultPlan(inc *store.Incident, srv *store.Server) (string, []store.PlanStep) {
	switch inc.Kind {
	case knowledge.SignalServiceStopped:
		name := strings.TrimPrefix(inc.Key, "svc:")
		for _, svc := range snapshotServices(srv) {
			if strings.EqualFold(svc, name) {
				name = svc
			}
		}
		plan, err := s.buildPlan(srv, []proposedStep{{Action: "service.start", Params: map[string]any{"name": name}, Reason: "Gestoppten Autostart-Dienst wieder starten"}})
		if err == nil {
			return fmt.Sprintf("Der Autostart-Dienst **%s** ist gestoppt.\n\nStandardlösung: Dienst starten. Startet er nicht dauerhaft, sollte die Ursache (Ereignisprotokoll, Abhängigkeiten) geprüft werden.", name), plan
		}
	case knowledge.SignalDiskCritical:
		plan, err := s.buildPlan(srv, []proposedStep{
			{Action: "disk.large_files", Params: map[string]any{"path": diskRoot(strings.TrimPrefix(inc.Key, "disk:"), srv.OS), "top": float64(15)}, Reason: "Größte Dateien ermitteln"},
			{Action: "temp.cleanup", Params: map[string]any{"older_than_days": float64(7)}, Reason: "Temporäre Dateien älter als 7 Tage löschen"},
		})
		if err == nil {
			return "Der Datenträger ist kritisch voll.\n\nStandardlösung: größte Dateien ermitteln und temporäre Dateien bereinigen. Für gezieltes Archivieren (z. B. IIS-Logs) empfiehlt sich eine KI-Analyse.", plan
		}
	}
	return "Für diesen Vorfall gibt es keine Standardlösung. Bitte manuell prüfen" + map[bool]string{true: " oder eine KI-Analyse starten.", false: "."}[s.ai != nil], nil
}

func snapshotServices(srv *store.Server) []string {
	if srv.Snapshot == nil {
		return nil
	}
	out := make([]string, len(srv.Snapshot.Services))
	for i, svc := range srv.Snapshot.Services {
		out[i] = svc.Name
	}
	return out
}

type proposedStep struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
	Reason string         `json:"reason"`
}

// buildPlan validates proposed steps against the catalog, the server's
// capabilities and the parameter rules, and renders their previews.
func (s *Server) buildPlan(srv *store.Server, steps []proposedStep) ([]store.PlanStep, error) {
	if len(steps) > maxPlanSteps {
		return nil, fmt.Errorf("höchstens %d Schritte", maxPlanSteps)
	}
	caps := map[string]bool{}
	for _, c := range srv.Capabilities {
		caps[c] = true
	}
	plan := []store.PlanStep{}
	for i, st := range steps {
		def, ok := actions.Get(st.Action)
		if !ok {
			return nil, fmt.Errorf("Schritt %d: unbekannte Aktion %q", i+1, st.Action)
		}
		if def.Name == "shell.run" {
			return nil, fmt.Errorf("Schritt %d: freie Skripte (shell.run) sind in vorbereiteten Lösungen nicht erlaubt", i+1)
		}
		if !caps[def.Name] {
			return nil, fmt.Errorf("Schritt %d: %s bietet %s nicht an", i+1, srv.Hostname, def.Name)
		}
		params, err := def.Validate(st.Params)
		if err != nil {
			return nil, fmt.Errorf("Schritt %d (%s): %v", i+1, def.Name, err)
		}
		if strings.TrimSpace(st.Reason) == "" {
			return nil, fmt.Errorf("Schritt %d: reason fehlt", i+1)
		}
		plan = append(plan, store.PlanStep{Action: def.Name, Params: params, Reason: st.Reason, Risk: string(def.Risk), ReadOnly: def.ReadOnly,
			Preview: def.Preview(srv.OS, params), Status: "pending"})
	}
	return plan, nil
}

func planSummary(inc *store.Incident) string {
	var b strings.Builder
	b.WriteString(firstLines(inc.Diagnosis, 8))
	if len(inc.Plan) > 0 {
		b.WriteString("\n\nVorbereitete Schritte (warten auf Bestätigung):")
		for i, st := range inc.Plan {
			fmt.Fprintf(&b, "\n%d. %s%s – %s", i+1, st.Action, paramSummary(st.Params), st.Reason)
		}
	}
	return b.String()
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n")
}

// finishIncidentAnalysis is called when the AI run of an incident ends.
func (s *Server) finishIncidentAnalysis(incidentID, answer string, runErr error) {
	ctx := context.Background()
	incidentMu.Lock()
	inc, err := s.store.GetIncident(ctx, incidentID)
	if err != nil || inc.Status != store.IncAnalyzing {
		incidentMu.Unlock()
		return // resolved or dismissed in the meantime
	}
	if runErr != nil {
		inc.Status, inc.Resolution = store.IncNew, "KI-Analyse fehlgeschlagen: "+runErr.Error()
		_ = s.store.SaveIncident(ctx, inc)
		incidentMu.Unlock()
		return
	}
	if strings.TrimSpace(inc.Diagnosis) == "" {
		inc.Diagnosis = answer
	}
	inc.Status = store.IncManual
	if len(inc.Plan) > 0 {
		inc.Status = store.IncProposed
	}
	_ = s.store.SaveIncident(ctx, inc)
	incidentMu.Unlock()
	title := "Analyse abgeschlossen – manuelle Lösung nötig: " + inc.Title
	if inc.Status == store.IncProposed {
		title = "Lösung vorbereitet: " + inc.Title
	}
	s.incidentNote(ctx, inc, store.SevInfo, title, planSummary(inc), "KI (automatisch)")
}

// toolProposeSolution is offered only in incident analyses.
func (s *Server) toolProposeSolution(ctx context.Context, run *Run, in map[string]any) (string, error) {
	diagnosis := str(in, "diagnosis")
	if diagnosis == "" {
		return "", errors.New("diagnosis fehlt")
	}
	var steps []proposedStep
	if raw, ok := in["steps"].([]any); ok {
		for _, r := range raw {
			m, _ := r.(map[string]any)
			p, _ := m["params"].(map[string]any)
			steps = append(steps, proposedStep{Action: str(m, "action"), Params: p, Reason: str(m, "reason")})
		}
	}
	incidentMu.Lock()
	defer incidentMu.Unlock()
	inc, err := s.store.GetIncident(ctx, run.incidentID)
	if err != nil {
		return "", err
	}
	srv, err := s.store.GetServer(ctx, inc.ServerID)
	if err != nil {
		return "", err
	}
	plan, err := s.buildPlan(srv, steps)
	if err != nil {
		return "", fmt.Errorf("Lösung ungültig, bitte korrigieren: %v", err)
	}
	inc.Diagnosis, inc.Plan = diagnosis, plan
	if err := s.store.SaveIncident(ctx, inc); err != nil {
		return "", err
	}
	if len(plan) == 0 {
		return "Diagnose gespeichert. Keine automatischen Schritte: Der Administrator löst das Problem manuell.", nil
	}
	return fmt.Sprintf("Lösung mit %d Schritt(en) gespeichert. Sie wird erst ausgeführt, wenn ein Administrator sie bestätigt.", len(plan)), nil
}

// ---------- execution after confirmation ----------

func (s *Server) executeIncident(inc *store.Incident, u *store.User, selected map[int]bool) {
	ctx := context.Background()
	actor := actorOf(u)
	failed := false
	for i := range inc.Plan {
		step := &inc.Plan[i]
		if !selected[i] {
			step.Status = "skipped"
			continue
		}
		params := make(map[string]any, len(step.Params))
		for k, v := range step.Params {
			params[k] = v
		}
		reason := fmt.Sprintf("Vorfall „%s“: %s (Lösung bestätigt von %s)", inc.Title, step.Reason, u.Name)
		cmd, dec, status, err := s.requestAction(ctx, actor, inc.ServerID, actionRequest{Action: step.Action, Params: params, Reason: reason})
		switch {
		case status == http.StatusForbidden:
			step.Status, step.Output = "blocked", "Von der Policy gesperrt (Regel "+dec.Rule+")."
			failed = true
		case err != nil:
			step.Status, step.Output = "failed", err.Error()
			failed = true
		}
		if failed {
			s.saveIncidentPlan(ctx, inc)
			break
		}
		step.CommandID = cmd.ID
		if cmd.Status == store.StatusPendingApproval {
			// The confirming admin's click counts as the approval, unless the
			// policy demands four eyes.
			if u.Role == policy.RoleAdmin && s.policy.AllowSelfApproval {
				if s.store.TransitionCommand(ctx, cmd.ID, store.StatusPendingApproval, store.StatusQueued, u.Name) == nil {
					_ = s.store.Audit(ctx, u.Name, u.Kind, "action.approved", inc.ServerID, map[string]any{"command": cmd.ID, "action": cmd.Action, "via": "incident " + inc.ID})
					s.wake(inc.ServerID)
				}
			} else {
				step.Status = "waiting_approval"
				s.saveIncidentPlan(ctx, inc)
			}
		}
		if step.Status != "waiting_approval" {
			step.Status = "running"
			s.saveIncidentPlan(ctx, inc)
		}
		limit := stepWaitLimit(step.Action)
		if step.Status == "waiting_approval" {
			limit += approvalWaitPlan
		}
		done, err := s.waitCommand(ctx, cmd.ID, limit)
		if err != nil || done == nil {
			step.Status, failed = "failed", true
		} else {
			switch done.Status {
			case store.StatusSucceeded:
				step.Status = "succeeded"
			case store.StatusPendingApproval, store.StatusQueued, store.StatusDispatched:
				step.Status, failed = "timeout", true
			default:
				step.Status, failed = done.Status, true
			}
			if r := done.Result; r != nil {
				out := strings.TrimSpace(r.Output)
				if r.Error != "" {
					out = strings.TrimSpace("Fehler: " + r.Error + "\n" + out)
				}
				if len(out) > 4000 {
					out = out[:4000] + "\n…"
				}
				step.Output = out
			}
		}
		s.saveIncidentPlan(ctx, inc)
		if failed {
			break
		}
	}
	if failed {
		s.finishExecution(ctx, inc, store.IncFailed, "Die Umsetzung wurde abgebrochen, weil ein Schritt nicht erfolgreich war.", store.SevCrit)
		return
	}
	verified, msg := s.verifyIncident(ctx, inc)
	switch {
	case verified:
		s.finishExecution(ctx, inc, store.IncResolved, "Lösung umgesetzt und geprüft: "+msg, store.SevOK)
	case msg == "":
		s.finishExecution(ctx, inc, store.IncResolved, "Lösung umgesetzt. Der Erfolg lässt sich für diesen Vorfall nicht automatisch prüfen.", store.SevOK)
	default:
		s.finishExecution(ctx, inc, store.IncFailed, "Lösung umgesetzt, aber das Problem besteht weiterhin: "+msg, store.SevCrit)
	}
}

func (s *Server) saveIncidentPlan(ctx context.Context, inc *store.Incident) {
	incidentMu.Lock()
	defer incidentMu.Unlock()
	if cur, err := s.store.GetIncident(ctx, inc.ID); err == nil {
		cur.Plan = inc.Plan
		_ = s.store.SaveIncident(ctx, cur)
	}
}

func (s *Server) finishExecution(ctx context.Context, inc *store.Incident, status, resolution, sev string) {
	incidentMu.Lock()
	cur, err := s.store.GetIncident(ctx, inc.ID)
	if err != nil {
		incidentMu.Unlock()
		return
	}
	cur.Plan, cur.Status, cur.Resolution = inc.Plan, status, resolution
	if status == store.IncResolved {
		cur.ResolvedAt = time.Now().UTC()
	}
	_ = s.store.SaveIncident(ctx, cur)
	incidentMu.Unlock()
	title := "Vorfall behoben: " + cur.Title
	if status != store.IncResolved {
		title = "Lösung nicht erfolgreich: " + cur.Title
	}
	s.incidentNote(ctx, cur, sev, title, resolution, cur.DecidedBy)
}

// stepWaitLimit is how long a plan step may take: the action's own timeout
// on the agent plus time for dispatch and result delivery.
func stepWaitLimit(action string) time.Duration {
	limit := 5 * time.Minute
	if def, ok := actions.Get(action); ok && def.TimeoutSeconds > 0 {
		limit = time.Duration(def.TimeoutSeconds) * time.Second
	}
	return limit + 3*time.Minute
}

// RecoverInterrupted repairs incidents whose in-memory work was lost when
// the control plane stopped (execution, analysis or an autopilot playbook
// in flight). Without this they would stay in a state nothing ever leaves.
func (s *Server) RecoverInterrupted(ctx context.Context) {
	incidentMu.Lock()
	list, err := s.store.ListIncidents(ctx, store.IncidentFilter{Open: true, Limit: 1000})
	if err != nil {
		incidentMu.Unlock()
		return
	}
	var notes []*store.Incident
	for _, inc := range list {
		switch inc.Status {
		case store.IncExecuting:
			for i := range inc.Plan {
				if st := inc.Plan[i].Status; st == "running" || st == "waiting_approval" || st == "pending" {
					inc.Plan[i].Status = "interrupted"
				}
			}
			inc.Status = store.IncFailed
			inc.Resolution = "Die Umsetzung wurde durch einen Neustart von ServerBrain unterbrochen. Bitte den Zustand des Servers prüfen (Aktionen/Tagebuch) und die Lösung bei Bedarf erneut umsetzen."
		case store.IncAnalyzing:
			inc.Status, inc.Resolution = store.IncNew, "Die Analyse wurde durch einen Neustart von ServerBrain unterbrochen und kann neu gestartet werden."
		case store.IncAutopilot:
			inc.Status, inc.Resolution = store.IncNew, "Der Autopilot wurde durch einen Neustart von ServerBrain unterbrochen."
		default:
			continue
		}
		_ = s.store.SaveIncident(ctx, inc)
		notes = append(notes, inc)
	}
	incidentMu.Unlock()
	for _, inc := range notes {
		s.incidentNote(ctx, inc, store.SevWarn, "Vorfall unterbrochen: "+inc.Title, inc.Resolution, "")
	}
	if len(notes) > 0 {
		s.log.Warn("recovered interrupted incidents", "count", len(notes))
	}
}

// verifyIncident waits for fresh telemetry and checks the original
// symptom. An empty message means the symptom cannot be checked.
func (s *Server) verifyIncident(ctx context.Context, inc *store.Incident) (bool, string) {
	check := func(srv *store.Server) (bool, string) {
		switch inc.Kind {
		case knowledge.SignalServiceStopped:
			name := strings.TrimPrefix(inc.Key, "svc:")
			for _, svc := range snapshotServices(srv) {
				if strings.EqualFold(svc, name) {
					name = svc
				}
			}
			if serviceStopped(srv, name) {
				return false, "Der Dienst " + name + " ist weiterhin gestoppt."
			}
			return true, "Der Dienst " + name + " läuft."
		case knowledge.SignalDiskCritical:
			disk := strings.TrimPrefix(inc.Key, "disk:")
			if srv.Snapshot != nil {
				for _, d := range srv.Snapshot.Metrics.Disks {
					if d.Name == disk && d.Total > 0 {
						pct := 100 * float64(d.Total-d.Free) / float64(d.Total)
						if pct >= 95 {
							return false, fmt.Sprintf("%s ist weiterhin zu %.0f %% belegt.", disk, pct)
						}
						return true, fmt.Sprintf("%s ist jetzt zu %.0f %% belegt (%s frei).", disk, pct, knowledge.GB(d.Free))
					}
				}
			}
			return false, "Keine Daten zum Datenträger " + disk + "."
		}
		return false, ""
	}
	if inc.Kind != knowledge.SignalServiceStopped && inc.Kind != knowledge.SignalDiskCritical {
		return false, ""
	}
	start := time.Now()
	deadline := start.Add(3*s.cfg.HeartbeatInterval + 5*time.Second)
	last := ""
	for time.Now().Before(deadline) {
		srv, err := s.store.GetServer(ctx, inc.ServerID)
		if err == nil && srv.LastSeen.After(start) {
			ok, msg := check(srv)
			if ok {
				return true, msg
			}
			last = msg
		}
		time.Sleep(time.Second)
	}
	if last == "" {
		last = "Der Server hat nach der Umsetzung keine neuen Daten gemeldet."
	}
	return false, last
}

// ---------- HTTP ----------

type incidentView struct {
	*store.Incident
	Effects []string `json:"effects"` // policy effect per step for the viewer
}

func (s *Server) viewIncident(ctx context.Context, inc *store.Incident, u *store.User) incidentView {
	v := incidentView{Incident: inc, Effects: make([]string, len(inc.Plan))}
	srv, err := s.store.GetServer(ctx, inc.ServerID)
	for i, st := range inc.Plan {
		def, ok := actions.Get(st.Action)
		if err != nil || !ok {
			v.Effects[i] = string(policy.Block)
			continue
		}
		dec := s.policy.Evaluate(policy.Request{Action: def, Hostname: srv.Hostname, Tags: srv.Tags, ActorType: u.Kind, Role: u.Role})
		if u.Role == policy.RoleViewer && !def.ReadOnly {
			dec.Effect = policy.Block
		}
		v.Effects[i] = string(dec.Effect)
	}
	return v
}

// GET /api/incidents?open=1&server=
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := s.store.ListIncidents(r.Context(), store.IncidentFilter{ServerID: q.Get("server"), Open: q.Get("open") == "1", Status: q.Get("status"), Limit: limit})
	if err != nil {
		s.internalErr(w, err)
		return
	}
	u := userFrom(r)
	out := make([]incidentView, len(list))
	for i, inc := range list {
		out[i] = s.viewIncident(r.Context(), inc, u)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) incidentFrom(w http.ResponseWriter, r *http.Request) *store.Incident {
	inc, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "incident not found")
		return nil
	}
	if err != nil {
		s.internalErr(w, err)
		return nil
	}
	return inc
}

// GET /api/incidents/{id}
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	if inc := s.incidentFrom(w, r); inc != nil {
		writeJSON(w, http.StatusOK, s.viewIncident(r.Context(), inc, userFrom(r)))
	}
}

// POST /api/incidents/{id}/execute {steps: [0,1,...]} – the confirmation.
func (s *Server) handleExecuteIncident(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Kind == policy.ActorAI {
		writeErr(w, http.StatusForbidden, "only people can confirm a solution")
		return
	}
	var body struct {
		Steps []int `json:"steps"`
	}
	_ = readJSON(r, 16<<10, &body)
	incidentMu.Lock()
	inc, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		incidentMu.Unlock()
		writeErr(w, http.StatusNotFound, "incident not found")
		return
	}
	if (inc.Status != store.IncProposed && inc.Status != store.IncFailed) || len(inc.Plan) == 0 {
		incidentMu.Unlock()
		writeErr(w, http.StatusConflict, "no prepared solution to execute (status "+inc.Status+")")
		return
	}
	selected := map[int]bool{}
	if len(body.Steps) == 0 {
		for i := range inc.Plan {
			selected[i] = true
		}
	}
	for _, i := range body.Steps {
		if i >= 0 && i < len(inc.Plan) {
			selected[i] = true
		}
	}
	for i := range inc.Plan {
		inc.Plan[i].Status, inc.Plan[i].Output, inc.Plan[i].CommandID = "pending", "", ""
	}
	inc.Status, inc.DecidedBy = store.IncExecuting, u.Name
	_ = s.store.SaveIncident(r.Context(), inc)
	incidentMu.Unlock()
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "incident.confirmed", inc.ServerID, map[string]any{"incident": inc.ID, "steps": len(selected)})
	s.incidentNote(r.Context(), inc, store.SevInfo, "Lösung bestätigt: "+inc.Title, planSummary(inc), u.Name)
	go s.executeIncident(inc, u, selected)
	writeJSON(w, http.StatusAccepted, s.viewIncident(r.Context(), inc, u))
}

// POST /api/incidents/{id}/analyze – (re)run the analysis now.
func (s *Server) handleAnalyzeIncident(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	inc := s.incidentFrom(w, r)
	if inc == nil {
		return
	}
	if err := s.analyzeIncident(r.Context(), inc.ID, true); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "incident.analyze", inc.ServerID, map[string]any{"incident": inc.ID})
	inc, _ = s.store.GetIncident(r.Context(), inc.ID)
	writeJSON(w, http.StatusAccepted, s.viewIncident(r.Context(), inc, u))
}

// POST /api/incidents/{id}/close {resolved: bool, note}
func (s *Server) handleCloseIncident(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var body struct {
		Resolved bool   `json:"resolved"`
		Note     string `json:"note"`
	}
	_ = readJSON(r, 16<<10, &body)
	incidentMu.Lock()
	inc, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil || !inc.IsOpen() || inc.Status == store.IncExecuting {
		incidentMu.Unlock()
		writeErr(w, http.StatusConflict, "incident cannot be closed now")
		return
	}
	inc.Status, inc.DecidedBy, inc.ResolvedAt = store.IncDismissed, u.Name, time.Now().UTC()
	title := "Vorfall verworfen: "
	if body.Resolved {
		inc.Status, title = store.IncResolved, "Vorfall manuell erledigt: "
	}
	inc.Resolution = strings.TrimSpace(body.Note)
	_ = s.store.SaveIncident(r.Context(), inc)
	incidentMu.Unlock()
	_ = s.store.Audit(r.Context(), u.Name, u.Kind, "incident."+inc.Status, inc.ServerID, map[string]any{"incident": inc.ID, "note": body.Note})
	s.incidentNote(r.Context(), inc, store.SevInfo, title+inc.Title, inc.Resolution, u.Name)
	writeJSON(w, http.StatusOK, s.viewIncident(r.Context(), inc, u))
}
