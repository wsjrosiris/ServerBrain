package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/knowledge"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Autopilot: deterministic self-healing playbooks, triggered by the
// learner's signals. No LLM is involved in the decision; every action goes
// through the policy as the "Autopilot" actor (type ai), so the policy
// decides what may run unattended. When a playbook fails or gives up, the
// incident is escalated to an automatic AI analysis (if configured).

// MaintenanceTag pauses the autopilot for a server.
const MaintenanceTag = "wartung"

type AutopilotConfig struct {
	// Grace is how long a stopped service may stay stopped before the
	// autopilot acts (services restarting on their own are left alone).
	Grace time.Duration
	// MaxAttempts per service within Window before escalating.
	MaxAttempts int
	Window      time.Duration
}

type Autopilot struct {
	s   *Server
	cfg AutopilotConfig
	ctx context.Context

	mu       sync.Mutex
	attempts map[string][]time.Time // server|service -> start attempts
	running  map[string]bool        // playbooks in flight
	pending  map[string]func()      // signals that arrived while running
}

var autopilotActor = Actor{Name: "Autopilot", Kind: policy.ActorAI, Role: policy.RoleOperator}

// EnableAutopilot activates the self-healing playbooks.
func (s *Server) EnableAutopilot(ctx context.Context, cfg AutopilotConfig) {
	if cfg.Grace == 0 {
		cfg.Grace = 2 * time.Minute
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Window == 0 {
		cfg.Window = 24 * time.Hour
	}
	s.autopilot = &Autopilot{s: s, cfg: cfg, ctx: ctx, attempts: map[string][]time.Time{}, running: map[string]bool{}, pending: map[string]func(){}}
}

// onSignal dispatches learner signals to the autopilot and the automatic
// AI analysis. It is called inside heartbeat processing, so all work runs
// in the background.
func (s *Server) onSignal(sig knowledge.Signal) {
	ap := s.autopilot
	switch sig.Kind {
	case knowledge.SignalServiceStopped:
		if ap != nil {
			ap.spawn(sig.ServerID+"|svc|"+strings.ToLower(sig.Service), func() { ap.restartService(sig) })
		} else {
			s.autoAnalyze(sig.ServerID, sig.Title+"\n"+sig.Detail)
		}
	case knowledge.SignalDiskCritical:
		if ap != nil {
			ap.spawn(sig.ServerID+"|disk|"+sig.Disk, func() { ap.inspectDisk(sig) })
		} else {
			s.autoAnalyze(sig.ServerID, sig.Title+"\n"+sig.Detail)
		}
	case knowledge.SignalCriticalEvent:
		s.autoAnalyze(sig.ServerID, sig.Title+"\n"+sig.Detail)
	}
}

// spawn runs a playbook in the background, one at a time per key. A signal
// arriving while the same playbook runs is not lost: it runs right after.
func (ap *Autopilot) spawn(key string, fn func()) {
	ap.mu.Lock()
	if ap.running[key] {
		ap.pending[key] = fn
		ap.mu.Unlock()
		return
	}
	ap.running[key] = true
	ap.mu.Unlock()
	go func() {
		for fn != nil {
			fn()
			ap.mu.Lock()
			fn = ap.pending[key]
			delete(ap.pending, key)
			if fn == nil {
				delete(ap.running, key)
			}
			ap.mu.Unlock()
		}
	}()
}

func (ap *Autopilot) note(serverID, sev, title, detail string) {
	_ = ap.s.learner.Note(context.Background(), serverID, store.CatAutopilot, sev, title, detail, autopilotActor.Name)
}

func hasTag(srv *store.Server, tag string) bool {
	for _, t := range srv.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

func (ap *Autopilot) sleep(d time.Duration) bool {
	select {
	case <-ap.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// recentlyStoppedByPerson reports whether someone deliberately stopped the
// service through ServerBrain in the last hour.
func (ap *Autopilot) recentlyStoppedByPerson(serverID, service string) bool {
	cmds, err := ap.s.store.ListCommands(ap.ctx, store.CommandFilter{ServerID: serverID, Limit: 100})
	if err != nil {
		return false
	}
	for _, c := range cmds {
		if c.Action == "service.stop" && strings.EqualFold(c.Params["name"], service) && time.Since(c.CreatedAt) < time.Hour && c.ActorType == policy.ActorHuman {
			return true
		}
	}
	return false
}

// restartService: playbook "automatic service stopped".
func (ap *Autopilot) restartService(sig knowledge.Signal) {
	if !ap.sleep(ap.cfg.Grace) {
		return
	}
	srv, err := ap.s.store.GetServer(ap.ctx, sig.ServerID)
	if err != nil {
		return
	}
	if hasTag(srv, MaintenanceTag) {
		ap.note(srv.ID, store.SevInfo, "Autopilot pausiert: "+sig.Service+" nicht neu gestartet", "Der Server ist mit dem Tag „"+MaintenanceTag+"“ im Wartungsmodus.")
		return
	}
	if !ap.s.online(srv) || !serviceStopped(srv, sig.Service) {
		return // the service recovered on its own, or the server is gone
	}
	if ap.recentlyStoppedByPerson(srv.ID, sig.Service) {
		ap.note(srv.ID, store.SevInfo, "Autopilot: "+sig.Service+" bewusst gestoppt – kein Neustart", "Der Dienst wurde in der letzten Stunde von einer Person über ServerBrain gestoppt.")
		return
	}
	key := srv.ID + "|" + strings.ToLower(sig.Service)
	ap.mu.Lock()
	var recent []time.Time
	for _, t := range ap.attempts[key] {
		if time.Since(t) < ap.cfg.Window {
			recent = append(recent, t)
		}
	}
	exhausted := len(recent) >= ap.cfg.MaxAttempts
	if !exhausted {
		recent = append(recent, time.Now())
	}
	ap.attempts[key] = recent
	ap.mu.Unlock()
	if exhausted {
		ap.note(srv.ID, store.SevCrit, "Autopilot gibt auf: "+sig.Service+" fällt wiederholt aus",
			fmt.Sprintf("%d Startversuche in %s. Weitere automatische Neustarts würden das Problem nur verdecken – Eskalation.", len(recent), ap.cfg.Window))
		ap.s.autoAnalyze(srv.ID, fmt.Sprintf("Der Autostart-Dienst %s auf %s fällt wiederholt aus; der Autopilot hat ihn bereits %d-mal gestartet.", sig.Service, srv.Hostname, len(recent)))
		return
	}
	reason := fmt.Sprintf("Autopilot: Autostart-Dienst %s ist seit über %s gestoppt (Versuch %d von %d)", sig.Service, ap.cfg.Grace.Round(time.Second), len(recent), ap.cfg.MaxAttempts)
	cmd, dec, status, err := ap.s.requestAction(ap.ctx, autopilotActor, srv.ID, actionRequest{Action: "service.start", Params: map[string]any{"name": sig.Service}, Reason: reason})
	switch {
	case status == http.StatusForbidden:
		ap.note(srv.ID, store.SevWarn, "Autopilot darf "+sig.Service+" nicht starten", "Die Policy blockiert service.start für den Autopilot (Regel "+dec.Rule+").")
		ap.s.autoAnalyze(srv.ID, sig.Title+"\n"+sig.Detail)
		return
	case err != nil:
		return // e.g. no service.start capability on this agent
	case cmd.Status == store.StatusPendingApproval:
		ap.note(srv.ID, store.SevInfo, "Autopilot schlägt Neustart von "+sig.Service+" vor", "Die Policy verlangt eine Freigabe (Regel "+dec.Rule+"). Der Vorschlag wartet unter „Freigaben“.")
		return
	}
	done, err := ap.s.waitCommand(ap.ctx, cmd.ID, actionWaitLimit)
	if err != nil || done.Status != store.StatusSucceeded {
		ap.s.autoAnalyze(srv.ID, fmt.Sprintf("%s\n%s\nDer Autopilot konnte den Dienst nicht starten.", sig.Title, sig.Detail))
	}
}

func serviceStopped(srv *store.Server, name string) bool {
	if srv.Snapshot == nil {
		return false
	}
	for _, svc := range srv.Snapshot.Services {
		if strings.EqualFold(svc.Name, name) {
			return svc.Status == "Stopped"
		}
	}
	return false
}

// inspectDisk: playbook "disk critical" – collect evidence, then analyse.
func (ap *Autopilot) inspectDisk(sig knowledge.Signal) {
	srv, err := ap.s.store.GetServer(ap.ctx, sig.ServerID)
	if err != nil {
		return
	}
	path := sig.Disk
	if srv.OS == "windows" && len(path) == 2 && path[1] == ':' {
		path += `\`
	}
	cmd, _, _, err := ap.s.requestAction(ap.ctx, autopilotActor, srv.ID, actionRequest{
		Action: "disk.large_files", Params: map[string]any{"path": path, "top": float64(15)},
		Reason: "Autopilot: " + sig.Title + " – größte Dateien ermitteln",
	})
	if err == nil && cmd.Status != store.StatusPendingApproval {
		_, _ = ap.s.waitCommand(ap.ctx, cmd.ID, 10*time.Minute) // the result is journaled
	}
	ap.s.autoAnalyze(srv.ID, sig.Title+"\n"+sig.Detail+"\nDie größten Dateien wurden bereits ermittelt (siehe Servertagebuch).")
}

// autoAnalyze starts a rate-limited, read-only AI analysis of an incident.
func (s *Server) autoAnalyze(serverID, incident string) {
	if s.ai == nil || !s.cfg.AutoAnalysis {
		return
	}
	interval := s.cfg.AutoAnalysisInterval
	if interval == 0 {
		interval = 30 * time.Minute
	}
	s.assistant.mu.Lock()
	if last, ok := s.assistant.lastAuto[serverID]; ok && time.Since(last) < interval {
		s.assistant.mu.Unlock()
		return
	}
	s.assistant.lastAuto[serverID] = time.Now()
	s.assistant.mu.Unlock()
	srv, err := s.store.GetServer(context.Background(), serverID)
	if err != nil {
		return
	}
	q := "Automatische Analyse: " + incident + "\n\nUntersuche die Ursache mit den Tools und empfiehl eine Lösung. Du arbeitest unbeaufsichtigt und darfst nur read-only Diagnose-Aktionen ausführen; Änderungen empfiehlst du nur."
	s.startRun("ServerBrain", "auto", autoActor, srv, q)
}
