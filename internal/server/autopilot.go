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
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "Wartungsmodus: kein automatischer Neustart.")
		return
	}
	if !ap.s.online(srv) {
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "")
		return
	}
	if !serviceStopped(srv, sig.Service) {
		return // recovered on its own; the incident closes via the running signal
	}
	if ap.recentlyStoppedByPerson(srv.ID, sig.Service) {
		ap.note(srv.ID, store.SevInfo, "Autopilot: "+sig.Service+" bewusst gestoppt – kein Neustart", "Der Dienst wurde in der letzten Stunde von einer Person über ServerBrain gestoppt.")
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "Der Dienst wurde bewusst von einer Person gestoppt.")
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
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), fmt.Sprintf("Der Autopilot hat den Dienst bereits %d-mal gestartet; er fällt wiederholt aus.", len(recent)))
		return
	}
	reason := fmt.Sprintf("Autopilot: Autostart-Dienst %s ist seit über %s gestoppt (Versuch %d von %d)", sig.Service, ap.cfg.Grace.Round(time.Second), len(recent), ap.cfg.MaxAttempts)
	cmd, dec, status, err := ap.s.requestAction(ap.ctx, autopilotActor, srv.ID, actionRequest{Action: "service.start", Params: map[string]any{"name": sig.Service}, Reason: reason})
	switch {
	case status == http.StatusForbidden:
		ap.note(srv.ID, store.SevWarn, "Autopilot darf "+sig.Service+" nicht starten", "Die Policy blockiert service.start für den Autopilot (Regel "+dec.Rule+").")
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "Die Policy erlaubt dem Autopilot keinen Neustart.")
		return
	case err != nil:
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "")
		return // e.g. no service.start capability on this agent
	case cmd.Status == store.StatusPendingApproval:
		ap.note(srv.ID, store.SevInfo, "Autopilot schlägt Neustart von "+sig.Service+" vor", "Die Policy verlangt eine Freigabe (Regel "+dec.Rule+"). Der Vorschlag wartet unter „Freigaben“.")
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "")
		return
	}
	done, err := ap.s.waitCommand(ap.ctx, cmd.ID, actionWaitLimit)
	if err != nil || done.Status != store.StatusSucceeded {
		ap.s.escalateIncident(srv.ID, svcKey(sig.Service), "Der Autopilot konnte den Dienst nicht starten.")
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
	ap.s.escalateIncident(srv.ID, "disk:"+sig.Disk, "Die größten Dateien wurden bereits vom Autopilot ermittelt (siehe Servertagebuch).")
}

func svcKey(service string) string { return "svc:" + strings.ToLower(service) }
