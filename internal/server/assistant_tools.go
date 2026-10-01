package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/knowledge"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// assistantTool is a tool the model can call. Tools return compact text:
// it is what the model reads, and what the UI shows in the run transcript.
type assistantTool struct {
	def   ai.Tool
	label func(in map[string]any) string
	run   func(ctx context.Context, run *Run, in map[string]any) (string, error)
}

func str(in map[string]any, k string) string {
	if v, ok := in[k].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func num(in map[string]any, k string, def, lo, hi int) int {
	v, ok := in[k].(float64)
	if !ok {
		return def
	}
	return max(lo, min(hi, int(v)))
}

var serverProp = map[string]any{"type": "string", "description": "Hostname (z. B. WEB-03) oder server_id"}

func (s *Server) aiTools(run *Run) []ai.Tool {
	tools := s.toolset(run)
	out := make([]ai.Tool, len(tools))
	for i, t := range tools {
		out[i] = t.def
	}
	return out
}

func (s *Server) toolByName(run *Run, name string) (assistantTool, bool) {
	for _, t := range s.toolset(run) {
		if t.def.Name == name {
			return t, true
		}
	}
	return assistantTool{}, false
}

// resolveServer accepts a hostname (case-insensitive) or a server id.
func (s *Server) resolveServer(ctx context.Context, ref string) (*store.Server, error) {
	if ref == "" {
		return nil, errors.New("parameter server fehlt")
	}
	if srv, err := s.store.GetServer(ctx, ref); err == nil {
		return srv, nil
	}
	list, err := s.store.ListServers(ctx, false)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, srv := range list {
		if strings.EqualFold(srv.Hostname, ref) {
			return s.store.GetServer(ctx, srv.ID)
		}
		names = append(names, srv.Hostname)
	}
	return nil, fmt.Errorf("server %q nicht gefunden; bekannte Server: %s", ref, strings.Join(names, ", "))
}

func (s *Server) toolset(run *Run) []assistantTool {
	tools := s.baseTools()
	if run != nil && run.incidentID != "" {
		tools = append(tools, assistantTool{
			def: ai.Tool{Name: "propose_solution", Description: "Speichert Diagnose und vorbereitete Lösung für den analysierten Vorfall. Die Schritte werden NICHT ausgeführt, sondern einem Administrator zur Bestätigung vorgelegt. Nur Aktionen aus list_actions; freie Skripte sind nicht erlaubt. Leere steps, wenn das Problem manuell gelöst werden muss.",
				Properties: map[string]any{
					"diagnosis": map[string]any{"type": "string", "description": "Markdown: Ursachenkette, Belege, ggf. manuelle Schritte"},
					"steps": map[string]any{"type": "array", "description": "Aktionen in Ausführungsreihenfolge (max. 8)", "items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"action": map[string]any{"type": "string"},
							"params": map[string]any{"type": "object"},
							"reason": map[string]any{"type": "string", "description": "Warum dieser Schritt nötig ist"},
						},
						"required": []string{"action", "reason"},
					}},
				}, Required: []string{"diagnosis", "steps"}},
			label: func(in map[string]any) string {
				n := 0
				if st, ok := in["steps"].([]any); ok {
					n = len(st)
				}
				return fmt.Sprintf("Bereitet eine Lösung mit %d Schritt(en) vor", n)
			},
			run: s.toolProposeSolution,
		})
	}
	return tools
}

func (s *Server) baseTools() []assistantTool {
	return []assistantTool{
		{
			def: ai.Tool{Name: "list_servers", Description: "Listet alle verwalteten Server mit Status, Betriebssystem, Rollen, Auslastung, vollstem Datenträger und Tags. Nutze das für Flottenfragen und um Server-Namen zu finden.",
				Properties: map[string]any{}},
			label: func(map[string]any) string { return "Liest die Serverliste" },
			run:   s.toolListServers,
		},
		{
			def: ai.Tool{Name: "get_alerts", Description: "Liefert die aktuell aktiven Alerts aller Server (offline, Datenträger, RAM/CPU, gestoppte Autostart-Dienste, Fehlerhäufung).",
				Properties: map[string]any{}},
			label: func(map[string]any) string { return "Liest aktive Alerts" },
			run: func(ctx context.Context, _ *Run, _ map[string]any) (string, error) {
				alerts, err := s.computeAlerts(ctx)
				if err != nil {
					return "", err
				}
				if len(alerts) == 0 {
					return "Keine aktiven Alerts.", nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%d aktive Alerts:\n", len(alerts))
				for _, a := range alerts {
					fmt.Fprintf(&b, "- [%s] %s (server_id %s): %s\n", a.Severity, a.Hostname, a.ServerID, a.Message)
				}
				return b.String(), nil
			},
		},
		{
			def: ai.Tool{Name: "get_server_context", Description: "Das gesammelte Wissen über einen Server: Steckbrief, Datenträger, Rollen, Abhängigkeiten, normale Auslastung, bekannte Fehlerbilder, Notizen der Administratoren (Obsidian) und das Servertagebuch. Immer zuerst aufrufen, wenn es um einen bestimmten Server geht.",
				Properties: map[string]any{"server": serverProp, "days": map[string]any{"type": "integer", "description": "Tagebuch-Zeitraum in Tagen (Standard 14)"}}, Required: []string{"server"}},
			label: func(in map[string]any) string { return "Liest das Wissen über " + str(in, "server") },
			run: func(ctx context.Context, _ *Run, in map[string]any) (string, error) {
				srv, err := s.resolveServer(ctx, str(in, "server"))
				if err != nil {
					return "", err
				}
				return s.buildContext(ctx, srv, num(in, "days", 14, 1, 365))
			},
		},
		{
			def: ai.Tool{Name: "get_services", Description: "Dienste eines Windows-Servers mit Status und Starttyp. filter grenzt per Teilstring auf Name/Anzeigename ein; only_problems liefert nur gestoppte Autostart-Dienste.",
				Properties: map[string]any{"server": serverProp, "filter": map[string]any{"type": "string"}, "only_problems": map[string]any{"type": "boolean"}}, Required: []string{"server"}},
			label: func(in map[string]any) string { return "Liest die Dienste von " + str(in, "server") },
			run:   s.toolServices,
		},
		{
			def: ai.Tool{Name: "get_events", Description: "Gespeicherte Event-Log-Einträge (Warnung und höher) eines Servers, neueste zuerst.",
				Properties: map[string]any{"server": serverProp, "hours": map[string]any{"type": "integer", "description": "Zeitraum in Stunden (Standard 24, max 720)"},
					"min_level": map[string]any{"type": "string", "enum": []string{"Warning", "Error", "Critical"}}, "source": map[string]any{"type": "string", "description": "Optional: nur diese Quelle (Teilstring)"},
					"limit": map[string]any{"type": "integer", "description": "Maximale Anzahl (Standard 40)"}}, Required: []string{"server"}},
			label: func(in map[string]any) string { return "Liest Ereignisse von " + str(in, "server") },
			run:   s.toolEvents,
		},
		{
			def: ai.Tool{Name: "get_journal", Description: "Servertagebuch: was wann passiert ist (Neustarts, gestoppte Dienste, neue Software, Fehlerbilder, Aktionen, Konsolensitzungen, frühere Analysen). Ohne server für alle Server.",
				Properties: map[string]any{"server": map[string]any{"type": "string", "description": "Optional: Hostname oder server_id"}, "days": map[string]any{"type": "integer", "description": "Zeitraum in Tagen (Standard 7)"}}},
			label: func(in map[string]any) string {
				if str(in, "server") == "" {
					return "Liest das Servertagebuch"
				}
				return "Liest das Tagebuch von " + str(in, "server")
			},
			run: s.toolJournal,
		},
		{
			def: ai.Tool{Name: "get_dependencies", Description: "Gelernter Abhängigkeitsgraph: welcher Server welchen Dienst auf welchem Server nutzt (aus beobachteten TCP-Verbindungen).",
				Properties: map[string]any{"server": map[string]any{"type": "string", "description": "Optional: nur Kanten dieses Servers"}}},
			label: func(map[string]any) string { return "Liest die Abhängigkeiten" },
			run: func(ctx context.Context, _ *Run, in map[string]any) (string, error) {
				id := ""
				if ref := str(in, "server"); ref != "" {
					srv, err := s.resolveServer(ctx, ref)
					if err != nil {
						return "", err
					}
					id = srv.ID
				}
				deps, err := s.store.Dependencies(ctx, id)
				if err != nil {
					return "", err
				}
				if len(deps) == 0 {
					return "Keine Abhängigkeiten bekannt.", nil
				}
				var b strings.Builder
				for _, d := range deps {
					fmt.Fprintf(&b, "- %s → %s Port %s %s (seit %s, zuletzt %s)\n", d.SrcHost, d.DstHost, knowledge.PortName(d.Port), d.Process, d.FirstSeen.Format("2006-01-02"), d.LastSeen.Format("2006-01-02 15:04"))
				}
				return b.String(), nil
			},
		},
		{
			def: ai.Tool{Name: "list_actions", Description: "Aktionen, die ein Server anbietet, mit Risiko, Parametern und der Policy-Entscheidung für dich (allow = läuft sofort, approve = braucht Freigabe, block = gesperrt).",
				Properties: map[string]any{"server": serverProp}, Required: []string{"server"}},
			label: func(in map[string]any) string { return "Prüft verfügbare Aktionen auf " + str(in, "server") },
			run:   s.toolListActions,
		},
		{
			def: ai.Tool{Name: "run_action", Description: "Fordert eine Aktion auf einem Server an. Die Policy entscheidet: Bei allow wird sie sofort ausgeführt und du erhältst die Ausgabe (wartet bis 2 Minuten); bei approve wartet sie auf die Freigabe eines Admins; bei block wird sie abgelehnt. Gib immer eine nachvollziehbare Begründung an.",
				Properties: map[string]any{
					"server": serverProp,
					"action": map[string]any{"type": "string", "description": "Name aus list_actions, z. B. disk.large_files"},
					"params": map[string]any{"type": "object", "description": "Parameter der Aktion, z. B. {\"path\": \"C:\\\\\"}"},
					"reason": map[string]any{"type": "string", "description": "Begründung, wird Freigebenden angezeigt und auditiert"},
				}, Required: []string{"server", "action", "reason"}},
			label: func(in map[string]any) string {
				label := "Fordert " + str(in, "action") + " auf " + str(in, "server") + " an"
				if p, ok := in["params"].(map[string]any); ok && len(p) > 0 {
					var parts []string
					for k, v := range p {
						if k != "script" {
							parts = append(parts, fmt.Sprintf("%s=%v", k, v))
						}
					}
					sort.Strings(parts)
					label += " (" + strings.Join(parts, ", ") + ")"
				}
				return label
			},
			run: s.toolRunAction,
		},
	}
}

func (s *Server) toolListServers(ctx context.Context, _ *Run, _ map[string]any) (string, error) {
	list, err := s.store.ListServers(ctx, false)
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "Es sind noch keine Server registriert.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d Server (hostname | server_id | status | OS | Rollen | CPU | RAM | vollster Datenträger | Tags):\n", len(list))
	for _, srv := range list {
		status := "offline"
		if s.online(srv) {
			status = "online"
		}
		facts, _ := s.store.Facts(ctx, srv.ID, "role:")
		var roles []string
		for _, f := range facts {
			name, _, _ := strings.Cut(f.Value, "|")
			roles = append(roles, name)
		}
		cpu, mem, disk := "–", "–", "–"
		if hb := srv.Snapshot; hb != nil {
			cpu = fmt.Sprintf("%.0f %%", hb.Metrics.CPUPercent)
			if hb.Metrics.MemTotal > 0 {
				mem = fmt.Sprintf("%.0f %%", 100*float64(hb.Metrics.MemUsed)/float64(hb.Metrics.MemTotal))
			}
			worst := -1.0
			for _, d := range hb.Metrics.Disks {
				if d.Total == 0 {
					continue
				}
				if p := 100 * float64(d.Total-d.Free) / float64(d.Total); p > worst {
					worst = p
					disk = fmt.Sprintf("%s %.0f %% (%s frei)", d.Name, p, knowledge.GB(d.Free))
				}
			}
		}
		fmt.Fprintf(&b, "- %s | %s | %s | %s | %s | %s | %s | %s | %s\n", srv.Hostname, srv.ID, status, srv.OSVersion, strings.Join(roles, ", "), cpu, mem, disk, strings.Join(srv.Tags, ", "))
	}
	return b.String(), nil
}

func (s *Server) toolServices(ctx context.Context, _ *Run, in map[string]any) (string, error) {
	srv, err := s.resolveServer(ctx, str(in, "server"))
	if err != nil {
		return "", err
	}
	if srv.Snapshot == nil || len(srv.Snapshot.Services) == 0 {
		return "Keine Dienstinformationen für diesen Server.", nil
	}
	filter := strings.ToLower(str(in, "filter"))
	onlyProblems, _ := in["only_problems"].(bool)
	var b strings.Builder
	n := 0
	for _, svc := range srv.Snapshot.Services {
		if filter != "" && !strings.Contains(strings.ToLower(svc.Name+" "+svc.DisplayName), filter) {
			continue
		}
		if onlyProblems && !(knowledge.IsAutoStart(svc.StartType) && svc.Status == "Stopped" && !knowledge.BenignStoppedServices[strings.ToLower(svc.Name)]) {
			continue
		}
		if n++; n > 150 {
			b.WriteString("… (weitere Dienste ausgelassen, Filter verwenden)\n")
			break
		}
		fmt.Fprintf(&b, "- %s (%s): %s, Start %s\n", svc.Name, svc.DisplayName, svc.Status, svc.StartType)
	}
	if n == 0 {
		return "Keine passenden Dienste.", nil
	}
	return fmt.Sprintf("Dienste auf %s (Stand %s):\n", srv.Hostname, srv.LastSeen.Format("2006-01-02 15:04:05")) + b.String(), nil
}

var levelRank = map[string]int{"Critical": 1, "Error": 2, "Warning": 3, "Information": 4}

func (s *Server) toolEvents(ctx context.Context, _ *Run, in map[string]any) (string, error) {
	srv, err := s.resolveServer(ctx, str(in, "server"))
	if err != nil {
		return "", err
	}
	hours := num(in, "hours", 24, 1, 720)
	limit := num(in, "limit", 40, 1, 200)
	minRank := levelRank[str(in, "min_level")]
	if minRank == 0 {
		minRank = 3
	}
	source := strings.ToLower(str(in, "source"))
	evs, err := s.store.Events(ctx, srv.ID, time.Now().Add(-time.Duration(hours)*time.Hour), 2000)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for _, e := range evs {
		if r := levelRank[e.Level]; r == 0 || r > minRank {
			continue
		}
		if source != "" && !strings.Contains(strings.ToLower(e.Source), source) {
			continue
		}
		if n++; n > limit {
			break
		}
		msg := oneLine(e.Message, 400)
		fmt.Fprintf(&b, "- %s [%s] %s/%s ID %d: %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Level, e.Log, e.Source, e.EventID, msg)
	}
	if n == 0 {
		return fmt.Sprintf("Keine passenden Ereignisse in den letzten %d Stunden.", hours), nil
	}
	return b.String(), nil
}

func (s *Server) toolJournal(ctx context.Context, _ *Run, in map[string]any) (string, error) {
	id := ""
	if ref := str(in, "server"); ref != "" {
		srv, err := s.resolveServer(ctx, ref)
		if err != nil {
			return "", err
		}
		id = srv.ID
	}
	days := num(in, "days", 7, 1, 365)
	list, err := s.store.ListJournal(ctx, store.JournalFilter{ServerID: id, Since: time.Now().AddDate(0, 0, -days), Limit: 120})
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "Keine Tagebucheinträge im Zeitraum.", nil
	}
	var b strings.Builder
	for _, e := range list {
		fmt.Fprintf(&b, "- %s %s [%s/%s] %s", e.TS.Format("2006-01-02 15:04"), e.Hostname, e.Category, e.Severity, e.Title)
		if e.Author != "ServerBrain" {
			b.WriteString(" — " + e.Author)
		}
		if d := strings.TrimSpace(e.Detail); d != "" && e.Category != store.CatAI {
			b.WriteString("\n  " + oneLine(d, 300))
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (s *Server) toolListActions(ctx context.Context, run *Run, in map[string]any) (string, error) {
	srv, err := s.resolveServer(ctx, str(in, "server"))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Aktionen auf %s (Betriebssystem %s):\n", srv.Hostname, srv.OS)
	for _, name := range srv.Capabilities {
		def, ok := actions.Get(name)
		if !ok {
			continue
		}
		dec := s.policy.Evaluate(policy.Request{Action: def, Hostname: srv.Hostname, Tags: srv.Tags, ActorType: run.actor.Kind, Role: run.actor.Role})
		if run.actor.Role == policy.RoleViewer && !def.ReadOnly {
			dec.Effect = policy.Block
		}
		var params []string
		for _, p := range def.Params {
			ps := p.Name + ":" + string(p.Type)
			if p.Required {
				ps += " (Pflicht)"
			} else if p.Default != "" {
				ps += "=" + p.Default
			}
			params = append(params, ps)
		}
		ro := ""
		if def.ReadOnly {
			ro = ", read-only"
		}
		fmt.Fprintf(&b, "- %s [Risiko %s%s, Policy: %s] %s Parameter: %s\n", def.Name, def.Risk, ro, dec.Effect, def.Description, orNone(strings.Join(params, ", ")))
	}
	return b.String(), nil
}

func orNone(s string) string {
	if s == "" {
		return "keine"
	}
	return s
}

func (s *Server) toolRunAction(ctx context.Context, run *Run, in map[string]any) (string, error) {
	srv, err := s.resolveServer(ctx, str(in, "server"))
	if err != nil {
		return "", err
	}
	params, _ := in["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	reason := str(in, "reason")
	if reason == "" {
		return "", errors.New("reason fehlt")
	}
	cmd, dec, status, err := s.requestAction(ctx, run.actor, srv.ID, actionRequest{Action: str(in, "action"), Params: params, Reason: reason})
	switch {
	case status == http.StatusForbidden:
		return fmt.Sprintf("Von der Policy gesperrt (Regel %s). Diese Aktion darfst du nicht ausführen; empfiehl sie dem Administrator stattdessen.", dec.Rule), nil
	case err != nil:
		return "", err
	}
	if cmd.Status == store.StatusPendingApproval {
		return fmt.Sprintf("Wartet auf Freigabe durch einen Admin (Regel %s, Befehl %s). Die Aktion ist NICHT ausgeführt. Der Admin findet sie unter „Freigaben“.", dec.Rule, cmd.ID), nil
	}
	done, err := s.waitCommand(ctx, cmd.ID, actionWaitLimit)
	if err != nil {
		return "", err
	}
	return describeCommand(done), nil
}

// waitCommand polls until a command reached a final state or the limit.
func (s *Server) waitCommand(ctx context.Context, id string, limit time.Duration) (*store.Command, error) {
	deadline := time.Now().Add(limit)
	for {
		c, err := s.store.GetCommand(ctx, id)
		if err != nil {
			return nil, err
		}
		switch c.Status {
		case store.StatusSucceeded, store.StatusFailed, store.StatusRejected, store.StatusExpired, store.StatusCancelled:
			return c, nil
		}
		if time.Now().After(deadline) {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return c, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func describeCommand(c *store.Command) string {
	var b strings.Builder
	switch c.Status {
	case store.StatusSucceeded:
		fmt.Fprintf(&b, "Ausgeführt: %s erfolgreich.\n", c.Action)
	case store.StatusFailed:
		fmt.Fprintf(&b, "Ausgeführt: %s FEHLGESCHLAGEN.\n", c.Action)
	case store.StatusQueued, store.StatusDispatched:
		fmt.Fprintf(&b, "%s läuft noch (Status %s, Befehl %s); das Ergebnis erscheint im Servertagebuch.\n", c.Action, c.Status, c.ID)
	default:
		fmt.Fprintf(&b, "%s: Status %s.\n", c.Action, c.Status)
	}
	if r := c.Result; r != nil {
		if r.Error != "" {
			b.WriteString("Fehler: " + r.Error + "\n")
		}
		if out := strings.TrimSpace(r.Output); out != "" {
			b.WriteString("Ausgabe:\n" + out + "\n")
		}
	}
	return b.String()
}
