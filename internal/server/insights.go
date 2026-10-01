package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/knowledge"
)

type Alert struct {
	ServerID string `json:"server_id"`
	Hostname string `json:"hostname"`
	Severity string `json:"severity"` // critical, warning
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	// Suggested is a remediation the UI or AI can offer ("explain & fix").
	Suggested *SuggestedAction `json:"suggested,omitempty"`
}

type SuggestedAction struct {
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
	Label  string            `json:"label"`
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	servers, err := s.store.ListServers(r.Context(), true)
	if err != nil {
		s.internalErr(w, err)
		return
	}
	errs, err := s.store.ErrorCounts(r.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		s.internalErr(w, err)
		return
	}
	alerts := []Alert{}
	for _, srv := range servers {
		add := func(sev, kind, msg string, sug *SuggestedAction) {
			alerts = append(alerts, Alert{ServerID: srv.ID, Hostname: srv.Hostname, Severity: sev, Kind: kind, Message: msg, Suggested: sug})
		}
		if !s.online(srv) {
			last := "never"
			if !srv.LastSeen.IsZero() {
				last = srv.LastSeen.Format(time.RFC3339)
			}
			add("critical", "offline", "Agent is not reporting (last seen: "+last+")", nil)
			continue
		}
		hb := srv.Snapshot
		if hb == nil {
			continue
		}
		for _, d := range hb.Metrics.Disks {
			if d.Total == 0 {
				continue
			}
			pct := 100 * float64(d.Total-d.Free) / float64(d.Total)
			msg := fmt.Sprintf("Disk %s is %.1f%% full (%s free)", d.Name, pct, humanBytes(d.Free))
			sug := &SuggestedAction{Action: "disk.large_files", Params: map[string]string{"path": diskRoot(d.Name, srv.OS)}, Label: "Find large files"}
			switch {
			case pct >= 95:
				add("critical", "disk", msg, sug)
			case pct >= 90:
				add("warning", "disk", msg, sug)
			}
		}
		if m := hb.Metrics; m.MemTotal > 0 && float64(m.MemUsed)/float64(m.MemTotal) >= 0.95 {
			add("warning", "memory", fmt.Sprintf("Memory usage at %.1f%%", 100*float64(m.MemUsed)/float64(m.MemTotal)),
				&SuggestedAction{Action: "process.list", Params: map[string]string{}, Label: "Show top processes"})
		}
		if hb.Metrics.CPUPercent >= 95 {
			add("warning", "cpu", fmt.Sprintf("CPU usage at %.0f%%", hb.Metrics.CPUPercent),
				&SuggestedAction{Action: "process.list", Params: map[string]string{}, Label: "Show top processes"})
		}
		for _, svc := range hb.Services {
			if strings.HasPrefix(strings.ToLower(svc.StartType), "auto") && strings.EqualFold(svc.Status, "stopped") && !knowledge.BenignStoppedServices[strings.ToLower(svc.Name)] {
				add("warning", "service", fmt.Sprintf("Automatic service %s (%s) is stopped", svc.Name, svc.DisplayName),
					&SuggestedAction{Action: "service.start", Params: map[string]string{"name": svc.Name}, Label: "Start " + svc.Name})
			}
		}
		if n := errs[srv.ID]; n >= 10 {
			add("warning", "errors", fmt.Sprintf("%d error events in the last hour", n), nil)
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if alerts[i].Severity != alerts[j].Severity {
			return alerts[i].Severity == "critical"
		}
		return alerts[i].Hostname < alerts[j].Hostname
	})
	writeJSON(w, http.StatusOK, alerts)
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", n>>10)
	}
}

func diskRoot(name, os string) string {
	if os == "windows" && len(name) == 2 && name[1] == ':' {
		return name + `\`
	}
	return name
}

// handleAITools exposes the action catalog as LLM tool definitions
// (Anthropic tool-use format: name, description, input_schema). An AI
// integration calls POST /api/servers/{id}/actions with an "ai" account
// token; the policy engine, not the model, decides what actually runs.
func (s *Server) handleAITools(w http.ResponseWriter, r *http.Request) {
	tools := []map[string]any{}
	for _, d := range actions.All() {
		props := map[string]any{
			"server_id": map[string]any{"type": "string", "description": "Target server ID"},
			"reason":    map[string]any{"type": "string", "description": "Why this action is needed; shown to approvers and recorded in the audit log"},
		}
		required := []string{"server_id", "reason"}
		for _, p := range d.Params {
			prop := map[string]any{"description": p.Description}
			if p.Type == actions.TypeInt {
				prop["type"] = "integer"
				prop["minimum"] = p.Min
				if p.Max != 0 {
					prop["maximum"] = p.Max
				}
			} else {
				prop["type"] = "string"
			}
			if p.Default != "" {
				prop["description"] = fmt.Sprintf("%s (default: %s)", p.Description, p.Default)
			}
			props[p.Name] = prop
			if p.Required {
				required = append(required, p.Name)
			}
		}
		desc := fmt.Sprintf("%s Risk: %s.", d.Description, d.Risk)
		if d.ReadOnly {
			desc += " Read-only."
		}
		tools = append(tools, map[string]any{
			"name":         strings.ReplaceAll(d.Name, ".", "_"),
			"description":  desc,
			"input_schema": map[string]any{"type": "object", "properties": props, "required": required},
		})
	}
	writeJSON(w, http.StatusOK, tools)
}
