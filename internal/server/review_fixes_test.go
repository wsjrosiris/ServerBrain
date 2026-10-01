package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/server"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Four eyes: a person must not approve what their own AI assistant requested.
func TestFourEyesCoversAIRequestsOnBehalfOfAPerson(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pol := policy.Default()
	pol.AllowSelfApproval = false
	a := newAIEnvPolicy(t, ctx, server.Config{}, false, true, pol)
	_, bob, _ := a.store.CreateUser(ctx, "bob", policy.RoleAdmin, policy.ActorHuman)
	a.llm.respond = func(turn int, q string, results []ai.ToolResult) *ai.Reply {
		if turn == 0 {
			return toolUse(call("r1", "run_action", map[string]any{"server": "WEB-03", "action": "system.reboot", "params": map[string]any{}, "reason": "Updates"}))
		}
		return final(results[0].Content)
	}
	_, res := a.call(a.admin, http.MethodPost, "/api/assistant", map[string]any{"question": "Starte WEB-03 neu"})
	a.waitRun(a.admin, res["id"].(string))
	pending := a.list(a.admin, "/api/commands?status=pending_approval")
	if len(pending) != 1 || pending[0]["on_behalf_of"] != "admin" {
		t.Fatalf("pending: %v", pending)
	}
	id := pending[0]["id"].(string)
	if code, _ := a.call(a.admin, http.MethodPost, "/api/commands/"+id+"/approve", nil); code != http.StatusForbidden {
		t.Fatalf("admin approved the request of their own AI assistant: %d", code)
	}
	if code, _ := a.call(bob, http.MethodPost, "/api/commands/"+id+"/approve", nil); code != http.StatusOK {
		t.Fatalf("second admin could not approve: %d", code)
	}
}

// Work held only in memory is lost on restart; incidents must not stay stuck.
func TestInterruptedIncidentsAreRecoveredOnStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAIEnvOpt(t, ctx, server.Config{}, false, false)
	mk := func(key, status string, plan []store.PlanStep) string {
		inc := &store.Incident{ServerID: a.id, Key: key, Kind: "service_stopped", Title: key, Severity: store.SevCrit, Status: status, Plan: plan}
		if err := a.store.CreateIncident(ctx, inc); err != nil {
			t.Fatal(err)
		}
		return inc.ID
	}
	executing := mk("svc:a", store.IncExecuting, []store.PlanStep{{Action: "service.start", Status: "succeeded"}, {Action: "service.start", Status: "running"}})
	analyzing := mk("svc:b", store.IncAnalyzing, nil)
	autopilot := mk("svc:c", store.IncAutopilot, nil)
	proposed := mk("svc:d", store.IncProposed, nil)

	a.srv.RecoverInterrupted(ctx) // what Run does on start

	get := func(id string) *store.Incident {
		inc, err := a.store.GetIncident(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return inc
	}
	if inc := get(executing); inc.Status != store.IncFailed || inc.Plan[0].Status != "succeeded" || inc.Plan[1].Status != "interrupted" || !strings.Contains(inc.Resolution, "Neustart") {
		t.Errorf("executing incident: %+v", inc)
	}
	if inc := get(analyzing); inc.Status != store.IncNew {
		t.Errorf("analyzing incident: %s", inc.Status)
	}
	if inc := get(autopilot); inc.Status != store.IncNew {
		t.Errorf("autopilot incident: %s", inc.Status)
	}
	if inc := get(proposed); inc.Status != store.IncProposed {
		t.Errorf("untouched incident changed: %s", inc.Status)
	}
	// Recovered incidents can be handled again.
	if code, _ := a.call(a.admin, http.MethodPost, "/api/incidents/"+executing+"/close", map[string]any{"resolved": true, "note": "geprüft"}); code != http.StatusOK {
		t.Errorf("recovered incident cannot be closed: %d", code)
	}
	if _, ok := a.journalTitles()["Vorfall unterbrochen: svc:a"]; !ok {
		t.Error("interruption not in diary")
	}
}
