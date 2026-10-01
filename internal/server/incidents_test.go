package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/server"
)

// openIncident waits for the single open incident and returns it.
func (a *aiEnv) incidentWithStatus(status string) map[string]any {
	a.t.Helper()
	var found map[string]any
	waitFor(a.t, func() bool {
		for _, inc := range a.list(a.admin, "/api/incidents") {
			if inc["status"] == status {
				found = inc
				return true
			}
		}
		return false
	}, a.journalTitles)
	return found
}

// confirmAndVerify executes the prepared solution and keeps the agent
// reporting until the incident is closed.
func (a *aiEnv) confirmAndVerify(token, id string) map[string]any {
	a.t.Helper()
	if code, res := a.call(token, http.MethodPost, "/api/incidents/"+id+"/execute", map[string]any{}); code != http.StatusAccepted {
		a.t.Fatalf("execute: %d %v", code, res)
	}
	var inc map[string]any
	waitFor(a.t, func() bool {
		a.agent.beat()
		_, inc = a.call(token, http.MethodGet, "/api/incidents/"+id, nil)
		return inc["status"] == "resolved" || inc["status"] == "failed"
	}, a.journalTitles)
	return inc
}

func TestIncidentAnalysedSolutionPreparedAndConfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAIEnv(t, ctx, server.Config{AutoAnalysis: true}, false)
	a.agent.setOnStart(func(name string) { a.agent.setService(name, "Running") })

	a.llm.respond = func(turn int, q string, results []ai.ToolResult) *ai.Reply {
		switch turn {
		case 0:
			if !strings.Contains(q, "Automatische Analyse eines Vorfalls: Dienst gestoppt: W3SVC") {
				return final("unerwartete Frage: " + q)
			}
			return toolUse(call("d1", "get_server_context", map[string]any{"server": "WEB-03"}),
				call("d2", "run_action", map[string]any{"server": "WEB-03", "action": "disk.large_files", "params": map[string]any{"path": `C:\`}, "reason": "Platz prüfen"}))
		case 1:
			// First proposal is invalid: free scripts are not allowed.
			return toolUse(call("p1", "propose_solution", map[string]any{"diagnosis": "x", "steps": []any{
				map[string]any{"action": "shell.run", "params": map[string]any{"script": "iisreset"}, "reason": "IIS zurücksetzen"}}}))
		case 2:
			if !results[0].IsError || !strings.Contains(results[0].Content, "shell.run") {
				return final("Validierung fehlte: " + results[0].Content)
			}
			return toolUse(call("p2", "propose_solution", map[string]any{
				"diagnosis": "## Diagnose\\nW3SVC wurde nach einem Absturz des App-Pools beendet.",
				"steps":     []any{map[string]any{"action": "service.start", "params": map[string]any{"name": "W3SVC"}, "reason": "Webserver wieder starten"}}}))
		default:
			return final("Lösung vorbereitet: W3SVC starten.")
		}
	}

	// 1. Error detected → incident → analysis → prepared solution.
	a.agent.setService("W3SVC", "Stopped")
	a.agent.beat()
	inc := a.incidentWithStatus("proposed")
	// An error event right afterwards is a symptom, not a new incident.
	a.agent.mu.Lock()
	a.agent.hb.Events = []protocol.Event{{Time: time.Now(), Log: "Application", Level: "Error", Source: "WAS", EventID: 5002, Message: "Application pool 'CustomerPortal' disabled"}}
	a.agent.mu.Unlock()
	a.agent.beat()
	a.agent.mu.Lock()
	a.agent.hb.Events = nil
	a.agent.mu.Unlock()
	if all := a.list(a.admin, "/api/incidents"); len(all) != 1 || !strings.Contains(all[0]["trigger"].(string), "Begleitendes Symptom: Neues Fehlerbild: WAS (ID 5002)") {
		t.Fatalf("symptom not correlated: %v", all)
	}
	plan := inc["plan"].([]any)
	step := plan[0].(map[string]any)
	if len(plan) != 1 || step["action"] != "service.start" || !strings.Contains(step["preview"].(string), "Start-Service") || inc["analysis_by"] != "KI" {
		t.Fatalf("prepared solution: %v", inc)
	}
	if !strings.Contains(inc["diagnosis"].(string), "App-Pools") || inc["effects"].([]any)[0] != "allow" {
		t.Errorf("diagnosis/effects: %v / %v", inc["diagnosis"], inc["effects"])
	}
	// Nothing was changed before the confirmation: only the read-only check ran.
	for _, c := range a.list(a.admin, "/api/commands") {
		if c["action"] != "disk.large_files" {
			t.Fatalf("executed without confirmation: %v", c)
		}
	}

	// 2. Only people with operator rights can confirm.
	_, viewer, _ := a.store.CreateUser(ctx, "auditor", policy.RoleViewer, policy.ActorHuman)
	_, bot, _ := a.store.CreateUser(ctx, "bot", policy.RoleOperator, policy.ActorAI)
	id := inc["id"].(string)
	if code, _ := a.call(viewer, http.MethodPost, "/api/incidents/"+id+"/execute", nil); code != http.StatusForbidden {
		t.Errorf("viewer confirmed: %d", code)
	}
	if code, _ := a.call(bot, http.MethodPost, "/api/incidents/"+id+"/execute", nil); code != http.StatusForbidden {
		t.Errorf("AI account confirmed: %d", code)
	}

	// 3. Confirmation → executed as the confirming person → verified.
	done := a.confirmAndVerify(a.admin, id)
	if done["status"] != "resolved" || !strings.Contains(done["resolution"].(string), "geprüft: Der Dienst W3SVC läuft") {
		t.Fatalf("after execution: %v", done)
	}
	if st := done["plan"].([]any)[0].(map[string]any); st["status"] != "succeeded" || !strings.Contains(st["output"].(string), "Running") {
		t.Errorf("step: %v", st)
	}
	var startCmd map[string]any
	for _, c := range a.list(a.admin, "/api/commands") {
		if c["action"] == "service.start" {
			startCmd = c
		}
	}
	if startCmd["requested_by"] != "admin" || startCmd["actor_type"] != "human" || !strings.Contains(startCmd["reason"].(string), "Lösung bestätigt von admin") {
		t.Errorf("command: %v", startCmd)
	}
	titles := a.journalTitles()
	for _, want := range []string{"Vorfall erkannt: Dienst gestoppt: W3SVC", "Lösung vorbereitet: Dienst gestoppt: W3SVC", "Lösung bestätigt: Dienst gestoppt: W3SVC", "Vorfall behoben: Dienst gestoppt: W3SVC"} {
		if _, ok := titles[want]; !ok {
			t.Errorf("diary misses %q", want)
		}
	}
	if code, _ := a.call(a.admin, http.MethodPost, "/api/incidents/"+id+"/execute", nil); code != http.StatusConflict {
		t.Errorf("re-executing a resolved incident: %d", code)
	}
}

func TestIncidentRuleBasedWithoutAI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAIEnvOpt(t, ctx, server.Config{HeartbeatInterval: time.Second}, false, false)

	// The start does not help: the verification must notice that.
	a.agent.setService("Spooler", "Stopped")
	a.agent.beat()
	inc := a.incidentWithStatus("proposed")
	if inc["analysis_by"] != "Regel" || inc["plan"].([]any)[0].(map[string]any)["action"] != "service.start" {
		t.Fatalf("rule-based plan: %v", inc)
	}
	failed := a.confirmAndVerify(a.admin, inc["id"].(string))
	if failed["status"] != "failed" || !strings.Contains(failed["resolution"].(string), "weiterhin gestoppt") {
		t.Fatalf("verification did not catch the persisting problem: %v", failed)
	}

	// Second attempt after fixing the cause: the agent now really starts it.
	a.agent.setOnStart(func(name string) { a.agent.setService(name, "Running") })
	ok := a.confirmAndVerify(a.admin, inc["id"].(string))
	if ok["status"] != "resolved" {
		t.Fatalf("retry: %v", ok)
	}

	// A person can also close an incident without running the solution.
	a.agent.setService("Spooler", "Stopped")
	a.agent.beat()
	again := a.incidentWithStatus("proposed")
	if code, res := a.call(a.admin, http.MethodPost, "/api/incidents/"+again["id"].(string)+"/close", map[string]any{"resolved": true, "note": "Druckdienst wird nicht mehr gebraucht"}); code != http.StatusOK || res["status"] != "resolved" {
		t.Fatalf("close: %d %v", code, res)
	}
	if _, ok := a.journalTitles()["Vorfall manuell erledigt: Dienst gestoppt: Spooler"]; !ok {
		t.Error("manual close not in diary")
	}
}
