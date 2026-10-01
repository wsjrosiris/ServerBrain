package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/server"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// ---------- scripted LLM ----------

// scriptLLM replays a scripted model. respond gets the conversation's turn
// number (0 = the question), the question and the tool results of the
// previous turn, and returns the next reply.
type scriptLLM struct {
	mu      sync.Mutex
	respond func(turn int, question string, results []ai.ToolResult) *ai.Reply
	seen    [][]ai.ToolResult // every batch of tool results, for assertions
	systems []string
}

func (p *scriptLLM) Name() string { return "script" }

func (p *scriptLLM) NewConversation(system string, tools []ai.Tool) ai.Conversation {
	p.mu.Lock()
	p.systems = append(p.systems, system)
	p.mu.Unlock()
	return &scriptConv{p: p}
}

type scriptConv struct {
	p        *scriptLLM
	turn     int
	question string
}

func (c *scriptConv) Ask(_ context.Context, text string) (*ai.Reply, error) {
	c.question = text
	r := c.p.respond(0, text, nil)
	c.turn = 1
	return r, nil
}

func (c *scriptConv) Answer(_ context.Context, results []ai.ToolResult) (*ai.Reply, error) {
	c.p.mu.Lock()
	c.p.seen = append(c.p.seen, results)
	c.p.mu.Unlock()
	r := c.p.respond(c.turn, c.question, results)
	c.turn++
	return r, nil
}

func call(id, name string, input map[string]any) ai.ToolCall {
	b, _ := json.Marshal(input)
	return ai.ToolCall{ID: id, Name: name, Input: b}
}

func toolUse(calls ...ai.ToolCall) *ai.Reply { return &ai.Reply{Stop: "tool_use", ToolCalls: calls} }
func final(text string) *ai.Reply            { return &ai.Reply{Stop: "end_turn", Text: text} }

// ---------- simulated Windows agent ----------

type fakeAgent struct {
	t       *testing.T
	url     string
	secret  string
	mu      sync.Mutex
	hb      protocol.Heartbeat
	exec    func(c protocol.Command) protocol.CommandResult
	onStart func(service string) // called when service.start succeeds
	ran     []protocol.Command
}

func (f *fakeAgent) setExec(fn func(c protocol.Command) protocol.CommandResult) {
	f.mu.Lock()
	f.exec = fn
	f.mu.Unlock()
}

func (f *fakeAgent) setOnStart(fn func(string)) {
	f.mu.Lock()
	f.onStart = fn
	f.mu.Unlock()
}

func (f *fakeAgent) post(path string, body any, out any) {
	f.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(b))
	if f.secret != "" {
		req.Header.Set("Authorization", "Bearer "+f.secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("%s: %s %s", path, resp.Status, data)
	}
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}

func enrollFake(t *testing.T, url, token string, hb protocol.Heartbeat) *fakeAgent {
	f := &fakeAgent{t: t, url: url, hb: hb}
	var res protocol.EnrollResponse
	f.post("/api/agent/enroll", protocol.EnrollRequest{EnrollmentToken: token, System: hb.System, AgentVersion: "test"}, &res)
	f.secret = res.AgentSecret
	f.beat()
	return f
}

func (f *fakeAgent) beat() {
	f.mu.Lock()
	hb := f.hb
	hb.Services = append([]protocol.Service(nil), f.hb.Services...)
	f.mu.Unlock()
	f.post("/api/agent/heartbeat", hb, nil)
}

func (f *fakeAgent) setService(name, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.hb.Services {
		if f.hb.Services[i].Name == name {
			f.hb.Services[i].Status = status
		}
	}
}

// serve answers commands like a real agent would.
func (f *fakeAgent) serve(ctx context.Context) {
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.url+"/api/agent/commands", nil)
		req.Header.Set("Authorization", "Bearer "+f.secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		var cmds []protocol.Command
		json.NewDecoder(resp.Body).Decode(&cmds)
		resp.Body.Close()
		for _, c := range cmds {
			f.mu.Lock()
			f.ran = append(f.ran, c)
			exec, onStart := f.exec, f.onStart
			f.mu.Unlock()
			res := exec(c)
			if c.Action == "service.start" && res.Success && onStart != nil {
				onStart(c.Params["name"])
			}
			res.Started, res.Finished = time.Now(), time.Now()
			f.post("/api/agent/commands/"+c.ID+"/result", res, nil)
		}
	}
}

func webServer() protocol.Heartbeat {
	return protocol.Heartbeat{
		AgentVersion: "test",
		System:       protocol.SystemInfo{Hostname: "WEB-03", OS: "windows", OSVersion: "Windows Server 2022", IPs: []string{"10.0.0.20"}},
		Metrics:      protocol.Metrics{CPUPercent: 5, MemTotal: 16 << 30, MemUsed: 8 << 30, Disks: []protocol.Disk{{Name: "C:", Total: 50 << 30, Free: 20 << 30}}},
		Services: []protocol.Service{
			{Name: "W3SVC", DisplayName: "World Wide Web Publishing Service", Status: "Running", StartType: "Auto"},
			{Name: "Spooler", DisplayName: "Print Spooler", Status: "Running", StartType: "Auto"},
		},
		Capabilities: []string{"service.start", "service.restart", "disk.large_files", "system.reboot", "eventlog.query"},
	}
}

type aiEnv struct {
	*env
	srv   *server.Server
	llm   *scriptLLM
	admin string
	agent *fakeAgent
	id    string
}

func newAIEnv(t *testing.T, ctx context.Context, cfg server.Config, autopilot bool) *aiEnv {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "sb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg.HeartbeatInterval, cfg.LongPollTimeout = 5*time.Second, time.Second
	srv := server.New(cfg, st, policy.Default(), log)
	llm := &scriptLLM{}
	srv.SetAI(llm)
	if autopilot {
		srv.EnableAutopilot(ctx, server.AutopilotConfig{Grace: time.Millisecond})
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	e := &env{t: t, ts: ts, store: st}
	_, admin, _ := st.CreateUser(ctx, "admin", policy.RoleAdmin, policy.ActorHuman)
	_, tok := e.call(admin, http.MethodPost, "/api/enrollment-tokens", map[string]any{})
	agent := enrollFake(t, ts.URL, tok["token"].(string), webServer())
	agent.exec = func(c protocol.Command) protocol.CommandResult {
		switch c.Action {
		case "disk.large_files":
			return protocol.CommandResult{Success: true, Output: "Largest files:\n  42.0 GiB  C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex2609.log"}
		case "service.start":
			return protocol.CommandResult{Success: true, Output: "Name: " + c.Params["name"] + "\nStatus: Running"}
		}
		return protocol.CommandResult{Success: true, Output: "ok"}
	}
	go agent.serve(ctx)
	id := e.list(admin, "/api/servers")[0]["id"].(string)
	return &aiEnv{env: e, srv: srv, llm: llm, admin: admin, agent: agent, id: id}
}

// waitRun follows a run until it is done and returns all steps.
func (a *aiEnv) waitRun(token, id string) (map[string]any, []map[string]any) {
	a.t.Helper()
	var steps []map[string]any
	next := 0
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		code, res := a.call(token, http.MethodGet, fmt.Sprintf("/api/assistant/%s/steps?after=%d", id, next), nil)
		if code != http.StatusOK {
			a.t.Fatalf("steps: %d %v", code, res)
		}
		for _, s := range res["steps"].([]any) {
			steps = append(steps, s.(map[string]any))
		}
		next = int(res["next"].(float64))
		run := res["run"].(map[string]any)
		if run["status"] != "running" {
			return run, steps
		}
	}
	a.t.Fatal("run did not finish")
	return nil, nil
}

func (a *aiEnv) journalTitles() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, j := range a.list(a.admin, "/api/journal?server="+a.id) {
		out[j["title"].(string)] = j
	}
	return out
}

func TestAIOperatorDiagnosesThroughPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAIEnv(t, ctx, server.Config{}, false)

	a.llm.respond = func(turn int, q string, results []ai.ToolResult) *ai.Reply {
		switch turn {
		case 0:
			return toolUse(
				call("c1", "get_server_context", map[string]any{"server": "web-03"}),
				call("c2", "run_action", map[string]any{"server": "WEB-03", "action": "disk.large_files", "params": map[string]any{"path": `C:\`}, "reason": "Speicherverbrauch prüfen"}),
			)
		case 1:
			return toolUse(call("c3", "run_action", map[string]any{"server": "WEB-03", "action": "system.reboot", "params": map[string]any{}, "reason": "Neustart nach Bereinigung"}))
		default:
			return final("## Diagnose\nIIS-Logs füllen C:.\n## Empfohlene Lösung\n1. Logs archivieren")
		}
	}

	code, res := a.call(a.admin, http.MethodPost, "/api/assistant", map[string]any{"question": "Warum ist WEB-03 down?", "server_id": a.id})
	if code != http.StatusCreated {
		t.Fatalf("start: %d %v", code, res)
	}
	run, steps := a.waitRun(a.admin, res["id"].(string))
	if run["status"] != "done" {
		t.Fatalf("run status %v, steps %v", run["status"], steps)
	}

	// Tool results the model saw: real knowledge and real agent output.
	first := a.llm.seen[0]
	if !strings.Contains(first[0].Content, "# Server WEB-03") || !strings.Contains(first[0].Content, "Servertagebuch") {
		t.Errorf("context tool result:\n%s", first[0].Content)
	}
	if !strings.Contains(first[1].Content, "Ausgeführt: disk.large_files erfolgreich") || !strings.Contains(first[1].Content, "u_ex2609.log") {
		t.Errorf("read-only action result:\n%s", first[1].Content)
	}
	// The risky action waits for a human.
	if !strings.Contains(a.llm.seen[1][0].Content, "Wartet auf Freigabe") {
		t.Errorf("reboot result: %s", a.llm.seen[1][0].Content)
	}
	pending := a.list(a.admin, "/api/commands?status=pending_approval")
	if len(pending) != 1 || pending[0]["action"] != "system.reboot" || pending[0]["requested_by"] != "KI für admin" || pending[0]["actor_type"] != "ai" {
		t.Fatalf("pending: %v", pending)
	}
	// The transcript shows the steps, and the answer.
	var kinds []string
	for _, s := range steps {
		kinds = append(kinds, s["kind"].(string))
	}
	// Parallel tool calls may interleave their steps.
	if got := strings.Join(kinds, ","); !strings.HasPrefix(got, "question,") || !strings.HasSuffix(got, ",answer") || strings.Count(got, "tool") != 3 || strings.Count(got, "result") != 3 {
		t.Errorf("steps: %s", got)
	}
	// The analysis is in the diary (and thus the Obsidian vault).
	if j, ok := a.journalTitles()["KI-Analyse: Warum ist WEB-03 down?"]; !ok || !strings.Contains(j["detail"].(string), "IIS-Logs") || j["author"] != "KI für admin" {
		t.Errorf("diary entry missing: %v", a.journalTitles())
	}

	// A viewer's AI cannot change anything, even where the policy would let
	// an operator's AI act.
	_, viewer, _ := a.store.CreateUser(ctx, "auditor", policy.RoleViewer, policy.ActorHuman)
	a.llm.respond = func(turn int, q string, results []ai.ToolResult) *ai.Reply {
		if turn == 0 {
			return toolUse(call("v1", "run_action", map[string]any{"server": "WEB-03", "action": "service.restart", "params": map[string]any{"name": "W3SVC"}, "reason": "test"}))
		}
		return final(results[0].Content)
	}
	_, res = a.call(viewer, http.MethodPost, "/api/assistant", map[string]any{"question": "Starte IIS neu"})
	_, steps = a.waitRun(viewer, res["id"].(string))
	if ans := steps[len(steps)-1]["detail"].(string); !strings.Contains(ans, "gesperrt") {
		t.Errorf("viewer AI was not blocked: %s", ans)
	}
	// Others cannot read someone's conversation.
	if code, _ := a.call(viewer, http.MethodGet, "/api/assistant/"+run["id"].(string)+"/steps?wait=0", nil); code != http.StatusForbidden {
		t.Errorf("viewer read admin conversation: %d", code)
	}
}

func TestAutopilotRestartsServiceAndEscalates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAIEnv(t, ctx, server.Config{AutoAnalysis: true}, true)
	a.llm.respond = func(turn int, q string, results []ai.ToolResult) *ai.Reply {
		if turn == 0 {
			if !strings.HasPrefix(q, "[Kontext") || !strings.Contains(q, "Automatische Analyse") {
				return final("unexpected question: " + q)
			}
			return toolUse(call("a1", "run_action", map[string]any{"server": "WEB-03", "action": "service.start", "params": map[string]any{"name": "W3SVC"}, "reason": "versuch"}))
		}
		return final("## Diagnose\nW3SVC stürzt ab, weil C: voll ist.\nAktionsergebnis: " + results[0].Content)
	}
	// Executing service.start brings the service back in the next heartbeat.
	a.agent.setOnStart(func(name string) { a.agent.setService(name, "Running") })

	// 1. W3SVC stops → autopilot starts it through the policy.
	a.agent.setService("W3SVC", "Stopped")
	a.agent.beat()
	waitFor(t, func() bool {
		_, ok := a.journalTitles()["Aktion ausgeführt: service.start (name=W3SVC)"]
		return ok
	}, a.journalTitles)
	j := a.journalTitles()["Aktion ausgeführt: service.start (name=W3SVC)"]
	if j["author"] != "Autopilot" || !strings.Contains(j["detail"].(string), "Autopilot: Autostart-Dienst W3SVC") {
		t.Errorf("autopilot entry: %v", j)
	}

	// 2. Maintenance mode: the autopilot leaves the server alone.
	a.call(a.admin, http.MethodPut, "/api/servers/"+a.id+"/tags", map[string]any{"tags": []string{"wartung"}})
	a.agent.beat() // W3SVC running again
	a.agent.setService("Spooler", "Stopped")
	a.agent.beat()
	waitFor(t, func() bool { _, ok := a.journalTitles()["Autopilot pausiert: Spooler nicht neu gestartet"]; return ok }, a.journalTitles)
	a.call(a.admin, http.MethodPut, "/api/servers/"+a.id+"/tags", map[string]any{"tags": []string{}})
	a.agent.setService("Spooler", "Running")
	a.agent.beat()

	// 3. A failing start escalates to a read-only automatic AI analysis.
	a.agent.setExec(func(c protocol.Command) protocol.CommandResult {
		if c.Action == "service.start" {
			return protocol.CommandResult{Success: false, Error: "exit code 1", Output: "Service 'W3SVC' cannot be started: disk full"}
		}
		return protocol.CommandResult{Success: true}
	})
	a.agent.setService("W3SVC", "Stopped")
	a.agent.beat()
	defer func() {
		if t.Failed() {
			for _, j := range a.list(a.admin, "/api/journal?server="+a.id) {
				t.Log(j["ts"], j["author"], j["title"])
			}
			for _, x := range a.list(a.admin, "/api/audit") {
				t.Log(x["actor"], x["event"], x["details"])
			}
		}
	}()
	waitFor(t, func() bool {
		for title := range a.journalTitles() {
			if strings.HasPrefix(title, "Automatische KI-Analyse:") {
				return true
			}
		}
		return false
	}, a.journalTitles)
	titles := a.journalTitles()
	if _, ok := titles["Aktion fehlgeschlagen: service.start (name=W3SVC)"]; !ok {
		t.Errorf("failed start not journaled: %v", titles)
	}
	for title, e := range titles {
		if strings.HasPrefix(title, "Automatische KI-Analyse:") {
			// The automatic analysis acts read-only: its service.start was blocked.
			if !strings.Contains(e["detail"].(string), "gesperrt") || e["author"] != "KI (automatisch)" {
				t.Errorf("auto analysis: %v", e)
			}
		}
	}
	runs := a.list(a.admin, "/api/assistant")
	if len(runs) == 0 || runs[0]["origin"] != "auto" {
		t.Errorf("auto run not listed: %v", runs)
	}
}

func waitFor(t *testing.T, cond func() bool, debug func() map[string]map[string]any) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var titles []string
	for k := range debug() {
		titles = append(titles, k)
	}
	t.Fatalf("condition not met in time; diary: %v", titles)
}
