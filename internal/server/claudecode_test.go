package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/server"
)

// TestMain lets the test binary double as a fake `claude` CLI: the Claude
// Code backend starts os.Args[0] with SB_FAKE_CLAUDE=1.
func TestMain(m *testing.M) {
	if os.Getenv("SB_FAKE_CLAUDE") == "1" {
		os.Exit(fakeClaude(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeClaude behaves like `claude -p ... --output-format stream-json`: it
// talks MCP to ServerBrain like Claude Code would and prints stream-json.
func fakeClaude(args []string) int {
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			flags[args[i]] = args[i+1]
			i++
		} else {
			flags[args[i]] = "true"
		}
	}
	emit := func(v any) { b, _ := json.Marshal(v); fmt.Println(string(b)) }
	fail := func(msg string) int {
		emit(map[string]any{"type": "result", "subtype": "error", "is_error": true, "result": msg, "session_id": "s"})
		return 1
	}
	// The invocation must lock Claude Code down to ServerBrain's tools.
	switch {
	case flags["--tools"] != "":
		return fail("built-in tools not disabled")
	case flags["--allowedTools"] != "mcp__serverbrain__*" || flags["--permission-mode"] != "dontAsk" || flags["--strict-mcp-config"] != "true":
		return fail(fmt.Sprintf("unsafe flags: %v", flags))
	case os.Getenv("ANTHROPIC_API_KEY") != "":
		return fail("API key leaked into subscription mode")
	case os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "sk-ant-oat-test":
		return fail("subscription token missing")
	case !strings.Contains(flags["--system-prompt"], "KI-Operator von ServerBrain"):
		return fail("system prompt missing")
	}
	var cfg struct {
		MCPServers map[string]struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(flags["--mcp-config"]), &cfg); err != nil {
		return fail("bad mcp config")
	}
	srv := cfg.MCPServers["serverbrain"]
	id := 0
	rpc := func(method string, params any) map[string]any {
		id++
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		for k, v := range srv.Headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	session := "sess-1"
	if flags["--resume"] == "sess-1" {
		session = "sess-2"
	}
	emit(map[string]any{"type": "system", "subtype": "init", "session_id": session, "mcp_servers": []any{map[string]any{"name": "serverbrain", "status": "connected"}}})
	init := rpc("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "fake-claude"}})
	if init["result"] == nil {
		return fail(fmt.Sprintf("initialize failed: %v", init))
	}
	list := rpc("tools/list", map[string]any{})
	var names []string
	for _, t := range list["result"].(map[string]any)["tools"].([]any) {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	emit(map[string]any{"type": "assistant", "session_id": session, "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": "Ich prüfe WEB-03."}}}})
	text := func(r map[string]any) string {
		res, _ := r["result"].(map[string]any)
		if res == nil {
			return fmt.Sprint(r)
		}
		c := res["content"].([]any)[0].(map[string]any)
		return fmt.Sprintf("%v|isError=%v", c["text"], res["isError"])
	}
	ctxRes := text(rpc("tools/call", map[string]any{"name": "get_server_context", "arguments": map[string]any{"server": "WEB-03"}}))
	actRes := text(rpc("tools/call", map[string]any{"name": "run_action", "arguments": map[string]any{"server": "WEB-03", "action": "disk.large_files", "params": map[string]any{"path": `C:\`}, "reason": "Platz prüfen"}}))
	rebootRes := text(rpc("tools/call", map[string]any{"name": "run_action", "arguments": map[string]any{"server": "WEB-03", "action": "system.reboot", "params": map[string]any{}, "reason": "test"}}))
	answer := fmt.Sprintf("TOOLS=%s\nCTX=%t\nACT=%s\nREBOOT=%s\nPROMPT=%s", strings.Join(names, ","),
		strings.Contains(ctxRes, "# Server WEB-03"), firstLineOf(actRes), firstLineOf(rebootRes), flags["-p"])
	emit(map[string]any{"type": "result", "subtype": "success", "is_error": false, "result": answer, "session_id": session, "num_turns": 3, "total_cost_usd": 0})
	return 0
}

func firstLineOf(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func TestClaudeCodeBackendUsesSubscriptionAndMCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api-must-not-be-used")
	a := newAIEnvOpt(t, ctx, server.Config{}, false, false)
	a.srv.SetAI(ai.NewClaudeCode(ai.ClaudeCodeConfig{
		Command: []string{os.Args[0]}, Env: []string{"SB_FAKE_CLAUDE=1"},
		OAuthToken: "sk-ant-oat-test", UseSubscription: true, Model: "claude-opus-5-5", Effort: "high",
	}))

	_, status := a.call(a.admin, http.MethodGet, "/api/assistant/status", nil)
	if status["enabled"] != true || !strings.Contains(status["model"].(string), "Claude-Abo") {
		t.Fatalf("status: %v", status)
	}
	code, res := a.call(a.admin, http.MethodPost, "/api/assistant", map[string]any{"question": "Warum ist WEB-03 down?", "server_id": a.id})
	if code != http.StatusCreated {
		t.Fatalf("start: %d %v", code, res)
	}
	run, steps := a.waitRun(a.admin, res["id"].(string))
	if run["status"] != "done" {
		t.Fatalf("run: %v %v", run, steps)
	}
	answer := steps[len(steps)-1]["detail"].(string)
	for _, want := range []string{
		"TOOLS=list_servers,get_alerts,get_server_context", // ServerBrain's tools, served via MCP
		"CTX=true", // real knowledge
		"ACT=Ausgeführt: disk.large_files erfolgreich", // executed through the policy on the agent
		"REBOOT=Wartet auf Freigabe",                   // risky actions still need a human
		"PROMPT=[Kontext: Die Frage bezieht sich auf den Server WEB-03",
	} {
		if !strings.Contains(answer, want) {
			t.Errorf("answer misses %q:\n%s", want, answer)
		}
	}
	// Live steps: text between tool calls and every tool call are visible.
	var kinds []string
	for _, s := range steps {
		kinds = append(kinds, s["kind"].(string)+":"+s["title"].(string))
	}
	joined := strings.Join(kinds, "\n")
	if !strings.Contains(joined, "status:Ich prüfe WEB-03.") || !strings.Contains(joined, "tool:Fordert disk.large_files auf WEB-03 an") {
		t.Errorf("steps:\n%s", joined)
	}
	// The command ran as the AI on behalf of the admin.
	var cmd map[string]any
	for _, c := range a.list(a.admin, "/api/commands") {
		if c["action"] == "disk.large_files" {
			cmd = c
		}
	}
	if cmd["requested_by"] != "KI für admin" || cmd["actor_type"] != "ai" {
		t.Errorf("command: %v", cmd)
	}

	// A follow-up question resumes the Claude Code session.
	if code, _ := a.call(a.admin, http.MethodPost, "/api/assistant/"+run["id"].(string)+"/ask", map[string]any{"question": "Und jetzt?"}); code != http.StatusAccepted {
		t.Fatalf("follow-up: %d", code)
	}
	_, steps = a.waitRun(a.admin, run["id"].(string))
	if last := steps[len(steps)-1]; last["kind"] != "answer" {
		t.Fatalf("follow-up steps: %v", steps)
	}

	// The MCP endpoint rejects anything without a live run token.
	resp, err := http.Post(a.srvMCPURL(t), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("MCP without token: %d", resp.StatusCode)
	}
}

// srvMCPURL finds the loopback MCP endpoint via a diagnostic accessor.
func (a *aiEnv) srvMCPURL(t *testing.T) string {
	u, err := a.srv.MCPURL()
	if err != nil {
		t.Fatal(err)
	}
	return u
}
