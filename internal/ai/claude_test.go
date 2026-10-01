package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestClaudeRequestShape checks the wire format against a mock Messages API:
// model, adaptive thinking, effort, refusal fallback, cached system prompt
// and tools, tool-use parsing and the append-only history.
func TestClaudeRequestShape(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	var betas []string
	turn := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(data, &body)
		mu.Lock()
		bodies = append(bodies, body)
		betas = append(betas, r.Header.Get("anthropic-beta"))
		turn++
		n := turn
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"tool_use",
				"content":[{"type":"thinking","thinking":"","signature":"sig123"},{"type":"text","text":"Ich prüfe den Server."},
				{"type":"tool_use","id":"toolu_1","name":"get_server_context","input":{"server":"WEB-03"}}],
				"usage":{"input_tokens":100,"output_tokens":20}}`)
			return
		}
		io.WriteString(w, `{"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"end_turn",
			"content":[{"type":"text","text":"## Diagnose\nDisk voll."}],"usage":{"input_tokens":150,"output_tokens":30}}`)
	}))
	defer ts.Close()

	c := NewClaude(ClaudeConfig{APIKey: "test", BaseURL: ts.URL})
	conv := c.NewConversation("SYSTEM", []Tool{{Name: "get_server_context", Description: "ctx", Properties: map[string]any{"server": map[string]any{"type": "string"}}, Required: []string{"server"}}})
	r1, err := conv.Ask(context.Background(), "Warum ist WEB-03 down?")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Stop != "tool_use" || len(r1.ToolCalls) != 1 || r1.ToolCalls[0].Name != "get_server_context" || !strings.Contains(string(r1.ToolCalls[0].Input), "WEB-03") || r1.Text != "Ich prüfe den Server." {
		t.Fatalf("reply 1: %+v", r1)
	}
	r2, err := conv.Answer(context.Background(), []ToolResult{{CallID: "toolu_1", Content: "Disk C: 99 %"}})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Stop != "end_turn" || !strings.Contains(r2.Text, "Disk voll") {
		t.Fatalf("reply 2: %+v", r2)
	}

	b := bodies[0]
	if b["model"] != "claude-opus-5-5" || b["fallbacks"] != "default" {
		t.Errorf("model/fallbacks: %v %v", b["model"], b["fallbacks"])
	}
	if th := b["thinking"].(map[string]any); th["type"] != "adaptive" {
		t.Errorf("thinking: %v", th)
	}
	if oc := b["output_config"].(map[string]any); oc["effort"] != "high" {
		t.Errorf("output_config: %v", oc)
	}
	if sys := b["system"].([]any)[0].(map[string]any); sys["cache_control"] == nil || sys["text"] != "SYSTEM" {
		t.Errorf("system: %v", sys)
	}
	tools := b["tools"].([]any)
	if tool := tools[len(tools)-1].(map[string]any); tool["cache_control"] == nil || tool["input_schema"].(map[string]any)["type"] != "object" {
		t.Errorf("tool: %v", tool)
	}
	if !strings.Contains(betas[0], "server-side-fallback-2026-07-01") {
		t.Errorf("beta header: %q", betas[0])
	}
	// Second request: full history, assistant turn verbatim (thinking
	// signature included), tool result in a user message.
	msgs := bodies[1]["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("history length %d", len(msgs))
	}
	asst, _ := json.Marshal(msgs[1])
	if !strings.Contains(string(asst), "sig123") || !strings.Contains(string(asst), "toolu_1") {
		t.Errorf("assistant turn not replayed verbatim: %s", asst)
	}
	res, _ := json.Marshal(msgs[2])
	if !strings.Contains(string(res), `"tool_result"`) || !strings.Contains(string(res), "Disk C: 99 %") {
		t.Errorf("tool result: %s", res)
	}
}
