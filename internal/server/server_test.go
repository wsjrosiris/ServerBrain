package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/agent"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/server"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

type env struct {
	t     *testing.T
	ts    *httptest.Server
	store *store.Store
}

func (e *env) call(token, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (e *env) list(token, path string) []map[string]any {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("%s: %v", path, err)
	}
	return out
}

func (e *env) waitStatus(token, id string, want ...string) map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, c := e.call(token, http.MethodGet, "/api/commands/"+id, nil)
		for _, w := range want {
			if c["status"] == w {
				return c
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.t.Fatalf("command %s did not reach %v", id, want)
	return nil
}

func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	st, err := store.Open(filepath.Join(t.TempDir(), "sb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := server.New(server.Config{HeartbeatInterval: 5 * time.Second, LongPollTimeout: 2 * time.Second}, st, policy.Default(), log)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	e := &env{t: t, ts: ts, store: st}

	_, admin, _ := st.CreateUser(ctx, "admin", policy.RoleAdmin, policy.ActorHuman)
	_, ai, _ := st.CreateUser(ctx, "copilot", policy.RoleOperator, policy.ActorAI)
	_, viewer, _ := st.CreateUser(ctx, "auditor", policy.RoleViewer, policy.ActorHuman)

	// Viewers cannot create enrollment tokens.
	if code, _ := e.call(viewer, http.MethodPost, "/api/enrollment-tokens", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("viewer created enrollment token: %d", code)
	}
	code, tok := e.call(admin, http.MethodPost, "/api/enrollment-tokens", map[string]any{"tags": []string{"web"}})
	if code != http.StatusCreated {
		t.Fatalf("enrollment token: %d", code)
	}

	// Enroll and start a real agent against the control plane.
	cfg := &agent.Config{ServerURL: ts.URL}
	ag, err := agent.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := ag.Enroll(ctx, tok["token"].(string)); err != nil {
		t.Fatal(err)
	}
	// The token was single-use.
	second, _ := agent.New(&agent.Config{ServerURL: ts.URL}, log)
	if err := second.Enroll(ctx, tok["token"].(string)); err == nil {
		t.Fatal("enrollment token reused")
	}
	go ag.Run(ctx)

	var serverID string
	deadline := time.Now().Add(10 * time.Second)
	for serverID == "" && time.Now().Before(deadline) {
		for _, s := range e.list(admin, "/api/servers") {
			if s["online"] == true {
				serverID = s["id"].(string)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if serverID == "" {
		t.Fatal("agent never came online")
	}

	u, _ := url.Parse(ts.URL)
	port := u.Port()

	// 1. Read-only action by the AI runs immediately and succeeds.
	code, res := e.call(ai, http.MethodPost, "/api/servers/"+serverID+"/actions", map[string]any{
		"action": "network.test_port", "params": map[string]any{"host": "127.0.0.1", "port": port}, "reason": "check connectivity",
	})
	if code != http.StatusAccepted {
		t.Fatalf("request action: %d %v", code, res)
	}
	id := res["command"].(map[string]any)["id"].(string)
	c := e.waitStatus(admin, id, store.StatusSucceeded, store.StatusFailed)
	if c["status"] != store.StatusSucceeded {
		t.Fatalf("test_port failed: %v", c["result"])
	}

	// 2. A risky action by the AI needs approval; the AI cannot approve it.
	code, res = e.call(ai, http.MethodPost, "/api/servers/"+serverID+"/actions", map[string]any{
		"action": "system.reboot", "params": map[string]any{"delay_seconds": 600}, "reason": "pending updates",
	})
	if code != http.StatusAccepted || res["command"].(map[string]any)["status"] != store.StatusPendingApproval {
		t.Fatalf("reboot should await approval: %d %v", code, res)
	}
	rid := res["command"].(map[string]any)["id"].(string)
	if code, _ := e.call(ai, http.MethodPost, "/api/commands/"+rid+"/approve", nil); code != http.StatusForbidden {
		t.Fatalf("AI approved its own request: %d", code)
	}
	if code, _ := e.call(admin, http.MethodPost, "/api/commands/"+rid+"/reject", nil); code != http.StatusOK {
		t.Fatalf("reject: %d", code)
	}
	if code, _ := e.call(admin, http.MethodPost, "/api/commands/"+rid+"/approve", nil); code != http.StatusConflict {
		t.Fatalf("approving a rejected command should conflict: %d", code)
	}

	// 3. Policy blocks: viewer changes, shell for non-admins, disabled capability.
	if code, _ := e.call(viewer, http.MethodPost, "/api/servers/"+serverID+"/actions", map[string]any{"action": "temp.cleanup"}); code != http.StatusForbidden {
		t.Fatalf("viewer action not blocked: %d", code)
	}
	if code, _ := e.call(admin, http.MethodPost, "/api/servers/"+serverID+"/actions", map[string]any{"action": "shell.run", "params": map[string]any{"script": "id"}}); code != http.StatusConflict {
		t.Fatalf("shell.run must be unavailable when the agent did not enable it: %d", code)
	}
	// 4. Parameter validation stops injection attempts.
	if code, _ := e.call(admin, http.MethodPost, "/api/servers/"+serverID+"/actions", map[string]any{"action": "network.test_port", "params": map[string]any{"host": "x;rm -rf /", "port": 1}}); code != http.StatusBadRequest {
		t.Fatalf("invalid params accepted: %d", code)
	}

	// 5. Preview shows the decision without creating a command.
	code, prev := e.call(ai, http.MethodPost, "/api/servers/"+serverID+"/actions/preview", map[string]any{"action": "files.archive_old", "params": map[string]any{"path": "/var/log/app"}})
	if code != http.StatusOK || prev["decision"].(map[string]any)["effect"] != "approve" {
		t.Fatalf("preview: %d %v", code, prev)
	}

	// 6. Everything is audited.
	events := map[string]bool{}
	for _, a := range e.list(admin, "/api/audit") {
		events[a["event"].(string)] = true
	}
	for _, want := range []string{"agent.enrolled", "action.requested", "command.dispatched", "command.succeeded", "action.rejected", "action.blocked"} {
		if !events[want] {
			t.Errorf("audit log misses %s (have %v)", want, events)
		}
	}
	if code, _ := e.call(viewer, http.MethodGet, "/api/audit", nil); code != http.StatusForbidden {
		t.Errorf("viewer read audit log: %d", code)
	}

	// 7. Telemetry arrived and the AI tool catalog is exposed.
	if pts := e.list(admin, "/api/servers/"+serverID+"/metrics"); len(pts) == 0 {
		t.Error("no metrics recorded")
	}
	if tools := e.list(ai, "/api/ai/tools"); len(tools) < 10 {
		t.Errorf("expected tool definitions, got %d", len(tools))
	}
}
