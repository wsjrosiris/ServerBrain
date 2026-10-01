package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/agent"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/server"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// transcript follows a session's output long-poll like the console does.
type transcript struct {
	e      *env
	token  string
	id     string
	next   int
	text   strings.Builder
	status string
	cwd    string
}

func (tr *transcript) poll() []map[string]any {
	tr.e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/sessions/%s/output?after=%d", tr.e.ts.URL, tr.id, tr.next), nil)
	req.Header.Set("Authorization", "Bearer "+tr.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tr.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Session map[string]any   `json:"session"`
		Chunks  []map[string]any `json:"chunks"`
		Next    int              `json:"next"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		tr.e.t.Fatal(err)
	}
	tr.next = out.Next
	tr.status, _ = out.Session["status"].(string)
	for _, c := range out.Chunks {
		if c["kind"] == "output" {
			tr.text.WriteString(c["text"].(string))
		}
		if c["kind"] == "ready" {
			tr.cwd, _ = c["cwd"].(string)
		}
	}
	return out.Chunks
}

// waitReady polls until the shell reports it is ready for input.
func (tr *transcript) waitReady() map[string]any {
	tr.e.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range tr.poll() {
			if c["kind"] == "ready" {
				return c
			}
			if c["kind"] == "error" {
				tr.e.t.Fatalf("session error: %v", c["text"])
			}
		}
	}
	tr.e.t.Fatalf("session %s never became ready (status %s)", tr.id, tr.status)
	return nil
}

func TestConsoleSessionRunsOnAgent(t *testing.T) {
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
	_, operator, _ := st.CreateUser(ctx, "op", policy.RoleOperator, policy.ActorHuman)
	_, ai, _ := st.CreateUser(ctx, "copilot", policy.RoleOperator, policy.ActorAI)
	_, tok := e.call(admin, http.MethodPost, "/api/enrollment-tokens", map[string]any{})

	ag, _ := agent.New(&agent.Config{ServerURL: ts.URL, EnableShell: true}, log)
	if err := ag.Enroll(ctx, tok["token"].(string)); err != nil {
		t.Fatal(err)
	}
	go ag.Run(ctx)
	var serverID string
	for deadline := time.Now().Add(10 * time.Second); serverID == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, s := range e.list(admin, "/api/servers") {
			if s["online"] == true {
				serverID = s["id"].(string)
			}
		}
	}
	if serverID == "" {
		t.Fatal("agent never came online")
	}

	// Only humans with policy permission may open a console.
	if code, _ := e.call(ai, http.MethodPost, "/api/servers/"+serverID+"/sessions", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("AI opened a session: %d", code)
	}
	if code, _ := e.call(operator, http.MethodPost, "/api/servers/"+serverID+"/sessions", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("operator opened a session despite policy: %d", code)
	}

	code, res := e.call(admin, http.MethodPost, "/api/servers/"+serverID+"/sessions", map[string]any{"reason": "investigate IIS"})
	if code != http.StatusCreated {
		t.Fatalf("open session: %d %v", code, res)
	}
	tr := &transcript{e: e, token: admin, id: res["session"].(map[string]any)["id"].(string)}
	tr.waitReady()
	if tr.status != "open" {
		t.Fatalf("status after ready: %s", tr.status)
	}

	input := func(code string) map[string]any {
		t.Helper()
		if c, r := e.call(admin, http.MethodPost, "/api/sessions/"+tr.id+"/input", map[string]any{"code": code}); c != http.StatusAccepted {
			t.Fatalf("input %q: %d %v", code, c, r)
		}
		return tr.waitReady()
	}

	// State persists between commands: variables and working directory.
	dir := t.TempDir()
	input("SB_TEST_VAR=persisted; cd " + dir)
	ready := input("echo value=$SB_TEST_VAR; pwd")
	if !strings.Contains(tr.text.String(), "value=persisted") {
		t.Fatalf("variable did not persist; output:\n%s", tr.text.String())
	}
	if tr.cwd != dir || ready["ok"] != true {
		t.Fatalf("cwd %q (want %q), ready %v", tr.cwd, dir, ready)
	}
	if r := input("false"); r["ok"] == true {
		t.Fatal("failing command reported as ok")
	}

	// Other users cannot type into someone else's session.
	if c, _ := e.call(operator, http.MethodPost, "/api/sessions/"+tr.id+"/input", map[string]any{"code": "id"}); c != http.StatusForbidden {
		t.Fatalf("foreign input accepted: %d", c)
	}

	// Reset gives a fresh shell (variable gone).
	if c, _ := e.call(admin, http.MethodPost, "/api/sessions/"+tr.id+"/reset", nil); c != http.StatusAccepted {
		t.Fatalf("reset: %d", c)
	}
	tr.waitReady()
	tr.text.Reset()
	input("echo value=${SB_TEST_VAR:-empty}")
	if !strings.Contains(tr.text.String(), "value=empty") {
		t.Fatalf("reset did not restart shell; output:\n%s", tr.text.String())
	}

	// "exit" ends the shell on the server and the session closes.
	if c, _ := e.call(admin, http.MethodPost, "/api/sessions/"+tr.id+"/input", map[string]any{"code": "exit"}); c != http.StatusAccepted {
		t.Fatal("exit not accepted")
	}
	for deadline := time.Now().Add(10 * time.Second); tr.status != "closed" && time.Now().Before(deadline); {
		tr.poll()
	}
	if tr.status != "closed" {
		t.Fatalf("session not closed after exit: %s", tr.status)
	}
	if c, _ := e.call(admin, http.MethodPost, "/api/sessions/"+tr.id+"/input", map[string]any{"code": "id"}); c != http.StatusConflict {
		t.Fatalf("input into closed session: %d", c)
	}

	// The session is summarized in the server diary.
	foundDiary := false
	for _, j := range e.list(admin, "/api/journal?server="+serverID) {
		if strings.HasPrefix(j["title"].(string), "Konsolensitzung:") {
			foundDiary = true
			if d := j["detail"].(string); !strings.Contains(d, "SB_TEST_VAR=persisted") || !strings.Contains(d, "investigate IIS") {
				t.Errorf("session diary detail: %s", d)
			}
		}
	}
	if !foundDiary {
		t.Error("console session not in diary")
	}

	// Every typed command is in the audit log.
	inputs := 0
	events := map[string]bool{}
	for _, a := range e.list(admin, "/api/audit") {
		events[a["event"].(string)] = true
		if a["event"] == "session.input" {
			inputs++
		}
	}
	if inputs < 4 {
		t.Errorf("expected audited inputs, got %d", inputs)
	}
	for _, want := range []string{"session.requested", "session.opened", "session.reset", "session.closed", "session.blocked"} {
		if !events[want] {
			t.Errorf("audit log misses %s", want)
		}
	}
}

func TestConsoleSessionApproval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, _ := store.Open(filepath.Join(t.TempDir(), "sb.db"))
	defer st.Close()
	pol := &policy.Policy{AllowSelfApproval: false, Rules: []policy.Rule{
		{Name: "console-needs-approval", Actions: []string{"shell.run"}, Effect: policy.Approve},
	}}
	srv := server.New(server.Config{HeartbeatInterval: 5 * time.Second, LongPollTimeout: 2 * time.Second}, st, pol, log)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	e := &env{t: t, ts: ts, store: st}
	_, alice, _ := st.CreateUser(ctx, "alice", policy.RoleAdmin, policy.ActorHuman)
	_, bob, _ := st.CreateUser(ctx, "bob", policy.RoleAdmin, policy.ActorHuman)
	_, tok := e.call(alice, http.MethodPost, "/api/enrollment-tokens", map[string]any{})
	ag, _ := agent.New(&agent.Config{ServerURL: ts.URL, EnableShell: true}, log)
	if err := ag.Enroll(ctx, tok["token"].(string)); err != nil {
		t.Fatal(err)
	}
	go ag.Run(ctx)
	var serverID string
	for deadline := time.Now().Add(10 * time.Second); serverID == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, s := range e.list(alice, "/api/servers") {
			if s["online"] == true {
				serverID = s["id"].(string)
			}
		}
	}

	_, res := e.call(alice, http.MethodPost, "/api/servers/"+serverID+"/sessions", map[string]any{"reason": "hotfix"})
	sess := res["session"].(map[string]any)
	if sess["status"] != "pending_approval" {
		t.Fatalf("expected pending approval, got %v", sess["status"])
	}
	id := sess["id"].(string)
	if c, _ := e.call(alice, http.MethodPost, "/api/sessions/"+id+"/input", map[string]any{"code": "id"}); c != http.StatusConflict {
		t.Fatalf("input before approval: %d", c)
	}
	if c, _ := e.call(alice, http.MethodPost, "/api/sessions/"+id+"/approve", nil); c != http.StatusForbidden {
		t.Fatalf("self approval allowed: %d", c)
	}
	if c, _ := e.call(bob, http.MethodPost, "/api/sessions/"+id+"/approve", nil); c != http.StatusOK {
		t.Fatalf("approval by second admin: %d", c)
	}
	tr := &transcript{e: e, token: alice, id: id}
	tr.waitReady()
	if tr.status != "open" {
		t.Fatalf("status after approval: %s", tr.status)
	}
	if c, _ := e.call(alice, http.MethodDelete, "/api/sessions/"+id, nil); c != http.StatusNoContent {
		t.Fatalf("close: %d", c)
	}
}
