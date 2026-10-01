package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ClaudeCode runs Claude through the Claude Code CLI in headless mode
// (`claude -p`). Unlike the API provider it can authenticate with a Claude
// subscription (Pro, Max, Team, Enterprise): create a long-lived token once
// with `claude setup-token` and pass it as CLAUDE_CODE_OAUTH_TOKEN, or log
// the service account in with `claude` → /login.
//
// Claude Code runs the agent loop itself. All built-in tools (shell, files,
// web) are disabled; the only tools it gets are ServerBrain's, served over
// MCP, so policy, approvals and audit apply exactly as with the API.
//
// Subscription use is meant for your own, internal ServerBrain. Anthropic
// does not allow offering claude.ai login to third parties in products
// built on Claude Code / the Agent SDK; use API keys for that.
type ClaudeCode struct {
	cfg ClaudeCodeConfig
}

type ClaudeCodeConfig struct {
	// Command is the CLI to run, default ["claude"]. Extra leading elements
	// are passed before ServerBrain's arguments.
	Command []string
	Model   string // e.g. claude-opus-5-5; empty = the CLI's default
	Effort  string // low, medium, high, xhigh, max; empty = default
	// OAuthToken (from `claude setup-token`) is passed as
	// CLAUDE_CODE_OAUTH_TOKEN. Empty: inherit the environment / stored login.
	OAuthToken string
	// UseSubscription removes ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN
	// from the CLI's environment: in -p mode an API key would otherwise take
	// precedence over the subscription.
	UseSubscription bool
	MaxTurns        int
	Dir             string   // working directory (default: a fresh temp dir)
	Env             []string // additional environment variables
}

func NewClaudeCode(cfg ClaudeCodeConfig) *ClaudeCode {
	if len(cfg.Command) == 0 {
		cfg.Command = []string{"claude"}
	}
	if cfg.MaxTurns == 0 {
		cfg.MaxTurns = 40
	}
	return &ClaudeCode{cfg: cfg}
}

func (c *ClaudeCode) Name() string {
	m := c.cfg.Model
	if m == "" {
		m = "Standardmodell"
	}
	if c.cfg.UseSubscription {
		return "Claude-Abo über Claude Code (" + m + ")"
	}
	return "Claude Code (" + m + ")"
}

const mcpServerName = "serverbrain"

func (c *ClaudeCode) args(req AgentRequest) ([]string, error) {
	mcp, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
		mcpServerName: map[string]any{"type": "http", "url": req.MCPURL, "headers": map[string]string{"Authorization": "Bearer " + req.MCPToken}},
	}})
	if err != nil {
		return nil, err
	}
	args := append([]string{}, c.cfg.Command[1:]...)
	args = append(args,
		"-p", req.Prompt,
		"--output-format", "stream-json", "--verbose",
		"--tools", "", // no shell, file or web tools – only ServerBrain's
		"--mcp-config", string(mcp), "--strict-mcp-config",
		"--allowedTools", "mcp__"+mcpServerName+"__*",
		"--permission-mode", "dontAsk", // anything not allowed above is denied
		"--system-prompt", req.System,
		"--max-turns", fmt.Sprint(c.cfg.MaxTurns),
	)
	if c.cfg.Model != "" {
		args = append(args, "--model", c.cfg.Model)
	}
	if c.cfg.Effort != "" {
		args = append(args, "--effort", c.cfg.Effort)
	}
	if req.SessionID != "" {
		args = append(args, "--resume", req.SessionID)
	}
	return args, nil
}

func (c *ClaudeCode) env() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if c.cfg.UseSubscription && (k == "ANTHROPIC_API_KEY" || k == "ANTHROPIC_AUTH_TOKEN") {
			continue
		}
		if c.cfg.OAuthToken != "" && k == "CLAUDE_CODE_OAUTH_TOKEN" {
			continue
		}
		env = append(env, kv)
	}
	if c.cfg.OAuthToken != "" {
		env = append(env, "CLAUDE_CODE_OAUTH_TOKEN="+c.cfg.OAuthToken)
	}
	return append(env, c.cfg.Env...)
}

// streamEvent covers the stream-json events ServerBrain needs.
type streamEvent struct {
	Type      string  `json:"type"`
	Subtype   string  `json:"subtype"`
	SessionID string  `json:"session_id"`
	Result    string  `json:"result"`
	IsError   bool    `json:"is_error"`
	NumTurns  int     `json:"num_turns"`
	CostUSD   float64 `json:"total_cost_usd"`
	Message   *struct {
		Content []contentBlock `json:"content"`
	} `json:"message"`
	Content []contentBlock `json:"content"`
	Error   string         `json:"error"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (c *ClaudeCode) RunAgent(ctx context.Context, req AgentRequest) (*AgentResult, error) {
	args, err := c.args(req)
	if err != nil {
		return nil, err
	}
	dir := c.cfg.Dir
	if dir == "" {
		// An empty working directory: no project CLAUDE.md, hooks or settings.
		if dir, err = os.MkdirTemp("", "serverbrain-claude-"); err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
	}
	cmd := exec.CommandContext(ctx, c.cfg.Command[0], args...)
	cmd.Dir, cmd.Env = dir, c.env()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &limited{w: &stderr, n: 64 << 10}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("Claude Code konnte nicht gestartet werden (%s): %w", c.cfg.Command[0], err)
	}
	var mu sync.Mutex
	res := &AgentResult{}
	var final *streamEvent
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev streamEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		mu.Lock()
		if ev.SessionID != "" {
			res.SessionID = ev.SessionID
		}
		mu.Unlock()
		switch ev.Type {
		case "assistant":
			blocks := ev.Content
			if ev.Message != nil {
				blocks = ev.Message.Content
			}
			for _, b := range blocks {
				if b.Type == "text" && strings.TrimSpace(b.Text) != "" && req.OnText != nil {
					req.OnText(b.Text)
				}
			}
		case "result":
			e := ev
			final = &e
		}
	}
	waitErr := cmd.Wait()
	if final == nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && waitErr != nil {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("Claude Code lieferte kein Ergebnis: %s", tail(msg, 800))
	}
	res.Text, res.Turns, res.CostUSD = final.Result, final.NumTurns, final.CostUSD
	if final.SessionID != "" {
		res.SessionID = final.SessionID
	}
	if final.IsError {
		msg := final.Result
		if msg == "" {
			msg = final.Error
		}
		if msg == "" {
			msg = final.Subtype
		}
		if strings.Contains(strings.ToLower(msg+stderr.String()), "login") || strings.Contains(strings.ToLower(msg+stderr.String()), "auth") {
			msg += " – ist Claude Code angemeldet? (`claude setup-token` → CLAUDE_CODE_OAUTH_TOKEN)"
		}
		return res, errors.New("Claude Code: " + tail(msg, 800))
	}
	return res, nil
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

type limited struct {
	w *bytes.Buffer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}
