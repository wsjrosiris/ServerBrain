// Package agent implements the ServerBrain agent that runs on each managed
// server. It connects outbound to the control plane, reports telemetry via
// heartbeats, long-polls for approved commands and executes them through the
// controlled action layer.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

type Agent struct {
	cfg      *Config
	log      *slog.Logger
	client   *http.Client
	executor *Executor

	interval   time.Duration
	lastEvents time.Time
	collector  *collector
}

func New(cfg *Config, log *slog.Logger) (*Agent, error) {
	client, err := httpClient(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	return &Agent{
		cfg:        cfg,
		log:        log,
		client:     client,
		executor:   NewExecutor(cfg),
		interval:   30 * time.Second,
		lastEvents: time.Now().Add(-1 * time.Hour),
		collector:  newCollector(),
	}, nil
}

func httpClient(cfg *Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}, nil
}

// Enroll registers the agent with the control plane using a one-time token
// and stores the returned credentials in cfg.
func (a *Agent) Enroll(ctx context.Context, token string) error {
	sys := a.collector.systemInfo()
	req := protocol.EnrollRequest{EnrollmentToken: token, System: sys, AgentVersion: Version}
	var resp protocol.EnrollResponse
	if err := a.do(ctx, http.MethodPost, "/api/agent/enroll", req, &resp, false); err != nil {
		return err
	}
	a.cfg.AgentID, a.cfg.Secret = resp.AgentID, resp.AgentSecret
	return nil
}

// Capabilities returns the actions this agent offers on this platform.
func (a *Agent) Capabilities() []string {
	return a.executor.Capabilities()
}

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.Secret == "" {
		return errors.New("agent is not enrolled")
	}
	a.log.Info("agent started", "version", Version, "server", a.cfg.ServerURL, "capabilities", len(a.Capabilities()))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.heartbeatLoop(ctx) }()
	go func() { defer wg.Done(); a.commandLoop(ctx) }()
	wg.Wait()
	return nil
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	backoff := time.Second
	for {
		if err := a.heartbeat(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("heartbeat failed", "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 2*time.Minute)
			continue
		}
		backoff = time.Second
		if !sleep(ctx, a.interval) {
			return
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) error {
	since := a.lastEvents
	now := time.Now()
	hb := a.collector.collect(ctx, since)
	hb.AgentVersion = Version
	hb.Capabilities = a.Capabilities()
	var resp protocol.HeartbeatResponse
	if err := a.do(ctx, http.MethodPost, "/api/agent/heartbeat", hb, &resp, true); err != nil {
		return err
	}
	a.lastEvents = now
	if resp.IntervalSeconds >= 5 {
		a.interval = time.Duration(resp.IntervalSeconds) * time.Second
	}
	return nil
}

func (a *Agent) commandLoop(ctx context.Context) {
	sem := make(chan struct{}, a.cfg.MaxConcurrent)
	backoff := time.Second
	for ctx.Err() == nil {
		var cmds []protocol.Command
		if err := a.do(ctx, http.MethodGet, "/api/agent/commands", nil, &cmds, true); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("command poll failed", "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, c := range cmds {
			sem <- struct{}{}
			go func(c protocol.Command) {
				defer func() { <-sem }()
				a.handleCommand(ctx, c)
			}(c)
		}
	}
}

func (a *Agent) handleCommand(ctx context.Context, c protocol.Command) {
	a.log.Info("executing command", "id", c.ID, "action", c.Action)
	res := a.executor.Execute(ctx, c)
	a.log.Info("command finished", "id", c.ID, "action", c.Action, "success", res.Success)
	// Results must not get lost on a transient network error.
	for attempt := 0; attempt < 5; attempt++ {
		err := a.do(context.WithoutCancel(ctx), http.MethodPost, "/api/agent/commands/"+c.ID+"/result", res, nil, true)
		if err == nil {
			return
		}
		a.log.Warn("reporting result failed", "id", c.ID, "err", err)
		time.Sleep(time.Duration(attempt+1) * 3 * time.Second)
	}
}

func (a *Agent) do(ctx context.Context, method, path string, body, out any, auth bool) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.ServerURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "serverbrain-agent/"+Version+" ("+runtime.GOOS+")")
	if auth {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Secret)
		req.Header.Set("X-Agent-ID", a.cfg.AgentID)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Capabilities computes the action names available on this host.
func capabilitiesFor(cfg *Config) []string {
	disabled := map[string]bool{}
	for _, d := range cfg.DisabledActions {
		disabled[d] = true
	}
	var out []string
	for _, d := range actions.All() {
		if !d.AvailableOn(runtime.GOOS) || disabled[d.Name] {
			continue
		}
		if d.Optional && !(d.Name == "shell.run" && cfg.EnableShell) {
			continue
		}
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}
