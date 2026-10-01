// Command sb-server runs the ServerBrain control plane.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // the diary time zone must work on hosts without tzdata

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/knowledge"
	"github.com/wsjrosiris/serverbrain/internal/policy"
	"github.com/wsjrosiris/serverbrain/internal/server"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

func main() {
	var (
		addr       = flag.String("addr", ":8443", "listen address")
		dbPath     = flag.String("db", "serverbrain.db", "SQLite database path")
		policyFile = flag.String("policy", "", "policy JSON file (default: built-in policy)")
		certFile   = flag.String("tls-cert", "", "TLS certificate (PEM); without it the server speaks plain HTTP (dev only)")
		keyFile    = flag.String("tls-key", "", "TLS private key (PEM)")
		clientCA   = flag.String("client-ca", "", "CA bundle for agent client certificates; enables mTLS on agent endpoints")
		interval   = flag.Duration("heartbeat", 30*time.Second, "agent heartbeat interval")
		trustProxy = flag.Bool("trust-proxy", false, "trust X-Forwarded-For for client addresses")
		newAdmin   = flag.String("create-admin", "", "create an additional admin user with this name, print its token and exit (token recovery)")
		vaultDir   = flag.String("vault", "vault", "Obsidian vault directory for the knowledge base and server diary (empty disables it)")
		vaultSub   = flag.String("vault-folder", "ServerBrain", "folder inside the vault that ServerBrain manages")
		timezone   = flag.String("timezone", "Europe/Berlin", "time zone for the server diary")
		aiMode     = flag.String("ai", "auto", "AI operator: auto (on when ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN/ANTHROPIC_PROFILE is set), on, off")
		aiModel    = flag.String("ai-model", "claude-opus-5-5", "Claude model for the AI operator")
		aiEffort   = flag.String("ai-effort", "high", "reasoning effort: low, medium, high, xhigh, max")
		aiAuto     = flag.Bool("ai-auto-analysis", true, "let the AI analyse critical incidents automatically (read-only)")
		autopilot  = flag.Bool("autopilot", true, "self-healing playbooks (restart stopped automatic services, inspect full disks)")
		apGrace    = flag.Duration("autopilot-grace", 2*time.Minute, "how long a service may stay stopped before the autopilot acts")
	)
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *newAdmin != "" {
		if err := createAdmin(*dbPath, *newAdmin); err != nil {
			log.Error("create admin", "err", err)
			os.Exit(1)
		}
		return
	}

	loc, err := time.LoadLocation(*timezone)
	if err != nil {
		log.Error("invalid -timezone", "err", err)
		os.Exit(2)
	}
	vault := vaultOptions{dir: *vaultDir, folder: *vaultSub, loc: loc}
	auto := automationOptions{aiMode: *aiMode, model: *aiModel, effort: *aiEffort, autoAnalysis: *aiAuto, autopilot: *autopilot, grace: *apGrace}
	if err := run(log, *addr, *dbPath, *policyFile, *certFile, *keyFile, *clientCA, *interval, *trustProxy, vault, auto); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func createAdmin(dbPath, name string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if _, tok, err := st.CreateUser(ctx, name, policy.RoleAdmin, policy.ActorHuman); err != nil {
		return fmt.Errorf("user %q could not be created (name taken?): %w", name, err)
	} else {
		_ = st.Audit(ctx, "system", "system", "user.created", name, map[string]any{"role": policy.RoleAdmin, "via": "cli"})
		fmt.Println(tok)
	}
	return nil
}

type automationOptions struct {
	aiMode, model, effort   string
	autoAnalysis, autopilot bool
	grace                   time.Duration
}

func aiCredentialsPresent() bool {
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

type vaultOptions struct {
	dir, folder string
	loc         *time.Location
}

func run(log *slog.Logger, addr, dbPath, policyFile, certFile, keyFile, clientCA string, interval time.Duration, trustProxy bool, vo vaultOptions, ao automationOptions) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	pol := policy.Default()
	if policyFile != "" {
		if pol, err = policy.Load(policyFile); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if n, err := st.CountUsers(ctx); err != nil {
		return err
	} else if n == 0 {
		_, tok, err := st.CreateUser(ctx, "admin", policy.RoleAdmin, policy.ActorHuman)
		if err != nil {
			return err
		}
		_ = st.Audit(ctx, "system", "system", "user.bootstrap", "admin", nil)
		fmt.Fprintf(os.Stderr, "\n  Bootstrap admin created. API token (shown only once):\n\n    %s\n\n", tok)
	}

	srv := server.New(server.Config{HeartbeatInterval: interval, RequireClientCert: clientCA != "", TrustProxy: trustProxy, AutoAnalysis: ao.autoAnalysis}, st, pol, log)
	switch {
	case ao.aiMode == "on" || (ao.aiMode == "auto" && aiCredentialsPresent()):
		srv.SetAI(ai.NewClaude(ai.ClaudeConfig{Model: ao.model, Effort: ao.effort}))
		log.Info("AI operator enabled", "model", ao.model, "effort", ao.effort, "auto_analysis", ao.autoAnalysis)
	case ao.aiMode == "auto":
		log.Info("AI operator disabled: no Anthropic credentials (set ANTHROPIC_API_KEY)")
	}
	if ao.autopilot {
		srv.EnableAutopilot(ctx, server.AutopilotConfig{Grace: ao.grace})
		log.Info("autopilot enabled", "grace", ao.grace)
	}
	go srv.Run(ctx)

	if vo.dir != "" {
		if err := os.MkdirAll(vo.dir, 0o755); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		v := knowledge.NewVault(vo.dir, vo.folder, vo.loc, st, log)
		srv.SetVault(v)
		go v.Run(ctx)
		log.Info("Obsidian vault enabled", "path", filepath.Join(vo.dir, vo.folder))
	}

	hs := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second, // > long-poll timeout
		IdleTimeout:       120 * time.Second,
	}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("client-ca: no certificates found")
		}
		// Browsers don't present certificates, so verification is enforced
		// per route: agent endpoints require a verified chain.
		hs.TLSConfig = &tls.Config{ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12}
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()

	if certFile != "" {
		log.Info("ServerBrain control plane listening (HTTPS)", "addr", addr, "mtls", clientCA != "")
		err = hs.ListenAndServeTLS(certFile, keyFile)
	} else {
		if clientCA != "" {
			return errors.New("-client-ca requires -tls-cert and -tls-key")
		}
		log.Warn("ServerBrain control plane listening on plain HTTP - use -tls-cert/-tls-key in production", "addr", addr)
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
