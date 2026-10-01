// Command sb-agent is the ServerBrain agent.
//
//	sb-agent enroll  -server https://brain.example.com -token sbe_...   # register with the control plane
//	sb-agent run                                                       # run in the foreground
//	sb-agent install                                                   # install as Windows service (Windows only)
//	sb-agent uninstall                                                 # remove the Windows service
//	sb-agent capabilities                                              # list actions offered on this host
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/wsjrosiris/serverbrain/internal/agent"
)

func usage() {
	fmt.Fprintf(os.Stderr, `ServerBrain agent %s

Usage:
  sb-agent enroll -server URL -token TOKEN [-config PATH] [-ca-file PEM] [-cert PEM -key PEM] [-enable-shell] [-archive-roots DIR;DIR]
  sb-agent run [-config PATH]
  sb-agent install [-config PATH]      (Windows) install and start the Windows service
  sb-agent uninstall                   (Windows) stop and remove the Windows service
  sb-agent capabilities [-config PATH]
`, agent.Version)
	os.Exit(2)
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Started by the Windows service control manager?
	if handled, err := runAsServiceIfNeeded(log); handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", agent.DefaultConfigPath(), "config file path")

	var err error
	switch cmd {
	case "enroll":
		server := fs.String("server", "", "control plane URL, e.g. https://brain.example.com:8443")
		token := fs.String("token", "", "one-time enrollment token")
		caFile := fs.String("ca-file", "", "CA certificate to trust for the control plane")
		cert := fs.String("cert", "", "client certificate for mTLS")
		key := fs.String("key", "", "client key for mTLS")
		shell := fs.Bool("enable-shell", false, "allow the shell.run action (remote PowerShell console)")
		roots := fs.String("archive-roots", "", "semicolon separated directories files.archive_old may touch")
		fs.Parse(args)
		if *server == "" || *token == "" {
			usage()
		}
		cfg := &agent.Config{ServerURL: *server, CAFile: *caFile, CertFile: *cert, KeyFile: *key, EnableShell: *shell}
		if *roots != "" {
			cfg.ArchiveRoots = strings.Split(*roots, ";")
		}
		err = enroll(log, cfg, *token, *configPath)
	case "run":
		fs.Parse(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = runAgent(ctx, log, *configPath)
	case "install":
		fs.Parse(args)
		err = installService(*configPath)
	case "uninstall":
		fs.Parse(args)
		err = uninstallService()
	case "capabilities":
		fs.Parse(args)
		cfg, lerr := agent.LoadConfig(*configPath)
		if lerr != nil {
			cfg = &agent.Config{}
		}
		a, aerr := agent.New(cfg, log)
		if aerr != nil {
			err = aerr
			break
		}
		for _, c := range a.Capabilities() {
			fmt.Println(c)
		}
	default:
		usage()
	}
	if err != nil {
		log.Error(cmd+" failed", "err", err)
		os.Exit(1)
	}
}

func enroll(log *slog.Logger, cfg *agent.Config, token, path string) error {
	a, err := agent.New(cfg, log)
	if err != nil {
		return err
	}
	if err := a.Enroll(context.Background(), token); err != nil {
		return err
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	log.Info("enrolled", "agent_id", cfg.AgentID, "config", path)
	return nil
}

func runAgent(ctx context.Context, log *slog.Logger, path string) error {
	cfg, err := agent.LoadConfig(path)
	if err != nil {
		return fmt.Errorf("load config (run 'sb-agent enroll' first): %w", err)
	}
	a, err := agent.New(cfg, log)
	if err != nil {
		return err
	}
	return a.Run(ctx)
}
