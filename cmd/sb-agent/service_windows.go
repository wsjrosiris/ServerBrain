//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/wsjrosiris/serverbrain/internal/agent"
)

const serviceName = "ServerBrainAgent"

type service struct {
	log *slog.Logger
}

func (s *service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, s.log, agent.DefaultConfigPath()) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				s.log.Error("agent stopped", "err", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func runAsServiceIfNeeded(log *slog.Logger) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	if el, err := eventlog.Open(serviceName); err == nil {
		defer el.Close()
		log = slog.New(slog.NewTextHandler(&eventLogWriter{el}, nil))
	}
	err = svc.Run(serviceName, &service{log: log})
	return true, err
}

// eventLogWriter forwards agent logs to the Windows Application event log.
type eventLogWriter struct{ el *eventlog.Log }

func (w *eventLogWriter) Write(p []byte) (int, error) {
	return len(p), w.el.Info(1, string(p))
}

func installService(configPath string) error {
	if configPath != agent.DefaultConfigPath() {
		return fmt.Errorf("the service reads %s; enroll with the default -config path", agent.DefaultConfigPath())
	}
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("no config at %s - run 'sb-agent enroll' first", configPath)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      "ServerBrain Agent",
		Description:      "Reports telemetry to the ServerBrain control plane and executes approved actions.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err := s.Start(); err != nil {
		return fmt.Errorf("service installed but failed to start: %w", err)
	}
	fmt.Println("Service", serviceName, "installed and started.")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	fmt.Println("Service", serviceName, "removed.")
	return nil
}
