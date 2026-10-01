//go:build !windows

package main

import (
	"errors"
	"log/slog"
)

func runAsServiceIfNeeded(*slog.Logger) (bool, error) { return false, nil }

func installService(string) error {
	return errors.New("service installation is only supported on Windows; use a systemd unit (see deploy/serverbrain-agent.service)")
}

func uninstallService() error { return installService("") }
