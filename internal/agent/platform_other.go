//go:build !windows

package agent

import "os"

func isReparsePoint(string) bool { return false }

func restrictPermissions(path string) error { return os.Chmod(path, 0o600) }
