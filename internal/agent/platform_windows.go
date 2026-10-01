//go:build windows

package agent

import (
	"os"
	"os/exec"
	"syscall"
)

func isReparsePoint(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// restrictPermissions limits the config file (which holds the agent secret)
// to SYSTEM and the local Administrators group.
func restrictPermissions(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F").Run()
}
