package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Config is the agent's local configuration. It is written on enrollment
// and contains the agent secret, so it must only be readable by the service
// account (SYSTEM / Administrators on Windows, root on Linux).
type Config struct {
	ServerURL string `json:"server_url"`
	AgentID   string `json:"agent_id,omitempty"`
	Secret    string `json:"secret,omitempty"`

	// TLS: CAFile pins the control plane CA; CertFile/KeyFile enable mTLS.
	CAFile   string `json:"ca_file,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// Local, server-independent safety switches. Even a compromised control
	// plane cannot run what the agent itself refuses.
	EnableShell     bool     `json:"enable_shell"`
	DisabledActions []string `json:"disabled_actions,omitempty"`
	// ArchiveRoots restricts files.archive_old to these directories.
	ArchiveRoots []string `json:"archive_roots,omitempty"`
	// MaxConcurrent limits parallel command execution.
	MaxConcurrent int `json:"max_concurrent,omitempty"`
}

// DefaultConfigPath returns the platform specific config location.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "ServerBrain", "agent.json")
	}
	return "/etc/serverbrain/agent.json"
}

// DefaultArchiveRoots are the directories files.archive_old may touch when
// nothing else is configured.
func DefaultArchiveRoots() []string {
	if runtime.GOOS == "windows" {
		return []string{`C:\inetpub\logs`, `C:\Windows\System32\LogFiles`}
	}
	return []string{"/var/log"}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return restrictPermissions(path)
}
