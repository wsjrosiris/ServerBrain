// Package protocol defines the wire types exchanged between the ServerBrain
// agent and the control plane. The agent always initiates the connection
// (outbound HTTPS), so no inbound ports are needed on managed servers.
package protocol

import (
	"encoding/json"
	"time"
)

// EnrollRequest is sent once by a new agent, authenticated by a one-time
// enrollment token created by an administrator.
type EnrollRequest struct {
	EnrollmentToken string     `json:"enrollment_token"`
	System          SystemInfo `json:"system"`
	AgentVersion    string     `json:"agent_version"`
}

// EnrollResponse returns the agent's identity and long-lived secret.
type EnrollResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Heartbeat carries the agent's current state. It doubles as the telemetry
// channel: metrics, inventory and new events ride along every interval.
type Heartbeat struct {
	AgentVersion string     `json:"agent_version"`
	System       SystemInfo `json:"system"`
	Metrics      Metrics    `json:"metrics"`
	Services     []Service  `json:"services"`
	Events       []Event    `json:"events"`
	Capabilities []string   `json:"capabilities"`
}

// HeartbeatResponse tells the agent how often to report.
type HeartbeatResponse struct {
	IntervalSeconds int `json:"interval_seconds"`
}

type SystemInfo struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	OSVersion string    `json:"os_version"`
	Domain    string    `json:"domain,omitempty"`
	CPUs      int       `json:"cpus"`
	BootTime  time.Time `json:"boot_time,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
}

type Metrics struct {
	CPUPercent  float64   `json:"cpu_percent"`
	MemTotal    uint64    `json:"mem_total"`
	MemUsed     uint64    `json:"mem_used"`
	Disks       []Disk    `json:"disks"`
	CollectedAt time.Time `json:"collected_at"`
}

type Disk struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	FS    string `json:"fs,omitempty"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`     // Running, Stopped, ...
	StartType   string `json:"start_type"` // Auto, Manual, Disabled
}

type Event struct {
	Time    time.Time `json:"time"`
	Log     string    `json:"log"`
	Level   string    `json:"level"` // Critical, Error, Warning, Information
	Source  string    `json:"source"`
	EventID int       `json:"event_id"`
	Message string    `json:"message"`
}

// Command is an approved action the agent should execute.
type Command struct {
	ID     string            `json:"id"`
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

// CommandResult is reported by the agent after execution.
type CommandResult struct {
	Success  bool            `json:"success"`
	Output   string          `json:"output"`
	Error    string          `json:"error,omitempty"`
	ExitCode int             `json:"exit_code"`
	Data     json.RawMessage `json:"data,omitempty"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
}
