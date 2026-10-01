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
	// Connections are listening ports and established TCP connections,
	// deduplicated by the agent. The control plane learns server-to-server
	// dependencies from them.
	Connections []Connection `json:"connections,omitempty"`
}

// Connection states.
const (
	ConnListen      = "listen"
	ConnEstablished = "established"
)

// Connection is a listening port (State listen, Local* set) or an outgoing
// or incoming established TCP connection.
type Connection struct {
	State      string `json:"state"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Process    string `json:"process,omitempty"`
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

// Interactive console sessions. The console never talks to a server
// directly: the control plane queues SessionOps, the agent picks them up
// over its outbound long-poll (GET /api/agent/sessions), runs them in a
// persistent shell process on the server and streams SessionOutput back.

// Session operation types.
const (
	SessionOpen  = "open"  // start the shell process
	SessionInput = "input" // execute Code in the running shell
	SessionReset = "reset" // kill and restart the shell (e.g. a hung command)
	SessionClose = "close" // terminate the shell
)

type SessionOp struct {
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	Code      string `json:"code,omitempty"`
}

// Session output kinds.
const (
	OutputText   = "output" // stdout/stderr text
	OutputReady  = "ready"  // the shell finished a command and waits for input
	OutputClosed = "closed" // the shell process ended
	OutputError  = "error"  // the session could not be started or failed
)

type SessionOutput struct {
	Seq  int    `json:"seq"` // per session, increasing; duplicates are dropped
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
	OK   bool   `json:"ok,omitempty"`  // ready: last command succeeded
	Cwd  string `json:"cwd,omitempty"` // ready: current directory
}
