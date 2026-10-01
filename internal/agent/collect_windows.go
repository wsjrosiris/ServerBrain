//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

// collectScript gathers system info, metrics, services and new event log
// entries in a single PowerShell invocation and prints compact JSON.
const collectScript = `
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  [pscustomobject]@{ name = $_.DeviceID; label = [string]$_.VolumeName; fs = [string]$_.FileSystem; total = [uint64]$_.Size; free = [uint64]$_.FreeSpace }
})
$services = @(Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display_name = $_.DisplayName; status = $(if ($_.State -eq 'Running') { 'Running' } elseif ($_.State -eq 'Stopped') { 'Stopped' } else { [string]$_.State }); start_type = [string]$_.StartMode }
})
$since = [datetime]::Parse($env:SB_SINCE, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System','Application'; Level = 1,2,3; StartTime = $since } -MaxEvents 200 | ForEach-Object {
  $msg = [string]$_.Message
  if ($msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) }
  [pscustomobject]@{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); log = $_.LogName; level = [string]$_.LevelDisplayName; level_num = [int]$_.Level; source = $_.ProviderName; event_id = $_.Id; message = $msg }
})
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
$all = @(Get-NetTCPConnection -State Listen,Established)
$listen = @{}
foreach ($t in $all) { if ([string]$t.State -eq 'Listen') { $listen[[int]$t.LocalPort] = $true } }
$seen = @{}
$conns = @(foreach ($t in $all) {
  $p = [string]$procs[[int]$t.OwningProcess]
  if ([string]$t.State -eq 'Listen') {
    $k = "L|$($t.LocalPort)"
    $c = [pscustomobject]@{ state = 'listen'; local_port = [int]$t.LocalPort; process = $p }
  } else {
    if ($t.RemoteAddress -in @('127.0.0.1', '::1')) { continue }
    if ($listen.ContainsKey([int]$t.LocalPort)) {
      # inbound client of a local service: remote port is irrelevant
      $k = "I|$($t.RemoteAddress)|$($t.LocalPort)"
      $c = [pscustomobject]@{ state = 'established'; local_port = [int]$t.LocalPort; remote_addr = [string]$t.RemoteAddress; remote_port = 0; process = $p }
    } else {
      $k = "E|$($t.RemoteAddress)|$($t.RemotePort)|$p"
      $c = [pscustomobject]@{ state = 'established'; local_port = 0; remote_addr = [string]$t.RemoteAddress; remote_port = [int]$t.RemotePort; process = $p }
    }
  }
  if (-not $seen.ContainsKey($k) -and $seen.Count -lt 1000) { $seen[$k] = $true; $c }
})
$ips = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress } | Where-Object { $_ })
[pscustomobject]@{
  hostname   = $env:COMPUTERNAME
  os_version = "$($os.Caption) $($os.Version)"
  domain     = [string]$cs.Domain
  cpus       = [int]$cs.NumberOfLogicalProcessors
  boot_time  = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  ips        = $ips
  cpu        = [double]$cpu
  mem_total  = [uint64]$os.TotalVisibleMemorySize * 1024
  mem_free   = [uint64]$os.FreePhysicalMemory * 1024
  disks      = $disks
  services   = $services
  events     = $events
  connections = $conns
} | ConvertTo-Json -Depth 4 -Compress
`

type winSnapshot struct {
	Hostname  string                    `json:"hostname"`
	OSVersion string                    `json:"os_version"`
	Domain    string                    `json:"domain"`
	CPUs      int                       `json:"cpus"`
	BootTime  string                    `json:"boot_time"`
	IPs       list[string]              `json:"ips"`
	CPU       float64                   `json:"cpu"`
	MemTotal  uint64                    `json:"mem_total"`
	MemFree   uint64                    `json:"mem_free"`
	Disks     list[protocol.Disk]       `json:"disks"`
	Services  list[protocol.Service]    `json:"services"`
	Events    list[winEvent]            `json:"events"`
	Conns     list[protocol.Connection] `json:"connections"`
}

type winEvent struct {
	Time     string `json:"time"`
	Log      string `json:"log"`
	Level    string `json:"level"`
	LevelNum int    `json:"level_num"`
	Source   string `json:"source"`
	EventID  int    `json:"event_id"`
	Message  string `json:"message"`
}

// list tolerates PowerShell's habit of emitting a single object instead of
// a one-element array.
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*l = nil
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var v []T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*l = v
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*l = []T{v}
	return nil
}

var levelNames = map[int]string{1: "Critical", 2: "Error", 3: "Warning", 4: "Information"}

type collector struct{}

func newCollector() *collector { return &collector{} }

func (c *collector) run(ctx context.Context, since time.Time) (*winSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(collectScript))
	cmd.Env = append(os.Environ(), "SB_SINCE="+since.UTC().Format(time.RFC3339))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var snap winSnapshot
	if err := json.Unmarshal(out, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

func (c *collector) systemInfo() protocol.SystemInfo {
	snap, err := c.run(context.Background(), time.Now())
	if err != nil {
		h, _ := os.Hostname()
		return protocol.SystemInfo{Hostname: h, OS: "windows"}
	}
	return snapSystem(snap)
}

func snapSystem(s *winSnapshot) protocol.SystemInfo {
	boot, _ := time.Parse(time.RFC3339Nano, s.BootTime)
	return protocol.SystemInfo{Hostname: s.Hostname, OS: "windows", OSVersion: s.OSVersion, Domain: s.Domain, CPUs: s.CPUs, BootTime: boot, IPs: s.IPs}
}

func (c *collector) collect(ctx context.Context, since time.Time) *protocol.Heartbeat {
	snap, err := c.run(ctx, since)
	if err != nil {
		h, _ := os.Hostname()
		return &protocol.Heartbeat{System: protocol.SystemInfo{Hostname: h, OS: "windows"}, Metrics: protocol.Metrics{CollectedAt: time.Now().UTC()}}
	}
	hb := &protocol.Heartbeat{
		System: snapSystem(snap),
		Metrics: protocol.Metrics{
			CPUPercent:  snap.CPU,
			MemTotal:    snap.MemTotal,
			MemUsed:     snap.MemTotal - min(snap.MemFree, snap.MemTotal),
			Disks:       snap.Disks,
			CollectedAt: time.Now().UTC(),
		},
		Services:    snap.Services,
		Connections: snap.Conns,
	}
	for _, e := range snap.Events {
		t, _ := time.Parse(time.RFC3339Nano, e.Time)
		level := levelNames[e.LevelNum]
		if level == "" {
			level = e.Level
		}
		hb.Events = append(hb.Events, protocol.Event{Time: t, Log: e.Log, Level: level, Source: e.Source, EventID: e.EventID, Message: e.Message})
	}
	return hb
}
