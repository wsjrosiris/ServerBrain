// Package actions is the controlled action layer: the closed set of things
// that may be executed on a server. Neither humans nor the AI send arbitrary
// commands; they request a named action with validated parameters. The
// control plane uses this catalog for validation, policy decisions and the
// "show commands" preview; the agent uses the very same definitions to
// execute, so the preview is exactly what runs.
//
// Parameters are never interpolated into scripts. They are passed to the
// interpreter as environment variables (SB_ARG_<NAME>), which rules out
// command injection through parameter values.
package actions

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Kind describes how the agent executes an action.
type Kind string

const (
	KindScript Kind = "script" // platform script (PowerShell on Windows, sh on Linux)
	KindNative Kind = "native" // implemented in Go inside the agent
)

type ParamType string

const (
	TypeString ParamType = "string"
	TypeInt    ParamType = "int"
)

type Param struct {
	Name        string    `json:"name"`
	Type        ParamType `json:"type"`
	Required    bool      `json:"required"`
	Default     string    `json:"default,omitempty"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern,omitempty"` // for strings
	MaxLen      int       `json:"max_len,omitempty"` // for strings; defaults to 256
	Min         int       `json:"min,omitempty"`     // for ints
	Max         int       `json:"max,omitempty"`     // for ints
}

type Def struct {
	Name        string  `json:"name"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Risk        Risk    `json:"risk"`
	ReadOnly    bool    `json:"read_only"`
	Kind        Kind    `json:"kind"`
	Params      []Param `json:"params"`
	// Scripts maps a platform ("windows", "linux") to the script source.
	// Only meaningful for KindScript.
	Scripts map[string]string `json:"-"`
	// Native is a human readable description of what a native action does.
	Native string `json:"-"`
	// Platforms lists where a native action is available; empty means all.
	Platforms []string `json:"-"`
	// Optional actions must be explicitly enabled in the agent config.
	Optional bool `json:"optional"`
	// TimeoutSeconds bounds execution on the agent.
	TimeoutSeconds int `json:"timeout_seconds"`
}

const (
	patName = `^[A-Za-z0-9_.\-$ ]+$`
	patLog  = `^[A-Za-z0-9_.\-/ ]+$`
	patHost = `^[A-Za-z0-9_.\-:]+$`
	patPath = `^[^\x00\r\n]+$`
	patGlob = `^[A-Za-z0-9_.\-*?]+$`
)

var catalog = []Def{
	{
		Name: "service.restart", Title: "Restart service", Risk: RiskLow, Kind: KindScript,
		Description:    "Restarts a service and reports its new state.",
		Params:         []Param{{Name: "name", Type: TypeString, Required: true, Pattern: patName, Description: "Service name"}},
		TimeoutSeconds: 120,
		Scripts: map[string]string{
			"windows": `Restart-Service -Name $env:SB_ARG_NAME -Force -ErrorAction Stop
Get-Service -Name $env:SB_ARG_NAME | Select-Object Name,DisplayName,Status | Format-List`,
			"linux": `systemctl restart -- "$SB_ARG_NAME" && systemctl --no-pager status -- "$SB_ARG_NAME" | head -n 5`,
		},
	},
	{
		Name: "service.start", Title: "Start service", Risk: RiskLow, Kind: KindScript,
		Description:    "Starts a stopped service.",
		Params:         []Param{{Name: "name", Type: TypeString, Required: true, Pattern: patName, Description: "Service name"}},
		TimeoutSeconds: 120,
		Scripts: map[string]string{
			"windows": `Start-Service -Name $env:SB_ARG_NAME -ErrorAction Stop
Get-Service -Name $env:SB_ARG_NAME | Select-Object Name,DisplayName,Status | Format-List`,
			"linux": `systemctl start -- "$SB_ARG_NAME" && systemctl --no-pager status -- "$SB_ARG_NAME" | head -n 5`,
		},
	},
	{
		Name: "service.stop", Title: "Stop service", Risk: RiskMedium, Kind: KindScript,
		Description:    "Stops a running service.",
		Params:         []Param{{Name: "name", Type: TypeString, Required: true, Pattern: patName, Description: "Service name"}},
		TimeoutSeconds: 120,
		Scripts: map[string]string{
			"windows": `Stop-Service -Name $env:SB_ARG_NAME -Force -ErrorAction Stop
Get-Service -Name $env:SB_ARG_NAME | Select-Object Name,DisplayName,Status | Format-List`,
			"linux": `systemctl stop -- "$SB_ARG_NAME" && systemctl --no-pager status -- "$SB_ARG_NAME" | head -n 5`,
		},
	},
	{
		Name: "process.list", Title: "Top processes", Risk: RiskLow, ReadOnly: true, Kind: KindScript,
		Description:    "Lists the processes using the most CPU time and memory.",
		Params:         []Param{{Name: "top", Type: TypeInt, Default: "20", Min: 1, Max: 200, Description: "Number of processes"}},
		TimeoutSeconds: 60,
		Scripts: map[string]string{
			"windows": `Get-Process | Sort-Object CPU -Descending | Select-Object -First ([int]$env:SB_ARG_TOP) Id,ProcessName,CPU,@{n='WorkingSetMB';e={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize | Out-String -Width 200`,
			"linux":   `ps -eo pid,comm,%cpu,rss --sort=-%cpu | head -n "$((SB_ARG_TOP + 1))"`,
		},
	},
	{
		Name: "eventlog.query", Title: "Query event log", Risk: RiskLow, ReadOnly: true, Kind: KindScript,
		Description: "Returns recent entries from a Windows event log.",
		Params: []Param{
			{Name: "log", Type: TypeString, Default: "System", Pattern: patLog, Description: "Log name, e.g. System, Application"},
			{Name: "level", Type: TypeInt, Default: "3", Min: 1, Max: 5, Description: "Maximum level: 1=Critical 2=Error 3=Warning 4=Information"},
			{Name: "hours", Type: TypeInt, Default: "24", Min: 1, Max: 720, Description: "Look-back window in hours"},
			{Name: "max", Type: TypeInt, Default: "50", Min: 1, Max: 500, Description: "Maximum number of entries"},
		},
		TimeoutSeconds: 120,
		Scripts: map[string]string{
			"windows": `$levels = 1..([int]$env:SB_ARG_LEVEL)
Get-WinEvent -FilterHashtable @{LogName=$env:SB_ARG_LOG; Level=$levels; StartTime=(Get-Date).AddHours(-[int]$env:SB_ARG_HOURS)} -MaxEvents ([int]$env:SB_ARG_MAX) -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List | Out-String -Width 300`,
		},
	},
	{
		Name: "iis.sites", Title: "List IIS sites and app pools", Risk: RiskLow, ReadOnly: true, Kind: KindScript,
		Description:    "Shows IIS sites, bindings and application pool states.",
		TimeoutSeconds: 60,
		Scripts: map[string]string{
			"windows": `Import-Module WebAdministration -ErrorAction Stop
Get-Website | Select-Object Name,State,PhysicalPath,@{n='Bindings';e={($_.Bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ', '}} | Format-Table -AutoSize | Out-String -Width 300
Get-ChildItem IIS:\AppPools | Select-Object Name,State,ManagedRuntimeVersion | Format-Table -AutoSize | Out-String -Width 200`,
		},
	},
	{
		Name: "iis.apppool.restart", Title: "Recycle IIS app pool", Risk: RiskLow, Kind: KindScript,
		Description:    "Restarts (recycles) an IIS application pool, starting it if stopped.",
		Params:         []Param{{Name: "name", Type: TypeString, Required: true, Pattern: patName, Description: "Application pool name"}},
		TimeoutSeconds: 120,
		Scripts: map[string]string{
			"windows": `Import-Module WebAdministration -ErrorAction Stop
$state = (Get-WebAppPoolState -Name $env:SB_ARG_NAME).Value
if ($state -eq 'Stopped') { Start-WebAppPool -Name $env:SB_ARG_NAME } else { Restart-WebAppPool -Name $env:SB_ARG_NAME }
Start-Sleep -Seconds 2
"AppPool $($env:SB_ARG_NAME): $((Get-WebAppPoolState -Name $env:SB_ARG_NAME).Value)"`,
		},
	},
	{
		Name: "windows_update.list", Title: "Pending Windows updates", Risk: RiskLow, ReadOnly: true, Kind: KindScript,
		Description:    "Lists updates that are applicable but not yet installed.",
		TimeoutSeconds: 600,
		Scripts: map[string]string{
			"windows": `$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
"$($r.Updates.Count) pending update(s)"
$r.Updates | ForEach-Object { "- [{0}] {1}" -f ($(if ($_.MsrcSeverity) { $_.MsrcSeverity } else { 'n/a' })), $_.Title }`,
		},
	},
	{
		Name: "disk.large_files", Title: "Find large files", Risk: RiskLow, ReadOnly: true, Kind: KindNative,
		Description: "Finds the largest files and directories below a path.",
		Native:      "Walk {path} recursively and report the {top} largest files and the largest top-level directories.",
		Params: []Param{
			{Name: "path", Type: TypeString, Required: true, Pattern: patPath, MaxLen: 1024, Description: `Root path, e.g. C:\`},
			{Name: "top", Type: TypeInt, Default: "20", Min: 1, Max: 200, Description: "Number of entries"},
		},
		TimeoutSeconds: 600,
	},
	{
		Name: "files.archive_old", Title: "Archive old files", Risk: RiskMedium, Kind: KindNative,
		Description: "Moves files older than N days into a ZIP archive in the same directory (e.g. IIS logs). Only allowed below the agent's configured archive roots.",
		Native:      "In {path}, zip all files matching {pattern} older than {older_than_days} days into ServerBrain-archive-<timestamp>.zip, verify the archive, then delete the originals.",
		Params: []Param{
			{Name: "path", Type: TypeString, Required: true, Pattern: patPath, MaxLen: 1024, Description: `Directory, e.g. C:\inetpub\logs\LogFiles`},
			{Name: "older_than_days", Type: TypeInt, Default: "30", Min: 1, Max: 3650, Description: "Minimum file age in days"},
			{Name: "pattern", Type: TypeString, Default: "*.log", Pattern: patGlob, Description: "File name pattern"},
		},
		TimeoutSeconds: 1800,
	},
	{
		Name: "temp.cleanup", Title: "Clean temporary files", Risk: RiskLow, Kind: KindNative,
		Description: "Deletes files older than N days from the system temp directories.",
		Native:      "Delete files older than {older_than_days} days from the system temp directories (Windows: C:\\Windows\\Temp and the service profile TEMP). Locked files are skipped.",
		Params: []Param{
			{Name: "older_than_days", Type: TypeInt, Default: "7", Min: 1, Max: 3650, Description: "Minimum file age in days"},
		},
		TimeoutSeconds: 900,
	},
	{
		Name: "network.test_port", Title: "Test TCP connectivity", Risk: RiskLow, ReadOnly: true, Kind: KindNative,
		Description: "Tests whether this server can open a TCP connection to host:port.",
		Native:      "Resolve {host} and attempt a TCP connection to port {port} with a 5 second timeout.",
		Params: []Param{
			{Name: "host", Type: TypeString, Required: true, Pattern: patHost, Description: "Target host name or IP"},
			{Name: "port", Type: TypeInt, Required: true, Min: 1, Max: 65535, Description: "TCP port"},
		},
		TimeoutSeconds: 30,
	},
	{
		Name: "system.reboot", Title: "Reboot server", Risk: RiskHigh, Kind: KindNative,
		Description: "Schedules an operating system reboot.",
		Native:      "Schedule a reboot in {delay_seconds} seconds (Windows: shutdown.exe /r /t {delay_seconds}).",
		Params: []Param{
			{Name: "delay_seconds", Type: TypeInt, Default: "60", Min: 0, Max: 3600, Description: "Delay before reboot"},
		},
		TimeoutSeconds: 30,
	},
	{
		Name: "shell.run", Title: "Run shell script", Risk: RiskCritical, Kind: KindNative, Optional: true,
		Description: "Runs an arbitrary script (PowerShell on Windows, sh on Linux). Must be enabled on the agent explicitly.",
		Native:      "Execute the given script with powershell.exe -NoProfile -NonInteractive (Windows) or /bin/sh (Linux).",
		Params: []Param{
			{Name: "script", Type: TypeString, Required: true, MaxLen: 65536, Description: "Script source"},
		},
		TimeoutSeconds: 600,
	},
}

var (
	byName   = map[string]*Def{}
	patterns = map[string]*regexp.Regexp{}
)

func init() {
	for i := range catalog {
		byName[catalog[i].Name] = &catalog[i]
		for _, p := range catalog[i].Params {
			if p.Pattern != "" && patterns[p.Pattern] == nil {
				patterns[p.Pattern] = regexp.MustCompile(p.Pattern)
			}
		}
	}
}

// All returns the catalog sorted by name.
func All() []Def {
	out := append([]Def(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get looks up an action definition by name.
func Get(name string) (*Def, bool) {
	d, ok := byName[name]
	return d, ok
}

// AvailableOn reports whether the action can run on the given GOOS.
func (d *Def) AvailableOn(platform string) bool {
	if d.Kind == KindScript {
		_, ok := d.Scripts[platform]
		return ok
	}
	if len(d.Platforms) == 0 {
		return true
	}
	for _, p := range d.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// Validate checks params against the definition, applies defaults and
// returns the normalized string map that is stored and sent to the agent.
func (d *Def) Validate(in map[string]any) (map[string]string, error) {
	known := map[string]bool{}
	out := map[string]string{}
	for _, p := range d.Params {
		known[p.Name] = true
		raw, present := in[p.Name]
		var s string
		if present && raw != nil {
			switch v := raw.(type) {
			case string:
				s = v
			case float64:
				if v != float64(int64(v)) {
					return nil, fmt.Errorf("parameter %q must be an integer", p.Name)
				}
				s = strconv.FormatInt(int64(v), 10)
			case int:
				s = strconv.Itoa(v)
			case int64:
				s = strconv.FormatInt(v, 10)
			default:
				return nil, fmt.Errorf("parameter %q has unsupported type %T", p.Name, raw)
			}
		}
		if s == "" {
			if p.Required {
				return nil, fmt.Errorf("parameter %q is required", p.Name)
			}
			if p.Default == "" {
				continue
			}
			s = p.Default
		}
		switch p.Type {
		case TypeInt:
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("parameter %q must be an integer", p.Name)
			}
			if n < p.Min || (p.Max != 0 && n > p.Max) {
				return nil, fmt.Errorf("parameter %q must be between %d and %d", p.Name, p.Min, p.Max)
			}
			s = strconv.Itoa(n)
		case TypeString:
			maxLen := p.MaxLen
			if maxLen == 0 {
				maxLen = 256
			}
			if len(s) > maxLen {
				return nil, fmt.Errorf("parameter %q exceeds %d characters", p.Name, maxLen)
			}
			if p.Pattern != "" && !patterns[p.Pattern].MatchString(s) {
				return nil, fmt.Errorf("parameter %q has an invalid value", p.Name)
			}
		}
		out[p.Name] = s
	}
	for k := range in {
		if !known[k] {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return out, nil
}

// EnvName returns the environment variable used to pass a parameter.
func EnvName(param string) string {
	return "SB_ARG_" + strings.ToUpper(param)
}

// Preview renders what the agent will execute for the given platform, so an
// operator can review it before approving ("show commands").
func (d *Def) Preview(platform string, params map[string]string) string {
	var b strings.Builder
	names := make([]string, 0, len(params))
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	if d.Kind == KindScript {
		if script, ok := d.Scripts[platform]; ok {
			for _, k := range names {
				fmt.Fprintf(&b, "# %s = %q\n", EnvName(k), params[k])
			}
			b.WriteString(script)
			return b.String()
		}
		return "(not available on " + platform + ")"
	}
	text := d.Native
	for _, k := range names {
		text = strings.ReplaceAll(text, "{"+k+"}", params[k])
	}
	b.WriteString("[native agent action] ")
	b.WriteString(text)
	if d.Name == "shell.run" {
		b.WriteString("\n\n")
		b.WriteString(params["script"])
	}
	return b.String()
}
