package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

const (
	maxSessions     = 5
	sessionIdleKill = 60 * time.Minute
	flushInterval   = 150 * time.Millisecond
	flushBytes      = 16 << 10
)

// psHost is a minimal PowerShell REPL. It reads one base64 encoded command
// per line from stdin and dot-sources it into the session scope, so
// variables, functions, modules and the current directory persist between
// commands - like an interactive PowerShell on the server. After each
// command it prints an end marker carrying success and the current path.
const psHost = `
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$__sbIn = [Console]::In
while ($true) {
  $__sbLine = $__sbIn.ReadLine()
  if ($null -eq $__sbLine) { break }
  $Error.Clear()
  $global:LASTEXITCODE = $null
  $__sbFailed = $false
  try {
    $__sbCode = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__sbLine))
    if ($__sbCode.Trim().Length -gt 0) {
      . ([scriptblock]::Create($__sbCode)) 2>&1 | Out-String -Stream -Width 220 | ForEach-Object { [Console]::Out.WriteLine($_); [Console]::Out.Flush() }
    }
  } catch {
    $__sbFailed = $true
    [Console]::Out.WriteLine(($_ | Out-String -Width 220).TrimEnd())
  }
  if ($Error.Count -gt 0 -or ($null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -ne 0)) { $__sbFailed = $true }
  $__sbCwd = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Location).Path))
  [Console]::Out.WriteLine('__SB_END_TOKEN__ ' + $(if ($__sbFailed) { '0' } else { '1' }) + ' ' + $__sbCwd)
  [Console]::Out.Flush()
}
`

// shHost is the equivalent REPL for Linux development agents.
const shHost = `exec 2>&1
while IFS= read -r __sb_line; do
  __sb_code=$(printf '%s' "$__sb_line" | base64 -d)
  eval "$__sb_code"
  __sb_rc=$?
  if [ $__sb_rc -eq 0 ]; then __sb_ok=1; else __sb_ok=0; fi
  printf '__SB_END_TOKEN__ %s %s\n' "$__sb_ok" "$(pwd | base64 | tr -d '\n')"
done
`

type sessionManager struct {
	a  *Agent
	mu sync.Mutex
	m  map[string]*shellSession
}

type shellSession struct {
	id     string
	mgr    *sessionManager
	marker string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	gen     int // incremented on reset, so a dying old process stays quiet
	lastUse time.Time
	closed  bool

	out chan protocol.SessionOutput
	seq int
}

func newSessionManager(a *Agent) *sessionManager {
	return &sessionManager{a: a, m: map[string]*shellSession{}}
}

// loop long-polls the control plane for session operations.
func (sm *sessionManager) loop(ctx context.Context) {
	backoff := time.Second
	reap := time.NewTicker(time.Minute)
	defer reap.Stop()
	for ctx.Err() == nil {
		select {
		case <-reap.C:
			sm.reapIdle()
		default:
		}
		var ops []protocol.SessionOp
		if err := sm.a.do(ctx, http.MethodGet, "/api/agent/sessions", nil, &ops, true); err != nil {
			if ctx.Err() != nil {
				break
			}
			sm.a.log.Warn("session poll failed", "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, op := range ops {
			sm.handle(ctx, op)
		}
	}
	sm.closeAll()
}

func (sm *sessionManager) handle(ctx context.Context, op protocol.SessionOp) {
	sm.mu.Lock()
	s := sm.m[op.SessionID]
	sm.mu.Unlock()

	switch op.Type {
	case protocol.SessionOpen:
		if s != nil {
			return
		}
		s = &shellSession{id: op.SessionID, mgr: sm, marker: "__SB_END_" + randHex(12) + "__", out: make(chan protocol.SessionOutput, 256)}
		go s.sender(ctx)
		sm.mu.Lock()
		if len(sm.m) >= maxSessions {
			sm.mu.Unlock()
			s.emit(protocol.SessionOutput{Kind: protocol.OutputError, Text: "too many open sessions on this agent"})
			close(s.out)
			return
		}
		sm.m[op.SessionID] = s
		sm.mu.Unlock()
		sm.a.log.Info("console session opened", "session", op.SessionID)
		if err := s.start(); err != nil {
			s.emit(protocol.SessionOutput{Kind: protocol.OutputError, Text: "starting shell failed: " + err.Error()})
			sm.remove(s)
		}
	case protocol.SessionInput:
		if s == nil {
			sm.orphan(ctx, op.SessionID)
			return
		}
		if err := s.write(op.Code); err != nil {
			s.emit(protocol.SessionOutput{Kind: protocol.OutputError, Text: "sending input failed: " + err.Error()})
		}
	case protocol.SessionReset:
		if s == nil {
			sm.orphan(ctx, op.SessionID)
			return
		}
		s.emit(protocol.SessionOutput{Kind: protocol.OutputText, Text: "--- session restarted ---\n"})
		s.kill()
		if err := s.start(); err != nil {
			s.emit(protocol.SessionOutput{Kind: protocol.OutputError, Text: "restarting shell failed: " + err.Error()})
			sm.remove(s)
		}
	case protocol.SessionClose:
		if s != nil {
			sm.remove(s)
		}
	}
}

// orphan tells the control plane that a session it still believes in does
// not exist here (for example after an agent restart).
func (sm *sessionManager) orphan(ctx context.Context, id string) {
	out := protocol.SessionOutput{Seq: 1 << 30, Kind: protocol.OutputClosed, Text: "session no longer exists on the agent (agent restarted?)"}
	_ = sm.a.do(ctx, http.MethodPost, "/api/agent/sessions/"+id+"/output", []protocol.SessionOutput{out}, nil, true)
}

func (sm *sessionManager) remove(s *shellSession) {
	sm.mu.Lock()
	delete(sm.m, s.id)
	sm.mu.Unlock()
	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.mu.Unlock()
	if already {
		return
	}
	s.kill()
	s.emit(protocol.SessionOutput{Kind: protocol.OutputClosed})
	close(s.out)
	sm.a.log.Info("console session closed", "session", s.id)
}

func (sm *sessionManager) reapIdle() {
	sm.mu.Lock()
	var idle []*shellSession
	for _, s := range sm.m {
		s.mu.Lock()
		if time.Since(s.lastUse) > sessionIdleKill {
			idle = append(idle, s)
		}
		s.mu.Unlock()
	}
	sm.mu.Unlock()
	for _, s := range idle {
		s.emit(protocol.SessionOutput{Kind: protocol.OutputText, Text: "--- closed after inactivity ---\n"})
		sm.remove(s)
	}
}

func (sm *sessionManager) closeAll() {
	sm.mu.Lock()
	all := make([]*shellSession, 0, len(sm.m))
	for _, s := range sm.m {
		all = append(all, s)
	}
	sm.mu.Unlock()
	for _, s := range all {
		sm.remove(s)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// start launches the shell process and its output reader.
func (s *shellSession) start() error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		host := strings.ReplaceAll(psHost, "__SB_END_TOKEN__", s.marker)
		cmd = exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(host))
	} else {
		cmd = exec.Command("/bin/sh", "-c", strings.ReplaceAll(shHost, "__SB_END_TOKEN__", s.marker))
	}
	cmd.Env = os.Environ()
	cmd.Dir = homeDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.cmd, s.stdin, s.lastUse = cmd, stdin, time.Now()
	s.mu.Unlock()

	go s.read(pr, gen)
	go func() {
		_ = cmd.Wait()
		pw.Close()
	}()
	// An empty command makes the shell report its prompt (ready + cwd).
	return s.write("")
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("SystemDrive"); d != "" {
			return d + `\`
		}
		return `C:\`
	}
	return "/"
}

func (s *shellSession) write(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stdin == nil {
		return errors.New("shell is not running")
	}
	s.lastUse = time.Now()
	_, err := io.WriteString(s.stdin, base64.StdEncoding.EncodeToString([]byte(code))+"\n")
	return err
}

func (s *shellSession) kill() {
	s.mu.Lock()
	cmd, stdin := s.cmd, s.stdin
	s.cmd, s.stdin = nil, nil
	s.gen++
	s.mu.Unlock()
	if stdin != nil {
		stdin.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func (s *shellSession) current(gen int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen == gen && !s.closed
}

// read parses shell output into text chunks and ready markers. Text is
// batched briefly so output streams live without one request per line.
func (s *shellSession) read(r io.Reader, gen int) {
	lines := make(chan string, 64)
	go func() {
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				lines <- line
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	var buf strings.Builder
	flush := func() {
		if buf.Len() > 0 && s.current(gen) {
			s.emit(protocol.SessionOutput{Kind: protocol.OutputText, Text: buf.String()})
		}
		buf.Reset()
	}
	tick := time.NewTicker(flushInterval)
	defer tick.Stop()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				flush()
				if s.current(gen) {
					// The shell exited on its own (e.g. "exit").
					s.mgr.remove(s)
				}
				return
			}
			if i := strings.Index(line, s.marker); i >= 0 {
				buf.WriteString(line[:i])
				flush()
				fields := strings.Fields(line[i+len(s.marker):])
				ready := protocol.SessionOutput{Kind: protocol.OutputReady}
				if len(fields) > 0 {
					ready.OK = fields[0] == "1"
				}
				if len(fields) > 1 {
					if cwd, err := base64.StdEncoding.DecodeString(fields[1]); err == nil {
						ready.Cwd = strings.TrimRight(string(cwd), "\r\n")
					}
				}
				if s.current(gen) {
					s.emit(ready)
				}
				continue
			}
			buf.WriteString(strings.ReplaceAll(line, "\r\n", "\n"))
			if buf.Len() >= flushBytes {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (s *shellSession) emit(o protocol.SessionOutput) {
	s.mu.Lock()
	s.seq++
	o.Seq = s.seq
	s.mu.Unlock()
	defer func() { recover() }() // out may be closed during shutdown
	s.out <- o
}

// sender delivers output to the control plane in order, batching whatever
// has accumulated and retrying on transient errors.
func (s *shellSession) sender(ctx context.Context) {
	path := "/api/agent/sessions/" + s.id + "/output"
	for o := range s.out {
		batch := []protocol.SessionOutput{o}
	drain:
		for len(batch) < 64 {
			select {
			case more, ok := <-s.out:
				if !ok {
					break drain
				}
				batch = append(batch, more)
			default:
				break drain
			}
		}
		for attempt := 0; attempt < 5; attempt++ {
			err := s.mgr.a.do(context.WithoutCancel(ctx), http.MethodPost, path, batch, nil, true)
			if err == nil {
				break
			}
			var se *statusError
			if errors.As(err, &se) && se.code == http.StatusNotFound {
				// The control plane no longer knows this session (restart or
				// closed): stop the shell instead of leaving it running.
				go s.mgr.remove(s)
				break
			}
			s.mgr.a.log.Warn("sending session output failed", "session", s.id, "err", err)
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
}
