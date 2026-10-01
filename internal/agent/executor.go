package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/wsjrosiris/serverbrain/internal/actions"
	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

const maxOutput = 1 << 20

// Executor runs commands from the controlled action catalog.
type Executor struct {
	cfg  *Config
	caps map[string]bool
}

func NewExecutor(cfg *Config) *Executor {
	e := &Executor{cfg: cfg, caps: map[string]bool{}}
	for _, c := range capabilitiesFor(cfg) {
		e.caps[c] = true
	}
	return e
}

func (e *Executor) Capabilities() []string {
	out := make([]string, 0, len(e.caps))
	for c := range e.caps {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Execute validates the command locally (defense in depth: the agent does
// not trust the control plane blindly) and runs it.
func (e *Executor) Execute(ctx context.Context, c protocol.Command) protocol.CommandResult {
	res := protocol.CommandResult{Started: time.Now().UTC(), ExitCode: -1}
	finish := func(out string, err error) protocol.CommandResult {
		res.Finished = time.Now().UTC()
		if len(out) > maxOutput {
			out = out[:maxOutput] + "\n... (output truncated)"
		}
		res.Output = out
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Success = true
			if res.ExitCode == -1 {
				res.ExitCode = 0
			}
		}
		return res
	}
	def, ok := actions.Get(c.Action)
	if !ok || !e.caps[c.Action] {
		return finish("", fmt.Errorf("action %q is not enabled on this agent", c.Action))
	}
	in := make(map[string]any, len(c.Params))
	for k, v := range c.Params {
		in[k] = v
	}
	params, err := def.Validate(in)
	if err != nil {
		return finish("", err)
	}
	timeout := time.Duration(def.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if def.Kind == actions.KindScript {
		out, code, err := runScript(ctx, def.Scripts[runtime.GOOS], params)
		res.ExitCode = code
		return finish(out, err)
	}
	var out string
	switch def.Name {
	case "disk.large_files":
		out, err = largeFiles(ctx, params["path"], atoi(params["top"]))
	case "files.archive_old":
		out, err = e.archiveOld(ctx, params["path"], params["pattern"], atoi(params["older_than_days"]))
	case "temp.cleanup":
		out, err = tempCleanup(ctx, atoi(params["older_than_days"]))
	case "network.test_port":
		out, err = testPort(ctx, params["host"], params["port"])
	case "system.reboot":
		out, err = reboot(ctx, atoi(params["delay_seconds"]))
	case "shell.run":
		var code int
		out, code, err = runScript(ctx, params["script"], nil)
		res.ExitCode = code
	default:
		err = fmt.Errorf("native action %q not implemented", def.Name)
	}
	return finish(out, err)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// runScript executes a script with the platform interpreter. Parameters are
// passed as environment variables only.
func runScript(ctx context.Context, script string, params map[string]string) (string, int, error) {
	if script == "" {
		return "", -1, errors.New("no script for this platform")
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Stop on errors and make output UTF-8; -EncodedCommand avoids any
		// quoting issues on the command line.
		full := "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8\n" + script
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(full))
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	cmd.Env = os.Environ()
	for k, v := range params {
		cmd.Env = append(cmd.Env, actions.EnvName(k)+"="+v)
	}
	var buf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &buf, n: maxOutput + 1}
	cmd.Stderr = cmd.Stdout
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return buf.String(), code, errors.New("timed out")
	}
	if err != nil {
		return buf.String(), code, fmt.Errorf("exit code %d", code)
	}
	return buf.String(), code, nil
}

func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, err := l.w.Write(q)
	return len(p), err
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func largeFiles(ctx context.Context, root string, top int) (string, error) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return "", errors.New("path must be absolute")
	}
	// Resolve a symlinked/junctioned start directory; links below it are
	// not followed.
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	type entry struct {
		path string
		size int64
	}
	var files []entry
	dirs := map[string]int64{}
	var total int64
	var skipped int
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			skipped++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || (d.IsDir() && p != root && isReparsePoint(p)) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			skipped++
			return nil
		}
		sz := info.Size()
		total += sz
		files = append(files, entry{p, sz})
		if rel, err := filepath.Rel(root, p); err == nil {
			if first := strings.SplitN(rel, string(filepath.Separator), 2); len(first) == 2 {
				dirs[filepath.Join(root, first[0])] += sz
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].size > files[j].size })
	var b strings.Builder
	fmt.Fprintf(&b, "Scanned %s: %d files, %s total", root, len(files), human(total))
	if skipped > 0 {
		fmt.Fprintf(&b, " (%d entries not accessible)", skipped)
	}
	if err != nil {
		b.WriteString(" - scan incomplete: " + err.Error())
	}
	b.WriteString("\n\nLargest directories:\n")
	var dl []entry
	for p, s := range dirs {
		dl = append(dl, entry{p, s})
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i].size > dl[j].size })
	for i := 0; i < len(dl) && i < top; i++ {
		fmt.Fprintf(&b, "  %10s  %s\n", human(dl[i].size), dl[i].path)
	}
	b.WriteString("\nLargest files:\n")
	for i := 0; i < len(files) && i < top; i++ {
		fmt.Fprintf(&b, "  %10s  %s\n", human(files[i].size), files[i].path)
	}
	return b.String(), nil
}

// withinRoots reports whether path lies inside one of the allowed roots.
func withinRoots(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, r := range roots {
		r = filepath.Clean(r)
		rel, err := filepath.Rel(r, path)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" {
			rel2, err := filepath.Rel(strings.ToLower(r), strings.ToLower(path))
			if err == nil {
				rel = rel2
			}
		}
		if rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)) {
			return true
		}
	}
	return false
}

func (e *Executor) archiveOld(ctx context.Context, dir, pattern string, days int) (string, error) {
	roots := e.cfg.ArchiveRoots
	if len(roots) == 0 {
		roots = DefaultArchiveRoots()
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || !withinRoots(dir, roots) {
		return "", fmt.Errorf("path %s is outside the allowed archive roots %v", dir, roots)
	}
	if real, err := filepath.EvalSymlinks(dir); err != nil || !withinRoots(real, roots) {
		return "", fmt.Errorf("path %s does not resolve inside the allowed archive roots", dir)
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	var victims []string
	var size int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if ok, _ := filepath.Match(pattern, d.Name()); !ok || strings.HasPrefix(d.Name(), "ServerBrain-archive-") {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			return nil
		}
		victims = append(victims, p)
		size += info.Size()
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(victims) == 0 {
		return fmt.Sprintf("No files matching %s older than %d days in %s.", pattern, days, dir), nil
	}
	archive := filepath.Join(dir, "ServerBrain-archive-"+time.Now().Format("20060102-150405")+".zip")
	if err := writeZip(ctx, archive, dir, victims); err != nil {
		os.Remove(archive)
		return "", fmt.Errorf("create archive: %w", err)
	}
	// Verify the archive before deleting anything.
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return "", fmt.Errorf("verify archive: %w", err)
	}
	n := len(zr.File)
	zr.Close()
	if n != len(victims) {
		return "", fmt.Errorf("verify archive: expected %d entries, found %d; originals kept", len(victims), n)
	}
	var removed int
	var failed []string
	for _, v := range victims {
		if err := os.Remove(v); err != nil {
			failed = append(failed, v)
			continue
		}
		removed++
	}
	ai, _ := os.Stat(archive)
	var asize int64
	if ai != nil {
		asize = ai.Size()
	}
	out := fmt.Sprintf("Archived %d files (%s) into %s (%s). Freed %s.", len(victims), human(size), archive, human(asize), human(size-asize))
	if len(failed) > 0 {
		out += fmt.Sprintf("\n%d files could not be deleted (in use?): %s", len(failed), strings.Join(failed[:min(len(failed), 10)], ", "))
	}
	return out, nil
}

func writeZip(ctx context.Context, archive, base string, files []string) error {
	f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	for _, p := range files {
		if ctx.Err() != nil {
			zw.Close()
			f.Close()
			return ctx.Err()
		}
		rel, _ := filepath.Rel(base, p)
		info, err := os.Stat(p)
		if err != nil {
			zw.Close()
			f.Close()
			return err
		}
		hdr, _ := zip.FileInfoHeader(info)
		hdr.Name = filepath.ToSlash(rel)
		hdr.Method = zip.Deflate
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			zw.Close()
			f.Close()
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			zw.Close()
			f.Close()
			return err
		}
		_, err = io.Copy(w, src)
		src.Close()
		if err != nil {
			zw.Close()
			f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func tempDirs() []string {
	if runtime.GOOS == "windows" {
		dirs := []string{filepath.Join(os.Getenv("SystemRoot"), "Temp")}
		if t := os.TempDir(); t != "" && !strings.EqualFold(filepath.Clean(t), filepath.Clean(dirs[0])) {
			dirs = append(dirs, t)
		}
		return dirs
	}
	return []string{"/tmp", "/var/tmp"}
}

func tempCleanup(ctx context.Context, days int) (string, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	var b strings.Builder
	for _, dir := range tempDirs() {
		var removed, failed int
		var freed int64
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if d != nil && d.IsDir() && p != dir {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != dir && isReparsePoint(p) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.ModTime().Before(cutoff) {
				return nil
			}
			if os.Remove(p) != nil {
				failed++
				return nil
			}
			removed++
			freed += info.Size()
			return nil
		})
		fmt.Fprintf(&b, "%s: removed %d files, freed %s, skipped %d locked files\n", dir, removed, human(freed), failed)
	}
	return b.String(), ctx.Err()
}

func testPort(ctx context.Context, host, port string) (string, error) {
	start := time.Now()
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(dctx, host)
	if err != nil {
		return fmt.Sprintf("DNS lookup for %s failed: %v", host, err), errors.New("dns lookup failed")
	}
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Sprintf("%s resolved to %s\nTCP connect to port %s FAILED after %s: %v", host, strings.Join(addrs, ", "), port, time.Since(start).Round(time.Millisecond), err), errors.New("connection failed")
	}
	remote := conn.RemoteAddr().String()
	conn.Close()
	return fmt.Sprintf("%s resolved to %s\nTCP connect to %s succeeded in %s", host, strings.Join(addrs, ", "), remote, time.Since(start).Round(time.Millisecond)), nil
}

func reboot(ctx context.Context, delay int) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", strconv.Itoa(delay), "/d", "p:0:0", "/c", "Reboot requested via ServerBrain")
	} else {
		mins := (delay + 59) / 60
		cmd = exec.CommandContext(ctx, "shutdown", "-r", "+"+strconv.Itoa(mins), "Reboot requested via ServerBrain")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("shutdown failed: %w", err)
	}
	return fmt.Sprintf("Reboot scheduled in %d seconds.\n%s", delay, out), nil
}
