//go:build windows

package agent

import (
	"bufio"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPowerShellHost drives the PowerShell REPL used for console sessions
// directly: state must persist between commands and every command must end
// with a marker carrying success and the current directory.
func TestPowerShellHost(t *testing.T) {
	marker := "__SB_END_test__"
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePS(strings.ReplaceAll(psHost, "__SB_END_TOKEN__", marker)))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	run := func(code string) (out []string, ok bool, cwd string) {
		t.Helper()
		io.WriteString(stdin, base64.StdEncoding.EncodeToString([]byte(code))+"\n")
		timeout := time.After(60 * time.Second)
		for {
			select {
			case l, open := <-lines:
				if !open {
					t.Fatalf("powershell exited; output so far: %v", out)
				}
				if i := strings.Index(l, marker); i >= 0 {
					f := strings.Fields(l[i+len(marker):])
					d, _ := base64.StdEncoding.DecodeString(f[1])
					return out, f[0] == "1", string(d)
				}
				out = append(out, l)
			case <-timeout:
				t.Fatalf("timeout running %q; output: %v", code, out)
			}
		}
	}
	dir := t.TempDir()
	if _, ok, _ := run(""); !ok {
		t.Fatal("empty command not ok")
	}
	if _, ok, cwd := run("$sbValue = 41; Set-Location -LiteralPath '" + dir + "'"); !ok || !strings.EqualFold(filepath.Clean(cwd), filepath.Clean(dir)) {
		t.Fatalf("set-location: ok=%v cwd=%q want %q", ok, cwd, dir)
	}
	out, ok, _ := run("$sbValue + 1")
	if !ok || !strings.Contains(strings.Join(out, "\n"), "42") {
		t.Fatalf("variable did not persist: ok=%v out=%v", ok, out)
	}
	if _, ok, _ := run("Get-Item -LiteralPath 'C:\\does-not-exist-sb'"); ok {
		t.Fatal("failing command reported ok")
	}
	if _, ok, _ := run("throw 'boom'"); ok {
		t.Fatal("throw reported ok")
	}
	if _, ok, _ := run("cmd.exe /c exit 3"); ok {
		t.Fatal("non-zero exit code reported ok")
	}
	if out, ok, _ := run("Get-Service | Select-Object -First 3 | Format-Table -AutoSize"); !ok || len(out) < 3 {
		t.Fatalf("formatted output: ok=%v out=%v", ok, out)
	}
}
