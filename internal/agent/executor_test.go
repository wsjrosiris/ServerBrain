package agent

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

func TestArchiveOldRespectsRootsAndAge(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	os.MkdirAll(logs, 0o755)
	old := time.Now().AddDate(0, 0, -40)
	for _, n := range []string{"a.log", "b.log", "keep.txt"} {
		p := filepath.Join(logs, n)
		os.WriteFile(p, []byte(strings.Repeat(n, 1000)), 0o644)
		os.Chtimes(p, old, old)
	}
	os.WriteFile(filepath.Join(logs, "fresh.log"), []byte("new"), 0o644)

	e := NewExecutor(&Config{ArchiveRoots: []string{logs}})
	res := e.Execute(context.Background(), protocol.Command{ID: "1", Action: "files.archive_old",
		Params: map[string]string{"path": logs, "older_than_days": "30", "pattern": "*.log"}})
	if !res.Success {
		t.Fatalf("archive failed: %s %s", res.Error, res.Output)
	}
	for n, want := range map[string]bool{"a.log": false, "b.log": false, "keep.txt": true, "fresh.log": true} {
		if _, err := os.Stat(filepath.Join(logs, n)); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", n, err == nil, want)
		}
	}
	zips, _ := filepath.Glob(filepath.Join(logs, "ServerBrain-archive-*.zip"))
	if len(zips) != 1 {
		t.Fatalf("expected one archive, got %v", zips)
	}
	zr, err := zip.OpenReader(zips[0])
	if err != nil || len(zr.File) != 2 {
		t.Fatalf("archive content: %v", err)
	}
	zr.Close()

	// Outside the allowed roots: refused.
	res = e.Execute(context.Background(), protocol.Command{ID: "2", Action: "files.archive_old",
		Params: map[string]string{"path": root, "older_than_days": "1"}})
	if res.Success || !strings.Contains(res.Error, "outside") {
		t.Fatalf("expected refusal outside roots, got %+v", res)
	}
	// Path traversal: refused.
	res = e.Execute(context.Background(), protocol.Command{ID: "3", Action: "files.archive_old",
		Params: map[string]string{"path": logs + "/../", "older_than_days": "1"}})
	if res.Success {
		t.Fatal("path traversal accepted")
	}
}

func TestAgentRefusesUnadvertisedActions(t *testing.T) {
	e := NewExecutor(&Config{DisabledActions: []string{"system.reboot"}})
	for _, a := range []string{"shell.run", "system.reboot", "does.not.exist"} {
		res := e.Execute(context.Background(), protocol.Command{ID: "x", Action: a, Params: map[string]string{"script": "id"}})
		if res.Success || !strings.Contains(res.Error, "not enabled") {
			t.Errorf("%s: expected refusal, got %+v", a, res)
		}
	}
	// Even if the control plane sent bad parameters, the agent re-validates.
	res := e.Execute(context.Background(), protocol.Command{ID: "y", Action: "network.test_port", Params: map[string]string{"host": "$(reboot)", "port": "80"}})
	if res.Success {
		t.Fatal("agent accepted invalid parameters")
	}
}

func TestLargeFiles(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "big"), 0o755)
	os.WriteFile(filepath.Join(root, "big", "huge.bin"), make([]byte, 1<<20), 0o644)
	os.WriteFile(filepath.Join(root, "small.txt"), []byte("x"), 0o644)
	out, err := largeFiles(context.Background(), root, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "huge.bin") || !strings.Contains(out, "1.0 MiB") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}
