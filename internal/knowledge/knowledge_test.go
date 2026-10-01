package knowledge

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

func TestDetectRoles(t *testing.T) {
	hb := &protocol.Heartbeat{
		System: protocol.SystemInfo{OS: "windows"},
		Services: []protocol.Service{
			{Name: "W3SVC", Status: "Running", StartType: "Auto"},
			{Name: "MSSQL$PROD", Status: "Running", StartType: "Auto"},
			{Name: "NTDS", Status: "Stopped", StartType: "Disabled"}, // disabled: not a role
		},
		Connections: []protocol.Connection{
			{State: "listen", LocalPort: 80}, {State: "listen", LocalPort: 445}, {State: "listen", LocalPort: 6379},
		},
	}
	got := map[string]string{}
	for _, r := range DetectRoles(hb) {
		got[r.Key] = r.Name
	}
	want := map[string]string{"web": "Webserver (IIS)", "mssql": "SQL Server", "redis": "Redis"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("role %s: got %q want %q (all: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["ad"]; ok {
		t.Error("disabled NTDS detected as role")
	}
	if _, ok := got["smb"]; ok {
		t.Error("port 445 on Windows must not count as file server")
	}
}

func TestMergePreservesUserContent(t *testing.T) {
	props := []Prop{{"typ", "serverbrain-server"}, {"rollen", []string{"IIS"}}}
	doc := Merge("", props, "generated v1", "# WEB-03\n\n{{block}}\n\n## Notizen\nplaceholder\n")
	if !strings.Contains(doc, "generated v1") || !strings.Contains(doc, "# WEB-03") {
		t.Fatalf("new doc:\n%s", doc)
	}
	// A person edits the note in Obsidian: own property and notes.
	edited := strings.Replace(doc, "---\n#", "---\n#", 1)
	edited = strings.Replace(edited, "typ: \"serverbrain-server\"", "typ: \"serverbrain-server\"\nverantwortlich: \"Team Web\"", 1)
	edited = strings.Replace(edited, "placeholder", "Wartungsfenster: Sonntag 02:00\nAnsprechpartner: Kai", 1)

	doc2 := Merge(edited, []Prop{{"typ", "serverbrain-server"}, {"rollen", []string{"IIS", "SQL"}}}, "generated v2", "unused")
	for _, want := range []string{"generated v2", "verantwortlich: \"Team Web\"", "Wartungsfenster: Sonntag 02:00", "  - \"SQL\""} {
		if !strings.Contains(doc2, want) {
			t.Errorf("merged doc misses %q:\n%s", want, doc2)
		}
	}
	if strings.Contains(doc2, "generated v1") {
		t.Error("old managed block kept")
	}
	notes := UserContent(doc2, "placeholder")
	if !strings.Contains(notes, "Ansprechpartner: Kai") || strings.Contains(notes, "generated") || strings.Contains(notes, "# WEB-03") {
		t.Errorf("user content: %q", notes)
	}
	// A note without markers (created by hand) gets the block inserted.
	doc3 := Merge("# SQL-01\nmeine Notiz\n", props, "auto", "unused")
	if !strings.Contains(doc3, "meine Notiz") || !strings.Contains(doc3, "auto") {
		t.Errorf("hand-made note:\n%s", doc3)
	}
}

type fixture struct {
	t   *testing.T
	st  *store.Store
	l   *Learner
	ctx context.Context
}

func newFixture(t *testing.T) *fixture {
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &fixture{t: t, st: st, l: NewLearner(st, slog.New(slog.NewTextHandler(io.Discard, nil))), ctx: context.Background()}
}

// beat stores a heartbeat for the server and runs the learner like the
// control plane does.
func (f *fixture) beat(id string, hb protocol.Heartbeat) {
	f.t.Helper()
	prev, err := f.st.GetServer(f.ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	events := hb.Events
	if err := f.st.RecordHeartbeat(f.ctx, id, "10.0.0.1", &hb); err != nil {
		f.t.Fatal(err)
	}
	hb.Events = events
	fleet, _ := f.st.ListServers(f.ctx, false)
	f.l.Observe(f.ctx, prev, &hb, fleet)
}

func (f *fixture) enroll(host string) string {
	tok, _, _ := f.st.CreateEnrollmentToken(f.ctx, "t", nil, 1, time.Hour)
	id, _, err := f.st.Enroll(f.ctx, tok, protocol.SystemInfo{Hostname: host, OS: "windows"}, "1", "")
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) titles(id string) []string {
	list, _ := f.st.ListJournal(f.ctx, store.JournalFilter{ServerID: id, Since: time.Now().Add(-time.Hour)})
	var out []string
	for i := len(list) - 1; i >= 0; i-- {
		out = append(out, list[i].Title)
	}
	return out
}

func hasPrefix(list []string, p string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func webHeartbeat() protocol.Heartbeat {
	return protocol.Heartbeat{
		AgentVersion: "1",
		System:       protocol.SystemInfo{Hostname: "WEB-03", OS: "windows", OSVersion: "Windows Server 2022", CPUs: 4, IPs: []string{"10.0.0.20"}, BootTime: time.Now().Add(-48 * time.Hour)},
		Metrics:      protocol.Metrics{MemTotal: 16 << 30, MemUsed: 8 << 30, Disks: []protocol.Disk{{Name: "C:", Total: 100 << 30, Free: 40 << 30}}},
		Services: []protocol.Service{
			{Name: "W3SVC", DisplayName: "World Wide Web Publishing Service", Status: "Running", StartType: "Auto"},
			{Name: "Spooler", Status: "Running", StartType: "Auto"},
			{Name: "BITS", Status: "Stopped", StartType: "Manual"},
		},
		Connections: []protocol.Connection{{State: "listen", LocalPort: 443, Process: "System"}, {State: "established", RemoteAddr: "10.0.0.10", RemotePort: 1433, Process: "w3wp"}},
	}
}

func TestLearnerDiary(t *testing.T) {
	f := newFixture(t)
	sql := f.enroll("SQL-01")
	web := f.enroll("WEB-03")
	f.beat(sql, protocol.Heartbeat{System: protocol.SystemInfo{Hostname: "SQL-01", OS: "windows", IPs: []string{"10.0.0.10"}},
		Connections: []protocol.Connection{{State: "listen", LocalPort: 1433, Process: "sqlservr"}}})

	hb := webHeartbeat()
	f.beat(web, hb)
	got := f.titles(web)
	if !hasPrefix(got, "Inventar erfasst") || !hasPrefix(got, "Neue Abhängigkeit: WEB-03 → SQL-01 Port 1433") {
		t.Fatalf("first heartbeat: %v", got)
	}
	roles, _ := f.st.Facts(f.ctx, web, "role:")
	if len(roles) != 1 || !strings.HasPrefix(roles[0].Value, "Webserver (IIS)") {
		t.Fatalf("roles: %v", roles)
	}

	// Nothing changed: nothing new in the diary.
	before := len(f.titles(web))
	f.beat(web, hb)
	if n := len(f.titles(web)); n != before {
		t.Fatalf("identical heartbeat produced entries: %v", f.titles(web)[before:])
	}

	// The IIS outage scenario: service stops, disk fills, new error, reboot,
	// software installed, manual service toggles (ignored).
	hb2 := webHeartbeat()
	hb2.Services[0].Status = "Stopped"
	hb2.Services[2].Status = "Running" // BITS manual: must not be journaled
	hb2.Services = append(hb2.Services, protocol.Service{Name: "MSSQL$EXPRESS", DisplayName: "SQL Server (EXPRESS)", Status: "Running", StartType: "Auto"})
	hb2.Metrics.Disks[0].Free = 2 << 30
	hb2.System.BootTime = time.Now()
	hb2.Events = []protocol.Event{
		{Level: "Error", Source: "W3SVC", EventID: 1000, Message: "The World Wide Web Publishing Service terminated unexpectedly."},
		{Level: "Error", Source: "W3SVC", EventID: 1000, Message: "again"},
	}
	f.beat(web, hb2)
	got = f.titles(web)[before:]
	for _, want := range []string{"Neustart erkannt", "Dienst gestoppt: W3SVC", "1 neue(r) Dienst(e) installiert", "Datenträger C: fast voll", "Neues Fehlerbild: W3SVC (ID 1000), 2×", "Neue Rolle erkannt: SQL Server"} {
		if !hasPrefix(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if hasPrefix(got, "Dienst gestoppt: BITS") || hasPrefix(got, "Dienst läuft wieder: BITS") {
		t.Error("manual service toggle journaled")
	}

	// Same error again: known pattern, no new entry. Recovery is journaled.
	before = len(f.titles(web))
	hb3 := hb2
	hb3.Services = append([]protocol.Service(nil), hb2.Services...)
	hb3.Services[0].Status = "Running"
	hb3.Metrics.Disks = []protocol.Disk{{Name: "C:", Total: 100 << 30, Free: 50 << 30}}
	hb3.Events = []protocol.Event{{Level: "Error", Source: "W3SVC", EventID: 1000, Message: "x"}}
	f.beat(web, hb3)
	got = f.titles(web)[before:]
	if hasPrefix(got, "Neues Fehlerbild") {
		t.Errorf("known error journaled again: %v", got)
	}
	for _, want := range []string{"Dienst läuft wieder: W3SVC", "Datenträger C: wieder unter 90 %"} {
		if !hasPrefix(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}

	// Offline / back online.
	srvs, _ := f.st.ListServers(f.ctx, false)
	f.l.CheckAvailability(f.ctx, srvs, -time.Second) // everything counts as overdue
	f.l.CheckAvailability(f.ctx, srvs, -time.Second) // journaled only once
	f.beat(web, hb3)
	got = f.titles(web)
	offline := 0
	for _, s := range got {
		if s == "Nicht mehr erreichbar" {
			offline++
		}
	}
	if offline != 1 || !hasPrefix(got, "Wieder erreichbar") {
		t.Errorf("availability entries: %v", got)
	}
}

func TestVaultRendering(t *testing.T) {
	f := newFixture(t)
	sql := f.enroll("SQL-01")
	web := f.enroll("WEB-03")
	f.beat(sql, protocol.Heartbeat{System: protocol.SystemInfo{Hostname: "SQL-01", OS: "windows", IPs: []string{"10.0.0.10"}},
		Connections: []protocol.Connection{{State: "listen", LocalPort: 1433, Process: "sqlservr"}}})
	f.beat(web, webHeartbeat())
	_ = f.l.Note(f.ctx, web, store.CatNote, store.SevInfo, "Zertifikat erneuert", "neues Zertifikat bis 2027", "kai")

	dir := t.TempDir()
	v := NewVault(dir, "ServerBrain", time.UTC, f.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	v.OfflineAfter = time.Hour
	if err := v.Render(f.ctx); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, "ServerBrain", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	note := read("Server/WEB-03.md")
	for _, want := range []string{"typ: \"serverbrain-server\"", "rollen:\n  - \"Webserver (IIS)\"", "[[ServerBrain/Server/SQL-01|SQL-01]] — Port 1433 (SQL Server) · Prozess w3wp", "## Notizen", "Zertifikat erneuert"} {
		if !strings.Contains(note, want) {
			t.Errorf("server note misses %q:\n%s", want, note)
		}
	}
	if !strings.Contains(read("Server/SQL-01.md"), "**Wird genutzt von:**\n- [[ServerBrain/Server/WEB-03|WEB-03]] — Port 1433 (SQL Server) · Dienst sqlservr") {
		t.Errorf("SQL note misses reverse dependency:\n%s", read("Server/SQL-01.md"))
	}
	infra := read("Infrastruktur.md")
	if !strings.Contains(infra, "```mermaid") || !strings.Contains(infra, "-->|1433 (SQL Server)|") {
		t.Errorf("infrastructure note:\n%s", infra)
	}
	day := time.Now().UTC().Format("2006-01-02")
	diary := read("Tagebuch/" + day[:4] + "/" + day + ".md")
	for _, want := range []string{"# Servertagebuch", "## [[ServerBrain/Server/WEB-03|WEB-03]]", "**Zertifikat erneuert** #sb/notiz — _kai_", "\tneues Zertifikat bis 2027"} {
		if !strings.Contains(diary, want) {
			t.Errorf("diary misses %q:\n%s", want, diary)
		}
	}

	// A person writes notes in Obsidian; the next render keeps them and
	// ServerBrain can read them back.
	p := filepath.Join(dir, "ServerBrain", "Server", "WEB-03.md")
	os.WriteFile(p, []byte(strings.Replace(note, notesPlaceholder, "App-Pool CustomerPortal crasht bei vollem Log-Laufwerk.", 1)), 0o644)
	_ = f.l.Note(f.ctx, web, store.CatNote, store.SevInfo, "Noch ein Eintrag", "", "kai")
	if err := v.Render(f.ctx); err != nil {
		t.Fatal(err)
	}
	note = read("Server/WEB-03.md")
	if !strings.Contains(note, "App-Pool CustomerPortal crasht") || !strings.Contains(note, "Noch ein Eintrag") {
		t.Errorf("manual note lost or block not updated:\n%s", note)
	}
	if manual, _ := v.ManualNotes(web); !strings.Contains(manual, "App-Pool CustomerPortal crasht") || strings.Contains(manual, "Steckbrief") {
		t.Errorf("manual notes read back: %q", manual)
	}

	// Unchanged knowledge does not rewrite files (no sync churn).
	st1, _ := os.Stat(p)
	time.Sleep(20 * time.Millisecond)
	if err := v.Render(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(p); !st2.ModTime().Equal(st1.ModTime()) {
		t.Error("unchanged note was rewritten")
	}
}
