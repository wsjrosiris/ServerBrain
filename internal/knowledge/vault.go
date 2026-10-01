package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Vault renders ServerBrain's knowledge into an Obsidian vault:
//
//	<vault>/<folder>/Start.md                     entry point
//	<vault>/<folder>/Infrastruktur.md             all servers, roles, dependency graph
//	<vault>/<folder>/Server/<HOST>.md             one note per server ("Steckbrief")
//	<vault>/<folder>/Tagebuch/<YYYY>/<DATE>.md    the server diary, one note per day
//
// Links use full vault paths, so the folder can live inside an existing
// vault without name clashes.
type Vault struct {
	Root         string
	Folder       string
	Loc          *time.Location
	OfflineAfter time.Duration
	BackfillDays int

	st  *store.Store
	log *slog.Logger

	dirty      chan struct{}
	mu         sync.Mutex
	lastRender time.Time
	names      map[string]string // server id -> note name (last render)
}

const notesPlaceholder = "_Eigene Notizen: Ansprechpartner, Besonderheiten, Wartungsfenster, bekannte Workarounds. ServerBrain überschreibt diesen Bereich nie und gibt ihn der KI als Kontext mit._"

func NewVault(root, folder string, loc *time.Location, st *store.Store, log *slog.Logger) *Vault {
	if loc == nil {
		loc = time.Local
	}
	return &Vault{Root: root, Folder: folder, Loc: loc, OfflineAfter: 90 * time.Second, BackfillDays: 30,
		st: st, log: log, dirty: make(chan struct{}, 1), names: map[string]string{}}
}

// Notify schedules a render soon (debounced).
func (v *Vault) Notify() {
	select {
	case v.dirty <- struct{}{}:
	default:
	}
}

// Run renders on changes (debounced) and at least once a minute.
func (v *Vault) Run(ctx context.Context) {
	if err := v.Render(ctx); err != nil {
		v.log.Error("vault render", "err", err)
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-v.dirty:
			// Let a burst of diary entries settle into one write.
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		if err := v.Render(ctx); err != nil {
			v.log.Error("vault render", "err", err)
		}
	}
}

func (v *Vault) base() string { return path.Clean(strings.Trim(filepath.ToSlash(v.Folder), "/")) }

func (v *Vault) file(rel string) string {
	return filepath.Join(v.Root, filepath.FromSlash(v.base()), filepath.FromSlash(rel))
}

// link builds an Obsidian wikilink with a vault-relative path.
func (v *Vault) link(rel, alias string) string {
	p := strings.TrimSuffix(path.Join(v.base(), rel), ".md")
	if alias == "" {
		return "[[" + p + "]]"
	}
	return "[[" + p + "|" + alias + "]]"
}

func (v *Vault) serverRel(name string) string { return "Server/" + name + ".md" }

func (v *Vault) dayRel(day string) string { return "Tagebuch/" + day[:4] + "/" + day + ".md" }

func (v *Vault) serverLink(names map[string]string, id, fallback string) string {
	if n, ok := names[id]; ok {
		return v.link(v.serverRel(n), n)
	}
	if fallback != "" {
		return fallback
	}
	return "(gelöschter Server)"
}

func (v *Vault) dayLink(day string) string {
	t, _ := time.Parse("2006-01-02", day)
	return v.link(v.dayRel(day), t.Format("02.01.2006"))
}

// noteNames assigns unique note names to servers.
func noteNames(servers []*store.Server) map[string]string {
	count := map[string]int{}
	for _, s := range servers {
		count[strings.ToLower(NoteName(s.Hostname))]++
	}
	out := map[string]string{}
	for _, s := range servers {
		n := NoteName(s.Hostname)
		if count[strings.ToLower(n)] > 1 {
			n += " (" + s.ID[:6] + ")"
		}
		out[s.ID] = n
	}
	return out
}

// Render writes all notes that changed.
func (v *Vault) Render(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	servers, err := v.st.ListServers(ctx, true)
	if err != nil {
		return err
	}
	names := noteNames(servers)
	v.names = names
	deps, err := v.st.Dependencies(ctx, "")
	if err != nil {
		return err
	}

	since := v.lastRender.Add(-time.Minute)
	if v.lastRender.IsZero() {
		since = time.Now().AddDate(0, 0, -v.BackfillDays)
	}
	started := time.Now()
	days, err := v.st.JournalDays(ctx, since, v.Loc)
	if err != nil {
		return err
	}
	written := 0
	for _, day := range days {
		n, err := v.renderDay(ctx, day, names)
		if err != nil {
			return err
		}
		written += n
	}
	allDays, err := v.st.JournalDays(ctx, time.Now().AddDate(0, 0, -v.BackfillDays), v.Loc)
	if err != nil {
		return err
	}
	for _, s := range servers {
		n, err := v.renderServer(ctx, s, names, deps)
		if err != nil {
			return err
		}
		written += n
	}
	n, err := v.renderInfrastructure(ctx, servers, names, deps)
	if err != nil {
		return err
	}
	written += n
	n, err = v.renderStart(servers, allDays)
	if err != nil {
		return err
	}
	written += n
	v.lastRender = started
	if written > 0 {
		v.log.Info("obsidian vault updated", "notes", written, "path", filepath.Join(v.Root, v.base()))
	}
	return nil
}

func (v *Vault) write(rel string, props []Prop, block, newBody string) (int, error) {
	p := v.file(rel)
	existing, _ := os.ReadFile(p)
	changed, err := writeIfChanged(p, Merge(string(existing), props, block, newBody))
	if changed {
		return 1, err
	}
	return 0, err
}

// ---------- diary ----------

var sevIcon = map[string]string{store.SevCrit: "🔴", store.SevWarn: "🟠", store.SevOK: "🟢", store.SevInfo: "🔹"}

func (v *Vault) renderDay(ctx context.Context, day string, names map[string]string) (int, error) {
	start, err := time.ParseInLocation("2006-01-02", day, v.Loc)
	if err != nil {
		return 0, err
	}
	entries, err := v.st.ListJournal(ctx, store.JournalFilter{Since: start, Until: start.AddDate(0, 0, 1), Limit: 5000})
	if err != nil {
		return 0, err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	groups := map[string][]store.JournalEntry{}
	var order []string
	for _, e := range entries {
		k := e.ServerID
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a == "" || b == "" {
			return b == ""
		}
		return strings.ToLower(groups[a][0].Hostname) < strings.ToLower(groups[b][0].Hostname)
	})
	var b strings.Builder
	crit, warn := 0, 0
	var hosts []string
	for _, k := range order {
		heading := "Allgemein"
		if k != "" {
			heading = v.serverLink(names, k, groups[k][0].Hostname)
			hosts = append(hosts, groups[k][0].Hostname)
		}
		fmt.Fprintf(&b, "## %s\n", heading)
		for _, e := range groups[k] {
			switch e.Severity {
			case store.SevCrit:
				crit++
			case store.SevWarn:
				warn++
			}
			fmt.Fprintf(&b, "- %s %s **%s** #sb/%s", e.TS.In(v.Loc).Format("15:04"), sevIcon[e.Severity], mdEscape(e.Title), e.Category)
			if e.Author != "" && e.Author != "ServerBrain" {
				fmt.Fprintf(&b, " — _%s_", mdEscape(e.Author))
			}
			b.WriteString("\n")
			if strings.TrimSpace(e.Detail) != "" {
				b.WriteString(indent(e.Detail) + "\n")
			}
		}
		b.WriteString("\n")
	}
	summary := fmt.Sprintf("> %d Einträge · %d kritisch · %d Warnungen · %d Server\n\n", len(entries), crit, warn, len(hosts))
	props := []Prop{
		{"typ", "serverbrain-tagebuch"},
		{"datum", day},
		{"eintraege", len(entries)},
		{"kritisch", crit},
		{"warnungen", warn},
		{"server", hosts},
		{"tags", []string{"serverbrain/tagebuch"}},
	}
	title := "# Servertagebuch " + start.Format("02.01.2006") + "\n\n"
	newBody := title + "{{block}}\n\n## Notizen des Tages\n\n"
	return v.write(v.dayRel(day), props, summary+strings.TrimRight(b.String(), "\n"), newBody)
}

// ---------- server notes ----------

func (v *Vault) renderServer(ctx context.Context, s *store.Server, names map[string]string, deps []store.Dependency) (int, error) {
	hb := s.Snapshot
	if hb == nil {
		hb = &protocol.Heartbeat{}
	}
	sys := hb.System
	name := names[s.ID]
	roleFacts, _ := v.st.Facts(ctx, s.ID, "role:")
	baseline, _ := v.st.Baseline(ctx, s.ID, time.Now().AddDate(0, 0, -7))
	sigs, _ := v.st.ErrorSignatures(ctx, s.ID, time.Now().AddDate(0, 0, -30), 10)
	recent, _ := v.st.ListJournal(ctx, store.JournalFilter{ServerID: s.ID, Since: time.Now().AddDate(0, 0, -v.BackfillDays), Limit: 15})
	online := !s.LastSeen.IsZero() && time.Since(s.LastSeen) < v.OfflineAfter

	var roles, roleTags []string
	var b strings.Builder
	status := "🔴 offline"
	if online {
		status = "🟢 online"
	}
	b.WriteString("> [!info] Steckbrief\n")
	var facts []string
	for _, x := range []string{sys.OSVersion, prefixed("Domäne ", sys.Domain)} {
		if x != "" {
			facts = append(facts, x)
		}
	}
	if sys.CPUs > 0 {
		facts = append(facts, fmt.Sprintf("%d CPUs", sys.CPUs))
	}
	if hb.Metrics.MemTotal > 0 {
		facts = append(facts, GB(hb.Metrics.MemTotal)+" RAM")
	}
	fmt.Fprintf(&b, "> %s\n", strings.Join(facts, " · "))
	fmt.Fprintf(&b, "> Status: %s · IP: %s · Agent %s\n", status, orDash(strings.Join(sys.IPs, ", ")), orDash(s.AgentVersion))
	fmt.Fprintf(&b, "> Registriert: %s", s.EnrolledAt.In(v.Loc).Format("02.01.2006"))
	if !sys.BootTime.IsZero() {
		fmt.Fprintf(&b, " · letzter Systemstart: %s", sys.BootTime.In(v.Loc).Format("02.01.2006 15:04"))
	}
	b.WriteString("\n\n## Rollen\n")
	if len(roleFacts) == 0 {
		b.WriteString("_Noch keine Rolle erkannt._\n")
	}
	for _, f := range roleFacts {
		nm, via, _ := strings.Cut(f.Value, "|")
		roles = append(roles, nm)
		roleTags = append(roleTags, "rolle/"+strings.TrimPrefix(f.Key, "role:"))
		fmt.Fprintf(&b, "- **%s** — erkannt über %s, seit %s\n", nm, via, f.FirstSeen.In(v.Loc).Format("02.01.2006"))
	}

	if len(hb.Metrics.Disks) > 0 {
		b.WriteString("\n## Datenträger\n| Laufwerk | Größe | Belegt | Frei |\n|---|---|---|---|\n")
		for _, d := range hb.Metrics.Disks {
			_, pct := diskLevel(d)
			fmt.Fprintf(&b, "| %s | %s | %.0f %% | %s |\n", mdEscape(strings.TrimSpace(d.Name+" "+d.Label)), GB(d.Total), pct, GB(d.Free))
		}
	}

	b.WriteString("\n## Abhängigkeiten\n")
	var out, in []string
	listenProc := map[int]string{}
	for _, c := range hb.Connections {
		if c.State == protocol.ConnListen && c.Process != "" {
			listenProc[c.LocalPort] = c.Process
		}
	}
	for _, d := range deps {
		if d.SrcID == s.ID {
			line := fmt.Sprintf("- %s — Port %s", v.serverLink(names, d.DstID, d.DstHost), PortName(d.Port))
			if d.Process != "" {
				line += " · Prozess " + d.Process
			}
			out = append(out, line+fmt.Sprintf(" · seit %s", d.FirstSeen.In(v.Loc).Format("02.01.2006")))
		}
		if d.DstID == s.ID {
			line := fmt.Sprintf("- %s — Port %s", v.serverLink(names, d.SrcID, d.SrcHost), PortName(d.Port))
			if p := listenProc[d.Port]; p != "" {
				line += " · Dienst " + p
			}
			in = append(in, line+fmt.Sprintf(" · seit %s", d.FirstSeen.In(v.Loc).Format("02.01.2006")))
		}
	}
	if len(out)+len(in) == 0 {
		b.WriteString("_Noch keine Verbindungen zu anderen verwalteten Servern beobachtet._\n")
	}
	if len(out) > 0 {
		b.WriteString("**Nutzt:**\n" + strings.Join(out, "\n") + "\n")
	}
	if len(in) > 0 {
		b.WriteString("**Wird genutzt von:**\n" + strings.Join(in, "\n") + "\n")
	}

	var ports []string
	for _, c := range hb.Connections {
		if c.State == protocol.ConnListen && c.LocalPort < 49152 {
			p := PortName(c.LocalPort)
			if c.Process != "" {
				p += " – " + c.Process
			}
			ports = append(ports, p)
		}
	}
	if len(ports) > 0 {
		sort.Strings(ports)
		ports = dedupe(ports)
		b.WriteString("\n## Lauschende Ports\n" + strings.Join(ports, " · ") + "\n")
	}

	var important []string
	for _, svc := range hb.Services {
		auto := IsAutoStart(svc.StartType)
		stoppedAuto := auto && svc.Status == "Stopped" && !BenignStoppedServices[strings.ToLower(svc.Name)]
		if IsRoleCritical(svc.Name) || stoppedAuto {
			icon := "🟢"
			if svc.Status != "Running" {
				icon = "🔴"
			}
			important = append(important, fmt.Sprintf("| %s %s | %s | %s | %s |", icon, mdEscape(svc.Name), mdEscape(svc.DisplayName), svc.Status, svc.StartType))
		}
	}
	if len(important) > 0 {
		sort.Strings(important)
		b.WriteString("\n## Wichtige Dienste\n| Dienst | Anzeigename | Status | Start |\n|---|---|---|---|\n" + strings.Join(important, "\n") + "\n")
	}

	if baseline.Samples > 0 {
		fmt.Fprintf(&b, "\n## Typische Auslastung (7 Tage)\nCPU ⌀ %.0f %% (max %.0f %%) · RAM ⌀ %.0f %% · Datenträger max %.0f %%\n",
			baseline.CPUAvg, baseline.CPUMax, baseline.MemAvg, baseline.DiskMax)
	}
	if len(sigs) > 0 {
		b.WriteString("\n## Bekannte Fehlerbilder (30 Tage)\n| Quelle | ID | Anzahl | Zuletzt | Meldung |\n|---|---|---|---|---|\n")
		for _, e := range sigs {
			msg := firstLines(e.Message, 1)
			if len(msg) > 140 {
				msg = msg[:140] + "…"
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %s | %s |\n", mdEscape(e.Source), e.EventID, e.Count, e.Last.In(v.Loc).Format("02.01. 15:04"), mdEscape(msg))
		}
	}
	if len(recent) > 0 {
		b.WriteString("\n## Letzte Tagebucheinträge\n")
		for _, e := range recent {
			day := e.TS.In(v.Loc).Format("2006-01-02")
			fmt.Fprintf(&b, "- %s %s %s %s\n", v.dayLink(day), e.TS.In(v.Loc).Format("15:04"), sevIcon[e.Severity], mdEscape(e.Title))
		}
	}

	tags := append([]string{"serverbrain/server"}, roleTags...)
	for _, t := range s.Tags {
		tags = append(tags, "server/"+strings.ReplaceAll(t, " ", "-"))
	}
	props := []Prop{
		{"typ", "serverbrain-server"},
		{"hostname", sys.Hostname},
		{"server_id", s.ID},
		{"status", map[bool]string{true: "online", false: "offline"}[online]},
		{"betriebssystem", orDash(sys.OSVersion)},
		{"domaene", sys.Domain},
		{"ip", sys.IPs},
		{"cpus", sys.CPUs},
		{"ram_gb", int(float64(hb.Metrics.MemTotal)/(1<<30) + 0.5)},
		{"rollen", roles},
		{"registriert", s.EnrolledAt.In(v.Loc).Format("2006-01-02")},
		{"tags", tags},
	}
	if sys.Hostname == "" {
		props[1].Value = s.Hostname
	}
	newBody := "# " + name + "\n\n{{block}}\n\n## Notizen\n" + notesPlaceholder + "\n"
	return v.write(v.serverRel(name), props, strings.TrimRight(b.String(), "\n"), newBody)
}

// ---------- infrastructure & start ----------

func (v *Vault) renderInfrastructure(ctx context.Context, servers []*store.Server, names map[string]string, deps []store.Dependency) (int, error) {
	var b strings.Builder
	online := 0
	roleIndex := map[string][]string{}
	b.WriteString("| Server | Status | Rollen | Betriebssystem | IP | Tags |\n|---|---|---|---|---|---|\n")
	for _, s := range servers {
		up := !s.LastSeen.IsZero() && time.Since(s.LastSeen) < v.OfflineAfter
		if up {
			online++
		}
		facts, _ := v.st.Facts(ctx, s.ID, "role:")
		var roles []string
		for _, f := range facts {
			nm, _, _ := strings.Cut(f.Value, "|")
			roles = append(roles, nm)
			roleIndex[nm] = append(roleIndex[nm], v.serverLink(names, s.ID, s.Hostname))
		}
		var ips []string
		osv := s.OSVersion
		if s.Snapshot != nil {
			ips = s.Snapshot.System.IPs
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", v.serverLink(names, s.ID, s.Hostname), map[bool]string{true: "🟢", false: "🔴"}[up],
			mdEscape(strings.Join(roles, ", ")), mdEscape(orDash(osv)), mdEscape(strings.Join(ips, ", ")), mdEscape(strings.Join(s.Tags, ", ")))
	}
	head := fmt.Sprintf("%d Server · %d online · %d bekannte Abhängigkeiten\n\n## Server\n", len(servers), online, len(deps))

	b.WriteString("\n## Abhängigkeiten\n")
	if len(deps) == 0 {
		b.WriteString("_Noch keine Verbindungen zwischen verwalteten Servern beobachtet. ServerBrain lernt sie automatisch aus den TCP-Verbindungen, die die Agenten melden._\n")
	} else {
		b.WriteString("```mermaid\ngraph LR\n")
		ids := map[string]string{}
		node := func(id, host string) string {
			if n, ok := ids[id]; ok {
				return n
			}
			n := fmt.Sprintf("n%d", len(ids)+1)
			ids[id] = n
			label := names[id]
			if label == "" {
				label = host
			}
			fmt.Fprintf(&b, "  %s[\"%s\"]\n", n, strings.ReplaceAll(label, `"`, "'"))
			return n
		}
		for _, d := range deps {
			src, dst := node(d.SrcID, d.SrcHost), node(d.DstID, d.DstHost)
			fmt.Fprintf(&b, "  %s -->|%s| %s\n", src, strings.ReplaceAll(PortName(d.Port), "|", "/"), dst)
		}
		b.WriteString("```\n\n| Von | Nach | Port | Prozess | Seit |\n|---|---|---|---|---|\n")
		for _, d := range deps {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", v.serverLink(names, d.SrcID, d.SrcHost), v.serverLink(names, d.DstID, d.DstHost),
				PortName(d.Port), mdEscape(d.Process), d.FirstSeen.In(v.Loc).Format("02.01.2006"))
		}
	}
	if len(roleIndex) > 0 {
		b.WriteString("\n## Rollen\n")
		var rs []string
		for r := range roleIndex {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		for _, r := range rs {
			fmt.Fprintf(&b, "- **%s**: %s\n", r, strings.Join(roleIndex[r], ", "))
		}
	}
	props := []Prop{{"typ", "serverbrain-infrastruktur"}, {"server", len(servers)}, {"online", online}, {"tags", []string{"serverbrain"}}}
	newBody := "# Infrastruktur\n\n{{block}}\n\n## Notizen\n_Eigene Notizen zur Gesamtinfrastruktur (Netzpläne, Verantwortlichkeiten, Standorte)._\n"
	return v.write("Infrastruktur.md", props, head+strings.TrimRight(b.String(), "\n"), newBody)
}

func (v *Vault) renderStart(servers []*store.Server, days []string) (int, error) {
	var b strings.Builder
	b.WriteString("ServerBrain lernt automatisch aus den Agenten auf deinen Servern und schreibt sein Wissen hierher:\n\n")
	b.WriteString("- " + v.link("Infrastruktur.md", "Infrastruktur") + " — alle Server, Rollen und der Abhängigkeitsgraph\n")
	b.WriteString("- **Server-Steckbriefe** in `" + v.base() + "/Server/` — Rollen, Datenträger, Abhängigkeiten, Fehlerbilder, Tagebuch\n")
	b.WriteString("- **Servertagebuch** in `" + v.base() + "/Tagebuch/` — was wann auf welchem Server passiert ist\n\n")
	b.WriteString("Bereiche zwischen den unsichtbaren `serverbrain`-Markern werden automatisch gepflegt. Alles andere gehört dir: Eigene Notizen, Links und Properties bleiben erhalten und werden der KI als Kontext mitgegeben.\n")
	if len(days) > 0 {
		b.WriteString("\n## Letzte Tagebuchtage\n")
		sorted := append([]string(nil), days...)
		sort.Sort(sort.Reverse(sort.StringSlice(sorted)))
		for i, d := range sorted {
			if i == 14 {
				break
			}
			b.WriteString("- " + v.dayLink(d) + "\n")
		}
	}
	props := []Prop{{"typ", "serverbrain-start"}, {"tags", []string{"serverbrain"}}}
	return v.write("Start.md", props, strings.TrimRight(b.String(), "\n"), "# ServerBrain\n\n{{block}}\n")
}

// ---------- reading back ----------

// ManualNotes returns what people wrote into a server's note in Obsidian.
func (v *Vault) ManualNotes(serverID string) (string, string) {
	v.mu.Lock()
	name := v.names[serverID]
	v.mu.Unlock()
	if name == "" {
		return "", ""
	}
	rel := v.serverRel(name)
	data, err := os.ReadFile(v.file(rel))
	if err != nil {
		return "", rel
	}
	return UserContent(string(data), notesPlaceholder), path.Join(v.base(), rel)
}

// Note returns the full Markdown of a server note.
func (v *Vault) Note(serverID string) string {
	v.mu.Lock()
	name := v.names[serverID]
	v.mu.Unlock()
	if name == "" {
		return ""
	}
	data, _ := os.ReadFile(v.file(v.serverRel(name)))
	return string(data)
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "–"
	}
	return s
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
