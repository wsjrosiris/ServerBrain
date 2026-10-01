package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// Learner turns observations into knowledge. It compares every heartbeat
// with what is already known and writes only meaningful changes to the
// server diary, so the diary stays readable: a stopped automatic service,
// a reboot, newly installed software, a new error pattern, a new
// dependency - not every metric sample.
type Learner struct {
	st  *store.Store
	log *slog.Logger
	// OnChange is called after new diary entries were written.
	OnChange func()
	// OnSignal receives structured observations that automation (autopilot,
	// automatic AI analysis) can react to. Called synchronously; keep it fast.
	OnSignal func(Signal)
}

// Signal kinds.
const (
	SignalServiceStopped = "service_stopped" // automatic/role-critical service stopped
	SignalDiskCritical   = "disk_critical"   // a disk crossed the critical threshold
	SignalCriticalEvent  = "critical_event"  // a Critical event log entry
	SignalOffline        = "offline"         // agent stopped reporting
	SignalNewError       = "new_error"       // first occurrence of an error pattern
	SignalServiceRunning = "service_running" // a stopped service runs again
	SignalDiskRecovered  = "disk_recovered"  // a disk is below the threshold again
	SignalOnline         = "online"          // agent reports again
)

// Signal is a structured observation about a server.
type Signal struct {
	Kind     string
	ServerID string
	Hostname string
	Service  string // service_stopped
	Disk     string // disk_critical, disk_recovered
	Source   string // new_error, critical_event: event source
	EventID  int
	Title    string // human readable summary (as in the diary)
	Detail   string
}

func (l *Learner) signal(sig Signal) {
	if l.OnSignal != nil {
		l.OnSignal(sig)
	}
}

func NewLearner(st *store.Store, log *slog.Logger) *Learner {
	return &Learner{st: st, log: log}
}

const (
	maxNewErrorEntries    = 5
	maxCriticalEntries    = 3
	diskWarnPct           = 90.0
	diskCritPct           = 95.0
	rebootToleranceWindow = 2 * time.Minute
)

func (l *Learner) add(ctx context.Context, serverID, cat, sev, title, detail string) {
	if _, err := l.st.AddJournal(ctx, store.JournalEntry{ServerID: serverID, Category: cat, Severity: sev, Title: title, Detail: detail}); err != nil {
		l.log.Error("journal", "err", err)
	}
}

func (l *Learner) changed() {
	if l.OnChange != nil {
		l.OnChange()
	}
}

// Note writes a diary entry on behalf of a person or subsystem.
func (l *Learner) Note(ctx context.Context, serverID, cat, sev, title, detail, author string) error {
	_, err := l.st.AddJournal(ctx, store.JournalEntry{ServerID: serverID, Category: cat, Severity: sev, Title: title, Detail: detail, Author: author})
	if err == nil {
		l.changed()
	}
	return err
}

// Observe learns from a heartbeat. prev is the server record before the
// heartbeat was stored (LastSeen zero on the very first heartbeat); fleet
// is used to resolve IP addresses to known servers.
func (l *Learner) Observe(ctx context.Context, prev *store.Server, hb *protocol.Heartbeat, fleet []*store.Server) {
	id := prev.ID
	first := prev.LastSeen.IsZero() || prev.Snapshot == nil || prev.Snapshot.System.Hostname == ""
	var old protocol.Heartbeat
	if prev.Snapshot != nil {
		old = *prev.Snapshot
	}

	// Availability: back online?
	if v, err := l.st.GetFact(ctx, id, "status"); err == nil && strings.HasPrefix(v, "offline") {
		detail := ""
		if _, since, ok := strings.Cut(v, "|"); ok {
			if ms, err := strconv.ParseInt(since, 10, 64); err == nil {
				detail = "Nicht erreichbar seit " + time.UnixMilli(ms).Format("02.01.2006 15:04") + " (" + humanDuration(time.Since(time.UnixMilli(ms))) + ")."
			}
		}
		l.add(ctx, id, store.CatAvailability, store.SevOK, "Wieder erreichbar", detail)
		l.signal(Signal{Kind: SignalOnline, ServerID: id, Hostname: hb.System.Hostname})
	}
	_, _ = l.st.SetFact(ctx, id, "status", "online")

	roles := DetectRoles(hb)
	host := hb.System.Hostname
	if first {
		l.add(ctx, id, store.CatInventory, store.SevInfo, "Inventar erfasst", inventorySummary(hb, roles))
	} else {
		l.compareSystem(ctx, id, &old, hb)
		l.compareServices(ctx, id, host, &old, hb)
	}
	l.learnRoles(ctx, id, roles, first)
	l.learnDisks(ctx, id, host, hb, first)
	l.learnEvents(ctx, id, host, hb.Events)
	l.learnDependencies(ctx, prev, hb, fleet)
	l.changed()
}

func inventorySummary(hb *protocol.Heartbeat, roles []Role) string {
	var parts []string
	if hb.System.OSVersion != "" {
		parts = append(parts, hb.System.OSVersion)
	}
	if hb.System.Domain != "" {
		parts = append(parts, "Domäne "+hb.System.Domain)
	}
	if hb.System.CPUs > 0 {
		parts = append(parts, fmt.Sprintf("%d CPUs", hb.System.CPUs))
	}
	if hb.Metrics.MemTotal > 0 {
		parts = append(parts, fmt.Sprintf("%s RAM", GB(hb.Metrics.MemTotal)))
	}
	parts = append(parts, fmt.Sprintf("%d Datenträger", len(hb.Metrics.Disks)))
	if len(hb.Services) > 0 {
		parts = append(parts, fmt.Sprintf("%d Dienste", len(hb.Services)))
	}
	out := strings.Join(parts, " · ")
	if len(hb.System.IPs) > 0 {
		out += "\nIP-Adressen: " + strings.Join(hb.System.IPs, ", ")
	}
	if len(roles) > 0 {
		names := make([]string, len(roles))
		for i, r := range roles {
			names[i] = r.Name
		}
		out += "\nErkannte Rollen: " + strings.Join(names, ", ")
	}
	return out
}

func (l *Learner) compareSystem(ctx context.Context, id string, old, hb *protocol.Heartbeat) {
	o, n := old.System, hb.System
	if !o.BootTime.IsZero() && !n.BootTime.IsZero() {
		if d := n.BootTime.Sub(o.BootTime); d > rebootToleranceWindow || d < -rebootToleranceWindow {
			l.add(ctx, id, store.CatSystem, store.SevWarn, "Neustart erkannt", "Systemstart um "+n.BootTime.Local().Format("02.01.2006 15:04")+".")
		}
	}
	if o.OSVersion != "" && n.OSVersion != "" && o.OSVersion != n.OSVersion {
		l.add(ctx, id, store.CatSoftware, store.SevInfo, "Betriebssystem geändert", o.OSVersion+" → "+n.OSVersion)
	}
	if old.AgentVersion != "" && hb.AgentVersion != "" && old.AgentVersion != hb.AgentVersion {
		l.add(ctx, id, store.CatSoftware, store.SevInfo, "ServerBrain-Agent aktualisiert", old.AgentVersion+" → "+hb.AgentVersion)
	}
	if o.Hostname != "" && o.Hostname != n.Hostname {
		l.add(ctx, id, store.CatSystem, store.SevWarn, "Hostname geändert", o.Hostname+" → "+n.Hostname)
	}
	if len(o.IPs) > 0 && len(n.IPs) > 0 && !sameSet(o.IPs, n.IPs) {
		l.add(ctx, id, store.CatNetwork, store.SevInfo, "IP-Adressen geändert", strings.Join(o.IPs, ", ")+" → "+strings.Join(n.IPs, ", "))
	}
	if o.Domain != "" && n.Domain != "" && !strings.EqualFold(o.Domain, n.Domain) {
		l.add(ctx, id, store.CatSystem, store.SevWarn, "Domäne geändert", o.Domain+" → "+n.Domain)
	}
	if o.CPUs > 0 && n.CPUs > 0 && o.CPUs != n.CPUs {
		l.add(ctx, id, store.CatSystem, store.SevInfo, "CPU-Anzahl geändert", fmt.Sprintf("%d → %d", o.CPUs, n.CPUs))
	}
	if om, nm := old.Metrics.MemTotal, hb.Metrics.MemTotal; om > 0 && nm > 0 && absDiff(om, nm) > om/20 {
		l.add(ctx, id, store.CatSystem, store.SevInfo, "Arbeitsspeicher geändert", GB(om)+" → "+GB(nm))
	}
}

func (l *Learner) compareServices(ctx context.Context, id, host string, old, hb *protocol.Heartbeat) {
	if len(old.Services) == 0 || len(hb.Services) == 0 {
		return // no inventory on one side (Linux agent, collection failure)
	}
	before := map[string]protocol.Service{}
	for _, s := range old.Services {
		before[strings.ToLower(s.Name)] = s
	}
	var installed, removed []string
	seen := map[string]bool{}
	for _, s := range hb.Services {
		key := strings.ToLower(s.Name)
		seen[key] = true
		p, ok := before[key]
		if !ok {
			installed = append(installed, label(s))
			continue
		}
		relevant := (IsAutoStart(s.StartType) && !BenignStoppedServices[key]) || IsRoleCritical(s.Name)
		switch {
		case p.Status == "Running" && s.Status == "Stopped" && relevant:
			title, detail := "Dienst gestoppt: "+s.Name, label(s)+" (Starttyp "+s.StartType+") ist nicht mehr aktiv."
			l.add(ctx, id, store.CatService, store.SevCrit, title, detail)
			l.signal(Signal{Kind: SignalServiceStopped, ServerID: id, Hostname: host, Service: s.Name, Title: title, Detail: detail})
		case p.Status == "Stopped" && s.Status == "Running" && relevant:
			l.add(ctx, id, store.CatService, store.SevOK, "Dienst läuft wieder: "+s.Name, label(s))
			l.signal(Signal{Kind: SignalServiceRunning, ServerID: id, Hostname: host, Service: s.Name})
		}
		if p.StartType != "" && s.StartType != "" && !strings.EqualFold(p.StartType, s.StartType) {
			l.add(ctx, id, store.CatService, store.SevInfo, "Starttyp geändert: "+s.Name, p.StartType+" → "+s.StartType)
		}
	}
	for key, s := range before {
		if !seen[key] {
			removed = append(removed, label(s))
		}
	}
	if len(installed) > 0 {
		sort.Strings(installed)
		l.add(ctx, id, store.CatSoftware, store.SevInfo, fmt.Sprintf("%d neue(r) Dienst(e) installiert", len(installed)), "- "+strings.Join(installed, "\n- "))
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		l.add(ctx, id, store.CatSoftware, store.SevInfo, fmt.Sprintf("%d Dienst(e) entfernt", len(removed)), "- "+strings.Join(removed, "\n- "))
	}
}

func label(s protocol.Service) string {
	if s.DisplayName != "" && !strings.EqualFold(s.DisplayName, s.Name) {
		return s.Name + " (" + s.DisplayName + ")"
	}
	return s.Name
}

func (l *Learner) learnRoles(ctx context.Context, id string, roles []Role, first bool) {
	known, err := l.st.Facts(ctx, id, "role:")
	if err != nil {
		return
	}
	current := map[string]Role{}
	for _, r := range roles {
		current["role:"+r.Key] = r
	}
	for _, f := range known {
		if _, ok := current[f.Key]; !ok {
			_ = l.st.DeleteFact(ctx, id, f.Key)
			l.add(ctx, id, store.CatRole, store.SevWarn, "Rolle nicht mehr erkannt: "+strings.SplitN(f.Value, "|", 2)[0], "")
		}
	}
	for key, r := range current {
		isNew, err := l.st.SetFact(ctx, id, key, r.Name+"|"+r.Via)
		if err == nil && isNew && !first {
			l.add(ctx, id, store.CatRole, store.SevInfo, "Neue Rolle erkannt: "+r.Name, "Erkannt über "+r.Via+".")
		}
	}
}

func diskLevel(d protocol.Disk) (string, float64) {
	if d.Total == 0 {
		return "ok", 0
	}
	pct := 100 * float64(d.Total-d.Free) / float64(d.Total)
	switch {
	case pct >= diskCritPct:
		return "crit", pct
	case pct >= diskWarnPct:
		return "warn", pct
	}
	return "ok", pct
}

func (l *Learner) learnDisks(ctx context.Context, id, host string, hb *protocol.Heartbeat, first bool) {
	known, err := l.st.Facts(ctx, id, "disk:")
	if err != nil {
		return
	}
	was := map[string]string{}
	for _, f := range known {
		was[f.Key] = f.Value
	}
	seen := map[string]bool{}
	for _, d := range hb.Metrics.Disks {
		key := "disk:" + d.Name
		seen[key] = true
		level, pct := diskLevel(d)
		prevLevel, existed := was[key]
		_, _ = l.st.SetFact(ctx, id, key, level)
		desc := fmt.Sprintf("%s ist zu %.0f %% belegt (%s frei von %s).", d.Name, pct, GB(d.Free), GB(d.Total))
		if level == "crit" && prevLevel != "crit" {
			defer l.signal(Signal{Kind: SignalDiskCritical, ServerID: id, Hostname: host, Disk: d.Name, Title: "Datenträger " + d.Name + " fast voll", Detail: desc})
		}
		switch {
		case !existed && !first:
			l.add(ctx, id, store.CatResource, store.SevInfo, "Neuer Datenträger: "+d.Name, fmt.Sprintf("%s %s, %s", d.Label, d.FS, GB(d.Total)))
			fallthrough
		case !existed:
			if level != "ok" {
				l.add(ctx, id, store.CatResource, sevFor(level), "Datenträger "+d.Name+" fast voll", desc)
			}
		case level == prevLevel:
		case level == "ok":
			l.add(ctx, id, store.CatResource, store.SevOK, "Datenträger "+d.Name+" wieder unter 90 %", desc)
			defer l.signal(Signal{Kind: SignalDiskRecovered, ServerID: id, Hostname: host, Disk: d.Name})
		case level == "crit" || prevLevel == "ok":
			l.add(ctx, id, store.CatResource, sevFor(level), "Datenträger "+d.Name+" fast voll", desc)
		}
	}
	for key := range was {
		if !seen[key] && len(hb.Metrics.Disks) > 0 {
			_ = l.st.DeleteFact(ctx, id, key)
			l.add(ctx, id, store.CatResource, store.SevInfo, "Datenträger entfernt: "+strings.TrimPrefix(key, "disk:"), "")
		}
	}
}

func sevFor(level string) string {
	if level == "crit" {
		return store.SevCrit
	}
	return store.SevWarn
}

func (l *Learner) learnEvents(ctx context.Context, id, host string, events []protocol.Event) {
	type sig struct {
		source string
		id     int
		count  int
		msg    string
		level  string
		at     time.Time
	}
	sigs := map[string]*sig{}
	var order []string
	critical := 0
	for _, e := range events {
		if e.Level != "Error" && e.Level != "Critical" {
			continue
		}
		if e.Level == "Critical" && critical < maxCriticalEntries {
			critical++
			title := fmt.Sprintf("Kritisches Ereignis: %s (ID %d)", e.Source, e.EventID)
			l.add(ctx, id, store.CatEvent, store.SevCrit, title, firstLines(e.Message, 6))
			l.signal(Signal{Kind: SignalCriticalEvent, ServerID: id, Hostname: host, Source: e.Source, EventID: e.EventID, Title: title, Detail: firstLines(e.Message, 6)})
		}
		k := fmt.Sprintf("errsig:%s|%d", e.Source, e.EventID)
		if s, ok := sigs[k]; ok {
			s.count++
			continue
		}
		sigs[k] = &sig{source: e.Source, id: e.EventID, count: 1, msg: e.Message, level: e.Level, at: e.Time}
		order = append(order, k)
	}
	newOnes, skipped := 0, 0
	for _, k := range order {
		s := sigs[k]
		total := s.count
		if v, err := l.st.GetFact(ctx, id, k); err == nil {
			n, _ := strconv.Atoi(v)
			total += n
		}
		isNew, err := l.st.SetFact(ctx, id, k, strconv.Itoa(total))
		if err != nil || !isNew {
			continue
		}
		if newOnes >= maxNewErrorEntries {
			skipped++
			continue
		}
		newOnes++
		title := fmt.Sprintf("Neues Fehlerbild: %s (ID %d)", s.source, s.id)
		if s.count > 1 {
			title += fmt.Sprintf(", %d×", s.count)
		}
		l.add(ctx, id, store.CatEvent, store.SevWarn, title, firstLines(s.msg, 6))
		if s.level == "Error" {
			l.signal(Signal{Kind: SignalNewError, ServerID: id, Hostname: host, Source: s.source, EventID: s.id, Title: title, Detail: firstLines(s.msg, 6)})
		}
	}
	if skipped > 0 {
		l.add(ctx, id, store.CatEvent, store.SevWarn, fmt.Sprintf("%d weitere neue Fehlerbilder", skipped), "Details in der Ereignisansicht von ServerBrain.")
	}
}

// learnDependencies resolves the remote ends of TCP connections to known
// servers and records directed edges client → service:port.
func (l *Learner) learnDependencies(ctx context.Context, self *store.Server, hb *protocol.Heartbeat, fleet []*store.Server) {
	if len(hb.Connections) == 0 {
		return
	}
	byIP := map[string]*store.Server{}
	names := map[string]string{}
	for _, s := range fleet {
		names[s.ID] = s.Hostname
		if s.Snapshot == nil {
			continue
		}
		for _, ip := range s.Snapshot.System.IPs {
			byIP[normIP(ip)] = s
		}
	}
	names[self.ID] = hb.System.Hostname
	for _, ip := range hb.System.IPs {
		delete(byIP, normIP(ip)) // never link a server to itself
	}
	type edge struct {
		src, dst string
		port     int
		process  string
	}
	edges := map[edge]bool{}
	for _, c := range hb.Connections {
		if c.State != protocol.ConnEstablished || c.RemoteAddr == "" {
			continue
		}
		other, ok := byIP[normIP(c.RemoteAddr)]
		if !ok || other.ID == self.ID {
			continue
		}
		if c.RemotePort > 0 {
			edges[edge{self.ID, other.ID, c.RemotePort, c.Process}] = true // outgoing
		} else if c.LocalPort > 0 {
			edges[edge{other.ID, self.ID, c.LocalPort, ""}] = true // incoming client
		}
	}
	for e := range edges {
		isNew, err := l.st.TouchDependency(ctx, e.src, e.dst, e.port, e.process)
		if err != nil || !isNew {
			continue
		}
		detail := ""
		if e.process != "" {
			detail = "Prozess: " + e.process
		}
		l.add(ctx, e.src, store.CatNetwork, store.SevInfo,
			fmt.Sprintf("Neue Abhängigkeit: %s → %s Port %s", names[e.src], names[e.dst], PortName(e.port)), detail)
	}
}

func normIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		return ip.String()
	}
	return s
}

// CheckAvailability journals servers that stopped reporting.
func (l *Learner) CheckAvailability(ctx context.Context, servers []*store.Server, offlineAfter time.Duration) {
	changed := false
	for _, s := range servers {
		if s.LastSeen.IsZero() || time.Since(s.LastSeen) < offlineAfter {
			continue
		}
		v, err := l.st.GetFact(ctx, s.ID, "status")
		if err == nil && strings.HasPrefix(v, "offline") {
			continue
		}
		_, _ = l.st.SetFact(ctx, s.ID, "status", "offline|"+strconv.FormatInt(s.LastSeen.UnixMilli(), 10))
		detail := "Der Agent meldet sich seit " + s.LastSeen.Local().Format("02.01.2006 15:04") + " nicht mehr (Server aus, Netzwerkproblem oder Agent gestoppt)."
		l.add(ctx, s.ID, store.CatAvailability, store.SevCrit, "Nicht mehr erreichbar", detail)
		l.signal(Signal{Kind: SignalOffline, ServerID: s.ID, Hostname: s.Hostname, Title: "Nicht mehr erreichbar", Detail: detail})
		changed = true
	}
	if changed {
		l.changed()
	}
}

// ---------- helpers ----------

// GB formats bytes as a rounded human size.
func GB(n uint64) string {
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.1f TB", float64(n)/(1<<40))
	case n >= 10<<30:
		return fmt.Sprintf("%.0f GB", float64(n)/(1<<30))
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	default:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\n")
	var out []string
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(ln))
		if len(out) == n {
			break
		}
	}
	res := strings.Join(out, "\n")
	if len(res) > 800 {
		res = res[:800] + "…"
	}
	return res
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	default:
		return fmt.Sprintf("%.0f Tage", d.Hours()/24)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
