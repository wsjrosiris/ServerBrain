# ServerBrain

**Eine AI Control Plane für Windows Server.** ServerBrain inventarisiert und überwacht Windows Server über einen leichtgewichtigen Agenten. Aktionen laufen über einen *kontrollierten Action Layer*. Die KI sitzt darüber als Operator und Assistent, steuert die Server aber nie direkt.

```
KI / Mensch → gewünschte Aktion → Policy Engine → (Freigabe) → Agent → Ausführung → Ergebnis → Audit Log
```

Dieses Repository enthält das **MVP (Phase 1)** und das Fundament für Phase 2: Capabilities, Policy Engine mit KI-Modi, Freigaben und Tool-Definitionen für Function Calling.

## Architektur

```text
┌──────────────────────────── sb-server (Control Plane) ────────────────────────────┐
│  Web-Konsole (eingebettet)   Operator-API (RBAC)     Agent-API                   │
│  Übersicht · Alerts          Server Registry         Enrollment                  │
│  Dienste · Events · Metriken Policy Engine           Heartbeat / Telemetrie      │
│  Aktionen · Freigaben        Command Dispatcher      Command Long-Polling        │
│  Remote-Konsole · Audit      Audit Log · SQLite      Ergebnisse                  │
└──────────────────────────────────────▲───────────────────────────────────────────┘
                                       │  HTTPS (optional mTLS), immer AUSGEHEND vom Server
             ┌─────────────────────────┴─────────────────────────┐
     ┌───────┴───────┐                                   ┌───────┴───────┐
     │ sb-agent      │  Windows-Service                  │ sb-agent      │
     │ WEB-03        │  CPU/RAM/Disk, Dienste,           │ SQL-01        │
     │               │  Event Log, Aktionen              │               │
     └───────────────┘                                   └───────────────┘
```

**Designentscheidungen**

- **Agent → Zentrale.** Der Agent baut die Verbindung selbst auf (Heartbeat + Long-Polling über HTTPS). Auf den Servern muss kein eingehender Port geöffnet werden, und das funktioniert auch hinter NAT oder einer Firewall.
- **Keine beliebigen Befehle.** Es gibt einen geschlossenen Katalog benannter Aktionen (`service.restart`, `files.archive_old` …) mit typisierten, validierten Parametern. Parameter landen **nie** im Skripttext, sondern als Umgebungsvariablen (`$env:SB_ARG_NAME`). Command Injection über Parameter ist damit ausgeschlossen.
- **„Show commands“ zeigt genau das, was läuft.** Vorschau und Ausführung nutzen dieselbe Definition (`internal/actions`).
- **Defense in Depth.** Der Agent validiert jeden Befehl erneut und führt nur aus, was er selbst als Capability anbietet. Die Remote-Shell (`shell.run`) muss lokal auf dem Server freigeschaltet werden. Auch eine kompromittierte Zentrale kann sie nicht aktivieren.
- **Alles wird auditiert:** Anfrage, Policy-Entscheidung, Freigabe/Ablehnung, Dispatch, Ergebnis, Enrollment, Benutzerverwaltung.
- **Ein Binary je Rolle, keine externen Abhängigkeiten.** Go, SQLite eingebettet (pure Go, kein CGO), Web-UI eingebettet ohne Build-Schritt.

## Schnellstart

Voraussetzung: Go ≥ 1.24.

```bash
make build                       # bin/sb-server, bin/sb-agent
./bin/sb-server -addr :8443 -db serverbrain.db \
    -tls-cert tls.crt -tls-key tls.key
```

Beim ersten Start gibt der Server einen **Admin-API-Token** aus (nur einmal). Damit meldest du dich unter `https://<host>:8443/` an. Token verloren? `sb-server -db serverbrain.db -create-admin admin2` legt einen weiteren Admin an.

> Ohne `-tls-cert` spricht der Server Klartext-HTTP. Das ist nur für die lokale Entwicklung gedacht.

### Windows Server hinzufügen

1. In der Konsole unter **Einstellungen → Server hinzufügen** einen Enrollment-Token erzeugen (einmalig verwendbar, mit Ablaufzeit, optional mit Tags wie `web, prod`).
2. Auf dem Server in einer PowerShell mit Administratorrechten:

```powershell
.\sb-agent.exe enroll -server https://brain.example.com:8443 -token sbe_...
.\sb-agent.exe install        # Windows-Service "ServerBrainAgent" (Autostart, Recovery)
```

Optionen für `enroll`:

| Flag | Bedeutung |
|---|---|
| `-ca-file ca.pem` | Eigene CA für das Zertifikat der Zentrale vertrauen |
| `-cert c.pem -key k.pem` | Client-Zertifikat für mTLS (Server mit `-client-ca` starten) |
| `-enable-shell` | Remote-PowerShell (interaktive Konsole und `shell.run`) auf diesem Server erlauben |
| `-archive-roots "C:\inetpub\logs;D:\Logs"` | Verzeichnisse, in denen `files.archive_old` arbeiten darf |

Die Konfiguration liegt in `C:\ProgramData\ServerBrain\agent.json`. Sie enthält das Agent-Secret, deshalb setzt der Agent die ACLs auf SYSTEM und Administratoren. `sb-agent capabilities` listet die lokal verfügbaren Aktionen.

Für die Entwicklung läuft der Agent auch unter Linux und meldet dann Metriken und Datenträger (`sb-agent run -config ./agent.json`, systemd-Unit unter `deploy/`).

## Funktionen (Phase 1)

| Bereich | Umfang |
|---|---|
| Registrierung | Enrollment-Tokens (einmalig/mehrfach, TTL, Tags), Agent-Secret, optional mTLS |
| Heartbeat & Telemetrie | CPU, RAM, Datenträger, Systeminfo (OS, Domäne, Boot-Zeit, IPs), Verlauf 7 Tage |
| Dienste | Komplette Dienstliste mit Status und Starttyp, Start/Stopp/Neustart per Klick |
| Event Logs | System/Application, Warnung und höher, inkrementell übertragen, 30 Tage Aufbewahrung |
| Alerts | Server offline, Disk ≥ 90/95 %, RAM/CPU ≥ 95 %, gestoppte Autostart-Dienste, Fehlerhäufung, jeweils mit **vorgeschlagener Aktion** |
| Second Brain | Automatisches Lernen von Rollen, Abhängigkeiten, Baselines und Fehlerbildern, **Servertagebuch**, **Obsidian-Vault** (siehe unten) |
| Remote PowerShell | Interaktive, dauerhafte PowerShell-Sitzung auf dem Server, **immer über den Agenten** (siehe unten). Lokal opt-in, standardmäßig nur für Admins, jede Eingabe auditiert |
| Aktionen | siehe Katalog unten, mit Vorschau der Befehle und Policy-Entscheidung vor der Ausführung |
| Freigaben | Warteschlange für Aktionen mit Effekt `approve`, Freigeben/Ablehnen/Zurückziehen, optional Vier-Augen-Prinzip |
| Audit Log | Lückenlose Protokollierung aller sicherheitsrelevanten Ereignisse |
| RBAC | Rollen `viewer` (nur lesen), `operator` (Aktionen anfordern), `admin` (freigeben, verwalten) |

### Aktionskatalog

| Aktion | Risiko | Beschreibung |
|---|---|---|
| `service.start` / `service.restart` | low | Dienst starten / neu starten |
| `service.stop` | medium | Dienst stoppen |
| `iis.apppool.restart` | low | IIS-AppPool recyceln (startet ihn, falls gestoppt) |
| `iis.sites` | low, read-only | IIS-Sites, Bindings, AppPool-Status |
| `process.list` | low, read-only | Top-Prozesse nach CPU |
| `eventlog.query` | low, read-only | Gezielte Event-Log-Abfrage |
| `windows_update.list` | low, read-only | Ausstehende Windows Updates |
| `disk.large_files` | low, read-only | Größte Dateien/Verzeichnisse finden |
| `network.test_port` | low, read-only | TCP-Erreichbarkeit testen („Warum erreicht APP-03 DB-01 nicht?“) |
| `temp.cleanup` | low | Alte Temp-Dateien löschen |
| `files.archive_old` | medium | Alte Dateien (z. B. IIS-Logs) zippen, Archiv prüfen, Originale löschen. Nur innerhalb der `archive_roots` |
| `system.reboot` | high | Neustart planen |
| `shell.run` | critical | Beliebiges Skript, lokal opt-in |

Neue Aktionen werden in `internal/actions/catalog.go` definiert. Skript-Aktionen brauchen nur den PowerShell-Code, native Aktionen eine Go-Implementierung in `internal/agent/executor.go`.

## Remote-Konsole

Die Konsole verbindet sich **nie direkt** mit einem Server: kein WinRM, kein RDP, keine eingehenden Ports. Jede Eingabe nimmt diesen Weg:

```text
Browser ──HTTPS──▶ Zentrale ──(Policy, Audit)──▶ Warteschlange
                                                     │
          Agent auf dem Server ◀──ausgehender Long-Poll──┘
                 │
                 ▼
   dauerhafte powershell.exe-Sitzung  ──Ausgabe live──▶ Zentrale ──▶ Browser
```

- **Echte Sitzung.** Der Agent startet pro Sitzung einen PowerShell-Prozess, der Befehle per Dot-Sourcing im selben Scope ausführt. Variablen, Funktionen, importierte Module und das aktuelle Verzeichnis bleiben erhalten. Der Prompt zeigt `PS C:ktueller\pfad>` und wird rot, wenn der letzte Befehl fehlschlug.
- **Live-Ausgabe.** Der Agent streamt die Ausgabe in kurzen Abständen (≈150 ms) an die Zentrale. Die Konsole holt sie per Long-Poll ab. Eingaben erreichen den Agenten sofort über einen eigenen Long-Poll-Kanal (`GET /api/agent/sessions`).
- **Kontrolle.** Eine Sitzung zu öffnen wird wie `shell.run` von der Policy geprüft (`allow` öffnet sofort, `approve` braucht eine Admin-Freigabe in **Freigaben**, `block` verweigert). KI-Konten können keine interaktiven Sitzungen öffnen, sie nutzen einzeln geprüfte Aktionen. Nur der Besitzer darf in seine Sitzung schreiben. Jede Eingabe landet mit Verzeichnis im Audit Log (`session.input`).
- **Lebenszyklus.** „Neu starten“ beendet einen hängenden Befehl, indem die Shell neu gestartet wird. Nach 30 Minuten Inaktivität schließt die Zentrale die Sitzung, maximal 5 Sitzungen pro Agent. Nach einem Reload setzt die Konsole eine offene Sitzung samt Verlauf fort. Sitzungen leben im Speicher: Nach einem Neustart der Zentrale beendet der Agent seine Shells.
- **Hinweis:** Befehle, die selbst von der Standardeingabe lesen (z. B. eine verschachtelte interaktive `cmd.exe`), sind nicht unterstützt. Interaktive Abfragen wie `Read-Host` schlagen im nicht-interaktiven Modus sofort fehl, statt zu hängen.

Für einzelne, freigabepflichtige Skripte (z. B. von der KI vorgeschlagen) gibt es weiterhin die Aktion `shell.run`.

## Second Brain: Wissen, Servertagebuch & Obsidian

ServerBrain **lernt automatisch** aus jedem Heartbeat und schreibt sein Wissen in einen **Obsidian-Vault**. Das sind normale Markdown-Dateien mit Links, Properties und Tags. Du öffnest den Ordner in Obsidian und hast eine lebende Dokumentation deiner Infrastruktur, inklusive Graph-Ansicht.

### Was ServerBrain lernt

| Wissen | Woher |
|---|---|
| **Rollen** (IIS, SQL Server, Domain Controller, DNS, DHCP, Hyper-V, Exchange, RDS, WSUS, Docker, Veeam …) | installierte Dienste, unter Linux lauschende Ports |
| **Abhängigkeiten** zwischen Servern („WEB-03 → SQL-01 Port 1433, Prozess w3wp“) | TCP-Verbindungen, die die Agenten melden (`Get-NetTCPConnection`), aufgelöst auf bekannte Server-IPs |
| **Normale Auslastung** (CPU/RAM/Disk, 7 Tage) | Metrikverlauf |
| **Bekannte Fehlerbilder** (Quelle + Event-ID, Häufigkeit) | Event Logs |
| **Inventar** (OS, Domäne, Hardware, IPs, Datenträger, lauschende Ports, wichtige Dienste) | Heartbeat |

### Servertagebuch

ServerBrain vergleicht jeden Heartbeat mit dem bisherigen Wissen und schreibt **nur echte Veränderungen** ins Tagebuch:

- Server aufgenommen, Inventar erfasst, nicht mehr erreichbar / wieder erreichbar
- Neustart erkannt, OS-, Hostname-, IP-, Domänen- und Hardware-Änderungen, Agent-Update
- Autostart- oder rollenkritischer Dienst gestoppt / läuft wieder, Starttyp geändert, Dienste installiert / entfernt
- Neue / nicht mehr erkannte Rolle, neuer Datenträger, Datenträger über 90 / 95 % bzw. wieder darunter
- **Neues Fehlerbild** (erstes Auftreten von Quelle + Event-ID). Wiederholungen werden nur gezählt. Kritische Ereignisse werden immer eingetragen.
- Neue Abhängigkeit entdeckt
- Ausgeführte, fehlgeschlagene und abgelehnte Aktionen (wer, warum, wer hat freigegeben, Ausgabe)
- Konsolensitzungen (wer, warum, welche Befehle)
- Eigene Einträge von Admins (Konsole → *Tagebuch*, oder `POST /api/servers/{id}/journal`)

Manuell gestartete Dienste, die ständig an- und ausgehen, und Metrik-Rauschen landen bewusst nicht im Tagebuch.

### Aufbau des Vaults

```text
<vault>/ServerBrain/
├── Start.md                     Einstieg, letzte Tagebuchtage
├── Infrastruktur.md             alle Server, Rollen-Index, Abhängigkeitsgraph (Mermaid)
├── Server/
│   ├── WEB-03.md                Steckbrief: Rollen, Datenträger, Abhängigkeiten (verlinkt),
│   └── SQL-01.md                Ports, wichtige Dienste, Auslastung, Fehlerbilder, letzte Einträge
└── Tagebuch/2026/
    └── 2026-10-01.md            Servertagebuch des Tages, gruppiert nach Server
```

- **Properties** (`typ`, `status`, `rollen`, `ip`, `ram_gb`, …) und Tags (`#serverbrain/server`, `#rolle/web`, `#sb/dienst` …) machen den Vault mit Dataview, Bases oder der Suche auswertbar.
- **Deine Notizen bleiben erhalten.** ServerBrain pflegt nur den Bereich zwischen den unsichtbaren `%% serverbrain:begin %%` / `%% serverbrain:end %%`-Markern und seine eigenen Properties. Alles darunter (z. B. „## Notizen“: Ansprechpartner, Wartungsfenster, Workarounds) und eigene Properties gehören dir.
- **Rückkanal zur KI.** Was du in Obsidian unter einen Server schreibst, liest ServerBrain zurück. Du siehst es in der Konsole unter *Wissen*, und es fließt in den KI-Kontext ein.
- Dateien werden nur geschrieben, wenn sich der Inhalt ändert. Sync-Tools sehen also keine unnötigen Änderungen.

### Einrichtung

```bash
sb-server -vault /srv/obsidian/Infrastruktur -vault-folder ServerBrain -timezone Europe/Berlin
```

Standard ist `-vault ./vault`, `-vault ""` schaltet es ab. Der Vault-Ordner muss nur dort erreichbar sein, wo Obsidian läuft, zum Beispiel über eine SMB-Freigabe, Syncthing, OneDrive/SharePoint, Obsidian Sync oder ein Git-Repository (Obsidian-Git-Plugin). `-vault-folder` erlaubt, ServerBrain in einen bestehenden Vault einzuhängen. Alle Links nutzen volle Pfade, deshalb gibt es keine Namenskonflikte.

### Wissen für die KI

`GET /api/knowledge/context?server=<id>` liefert ein kompaktes Markdown-Briefing: Steckbrief, Rollen, Abhängigkeiten, normale Auslastung, bekannte Fehlerbilder, **deine Obsidian-Notizen** und das Servertagebuch der letzten Tage. Das ist das Gedächtnis, das ein KI-Assistent liest, bevor er „Warum ist WEB-03 down?“ beantwortet.

## Policy Engine & KI-Modi

Regeln werden von oben nach unten ausgewertet. Die erste passende Regel gewinnt, ohne Treffer wird **blockiert**. Eine Regel matcht auf Aktion (Glob), Risiko, read-only, Hostname (Glob), Tags, Akteurstyp (`human`/`ai`) und Rolle. Ihr Effekt ist `allow`, `approve` oder `block`.

KI-Integrationen bekommen ein eigenes Konto vom Typ **`ai`**. Damit lassen sich die drei Betriebsmodi rein über die Policy abbilden:

| Modus | Policy |
|---|---|
| **Read-only** | `ai` + `read_only: true` → allow, alles andere → block |
| **Assisted** | `ai` → approve (Mensch bestätigt jeden Eingriff) |
| **Autonomous** | `ai` + ausgewählte Low-Risk-Aktionen (z. B. `service.restart`, `temp.cleanup`) → allow |

Die eingebaute Standard-Policy ist eine Mischung daraus: Read-only-Aktionen sind erlaubt, Dienst-Neustarts und Temp-Cleanup darf die KI autonom ausführen, alles andere braucht Freigabe. Reboots brauchen immer eine Freigabe, und die Shell ist nur Menschen mit Admin-Rolle vorbehalten. KI-Konten können nie Admin sein und nie freigeben. Ein ausführliches Beispiel mit Tags (Domain Controller geschützt, Vier-Augen-Prinzip für `prod`) liegt in [`deploy/policy.example.json`](deploy/policy.example.json). Aktivieren mit `sb-server -policy policy.json`.

### KI anbinden (Phase 2-Vorbereitung)

`GET /api/ai/tools` liefert den Aktionskatalog als Tool-Definitionen im Format `name` / `description` / `input_schema`, direkt nutzbar für Function Calling. Das LLM ruft die Tools auf, die Integration übersetzt sie in `POST /api/servers/{id}/actions` mit dem Token des KI-Kontos. **Was tatsächlich passiert, entscheidet die Policy, nicht das Modell.** Die Begründung (`reason`) der KI sehen Freigebende in der Konsole, und sie landet im Audit Log.

```text
LLM ──tool call──▶ Integration ──POST /actions (ai-Token)──▶ Policy Engine ──▶ allow / approve / block
```

## API (Auszug)

Alle Operator-Endpunkte erwarten `Authorization: Bearer <token>`.

| Methode & Pfad | Rolle | Zweck |
|---|---|---|
| `GET /api/servers`, `GET /api/servers/{id}` | viewer | Inventar inkl. Snapshot und Capabilities |
| `GET /api/servers/{id}/metrics?hours=6` | viewer | Metrik-Verlauf |
| `GET /api/servers/{id}/events?hours=24`, `GET /api/events` | viewer | Event-Log-Einträge |
| `GET /api/alerts` | viewer | Aktive Alerts mit vorgeschlagenen Aktionen |
| `POST /api/servers/{id}/actions/preview` | viewer | Validierung, Befehlsvorschau und Policy-Entscheidung, ohne auszuführen |
| `POST /api/servers/{id}/actions` | viewer* | Aktion anfordern `{action, params, reason}` (*Viewer nur read-only) |
| `GET /api/commands[?status=&server=]`, `GET /api/commands/{id}` | viewer | Aktionen und Ergebnisse |
| `POST /api/commands/{id}/approve` · `/reject` | admin | Freigabe |
| `POST /api/commands/{id}/cancel` | operator | Eigene Anfrage zurückziehen |
| `GET /api/actions`, `GET /api/ai/tools`, `GET /api/policy` | viewer | Katalog, Tool-Definitionen, aktive Policy |
| `POST /api/servers/{id}/sessions` | operator* | Konsolen-Sitzung öffnen `{reason}` (*Policy für `shell.run`, Standard: nur Admins) |
| `GET /api/sessions/{sid}/output?after=N` | Besitzer/admin | Long-Poll auf neue Ausgabe |
| `POST /api/sessions/{sid}/input` · `/reset` · `DELETE /api/sessions/{sid}` | Besitzer | Befehl senden, Shell neu starten, beenden |
| `POST /api/sessions/{sid}/approve` · `/reject` | admin | Sitzung freigeben |
| `GET /api/journal?server=&days=7` | viewer | Servertagebuch |
| `POST /api/journal`, `POST /api/servers/{id}/journal` | operator | Eigener Tagebucheintrag `{title, detail}` |
| `GET /api/servers/{id}/knowledge` | viewer | Gelerntes Wissen und Obsidian-Notizen |
| `GET /api/dependencies` | viewer | Gelernter Abhängigkeitsgraph |
| `GET /api/knowledge/context?server=` | viewer | Markdown-Briefing für die KI |
| `GET /api/audit` | admin | Audit Log |
| `POST /api/enrollment-tokens`, `GET/POST /api/users` | admin | Verwaltung |

Agent-Endpunkte: `POST /api/agent/enroll`, `POST /api/agent/heartbeat`, `GET /api/agent/commands` (Long-Poll), `POST /api/agent/commands/{id}/result`, `GET /api/agent/sessions` (Long-Poll), `POST /api/agent/sessions/{sid}/output`.

## Entwicklung

```bash
make test     # Unit- und End-to-End-Tests (echter Agent gegen echten Server), mit -race
make vet      # go vet für Linux und Windows
make dist     # Release-Binaries (Agent für windows/amd64 + arm64)
```

```
cmd/sb-server         Control Plane
cmd/sb-agent          Agent (CLI + Windows-Service)
internal/actions      Aktionskatalog: Validierung, Vorschau, Skripte
internal/policy       Policy Engine
internal/store        SQLite-Persistenz
internal/server       HTTP-API, Alerts, Sessions, eingebettete Web-Konsole (web/static)
internal/knowledge    Second Brain: Rollen, Lerner (Tagebuch, Abhängigkeiten), Obsidian-Vault
internal/agent        Collector (PowerShell/CIM unter Windows), Executor, native Aktionen
internal/protocol     Wire-Typen Agent ↔ Zentrale
deploy/               Beispiel-Policy, systemd-Units
```

## Roadmap

**Phase 2: KI-Diagnose.** Diagnose-Assistent in der Konsole („Warum ist WEB-03 down?“) mit Tool Calling auf Basis von `/api/ai/tools`, „Explain & Fix“-Ansicht mit Diagnosepfad und empfohlenen Schritten, automatische Remediation über Policy-gesteuerte Autonomie, feinere RBAC (Server-Gruppen, Tag-Scopes), SSO/OIDC.

**Phase 3: Infrastruktur-Kontext.** Serverübergreifende Root-Cause-Analyse auf Basis des gelernten Abhängigkeitsgraphen und des Tagebuchs, Flottenoperationen („auf allen Servern mit < 10 GB frei …“), Self-Healing-Playbooks, Compliance-Checks, Multi-Tenant, PostgreSQL als Backend.

**Technische Härtung.** Agent-Selbstupdate mit signierten Binaries, signierte Commands (Ende-zu-Ende vom Freigebenden bis zum Agenten), Rotation der Agent-Secrets, Export des Audit Logs (Syslog/SIEM), WebSocket-Live-Updates in der UI.
