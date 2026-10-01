# ServerBrain – Entwicklungsplan

Stand: Oktober 2026 · lebendes Dokument, wird mit jedem Meilenstein aktualisiert.

## 1. Wo wir stehen

| Baustein | Status |
|---|---|
| Agent (Windows-Service, ausgehende Verbindung, Telemetrie, Event Logs, Dienste, Netzwerkverbindungen) | ✅ |
| Kontrollierter Action Layer (Katalog, Parameter als Umgebungsvariablen, lokale Re-Validierung) | ✅ |
| Policy Engine (allow/approve/block, Akteurstyp human/ai, Rollen, Tags) + Freigaben + Audit | ✅ |
| Interaktive PowerShell-Sitzung über den Agenten | ✅ |
| Second Brain: Lerner, Rollen, Abhängigkeiten, Servertagebuch, Obsidian-Vault | ✅ |
| KI-Operator: Assistent mit Tool Use, Explain & Fix, automatische Incident-Analyse (M1) | ✅ |
| Autopilot: Self-Healing-Playbooks mit Eskalation (M2) | ✅ |

Vor M1/M2 fehlte die Schicht, die das Produkt ausmacht: **eine KI, die dieses Wissen nutzt, Probleme erklärt und unter Kontrolle der Policy behebt.** Diese Lücke schließen M1 und M2.

## 2. Brainstorming

Ungefilterte Ideensammlung, gruppiert. Bewertung: **Nutzen** (1–5), **Aufwand** (S/M/L), **Risiko** (niedrig/mittel/hoch).

### 2.1 KI-Operator

| # | Idee | Nutzen | Aufwand | Risiko |
|---|---|---|---|---|
| K1 | **KI-Assistent im Chat** („Warum ist WEB-03 down?“): Die KI liest Wissen, Tagebuch und Ereignisse über Tools, führt Read-only-Diagnosen aus und schlägt Fixes vor | 5 | M | mittel |
| K2 | **Explain & Fix** direkt am Alert: ein Klick startet die Diagnose mit vollem Kontext | 5 | S | niedrig |
| K3 | **Automatische Incident-Analyse**: Bei kritischen Tagebuch-Einträgen analysiert die KI selbstständig und schreibt die Diagnose ins Tagebuch und nach Obsidian | 5 | M | mittel |
| K4 | Flottenfragen in natürlicher Sprache („Welche Server haben < 10 GB frei?“) | 4 | S (über K1-Tools) | niedrig |
| K5 | KI darf Aktionen nur **über die Policy** anfordern (Akteur `ai`, Rolle maximal die des fragenden Menschen) | 5 | S | senkt Risiko |
| K6 | Begründung (`reason`) der KI wird Freigebenden angezeigt und auditiert | 4 | S | – |
| K7 | Wöchentlicher KI-Bericht pro Server/Infrastruktur als Obsidian-Notiz | 3 | M | niedrig |
| K8 | KI schlägt Policy-Regeln vor („service.restart auf web-Servern autonom erlauben?“) | 3 | M | mittel |
| K9 | Runbook-Generierung aus dem Tagebuch (wiederkehrende Fixes → Playbook) | 4 | L | mittel |
| K10 | Sprach-/Teams-/Slack-Anbindung des Assistenten | 3 | M | mittel |

### 2.2 Self-Healing / Autopilot

| # | Idee | Nutzen | Aufwand | Risiko |
|---|---|---|---|---|
| A1 | **Autopilot-Playbooks** (deterministisch, ohne LLM): gestoppter Autostart-Dienst → nach Karenzzeit starten | 5 | M | mittel |
| A2 | Datenträger kritisch → automatisch große Dateien ermitteln, Ergebnis ins Tagebuch, KI-Analyse anstoßen | 4 | S | niedrig |
| A3 | Rate-Limits und Eskalation: max. N Versuche, danach KI-Analyse und Mensch | 5 | S | senkt Risiko |
| A4 | Wartungsfenster (Tags/Zeitfenster), in denen der Autopilot nichts tut | 4 | M | senkt Risiko |
| A5 | Eigene Playbooks als JSON/YAML (Trigger → Aktion → Prüfung) | 4 | L | mittel |
| A6 | Verifikation nach dem Fix (z. B. HTTP-Healthcheck nach IIS-Neustart) | 4 | M | niedrig |

### 2.3 Monitoring & Wissen

| # | Idee | Nutzen | Aufwand |
|---|---|---|---|
| W1 | HTTP-/TCP-Healthchecks pro Server (Dienst-Ebene statt nur Host-Ebene) | 4 | M |
| W2 | Zertifikatsablauf (lokaler Speicher, IIS-Bindings) | 4 | S |
| W3 | Windows-Update-Stand und letzter Patch im Steckbrief | 4 | S |
| W4 | Installierte Software (Registry Uninstall-Keys) ins Inventar und Tagebuch | 3 | S |
| W5 | Geplante Tasks und deren letzter Status | 3 | S |
| W6 | Anomalieerkennung gegen die gelernte Baseline (statt fester Schwellwerte) | 4 | M |
| W7 | Bereinigung veralteter Abhängigkeiten (last_seen > 30 Tage) | 3 | S |
| W8 | Externe Ziele (Internet, SaaS) als eigene Knoten im Graphen | 2 | M |

### 2.4 Plattform & Betrieb

| # | Idee | Nutzen | Aufwand |
|---|---|---|---|
| P1 | SSO/OIDC (Entra ID) statt API-Tokens | 4 | M |
| P2 | Agent-Selbstupdate mit signierten Binaries | 4 | L |
| P3 | Signierte Commands (Freigebender → Agent, Ende-zu-Ende) | 4 | L |
| P4 | PostgreSQL-Backend, Hochverfügbarkeit | 3 | L |
| P5 | Multi-Tenant (MSP-Szenario) | 3 | L |
| P6 | MSI-Installer + GPO/Intune-Rollout | 4 | M |
| P7 | Audit-Export (Syslog/SIEM) | 3 | S |
| P8 | Live-Updates per WebSocket/SSE in der UI | 2 | M |

## 3. Priorisierung

Leitfrage: *Was macht ServerBrain zu einer „AI Control Plane“ und nicht zu einem weiteren Monitoring-Tool?* Das sind K1–K6 und A1–A3. Sie bauen direkt auf dem vorhandenen Fundament auf (Wissen, Tagebuch, Policy) und liefern den Kern-Use-Case aus dem Konzept: **„WEB-03 ist down → Ursache erklärt → Fix mit Freigabe → Ergebnis im Tagebuch“**.

Bewusst später:

- **P1–P6:** wichtig für den Produktivbetrieb, aber ohne neuen Nutzen für den Kern-Use-Case.
- **W1–W8:** verbessern die Datenbasis inkrementell und passen gut in einzelne kleine Iterationen.
- **K9 und A5:** brauchen erst Erfahrung aus dem Betrieb von K3 und A1.

## 4. Roadmap

### Meilenstein 1 – KI-Operator ✅

Ziel: Der Admin fragt in natürlicher Sprache, die KI diagnostiziert mit echten Daten und schlägt Fixes vor. Ausführung nur über die Policy.

1. **LLM-Anbindung** (`internal/ai`): Claude über das offizielle Go-SDK (Modell `claude-opus-5-5`, adaptive Thinking, Effort konfigurierbar, serverseitiger Refusal-Fallback). Austauschbar über ein Interface, in Tests durch ein Skript-LLM ersetzt.
2. **Gemeinsame Aktions-Pipeline** `requestAction(actor, server, action, params, reason)` für Menschen, KI und Autopilot. Dadurch gelten Policy, Freigaben, Audit und Tagebuch überall identisch.
3. **Tools für die KI:** Server auflisten, Alerts, Wissen/Kontext eines Servers, Ereignisse, Tagebuch, Abhängigkeiten, Aktion anfordern (wartet auf das Ergebnis oder meldet „Freigabe nötig“), Erkenntnis ins Tagebuch schreiben.
4. **Assistent-API + UI:** Fragen stellen, Folgefragen, live sichtbare Schritte („liest Ereignisse von WEB-03“, „führt disk.large_files aus“), Antwort in Markdown.
5. **Explain & Fix:** Button „KI-Diagnose“ an jedem Alert und auf der Serverseite.
6. **Automatische Incident-Analyse:** Kritische Tagebuch-Ereignisse lösen (rate-limitiert) eine KI-Analyse aus. Das Ergebnis landet im Tagebuch und damit in Obsidian.

**Akzeptanzkriterien:** Ein End-to-End-Test mit Skript-LLM prüft, dass Tool-Aufrufe echte Daten liefern, dass eine KI-Aktion durch die Policy läuft (read-only sofort ausgeführt, riskante Aktion wartet auf Freigabe) und dass die Analyse im Tagebuch steht. Ohne API-Key bleibt alles andere voll funktionsfähig.

### Meilenstein 2 – Autopilot (Self-Healing) ✅

1. **Signale aus dem Lerner** (strukturiert statt Text): Dienst gestoppt, Datenträger kritisch, kritisches Ereignis, Server offline.
2. **Playbooks:**
   - *Autostart-Dienst gestoppt* → Karenzzeit → `service.start` als Akteur „Autopilot“ (Policy entscheidet) → max. 3 Versuche in 24 h → danach Eskalation an die KI-Analyse.
   - *Datenträger kritisch* → `disk.large_files` (read-only) → Ergebnis ins Tagebuch → KI-Analyse.
3. **Wartungsmodus** per Server-Tag `wartung`: Der Autopilot pausiert.
4. Abschaltbar (`-autopilot=false`), alles auditiert und im Tagebuch.

### Meilenstein 3 – Tiefere Daten ⟵ *nächste Iteration*

W1 Healthchecks, W2 Zertifikate, W3 Update-Stand, W4 Software-Inventar, W7 Bereinigung veralteter Abhängigkeiten, A6 Verifikation nach Fixes.

### Meilenstein 4 – Produktionsreife

P6 MSI/GPO-Rollout, P1 SSO, P2 Selbstupdate, P3 signierte Commands, P7 Audit-Export.

### Meilenstein 5 – Lernende Automatisierung

K7 Berichte, K8 Policy-Vorschläge, K9 Runbooks aus dem Tagebuch, A5 eigene Playbooks, W6 Anomalieerkennung.

## 5. Architekturentscheidungen für M1/M2

- **Die KI ist ein Akteur wie jeder andere.** Sie bekommt keinen Sonderweg zu den Servern. Jede Aktion läuft durch `requestAction` → Policy → (Freigabe) → Agent. Fragt ein Mensch, handelt die KI mit Akteurstyp `ai` und **höchstens dessen Rolle**: Ein Viewer kann über die KI nur Read-only-Aktionen auslösen.
- **Tools liefern Fakten, keine Befehle.** Die KI sieht dieselben Daten wie die Konsole (Wissen, Tagebuch, Ereignisse) in kompakter Textform. Freier Shell-Zugriff (`shell.run`) bleibt für KI-Akteure per Policy blockiert.
- **Append-only-Gesprächsverlauf** (Antworten unverändert zurückgeben) erhält das Reasoning des Modells über Tool-Aufrufe hinweg und funktioniert mit Prompt-Caching (stabiler Systemprompt und stabile Tool-Liste vorne).
- **Autopilot ohne LLM.** Deterministische Playbooks sind vorhersagbar, testbar und kostenlos. Das LLM kommt erst bei der Eskalation dazu.
- **Alles landet im Tagebuch.** KI-Analysen, Autopilot-Eingriffe und Eskalationen werden Teil des Second Brain. Die nächste Analyse kennt damit die Vorgeschichte.

## 6. Risiken & Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| KI halluziniert eine Ursache | Systemprompt verlangt Belege aus Tool-Ergebnissen. Die Analyse nennt die geprüften Daten. Schritte sind in der UI sichtbar. |
| KI löst schädliche Aktion aus | Policy, Rollenbegrenzung, Freigaben, `shell.run` für KI blockiert, Audit |
| Prompt-Injection über Event-Log-Texte | Tool-Ergebnisse werden als Daten gekennzeichnet. Aktionen bleiben policy-gebunden. Riskante Aktionen erfordern immer Freigabe. |
| Kosten durch Auto-Analyse | Rate-Limit pro Server, nur kritische Ereignisse, abschaltbar |
| Autopilot-Schleifen (Dienst crasht sofort wieder) | Max. 3 Versuche in 24 h, dann Eskalation statt weiterer Neustarts |
| Kein API-Key / keine Internetverbindung | KI-Funktionen sind optional. Monitoring, Tagebuch und Autopilot laufen ohne. |

## 7. Umsetzungsstand M1/M2

| Plan | Umsetzung |
|---|---|
| LLM-Anbindung | `internal/ai` (Interface + Claude-Adapter, gegen einen Mock der Messages API getestet: adaptive Thinking, Effort, Fallback, Caching, Verlauf append-only) |
| Gemeinsame Aktions-Pipeline | `Server.requestAction(actor, …)` für Konsole, KI und Autopilot |
| Tools | `list_servers`, `get_alerts`, `get_server_context`, `get_services`, `get_events`, `get_journal`, `get_dependencies`, `list_actions`, `run_action` |
| Assistent-API + UI | `/api/assistant…`, Seite *KI-Assistent* mit Live-Schritten und Folgefragen |
| Explain & Fix | Button *KI-Diagnose* an Alerts, *KI fragen* auf der Serverseite |
| Automatische Analyse | Signale des Lerners → read-only Analyse (rate-limitiert) → Tagebuch/Obsidian |
| Autopilot | Playbooks Dienst-Neustart (Karenzzeit, 3 Versuche/24 h, Eskalation, Wartungs-Tag, „bewusst gestoppt“-Erkennung) und Datenträger-Analyse |
| Tests | Skript-LLM + simulierter Windows-Agent: Diagnose über die Policy, Freigabepflicht, Viewer-Begrenzung, Autopilot-Neustart, Wartungsmodus, Eskalation |

Offen und in M3+ eingeplant: Verifikation nach Fixes (A6), Konfigurierbarkeit der Playbooks (A5), Kosten-Reporting der KI-Nutzung.
