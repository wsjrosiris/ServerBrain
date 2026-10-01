"use strict";
// ServerBrain operator console. Plain JS, no build step. All dynamic content
// is inserted via textContent / DOM APIs (never innerHTML) to avoid XSS.

const state = { token: null, me: null, catalog: [], timer: null };

// ---------- helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function svg(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "Authorization": "Bearer " + state.token, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) { logout(); throw new Error("Nicht angemeldet"); }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error((data && data.error) || res.statusText);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

const fmtBytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + " " + u[i];
};
const fmtTime = (t) => t && !t.startsWith("0001") ? new Date(t).toLocaleString("de-DE") : "–";
const ago = (t) => {
  if (!t || t.startsWith("0001")) return "nie";
  const s = Math.round((Date.now() - new Date(t)) / 1000);
  if (s < 60) return "vor " + s + " s";
  if (s < 3600) return "vor " + Math.round(s / 60) + " min";
  if (s < 86400) return "vor " + Math.round(s / 3600) + " h";
  return "vor " + Math.round(s / 86400) + " d";
};
const pct = (used, total) => total ? (100 * used / total) : 0;
const isAdmin = () => state.me && state.me.role === "admin";
const canOperate = () => state.me && state.me.role !== "viewer";

function meter(label, value, detail) {
  const fill = h("span", { class: value >= 95 ? "crit" : value >= 85 ? "warn" : "" });
  fill.style.width = Math.min(100, Math.max(0, value)).toFixed(1) + "%";
  return h("div", { class: "meter" },
    h("div", { class: "meter-label" }, h("span", {}, label), h("span", {}, detail || value.toFixed(0) + " %")),
    h("div", { class: "bar" }, fill));
}

function sev(text, cls) { return h("span", { class: "sev " + (cls || text) }, text); }

function spark(points, key, max) {
  const w = 300, ht = 60;
  const el = svg("svg", { viewBox: `0 0 ${w} ${ht}`, preserveAspectRatio: "none", class: "spark" });
  if (points.length < 2) return el;
  const vals = points.map((p) => typeof key === "function" ? key(p) : p[key]);
  const m = max || Math.max(...vals, 1);
  const xy = vals.map((v, i) => [(i / (vals.length - 1)) * w, ht - (v / m) * (ht - 4) - 2]);
  const d = xy.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  el.append(svg("path", { d: d + ` L${w} ${ht} L0 ${ht} Z`, class: "area" }));
  el.append(svg("path", { d, class: "line" }));
  return el;
}

function setView(...nodes) {
  const app = document.getElementById("app");
  app.replaceChildren(...nodes.flat().filter(Boolean));
}

function every(ms, fn) {
  clearInterval(state.timer);
  state.timer = setInterval(fn, ms);
}

function errorBox(e) { return h("div", { class: "error" }, "Fehler: " + e.message); }

// ---------- modal ----------

function openModal(...nodes) {
  const m = document.getElementById("modal");
  document.getElementById("modal-body").replaceChildren(...nodes.flat().filter(Boolean));
  m.hidden = false;
}
function closeModal() { document.getElementById("modal").hidden = true; }
document.getElementById("modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

// ---------- auth ----------

function logout() {
  try { sessionStorage.removeItem("sb_token"); } catch (_) { /* ignore */ }
  state.token = null; state.me = null;
  document.getElementById("nav").hidden = true;
  document.getElementById("whoami").replaceChildren();
  renderLogin();
}

function renderLogin(msg) {
  clearInterval(state.timer);
  const input = h("input", { type: "password", placeholder: "sbu_…", autocomplete: "off" });
  const form = h("form", { class: "panel login", onsubmit: async (e) => {
      e.preventDefault();
      state.token = input.value.trim();
      try { await boot(); } catch (err) { renderLogin(err.message); }
    } },
    h("h1", {}, "ServerBrain anmelden"),
    h("p", { class: "muted" }, "API-Token eingeben. Beim ersten Start gibt sb-server einen Admin-Token auf der Konsole aus."),
    msg ? h("div", { class: "error" }, msg) : null,
    input,
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Anmelden")));
  setView(form);
  input.focus();
}

async function boot() {
  state.me = await api("GET", "/api/me");
  try { sessionStorage.setItem("sb_token", state.token); } catch (_) { /* ignore */ }
  state.catalog = await api("GET", "/api/actions");
  document.getElementById("nav").hidden = false;
  for (const el of document.querySelectorAll(".admin-only")) el.hidden = !isAdmin();
  document.getElementById("whoami").replaceChildren(
    h("span", {}, state.me.name + " · " + state.me.role + (state.me.kind === "ai" ? " · KI" : "")),
    h("button", { class: "small", onclick: logout }, "Abmelden"));
  route();
  refreshApprovalCount();
}

async function refreshApprovalCount() {
  if (!state.token) return;
  try {
    const list = await api("GET", "/api/commands?status=pending_approval");
    const b = document.getElementById("approval-count");
    b.textContent = list.length;
    b.hidden = list.length === 0;
  } catch (_) { /* ignore */ }
}
setInterval(refreshApprovalCount, 15000);

// ---------- routing ----------

function route() {
  if (!state.token) return renderLogin();
  closeModal();
  const hash = location.hash.replace(/^#/, "") || "/";
  const parts = hash.split("/").filter(Boolean);
  const name = parts[0] || "overview";
  for (const a of document.querySelectorAll("nav a")) a.classList.toggle("active", a.dataset.route === (name === "servers" ? "overview" : name));
  clearInterval(state.timer);
  const views = { overview: viewOverview, servers: () => viewServer(parts[1]), approvals: viewApprovals, commands: viewCommands, events: viewEvents, audit: viewAudit, settings: viewSettings };
  (views[name] || viewOverview)();
}
window.addEventListener("hashchange", route);

// ---------- overview ----------

async function viewOverview() {
  const alertsPanel = h("div", { class: "panel" }, h("h2", {}, "Alerts"), h("div", { class: "empty" }, "Lade…"));
  const grid = h("div", { class: "grid" });
  const summary = h("p", { class: "muted" });
  setView(h("h1", {}, "Übersicht"), summary, alertsPanel, h("h2", {}, "Server"), grid);

  async function load() {
    try {
      const [servers, alerts] = await Promise.all([api("GET", "/api/servers"), api("GET", "/api/alerts")]);
      const online = servers.filter((s) => s.online).length;
      summary.textContent = `${servers.length} Server · ${online} online · ${alerts.filter((a) => a.severity === "critical").length} kritische Alerts`;
      alertsPanel.replaceChildren(h("h2", {}, "Alerts"),
        ...(alerts.length ? alerts.map(renderAlert) : [h("div", { class: "empty" }, "Keine aktiven Alerts.")]));
      grid.replaceChildren(...(servers.length ? servers.map(serverCard) : [h("div", { class: "panel empty" },
        "Noch keine Server registriert. Unter Einstellungen einen Enrollment-Token erzeugen und den Agenten installieren.")]));
    } catch (e) { summary.replaceChildren(errorBox(e)); }
  }
  await load();
  every(15000, load);
}

function renderAlert(a) {
  return h("div", { class: "alert" },
    sev(a.severity),
    h("a", { href: "#/servers/" + a.server_id }, h("strong", {}, a.hostname)),
    h("span", { class: "msg" }, a.message),
    a.suggested && canOperate() ? h("button", { class: "small", onclick: () => actionDialog(a.server_id, a.hostname, a.suggested.action, a.suggested.params, a.message) }, a.suggested.label) : null);
}

function serverCard(s) {
  const m = (s.snapshot && s.snapshot.metrics) || {};
  const disks = m.disks || [];
  const worst = disks.reduce((acc, d) => { const p = pct(d.total - d.free, d.total); return p > acc.p ? { p, d } : acc; }, { p: 0, d: null });
  return h("a", { class: "card", href: "#/servers/" + s.id },
    h("div", { class: "card-head" },
      h("span", { class: "dot " + (s.online ? "on" : "off"), title: s.online ? "online" : "offline" }),
      h("strong", {}, s.hostname)),
    h("div", { class: "muted small" }, s.os_version || s.os, " · zuletzt ", ago(s.last_seen)),
    meter("CPU", m.cpu_percent || 0),
    meter("RAM", pct(m.mem_used, m.mem_total), m.mem_total ? fmtBytes(m.mem_used) + " / " + fmtBytes(m.mem_total) : "–"),
    worst.d ? meter("Disk " + worst.d.name, worst.p, fmtBytes(worst.d.free) + " frei") : null,
    h("div", {}, (s.tags || []).map((t) => h("span", { class: "tag" }, t))));
}

// ---------- server detail ----------

async function viewServer(id) {
  const head = h("div");
  const body = h("div");
  setView(h("div", { class: "row" }, h("a", { href: "#/" }, "← Übersicht")), head, body);
  let tab = "overview";
  let server = null;

  const tabs = [["overview", "Übersicht"], ["services", "Dienste"], ["events", "Ereignisse"], ["actions", "Aktionen"], ["console", "Konsole"]];
  const tabBar = h("div", { class: "tabs" });
  function renderTabs() {
    tabBar.replaceChildren(...tabs.map(([k, label]) => h("button", { class: tab === k ? "active" : "", onclick: () => { tab = k; renderTabs(); renderTab(); } }, label)));
  }

  async function load() {
    try {
      server = await api("GET", "/api/servers/" + id);
    } catch (e) { head.replaceChildren(errorBox(e)); return; }
    const sys = (server.snapshot && server.snapshot.system) || {};
    head.replaceChildren(
      h("h1", { class: "row" }, h("span", { class: "dot " + (server.online ? "on" : "off") }), server.hostname,
        (server.tags || []).map((t) => h("span", { class: "tag" }, t))),
      h("p", { class: "muted" }, [server.os_version || server.os, sys.domain, "Agent " + server.agent_version, (sys.ips || []).join(", "), "zuletzt " + ago(server.last_seen)].filter(Boolean).join(" · ")),
      tabBar);
    if (tab === "overview") renderTab();
  }

  async function renderTab() {
    if (!server) return;
    try {
      if (tab === "overview") body.replaceChildren(await serverOverview(server));
      if (tab === "services") body.replaceChildren(serverServices(server));
      if (tab === "events") body.replaceChildren(await serverEvents(server));
      if (tab === "actions") body.replaceChildren(await serverActions(server));
      if (tab === "console") body.replaceChildren(serverConsole(server));
    } catch (e) { body.replaceChildren(errorBox(e)); }
  }

  renderTabs();
  await load();
  renderTab();
  every(20000, load);
}

async function serverOverview(s) {
  const pts = await api("GET", `/api/servers/${s.id}/metrics?hours=6`);
  const hb = s.snapshot || {};
  const m = hb.metrics || {};
  const sys = hb.system || {};
  const chart = (title, key, max, cur) => h("div", { class: "panel" }, h("div", { class: "meter-label" }, h("strong", {}, title), h("span", {}, cur)), spark(pts, key, max));
  return h("div", {},
    h("div", { class: "grid" },
      chart("CPU (6 h)", "cpu", 100, (m.cpu_percent || 0).toFixed(0) + " %"),
      chart("RAM (6 h)", (p) => pct(p.mem_used, p.mem_total), 100, pct(m.mem_used, m.mem_total).toFixed(0) + " %"),
      chart("Volste Disk (6 h)", "disk_used_pct", 100, pts.length ? pts[pts.length - 1].disk_used_pct.toFixed(1) + " %" : "–")),
    h("div", { class: "cols" },
      h("div", { class: "panel" }, h("h2", {}, "Datenträger"),
        (m.disks || []).map((d) => meter(`${d.name} ${d.label || ""} (${d.fs || ""})`, pct(d.total - d.free, d.total), fmtBytes(d.free) + " frei von " + fmtBytes(d.total)))),
      h("div", { class: "panel" }, h("h2", {}, "System"),
        h("dl", { class: "kv" },
          h("dt", {}, "Hostname"), h("dd", {}, sys.hostname || s.hostname),
          h("dt", {}, "Betriebssystem"), h("dd", {}, sys.os_version || s.os),
          h("dt", {}, "Domäne"), h("dd", {}, sys.domain || "–"),
          h("dt", {}, "CPUs"), h("dd", {}, sys.cpus || "–"),
          h("dt", {}, "Letzter Boot"), h("dd", {}, fmtTime(sys.boot_time)),
          h("dt", {}, "IP-Adressen"), h("dd", {}, (sys.ips || []).join(", ") || "–"),
          h("dt", {}, "Registriert"), h("dd", {}, fmtTime(s.enrolled_at)),
          h("dt", {}, "Verbindung von"), h("dd", {}, s.remote_addr || "–"),
          h("dt", {}, "Capabilities"), h("dd", {}, (s.capabilities || []).map((c) => h("span", { class: "tag" }, c)))),
        isAdmin() ? h("div", { class: "row" },
          h("button", { class: "small", onclick: () => editTags(s) }, "Tags bearbeiten"),
          h("button", { class: "small danger", onclick: () => deleteServer(s) }, "Server entfernen")) : null)));
}

function editTags(s) {
  const input = h("input", { value: (s.tags || []).join(", ") });
  openModal(h("h2", {}, "Tags für " + s.hostname), h("label", {}, "Kommagetrennt, z. B. web, prod"), input,
    h("div", { class: "row decision" },
      h("button", { class: "primary", onclick: async () => {
        const tags = input.value.split(",").map((t) => t.trim()).filter(Boolean);
        await api("PUT", `/api/servers/${s.id}/tags`, { tags });
        closeModal(); route();
      } }, "Speichern"),
      h("button", { onclick: closeModal }, "Abbrechen")));
}

async function deleteServer(s) {
  if (!confirm(`Server ${s.hostname} entfernen? Der Agent muss danach neu registriert werden.`)) return;
  await api("DELETE", "/api/servers/" + s.id);
  location.hash = "#/";
}

function serverServices(s) {
  const services = ((s.snapshot && s.snapshot.services) || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  const filter = h("input", { placeholder: "Dienste filtern…" });
  const onlyProblems = h("input", { type: "checkbox" });
  const tbody = h("tbody");
  const has = (c) => (s.capabilities || []).includes(c);
  function render() {
    const q = filter.value.toLowerCase();
    const rows = services.filter((x) => (!q || x.name.toLowerCase().includes(q) || (x.display_name || "").toLowerCase().includes(q)) &&
      (!onlyProblems.checked || (x.start_type.toLowerCase().startsWith("auto") && x.status === "Stopped")));
    tbody.replaceChildren(...rows.map((x) => h("tr", {},
      h("td", {}, h("strong", {}, x.name), h("div", { class: "muted small" }, x.display_name)),
      h("td", {}, sev(x.status, x.status === "Running" ? "succeeded" : x.start_type.toLowerCase().startsWith("auto") ? "failed" : "queued")),
      h("td", {}, x.start_type),
      h("td", {}, canOperate() ? h("div", { class: "row" },
        x.status !== "Running" && has("service.start") ? h("button", { class: "small", onclick: () => actionDialog(s.id, s.hostname, "service.start", { name: x.name }) }, "Starten") : null,
        x.status === "Running" && has("service.restart") ? h("button", { class: "small", onclick: () => actionDialog(s.id, s.hostname, "service.restart", { name: x.name }) }, "Neustart") : null,
        x.status === "Running" && has("service.stop") ? h("button", { class: "small danger", onclick: () => actionDialog(s.id, s.hostname, "service.stop", { name: x.name }) }, "Stoppen") : null) : null))));
  }
  filter.addEventListener("input", render);
  onlyProblems.addEventListener("change", render);
  render();
  return h("div", { class: "panel" },
    h("div", { class: "row" }, filter, h("label", { class: "row" }, onlyProblems, "nur gestoppte Autostart-Dienste")),
    services.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Dienst"), h("th", {}, "Status"), h("th", {}, "Starttyp"), h("th", {}, ""))), tbody)
      : h("div", { class: "empty" }, "Keine Dienstinformationen (nur auf Windows-Servern verfügbar)."));
}

function eventsTable(events, withHost) {
  if (!events.length) return h("div", { class: "empty" }, "Keine Ereignisse im Zeitraum.");
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), withHost ? h("th", {}, "Server") : null, h("th", {}, "Level"), h("th", {}, "Quelle"), h("th", {}, "ID"), h("th", {}, "Meldung"))),
    h("tbody", {}, events.map((e) => h("tr", {},
      h("td", { class: "small" }, fmtTime(e.time)),
      withHost ? h("td", {}, h("a", { href: "#/servers/" + e.server_id }, e.hostname || e.server_id)) : null,
      h("td", {}, sev(e.level)),
      h("td", { class: "small" }, e.log + " / " + e.source),
      h("td", {}, e.event_id),
      h("td", { class: "small" }, e.message.length > 400 ? e.message.slice(0, 400) + "…" : e.message)))));
}

async function serverEvents(s) {
  const events = await api("GET", `/api/servers/${s.id}/events?hours=48`);
  return h("div", { class: "panel" }, h("h2", {}, "Warnungen & Fehler (48 h)"), eventsTable(events, false));
}

async function serverActions(s) {
  const cmds = await api("GET", "/api/commands?limit=50&server=" + s.id);
  const offered = state.catalog.filter((a) => (s.capabilities || []).includes(a.name) && a.name !== "shell.run");
  return h("div", {},
    canOperate() || state.me.role === "viewer" ? h("div", { class: "panel" }, h("h2", {}, "Verfügbare Aktionen"),
      h("table", {}, h("tbody", {}, offered.map((a) => h("tr", {},
        h("td", {}, h("strong", {}, a.title), h("div", { class: "muted small" }, a.name + " — " + a.description)),
        h("td", {}, sev(a.risk), a.read_only ? h("span", { class: "tag" }, "read-only") : null),
        h("td", {}, h("button", { class: "small", onclick: () => actionDialog(s.id, s.hostname, a.name, {}) }, "Ausführen…"))))))) : null,
    h("div", { class: "panel" }, h("h2", {}, "Letzte Aktionen"), commandsTable(cmds, false)));
}

function serverConsole(s) {
  if (!(s.capabilities || []).includes("shell.run")) {
    return h("div", { class: "panel" }, h("h2", {}, "Remote-Konsole"),
      h("p", { class: "muted" }, "Die Konsole ist auf diesem Agenten deaktiviert. Aktivieren mit ",
        h("code", {}, "sb-agent enroll … -enable-shell"), " bzw. ", h("code", {}, "\"enable_shell\": true"), " in agent.json. Ausführung unterliegt der Policy (standardmäßig nur Admins) und wird vollständig auditiert."));
  }
  const script = h("textarea", { placeholder: s.os === "windows" ? "Get-Service W3SVC | Format-List *" : "uname -a", spellcheck: "false" });
  const reason = h("input", { placeholder: "Grund (für Audit-Log)" });
  const out = h("div");
  const run = async () => {
    if (!script.value.trim()) return;
    out.replaceChildren(h("div", { class: "muted" }, "Sende…"));
    try {
      const res = await api("POST", `/api/servers/${s.id}/actions`, { action: "shell.run", params: { script: script.value }, reason: reason.value });
      out.replaceChildren(commandResultView(res.command));
      followCommand(res.command.id, out);
    } catch (e) { out.replaceChildren(errorBox(e)); }
  };
  script.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  return h("div", { class: "panel" }, h("h2", {}, (s.os === "windows" ? "PowerShell" : "Shell") + " auf " + s.hostname),
    script, reason, h("div", { class: "row decision" }, h("button", { class: "primary", onclick: run }, "Ausführen (Strg+Enter)")), out);
}

// ---------- actions ----------

function paramInput(p, value) {
  const v = value !== undefined ? value : (p.default || "");
  if (p.name === "script") return h("textarea", { name: p.name }, v);
  return h("input", { name: p.name, value: v, type: p.type === "int" ? "number" : "text", min: p.type === "int" ? p.min : null, max: p.type === "int" && p.max ? p.max : null });
}

function actionDialog(serverId, hostname, actionName, params, context) {
  const def = state.catalog.find((a) => a.name === actionName);
  if (!def) return;
  const inputs = def.params.map((p) => [p, paramInput(p, params && params[p.name])]);
  const reason = h("input", { placeholder: "Warum? (wird Freigebenden angezeigt und auditiert)", value: context || "" });
  const preview = h("div");
  const result = h("div");
  const collect = () => {
    const out = {};
    for (const [p, el] of inputs) if (el.value !== "") out[p.name] = p.type === "int" ? Number(el.value) : el.value;
    return out;
  };
  const showPreview = async () => {
    try {
      const res = await api("POST", `/api/servers/${serverId}/actions/preview`, { action: def.name, params: collect() });
      const d = res.decision;
      preview.replaceChildren(
        h("div", { class: "decision" }, h("strong", {}, "Policy:"), sev(d.effect), h("span", { class: "muted small" }, d.rule),
          d.effect === "approve" ? h("span", {}, "→ erfordert Freigabe durch einen Admin") : null,
          d.effect === "block" ? h("span", {}, "→ diese Aktion ist für dich gesperrt") : null),
        h("details", {}, h("summary", {}, "Befehle anzeigen"), h("pre", {}, res.preview)));
    } catch (e) { preview.replaceChildren(errorBox(e)); }
  };
  const execute = async () => {
    try {
      const res = await api("POST", `/api/servers/${serverId}/actions`, { action: def.name, params: collect(), reason: reason.value });
      result.replaceChildren(commandResultView(res.command));
      followCommand(res.command.id, result);
      refreshApprovalCount();
    } catch (e) {
      result.replaceChildren(errorBox(e));
    }
  };
  for (const [, el] of inputs) el.addEventListener("change", showPreview);
  openModal(
    h("h2", {}, def.title + " auf " + hostname),
    h("p", { class: "muted" }, def.description, " ", sev(def.risk)),
    inputs.map(([p, el]) => h("div", {}, h("label", {}, p.name + (p.required ? " *" : "") + " — " + p.description), el)),
    h("label", {}, "Begründung"), reason,
    preview,
    h("div", { class: "row decision" },
      h("button", { class: "primary", onclick: execute, disabled: !canOperate() && !def.read_only }, "Ausführen"),
      h("button", { onclick: closeModal }, "Schließen")),
    result);
  showPreview();
}

function commandResultView(c) {
  const r = c.result;
  return h("div", { class: "panel" },
    h("div", { class: "decision" }, sev(c.status), h("strong", {}, c.action), h("span", { class: "muted small" }, (c.hostname || "") + " · " + fmtTime(c.created_at) + " · von " + c.requested_by + (c.actor_type === "ai" ? " (KI)" : ""))),
    c.status === "pending_approval" ? h("div", { class: "notice" }, "Wartet auf Freigabe durch einen Admin.") : null,
    c.reason ? h("div", { class: "small" }, "Grund: " + c.reason) : null,
    c.decided_by ? h("div", { class: "small muted" }, "Entschieden von " + c.decided_by) : null,
    r ? h("div", {},
      r.error ? h("div", { class: "error" }, r.error) : null,
      r.output ? h("pre", {}, r.output) : null,
      h("div", { class: "muted small" }, "Exit-Code " + r.exit_code + " · Dauer " + ((new Date(r.finished) - new Date(r.started)) / 1000).toFixed(1) + " s")) : null);
}

function followCommand(id, container) {
  const done = ["succeeded", "failed", "rejected", "expired", "cancelled"];
  let tries = 0;
  const tick = async () => {
    if (!container.isConnected || tries++ > 600) return;
    try {
      const c = await api("GET", "/api/commands/" + id);
      container.replaceChildren(commandResultView(c));
      if (done.includes(c.status)) return;
    } catch (_) { /* keep polling */ }
    setTimeout(tick, 1500);
  };
  setTimeout(tick, 800);
}

function commandsTable(cmds, withHost) {
  if (!cmds.length) return h("div", { class: "empty" }, "Noch keine Aktionen.");
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), withHost ? h("th", {}, "Server") : null, h("th", {}, "Aktion"), h("th", {}, "Risiko"), h("th", {}, "Status"), h("th", {}, "Angefordert von"))),
    h("tbody", {}, cmds.map((c) => h("tr", { class: "clickable", onclick: () => { openModal(commandResultView(c), h("details", {}, h("summary", {}, "Befehle anzeigen"), h("pre", {}, c.preview))); followCommand(c.id, document.getElementById("modal-body").firstChild); } },
      h("td", { class: "small" }, fmtTime(c.created_at)),
      withHost ? h("td", {}, c.hostname) : null,
      h("td", {}, h("strong", {}, c.action), h("div", { class: "muted small" }, Object.entries(c.params || {}).filter(([k]) => k !== "script").map(([k, v]) => k + "=" + v).join(" "))),
      h("td", {}, sev(c.risk, c.risk === "critical" ? "critical-risk" : c.risk)),
      h("td", {}, sev(c.status)),
      h("td", { class: "small" }, c.requested_by + (c.actor_type === "ai" ? " (KI)" : ""))))));
}

// ---------- approvals / commands / events / audit ----------

async function viewApprovals() {
  const box = h("div");
  setView(h("h1", {}, "Freigaben"), h("p", { class: "muted" }, "Aktionen, die laut Policy eine menschliche Freigabe brauchen. Prüfe die Befehle, bevor du freigibst."), box);
  async function load() {
    try {
      const list = await api("GET", "/api/commands?status=pending_approval");
      box.replaceChildren(...(list.length ? list.map((c) => h("div", { class: "panel" },
        h("div", { class: "decision" }, sev(c.risk, c.risk === "critical" ? "critical-risk" : c.risk), h("strong", {}, c.action), "auf",
          h("a", { href: "#/servers/" + c.server_id }, c.hostname), h("span", { class: "muted small" }, fmtTime(c.created_at))),
        h("div", {}, "Angefordert von ", h("strong", {}, c.requested_by), c.actor_type === "ai" ? " (KI-Agent)" : "", " · Regel ", h("code", {}, c.policy_rule)),
        c.reason ? h("div", { class: "notice" }, c.reason) : null,
        h("pre", {}, c.preview),
        isAdmin() ? h("div", { class: "row" },
          h("button", { class: "primary", onclick: async () => { try { await api("POST", `/api/commands/${c.id}/approve`); load(); refreshApprovalCount(); } catch (e) { alert(e.message); } } }, "Freigeben & ausführen"),
          h("button", { class: "danger", onclick: async () => { try { await api("POST", `/api/commands/${c.id}/reject`); load(); refreshApprovalCount(); } catch (e) { alert(e.message); } } }, "Ablehnen"))
          : h("div", { class: "muted small" }, "Nur Admins können freigeben."),
        c.requested_by === state.me.name ? h("button", { class: "small", onclick: async () => { await api("POST", `/api/commands/${c.id}/cancel`); load(); refreshApprovalCount(); } }, "Zurückziehen") : null))
        : [h("div", { class: "panel empty" }, "Nichts freizugeben.")]));
    } catch (e) { box.replaceChildren(errorBox(e)); }
  }
  await load();
  every(10000, load);
}

async function viewCommands() {
  const status = h("select", {}, ["", "pending_approval", "queued", "dispatched", "succeeded", "failed", "rejected", "expired", "cancelled"].map((s) => h("option", { value: s }, s || "alle Status")));
  const box = h("div", { class: "panel" });
  setView(h("h1", {}, "Aktionen"), h("div", { class: "row" }, status), box);
  async function load() {
    try { box.replaceChildren(commandsTable(await api("GET", "/api/commands?limit=200&status=" + status.value), true)); }
    catch (e) { box.replaceChildren(errorBox(e)); }
  }
  status.addEventListener("change", load);
  await load();
  every(10000, load);
}

async function viewEvents() {
  const box = h("div", { class: "panel" });
  setView(h("h1", {}, "Ereignisse (24 h, Warnung und höher)"), box);
  try {
    const [events, servers] = await Promise.all([api("GET", "/api/events?hours=24"), api("GET", "/api/servers")]);
    const names = Object.fromEntries(servers.map((s) => [s.id, s.hostname]));
    for (const e of events) e.hostname = names[e.server_id];
    box.replaceChildren(eventsTable(events, true));
  } catch (e) { box.replaceChildren(errorBox(e)); }
}

async function viewAudit() {
  const box = h("div", { class: "panel" });
  setView(h("h1", {}, "Audit-Log"), h("p", { class: "muted" }, "Jede Anfrage, Policy-Entscheidung, Freigabe und Ausführung wird protokolliert."), box);
  try {
    const list = await api("GET", "/api/audit?limit=500");
    box.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), h("th", {}, "Akteur"), h("th", {}, "Ereignis"), h("th", {}, "Ziel"), h("th", {}, "Details"))),
      h("tbody", {}, list.map((a) => h("tr", {},
        h("td", { class: "small" }, fmtTime(a.ts)),
        h("td", {}, a.actor, h("div", { class: "muted small" }, a.actor_type)),
        h("td", {}, h("code", {}, a.event)),
        h("td", { class: "small" }, a.target),
        h("td", { class: "small" }, Object.keys(a.details || {}).length ? JSON.stringify(a.details) : ""))))));
  } catch (e) { box.replaceChildren(errorBox(e)); }
}

// ---------- settings ----------

async function viewSettings() {
  const parts = [h("h1", {}, "Einstellungen")];
  if (isAdmin()) {
    const tags = h("input", { placeholder: "z. B. web, prod" });
    const uses = h("input", { type: "number", value: "1", min: "1" });
    const ttl = h("input", { type: "number", value: "24", min: "1" });
    const out = h("div");
    parts.push(h("div", { class: "panel" }, h("h2", {}, "Server hinzufügen"),
      h("p", { class: "muted" }, "Erzeuge einen Enrollment-Token und führe den Befehl auf dem Windows Server (als Administrator) aus. Der Agent baut die Verbindung ausgehend auf – es werden keine eingehenden Ports benötigt."),
      h("div", { class: "cols" }, h("div", {}, h("label", {}, "Tags"), tags), h("div", { class: "row" }, h("div", {}, h("label", {}, "Verwendungen"), uses), h("div", {}, h("label", {}, "Gültig (Stunden)"), ttl))),
      h("div", { class: "row decision" }, h("button", { class: "primary", onclick: async () => {
        try {
          const res = await api("POST", "/api/enrollment-tokens", { tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean), uses: Number(uses.value), ttl_hours: Number(ttl.value) });
          const url = location.origin;
          out.replaceChildren(
            h("div", { class: "notice" }, "Token gültig bis " + fmtTime(res.expires_at) + " (" + res.uses + "× verwendbar). Er wird nur einmal angezeigt."),
            h("pre", {}, `# PowerShell (als Administrator)\n.\\sb-agent.exe enroll -server ${url} -token ${res.token}\n.\\sb-agent.exe install`));
        } catch (e) { out.replaceChildren(errorBox(e)); }
      } }, "Enrollment-Token erzeugen")), out));

    const uname = h("input", { placeholder: "Name" });
    const role = h("select", {}, ["viewer", "operator", "admin"].map((r) => h("option", { value: r }, r)));
    const kind = h("select", {}, h("option", { value: "human" }, "Mensch"), h("option", { value: "ai" }, "KI-Agent"));
    const uout = h("div");
    const users = await api("GET", "/api/users");
    parts.push(h("div", { class: "panel" }, h("h2", {}, "Benutzer & API-Tokens"),
      h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Rolle"), h("th", {}, "Typ"), h("th", {}, "Erstellt"))),
        h("tbody", {}, users.map((u) => h("tr", {}, h("td", {}, u.name), h("td", {}, u.role), h("td", {}, u.kind === "ai" ? "KI-Agent" : "Mensch"), h("td", { class: "small" }, fmtTime(u.created_at)))))),
      h("div", { class: "row decision" }, uname, role, kind, h("button", { onclick: async () => {
        try {
          const res = await api("POST", "/api/users", { name: uname.value.trim(), role: role.value, kind: kind.value });
          uout.replaceChildren(h("div", { class: "notice" }, "Token für " + res.user.name + " (nur einmal sichtbar):"), h("pre", {}, res.token));
        } catch (e) { uout.replaceChildren(errorBox(e)); }
      } }, "Anlegen")), uout,
      h("p", { class: "muted small" }, "KI-Agenten-Konten werden von der Policy separat behandelt (actor_type \"ai\"): z. B. read-only, Freigabe erforderlich oder autonome Low-Risk-Aktionen. Tool-Definitionen für Function Calling: GET /api/ai/tools")));
  }
  const pol = await api("GET", "/api/policy");
  parts.push(h("div", { class: "panel" }, h("h2", {}, "Aktive Policy"),
    h("p", { class: "muted" }, "Regeln werden von oben nach unten geprüft, die erste passende Regel gewinnt. Ohne Treffer wird blockiert. Eigene Policy: sb-server -policy policy.json"),
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Regel"), h("th", {}, "Bedingungen"), h("th", {}, "Effekt"))),
      h("tbody", {}, pol.rules.map((r) => h("tr", {},
        h("td", {}, r.name),
        h("td", { class: "small" }, Object.entries(r).filter(([k]) => !["name", "effect"].includes(k)).map(([k, v]) => k + ": " + (Array.isArray(v) ? v.join(", ") : v)).join(" · ") || "immer"),
        h("td", {}, sev(r.effect)))))),
    h("p", { class: "muted small" }, "Selbstfreigabe erlaubt: " + (pol.allow_self_approval ? "ja" : "nein (Vier-Augen-Prinzip)"))));
  setView(...parts);
}

// ---------- start ----------

try { state.token = sessionStorage.getItem("sb_token"); } catch (_) { state.token = null; }
if (state.token) boot().catch(() => renderLogin()); else renderLogin();
