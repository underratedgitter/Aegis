"use strict";

// ── Constants ──────────────────────────────────────────────────────────────────
const POLL_MS = 5000;
const TIMELINE_LIMIT = 20;
const EVIDENCE_LIMIT = 10;
const INCIDENT_LIMIT = 200;
const SPARK_POINTS = 48;
const TOAST_LIMIT = 4;
const DEFAULT_APPROVER = "demo-operator";
const APPROVER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._@+-]{1,79}$/;
const FINAL_STATUSES = new Set(["resolved", "closed"]);
const STATUS_ORDER = {open: 0, investigating: 1, recommendation_pending: 2, approved: 3, executing: 3};

const ROUTES = {
  overview: {title: "Overview", eyebrow: "Production control room"},
  incidents: {title: "Incidents", eyebrow: "Live queue"},
  chaos: {title: "Chaos lab", eyebrow: "Controlled failure"},
  telemetry: {title: "Telemetry", eyebrow: "Metrics and logs"},
  runbooks: {title: "Runbooks", eyebrow: "Knowledge base"},
  audit: {title: "Audit log", eyebrow: "Accountability"},
  settings: {title: "Settings", eyebrow: "Access and engine"},
};

// Display metadata for the snapshot metrics. "alert" mirrors the thresholds in aegis/incidents.py
// and puts the alert line at the middle of each bar.
const pct = (v) => `${(v * 100).toFixed(1)}%`;
const METRICS = {
  checkout_error_rate: {label: "Checkout error rate", hint: "5xx share of requests · alert above 15%", format: pct, alert: 0.15},
  checkout_p95_latency: {label: "Checkout p95 latency", hint: "95th percentile response time · alert above 750 ms", format: (v) => (v < 1 ? `${Math.round(v * 1000)} ms` : `${v.toFixed(2)} s`), alert: 0.75},
  inventory_dependency_errors: {label: "Inventory dependency errors", hint: "Failed calls to inventory per second · alert above 0.05/s", format: (v) => `${v.toFixed(2)}/s`, alert: 0.05},
  checkout_cpu_burn: {label: "Checkout CPU burn", hint: "CPU stress gauge · alert above 0.5", format: (v) => v.toFixed(2), alert: 0.5},
};

// ── State ──────────────────────────────────────────────────────────────────────
const state = {
  route: {name: "overview", id: null},
  overview: null,
  incidents: null,
  incidentsTotal: 0,
  metrics: null,
  logs: null,
  ready: null,
  live: false,
  audit: null,
  runbooks: null,
  detail: {id: null, incident: null},
  errors: {},
  busy: null,
  connected: null,
  autoRefresh: true,
  samples: new Map(),
  chaosLog: [],
  runOnce: null,
};

const $ = (id) => document.getElementById(id);

// ── In-place DOM patching ──────────────────────────────────────────────────────
// Views re-render on every poll. Replacing unchanged markup makes the page flash and drops hover,
// focus, selection and scroll position, so write only what actually changed.
const renderedHtml = new WeakMap();

function syncAttributes(current, wanted) {
  for (const {name} of [...current.attributes]) {
    // "style" is only ever written through the CSSOM (bar widths) and a <details> element owns "open".
    if (name === "style" || (name === "open" && current.nodeName === "DETAILS")) continue;
    if (!wanted.hasAttribute(name)) current.removeAttribute(name);
  }
  for (const {name, value} of wanted.attributes) {
    if (name === "open" && current.nodeName === "DETAILS") continue;
    if (current.getAttribute(name) !== value) current.setAttribute(name, value);
  }
}

// Patch the children of `parent` in place to match `wanted`, keeping every node that is unchanged.
function patchChildren(parent, wanted) {
  const target = wanted.childNodes;
  for (let i = 0; i < target.length; i++) {
    const next = target[i];
    const current = parent.childNodes[i];
    if (!current) parent.appendChild(next.cloneNode(true));
    else if (current.nodeName !== next.nodeName) parent.replaceChild(next.cloneNode(true), current);
    else if (next.nodeType === Node.ELEMENT_NODE) {
      syncAttributes(current, next);
      patchChildren(current, next);
    } else if (current.data !== next.data) current.data = next.data;
  }
  while (parent.childNodes.length > target.length) parent.lastChild.remove();
}

function setHtml(target, html) {
  const el = typeof target === "string" ? $(target) : target;
  if (renderedHtml.get(el) === html) return;
  const template = document.createElement("template");
  template.innerHTML = html;
  patchChildren(el, template.content);
  renderedHtml.set(el, html);
  // Bar widths are set through the CSSOM: inline style attributes are not part of the markup.
  for (const bar of el.querySelectorAll("[data-pct]")) {
    const width = `${bar.dataset.pct}%`;
    if (bar.style.width !== width) bar.style.width = width;
  }
}

// Writing identical text or classes still queues DOM mutations; skip them.
function setText(id, text) {
  const el = $(id);
  if (el.textContent === text) return;
  if (el.firstChild?.nodeType === Node.TEXT_NODE && !el.firstChild.nextSibling) el.firstChild.data = text;
  else el.textContent = text;
}

function setClass(id, className) {
  const el = $(id);
  if (el.className !== className) el.className = className;
}

function setDisabled(id, disabled) {
  const el = $(id);
  if (el.disabled !== disabled) el.disabled = disabled;
}

// ── Formatting ─────────────────────────────────────────────────────────────────
function esc(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  }[char]));
}

const pretty = (value) => String(value ?? "").replaceAll("_", " ");
const fmt = (value) => value == null ? "—" : typeof value === "number" ? value.toFixed(value < 1 ? 3 : 1) : value;

function toDate(iso) {
  if (!iso) return null;
  // Log timestamps carry no zone and are UTC.
  const date = new Date(/(?:Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : `${iso}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtClock(iso) {
  const date = toDate(iso);
  return date ? date.toLocaleTimeString([], {hour12: false}) : "—";
}

function fmtStamp(iso) {
  const date = toDate(iso);
  if (!date) return "—";
  if (date.toDateString() === new Date().toDateString()) return fmtClock(iso);
  return `${date.toLocaleDateString([], {month: "short", day: "numeric"})} ${fmtClock(iso)}`;
}

function fmtDuration(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return "—";
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total}s`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${String(total % 60).padStart(2, "0")}s`;
  return `${Math.floor(total / 3600)}h ${String(Math.floor((total % 3600) / 60)).padStart(2, "0")}m`;
}

function incidentDuration(incident) {
  const start = toDate(incident.first_seen);
  const end = incident.resolved_at ? toDate(incident.resolved_at) : new Date();
  return start && end ? (end - start) / 1000 : null;
}

// Stable order so the list does not reshuffle every time a signal refreshes last_seen.
function sortIncidents(incidents) {
  return [...incidents].sort((a, b) =>
    (STATUS_ORDER[a.status] ?? 4) - (STATUS_ORDER[b.status] ?? 4) || b.first_seen.localeCompare(a.first_seen));
}

const iconSvg = (name) => `<svg class="icon" aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`;
const incidentHref = (id) => `#/incidents/${encodeURIComponent(id)}`;

// ── Session storage (the key never leaves this tab) ────────────────────────────
function storageGet(name) {
  try {
    return sessionStorage.getItem(name) || "";
  } catch {
    return "";
  }
}

function storageSet(name, value) {
  try {
    if (value) sessionStorage.setItem(name, value);
    else sessionStorage.removeItem(name);
    return true;
  } catch {
    return false;
  }
}

const getApiKey = () => storageGet("aegis-api-key");
const getApprover = () => storageGet("aegis-approver") || DEFAULT_APPROVER;

function updateKeyChip() {
  setText("key-chip-text", getApiKey() ? "Key set" : "No key");
}

// ── API ────────────────────────────────────────────────────────────────────────
class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// The bearer header for protected routes; the key is only sent when one is set.
function authHeaders(headers = {}) {
  const key = getApiKey();
  if (key) headers.Authorization = `Bearer ${key}`;
  return headers;
}

// Options for a state-changing POST.
function postOptions(body) {
  const headers = authHeaders();
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return {method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body)};
}

function errorDetail(payload) {
  const detail = payload?.detail;
  if (Array.isArray(detail)) return detail.map((item) => item.msg).filter(Boolean).join("; ");
  return typeof detail === "string" ? detail : "";
}

async function getJson(url, options) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new ApiError("Cannot reach the control plane.", 0);
  }
  // A proxy error page or 5xx may not be JSON; keep the HTTP status as the message.
  const payload = await response.json().catch(() => ({detail: `HTTP ${response.status}`}));
  if (response.status === 401) throw new ApiError("API key required. Add the AEGIS_API_KEY in Settings.", 401);
  if (response.status === 429) {
    const wait = response.headers.get("Retry-After");
    throw new ApiError(wait ? `Too many attempts. Retry in ${wait}s.` : "Rate limit exceeded. Slow down and retry shortly.", 429);
  }
  if (!response.ok) throw new ApiError(errorDetail(payload) || "Request failed", response.status);
  return payload;
}

// A user-initiated write: on 401 ask for the key once and retry with it.
async function post(url, body) {
  try {
    return await getJson(url, postOptions(body));
  } catch (error) {
    if (error.status !== 401) throw error;
    if (!(await askForKey(error.message))) throw error;
    return getJson(url, postOptions(body));
  }
}

// ── Toasts and dialogs ─────────────────────────────────────────────────────────
function toast(message, kind = "ok", timeout = kind === "error" ? 8000 : 4500) {
  const container = $("toasts");
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  if (kind === "error") el.setAttribute("role", "alert");
  el.innerHTML = iconSvg(kind === "ok" ? "check" : "alert");
  const text = document.createElement("p");
  text.textContent = message;
  const close = document.createElement("button");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss notification");
  close.textContent = "×";
  close.addEventListener("click", () => el.remove());
  el.append(text, close);
  container.append(el);
  while (container.children.length > TOAST_LIMIT) container.firstElementChild.remove();
  setTimeout(() => el.remove(), timeout);
}

function openDialog(dialog) {
  dialog.returnValue = "";
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue), {once: true});
    dialog.showModal();
  });
}

// rows: [label, value] pairs shown in the dialog; danger moves the default focus to Cancel.
async function confirmDialog({title, message, rows = [], confirmLabel = "Confirm", variant = "", danger = false}) {
  setText("confirm-title", title);
  const body = $("confirm-body");
  body.replaceChildren();
  if (message) {
    const p = document.createElement("p");
    p.textContent = message;
    body.append(p);
  }
  if (rows.length) {
    const dl = document.createElement("dl");
    for (const [label, value] of rows) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      dl.append(dt, dd);
    }
    body.append(dl);
  }
  const ok = $("confirm-ok");
  ok.textContent = confirmLabel;
  ok.className = `btn ${variant}`.trim();
  const result = openDialog($("confirm-dialog"));
  (danger ? $("confirm-cancel") : ok).focus();
  return (await result) === "confirm";
}

let keyPrompt = null;
function askForKey(message) {
  keyPrompt ??= (async () => {
    if (message) setText("key-body", message);
    const input = $("key-dialog-input");
    input.value = "";
    const result = openDialog($("key-dialog"));
    input.focus();
    const outcome = await result;
    const key = input.value.trim();
    input.value = "";
    if (outcome !== "save" || !key) return false;
    if (!storageSet("aegis-api-key", key)) toast("Could not store the API key in this browser.", "error");
    updateKeyChip();
    syncSettingsForm();
    return true;
  })().finally(() => { keyPrompt = null; });
  return keyPrompt;
}

// ── Reusable states ────────────────────────────────────────────────────────────
const loadingHtml = (rows = 3) => `<div class="skeletons" role="status" aria-label="Loading"><div class="skel tall"></div>${'<div class="skel"></div><div class="skel w60"></div>'.repeat(rows - 1)}</div>`;

function emptyHtml(title, text, icon = "inbox", extra = "") {
  return `<div class="state">${iconSvg(icon)}<h3>${esc(title)}</h3><p>${text}</p>${extra}</div>`;
}

function errorHtml(error) {
  if (error.status === 401) {
    return `<div class="state state-locked">${iconSvg("lock")}<h3>API key required</h3><p>This view is protected. Provide the AEGIS_API_KEY to see it.</p><button type="button" class="btn" data-action="prompt-key">Enter API key</button></div>`;
  }
  return `<div class="state state-error">${iconSvg("alert")}<h3>Could not load this view</h3><p>${esc(error.message)}</p><button type="button" class="btn btn-ghost" data-action="refresh">Try again</button></div>`;
}

// What a container shows when it has no data yet: an error or a loading skeleton.
const pendingHtml = (name, rows) => (state.errors[name] ? errorHtml(state.errors[name]) : loadingHtml(rows));

// ── Metrics ────────────────────────────────────────────────────────────────────
function recordSamples(metrics) {
  for (const metric of metrics) {
    if (metric.value == null) continue;
    const list = state.samples.get(metric.name) ?? [];
    list.push(metric.value);
    if (list.length > SPARK_POINTS) list.shift();
    state.samples.set(metric.name, list);
  }
}

function sparkHtml(values) {
  if (values.length < 2) return `<svg class="spark" viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true"><line x1="0" y1="16" x2="100" y2="16"/></svg>`;
  const low = Math.min(...values);
  const span = Math.max(...values) - low || 1;
  const points = values.map((v, i) => `${((i / (values.length - 1)) * 100).toFixed(1)},${(28 - ((v - low) / span) * 24).toFixed(1)}`).join(" ");
  return `<svg class="spark" viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true"><polyline points="${points}"/></svg>`;
}

function metricHtml(metric, {spark = false} = {}) {
  const meta = METRICS[metric.name] ?? {label: pretty(metric.name), hint: metric.query ?? "", format: fmt, alert: null};
  const known = metric.value != null;
  const scale = meta.alert ? meta.alert * 2 : 1;
  const ratio = known ? Math.min(1, Math.max(0, metric.value / scale)) : 0;
  const tone = known && meta.alert && metric.value > meta.alert ? " is-bad" : known && meta.alert && metric.value > meta.alert * 0.6 ? " is-warn" : "";
  const hint = metric.error ? `Unavailable: ${metric.error}` : meta.hint;
  return `<div class="metric">
    <span class="metric-name">${esc(meta.label)}</span>
    <span class="metric-value${known ? "" : " is-empty"}">${known ? esc(meta.format(metric.value)) : "—"}</span>
    <span class="metric-hint">${esc(hint)}</span>
    ${spark ? `<div class="metric-spark">${sparkHtml(state.samples.get(metric.name) ?? [])}</div>` : `<div class="bar" aria-hidden="true"><i class="bar-fill${tone}" data-pct="${(ratio * 100).toFixed(1)}"></i></div>`}
  </div>`;
}

const metricsListHtml = (metrics, options) => `<div class="metric-list">${metrics.map((m) => metricHtml(m, options)).join("")}</div>`;

// ── Overview ───────────────────────────────────────────────────────────────────
function healthRow(name, ok, detail, status) {
  return `<li class="health-row"><span class="dot ${ok ? "dot-ok" : "dot-bad"}" aria-hidden="true"></span><span>${esc(name)}<small>${esc(detail)}</small></span><span>${esc(status)}</span></li>`;
}

function sloHtml(slo) {
  if (!slo) return "";
  const budget = slo.error_budget_remaining;
  const tone = budget == null ? "" : budget < 0.25 ? " is-bad" : budget < 0.6 ? " is-warn" : "";
  const actual = slo.actual == null ? "no traffic in window" : `${(slo.actual * 100).toFixed(2)}% available`;
  return `<div class="slo"><div class="slo-head"><strong>${esc(slo.name)}</strong><span>target ${(slo.target * 100).toFixed(1)}% · ${esc(slo.window)}</span></div>
    <div class="slo-head"><span>${esc(actual)}</span><span>${budget == null ? "—" : `${(budget * 100).toFixed(0)}% budget left`}</span></div>
    <div class="bar" role="img" aria-label="Error budget remaining"><i class="bar-fill${tone}" data-pct="${budget == null ? 0 : (budget * 100).toFixed(1)}"></i></div></div>`;
}

function incidentRowHtml(incident) {
  return `<a class="incident-row" href="${incidentHref(incident.id)}">
    <span class="row-badges"><span class="badge severity-${esc(incident.severity)}">${esc(incident.severity)}</span><span class="badge status-${esc(incident.status)}">${esc(pretty(incident.status))}</span></span>
    <span class="incident-title">${esc(incident.title)}</span><time datetime="${esc(incident.last_seen)}">${esc(fmtStamp(incident.last_seen))}</time></a>`;
}

function setKpi(id, text, tone = "") {
  setText(id, text);
  setClass(id, `kpi-value ${tone}`.trim());
}

function renderOverview() {
  const o = state.overview;
  if (!o) {
    setHtml("ov-metrics", pendingHtml("overview", 4));
    setHtml("ov-health", pendingHtml("overview", 4));
    setHtml("ov-incidents", pendingHtml("overview", 3));
    return;
  }
  setKpi("kpi-open", String(o.open_incidents), o.open_incidents ? "tone-warn" : "tone-good");
  setKpi("kpi-mttr", o.mttr_seconds == null ? "—" : fmtDuration(o.mttr_seconds));
  setText("kpi-mttr-sub", `${o.resolved_incidents} resolved incident${o.resolved_incidents === 1 ? "" : "s"}`);
  const telemetryUp = Object.values(o.telemetry).filter((t) => t.available).length;
  setKpi("kpi-telemetry", `${telemetryUp}/2`, telemetryUp === 2 ? "tone-good" : "tone-bad");
  const servicesUp = o.services.filter((s) => s.available).length;
  setKpi("kpi-services", `${servicesUp}/2`, servicesUp === 2 ? "tone-good" : "tone-bad");
  const budget = o.slos?.[0]?.error_budget_remaining;
  setKpi("kpi-budget", budget == null ? "—" : `${(budget * 100).toFixed(0)}%`, budget == null ? "" : budget < 0.25 ? "tone-bad" : budget < 0.6 ? "tone-warn" : "tone-good");
  setNavBadge(o.open_incidents);

  setHtml("ov-metrics", state.metrics ? metricsListHtml(state.metrics) : pendingHtml("overview", 4));

  const services = o.services.map((s) => healthRow(s.name, s.available, s.error ?? `HTTP ${s.status_code ?? "—"}`, s.available ? "healthy" : "down"));
  const sources = Object.entries(o.telemetry).map(([name, t]) => healthRow(name, t.available, t.error ?? "reachable", t.available ? "healthy" : "down"));
  const assisted = o.agent_assisted_rate == null ? "" : `<div class="slo-head"><span>Agent-assisted incidents</span><strong>${Math.round(o.agent_assisted_rate * 100)}%</strong></div>`;
  setHtml("ov-health", `<ul class="health-list">${services.join("")}${sources.join("")}</ul>${sloHtml(o.slos?.[0])}${assisted ? `<div class="slo">${assisted}</div>` : ""}`);

  setHtml("ov-incidents", o.incidents.length
    ? `<div class="incident-rows">${o.incidents.slice(0, 6).map(incidentRowHtml).join("")}</div>`
    : emptyHtml("No incidents yet", `Everything is quiet. Inject a fault from the <a href="#/chaos">Chaos lab</a> to see Aegis respond.`, "shield"));
}

async function loadOverview() {
  const [overview, metrics] = await Promise.all([getJson("/api/overview"), getJson("/api/metrics")]);
  state.overview = overview;
  state.metrics = metrics;
  recordSamples(metrics);
  delete state.errors.overview;
}

// ── Incidents ──────────────────────────────────────────────────────────────────
function setNavBadge(count) {
  const badge = $("nav-open");
  setText("nav-open", String(count));
  if (badge.hidden !== (count === 0)) badge.hidden = count === 0;
}

function incidentFilters() {
  return {search: $("inc-search").value.trim().toLowerCase(), status: $("inc-status").value, severity: $("inc-severity").value};
}

function filterIncidents(incidents) {
  const {search, status, severity} = incidentFilters();
  return incidents.filter((i) =>
    (!search || [i.title, i.id, i.root_cause_key].some((field) => field.toLowerCase().includes(search)))
    && (!status || i.status === status)
    && (!severity || i.severity === severity));
}

function incidentItemHtml(incident) {
  const current = state.route.id === incident.id ? ` aria-current="true"` : "";
  return `<li><a class="incident-item" href="${incidentHref(incident.id)}"${current}>
    <span class="row"><span class="badge severity-${esc(incident.severity)}">${esc(incident.severity)}</span><span class="badge status-${esc(incident.status)}">${esc(pretty(incident.status))}</span></span>
    <span class="incident-title">${esc(incident.title)}</span>
    <span class="incident-meta"><span>${esc(incident.id)} · ${esc(incident.root_cause_key)}</span><span>${esc(fmtStamp(incident.last_seen))}</span></span></a></li>`;
}

function renderIncidentList() {
  if (!state.incidents) {
    setHtml("incident-list", pendingHtml("incidents", 4));
    setText("inc-count", state.errors.incidents ? "Unavailable" : "Loading…");
    setDisabled("batch-approve", true);
    return;
  }
  const visible = filterIncidents(state.incidents);
  const total = state.incidentsTotal;
  const filtered = visible.length !== state.incidents.length;
  setText("inc-count", `${visible.length}${filtered ? ` of ${state.incidents.length}` : ""} incident${visible.length === 1 ? "" : "s"}${total > state.incidents.length ? ` (newest ${state.incidents.length} of ${total})` : ""}`);
  const pending = state.incidents.filter((i) => i.status === "recommendation_pending").length;
  setText("batch-approve", pending ? `Approve pending (${pending})` : "Approve pending");
  setDisabled("batch-approve", pending === 0 || state.busy !== null);
  if (visible.length) {
    setHtml("incident-list", `<ul>${visible.map(incidentItemHtml).join("")}</ul>`);
  } else if (state.incidents.length) {
    setHtml("incident-list", emptyHtml("No matches", "No incidents match the current search and filters.", "search"));
  } else {
    setHtml("incident-list", emptyHtml("No incidents yet", `Nothing has fired. Inject a fault from the <a href="#/chaos">Chaos lab</a> to create one.`, "shield"));
  }
}

function actionButton(action, id, label, variant = "") {
  const disabled = state.busy !== null ? " disabled" : "";
  const text = state.busy === `${action}:${id}` ? "Working…" : label;
  return `<button type="button" class="btn ${variant}" data-action="${action}" data-id="${esc(id)}"${disabled}>${text}</button>`;
}

function paramChips(parameters) {
  return Object.entries(parameters ?? {}).map(([k, v]) => `<span class="chip">${esc(k)}=${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span>`).join("");
}

function recommendationHtml(incident) {
  const rec = incident.data?.recommendation;
  if (!rec) return "";
  const approval = incident.data.approval;
  const remediation = incident.data.remediation;
  const done = FINAL_STATUSES.has(incident.status);
  const lines = [];
  if (approval) lines.push(`Approved by <strong>${esc(approval.approver)}</strong> at ${esc(fmtStamp(approval.approved_at))}.`);
  if (remediation) {
    lines.push(`Executed by <strong>${esc(remediation.approver)}</strong> at ${esc(fmtStamp(remediation.at))}.`);
    lines.push(`<pre class="result-pre">${esc(JSON.stringify(remediation.result ?? {}, null, 2).slice(0, 800))}</pre>`);
  }
  return `<section class="rec-card${done ? " is-done" : ""}" aria-label="Recommended remediation">
    <h3>Proposed safe remediation</h3>
    <p><strong>${esc(rec.action)}</strong> on <strong>${esc(rec.target)}</strong>${rec.reason ? ` · ${esc(rec.reason)}` : ""}</p>
    ${Object.keys(rec.parameters ?? {}).length ? `<div class="params">${paramChips(rec.parameters)}</div>` : ""}
    ${lines.map((line) => (line.startsWith("<pre") ? line : `<p>${line}</p>`)).join("")}
  </section>`;
}

function signalHtml(evidence) {
  if (!evidence) return "";
  return `<dl class="signal-box" aria-label="Latest signal">
    <div class="wide"><dt>Latest signal</dt><dd title="${esc(evidence.query)}">${esc(pretty(evidence.rule))}</dd></div>
    <div><dt>Value</dt><dd>${esc(fmt(evidence.value))}</dd></div>
    <div><dt>Threshold</dt><dd>${esc(fmt(evidence.threshold))}</dd></div>
    <div><dt>Z-score</dt><dd>${esc(evidence.z_score == null ? "—" : evidence.z_score.toFixed(1))}</dd></div></dl>`;
}

function evidenceHtml(items) {
  if (!items.length) return emptyHtml("No agent evidence yet", "Evidence appears once the investigation has run.", "search").replace("class=\"state\"", "class=\"state state-compact\"");
  const shown = items.slice(0, EVIDENCE_LIMIT).map((item) => {
    const detail = String(item.detail ?? "");
    const summary = detail.split("\n").find((line) => line.trim()) ?? "";
    return `<details><summary><span class="ev-src">${esc(item.source)} · ${esc(item.label || "observation")}</span><span class="ev-sum">${esc(summary)}</span></summary><pre>${esc(detail)}</pre></details>`;
  });
  const more = items.length - EVIDENCE_LIMIT;
  return `<div class="evidence">${shown.join("")}</div>${more > 0 ? `<p class="timeline-more">${more} more evidence item${more === 1 ? "" : "s"} not shown</p>` : ""}`;
}

function investigationHtml(incident) {
  const investigation = incident.data?.investigation;
  const checks = (investigation?.next_checks ?? []).map((c) => `<li>${esc(c)}</li>`).join("");
  const tools = (investigation?.tools_used ?? []).map((t) => `<span class="chip">${esc(t)}</span>`).join("");
  const pendingText = FINAL_STATUSES.has(incident.status) ? "No investigation was recorded for this incident." : "The agent is still collecting evidence…";
  return `<h3 class="section-title">Agent investigation</h3>
    <p class="hypothesis">${esc(investigation?.hypothesis || pendingText)}</p>
    ${investigation ? `<p class="badges"><span class="badge conf-${esc(investigation.confidence)}">${esc(investigation.confidence)} confidence</span><span class="badge">${esc(pretty(investigation.mode))}</span></p>` : ""}
    ${signalHtml(incident.data?.latest_evidence)}
    ${evidenceHtml(investigation?.evidence ?? [])}
    ${checks ? `<h3 class="section-title chips">Next checks</h3><ul class="checks">${checks}</ul>` : ""}
    ${tools ? `<div class="chips" aria-label="Tools used">${tools}</div>` : ""}
    ${investigation?.fallback_reason ? `<p class="muted chips">Local fallback: ${esc(investigation.fallback_reason)}</p>` : ""}`;
}

function timelineHtml(events) {
  // An open incident logs events continuously; rendering them all makes the page grow on each poll.
  const shown = events.slice(-TIMELINE_LIMIT);
  const hidden = events.length - shown.length;
  return `<h3 class="section-title">Timeline</h3>${hidden ? `<p class="timeline-more">${hidden} earlier events not shown</p>` : ""}
    <ol class="timeline">${shown.map((e) => `<li class="timeline-item kind-${esc(e.kind)}"><small>${esc(fmtStamp(e.at))} · ${esc(e.kind)}</small><p>${esc(e.message)}</p></li>`).join("")}</ol>`;
}

function detailHtml(incident) {
  const pending = incident.status === "recommendation_pending";
  const approved = incident.status === "approved";
  const canInvestigate = !FINAL_STATUSES.has(incident.status) && incident.status !== "executing";
  const buttons = [
    pending ? actionButton("approve", incident.id, "Approve remediation") : "",
    approved ? actionButton("execute", incident.id, "Execute fix", "btn-warn") : "",
    canInvestigate ? actionButton("investigate", incident.id, "Re-investigate", "btn-ghost") : "",
  ].join("");
  return `<div class="detail">
    <a class="back-link" href="#/incidents">${iconSvg("back")}All incidents</a>
    <div class="detail-head">
      <div class="row"><span class="badge severity-${esc(incident.severity)}">${esc(incident.severity)}</span><span class="badge status-${esc(incident.status)}">${esc(pretty(incident.status))}</span><span class="root">${esc(incident.root_cause_key)}</span></div>
      <h2>${esc(incident.title)}</h2>
      <dl class="facts">
        <div><dt>Incident</dt><dd>${esc(incident.id)}</dd></div>
        <div><dt>Detected</dt><dd>${esc(fmtStamp(incident.first_seen))}</dd></div>
        <div><dt>Last signal</dt><dd>${esc(fmtStamp(incident.last_seen))}</dd></div>
        <div><dt>${incident.resolved_at ? "Time to resolve" : "Open for"}</dt><dd>${esc(fmtDuration(incidentDuration(incident)))}</dd></div>
      </dl>
    </div>
    ${buttons ? `<div class="actions">${buttons}</div>` : ""}
    ${recommendationHtml(incident)}
    <div class="columns"><section aria-label="Investigation">${investigationHtml(incident)}</section><section aria-label="Timeline">${timelineHtml(incident.events ?? [])}</section></div>
  </div>`;
}

function renderDetail() {
  const {id, incident, error} = state.detail;
  $("view-incidents").classList.toggle("has-selection", id !== null);
  if (id === null) {
    setHtml("detail", emptyHtml("Select an incident", "The agent's investigation trail and recommendation will appear here.", "incidents"));
  } else if (incident) {
    setHtml("detail", detailHtml(incident));
  } else if (error) {
    const missing = error.status === 404;
    setHtml("detail", `<div class="detail"><a class="back-link" href="#/incidents">${iconSvg("back")}All incidents</a>${missing ? emptyHtml("Incident not found", "It may have been removed. Pick another from the list.", "search") : errorHtml(error)}</div>`);
  } else {
    setHtml("detail", `<div class="detail"><a class="back-link" href="#/incidents">${iconSvg("back")}All incidents</a>${loadingHtml(5)}</div>`);
  }
}

const renderIncidents = () => { renderIncidentList(); renderDetail(); };

async function loadIncidents() {
  const wanted = state.route.id;
  const request = getJson(`/api/incidents?limit=${INCIDENT_LIMIT}`);
  const detail = wanted ? getJson(`/api/incidents/${encodeURIComponent(wanted)}`).then((incident) => ({incident}), (error) => ({error})) : null;
  const list = await request;
  state.incidents = sortIncidents(list.incidents);
  state.incidentsTotal = list.pagination.total;
  delete state.errors.incidents;
  setNavBadge(state.incidents.filter((i) => !FINAL_STATUSES.has(i.status)).length);
  if (detail) {
    const result = await detail;
    if (state.route.id === wanted) state.detail = {id: wanted, incident: result.incident ?? null, error: result.error ?? null};
  }
}

// ── Incident actions ───────────────────────────────────────────────────────────
async function perform(key, work) {
  state.busy = key;
  renderCurrent();
  try {
    await work();
  } catch (error) {
    toast(error.status === 401 ? "Action cancelled: an API key is required." : error.message, error.status === 401 ? "warn" : "error");
  } finally {
    state.busy = null;
    renderCurrent();
    refresh();
  }
}

const currentIncident = (id) => (state.detail.incident?.id === id ? state.detail.incident : null);

async function approveIncident(id) {
  const incident = currentIncident(id);
  const rec = incident?.data?.recommendation;
  const approver = getApprover();
  const confirmed = await confirmDialog({
    title: "Approve this remediation?",
    message: "Approving records your name against the recommended action. Nothing runs until someone executes it.",
    rows: [["Incident", incident?.title ?? id], ["Action", rec ? `${rec.action} on ${rec.target}` : "—"], ["Approver", approver]],
    confirmLabel: "Approve",
  });
  if (!confirmed) return;
  await perform(`approve:${id}`, async () => {
    await post(`/api/incidents/${encodeURIComponent(id)}/approve`, {approver});
    toast("Remediation approved. You can execute it now.");
  });
}

async function executeIncident(id) {
  const incident = currentIncident(id);
  const rec = incident?.data?.recommendation;
  const approver = getApprover();
  const confirmed = await confirmDialog({
    title: "Execute this fix?",
    message: "This calls the service admin API and changes live state. The action was approved and is limited to a known-safe operation.",
    rows: [["Incident", incident?.title ?? id], ["Action", rec ? `${rec.action} on ${rec.target}` : "—"], ["Executed by", approver]],
    confirmLabel: "Execute fix",
    variant: "btn-warn",
    danger: true,
  });
  if (!confirmed) return;
  await perform(`execute:${id}`, async () => {
    const result = await post(`/api/incidents/${encodeURIComponent(id)}/execute`, {approver});
    toast(`Executed ${result.action} on ${result.target}. Aegis will verify recovery.`);
  });
}

async function investigateIncident(id) {
  await perform(`investigate:${id}`, async () => {
    const result = await post(`/api/incidents/${encodeURIComponent(id)}/investigate`);
    toast(`Investigation complete (${result.investigation.confidence} confidence).`);
  });
}

async function batchApprove() {
  const pending = (state.incidents ?? []).filter((i) => i.status === "recommendation_pending").length;
  if (!pending) {
    toast("No incidents are waiting for approval.", "warn");
    return;
  }
  const confirmed = await confirmDialog({
    title: `Approve ${pending} pending incident${pending === 1 ? "" : "s"}?`,
    message: "Every incident with a valid pending recommendation is approved in one step. Execution stays a separate action.",
    rows: [["Approver", getApprover()]],
    confirmLabel: `Approve ${pending}`,
  });
  if (!confirmed) return;
  await perform("batch", async () => {
    const result = await post("/api/incidents/batch/approve", {approver: getApprover()});
    const skipped = pending - result.count;
    toast(`Approved ${result.count} incident${result.count === 1 ? "" : "s"}${skipped > 0 ? `; ${skipped} skipped (changed or failed validation)` : ""}.`, skipped > 0 ? "warn" : "ok");
  });
}

async function exportIncidents(format) {
  try {
    const response = await fetch(`/api/incidents/export?format=${format}`);
    if (!response.ok) throw new ApiError(`Export failed (HTTP ${response.status}).`, response.status);
    const text = format === "json" ? JSON.stringify(await response.json(), null, 2) : await response.text();
    const blob = new Blob([text], {type: format === "json" ? "application/json" : "text/csv"});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aegis-incidents-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    toast(`Exported incidents as ${format.toUpperCase()}.`);
  } catch (error) {
    toast(error instanceof ApiError ? error.message : "Cannot reach the control plane.", "error");
  }
}

// ── Chaos lab ──────────────────────────────────────────────────────────────────
function renderChaos() {
  setDisabled("chaos-submit", state.busy !== null);
  setHtml("chaos-history", state.chaosLog.length
    ? `<ul class="history">${state.chaosLog.map((entry) => `<li><strong>${esc(pretty(entry.fault))} on ${esc(entry.service)}</strong><small>${esc(fmtClock(entry.at))} · ${entry.duration}s · intensity ${entry.intensity} · ${entry.ok ? "injected" : `failed: ${esc(entry.message)}`}</small></li>`).join("")}</ul>`
    : emptyHtml("Nothing injected yet", `Faults you inject appear here. Watch the <a href="#/incidents">incident queue</a> for Aegis to react.`, "chaos"));
}

async function injectFault(event) {
  event.preventDefault();
  const form = new FormData($("chaos-form"));
  const payload = {
    service: form.get("service"),
    fault: form.get("fault"),
    duration_seconds: Number(form.get("duration")),
    intensity: Number(form.get("intensity")),
  };
  if (!(payload.duration_seconds >= 1 && payload.duration_seconds <= 900)) {
    toast("Duration must be between 1 and 900 seconds.", "error");
    $("chaos-duration").focus();
    return;
  }
  if (!(payload.intensity >= 0.1 && payload.intensity <= 10)) {
    toast("Intensity must be between 0.1 and 10.", "error");
    $("chaos-intensity").focus();
    return;
  }
  const confirmed = await confirmDialog({
    title: "Inject this fault?",
    message: "This degrades a running service on purpose. It clears itself when the duration ends.",
    rows: [["Service", payload.service], ["Fault", pretty(payload.fault)], ["Duration", `${payload.duration_seconds}s`], ["Intensity", String(payload.intensity)]],
    confirmLabel: "Inject fault",
    variant: "btn-danger",
    danger: true,
  });
  if (!confirmed) return;
  const entry = {at: new Date().toISOString(), service: payload.service, fault: payload.fault, duration: payload.duration_seconds, intensity: payload.intensity, ok: false, message: ""};
  setText("chaos-hint", "Injecting…");
  await perform("chaos", async () => {
    try {
      await post("/api/chaos", payload);
      entry.ok = true;
      toast("Fault injected. The engine will evaluate within a few seconds.");
      setTimeout(refresh, 1500);
    } catch (error) {
      entry.message = error.message;
      throw error;
    } finally {
      state.chaosLog.unshift(entry);
      state.chaosLog.length = Math.min(state.chaosLog.length, 20);
      setText("chaos-hint", entry.ok ? "Injected." : entry.message);
    }
  });
}

// ── Telemetry ──────────────────────────────────────────────────────────────────
async function fetchReady() {
  let response;
  try {
    response = await fetch("/readyz");
  } catch {
    throw new ApiError("Cannot reach the control plane.", 0);
  }
  // 503 still carries the check results; that is the interesting case.
  const body = await response.json().catch(() => null);
  if (!body?.checks) throw new ApiError(`Readiness check failed (HTTP ${response.status}).`, response.status);
  return body;
}

async function fetchLive() {
  try {
    const response = await fetch("/healthz");
    return response.ok;
  } catch {
    return false;
  }
}

function logUrl() {
  const service = $("log-service").value;
  return `/api/logs?limit=${encodeURIComponent($("log-limit").value)}${service ? `&service=${encodeURIComponent(service)}` : ""}`;
}

function readyRows(ready) {
  return Object.entries(ready.checks).map(([name, value]) => healthRow(name, value === "ok", name === "prometheus" || name === "loki" ? "telemetry backend" : "core component", value));
}

function logRowHtml(entry) {
  const level = String(entry.level ?? "info").toLowerCase();
  const extras = ["route", "status", "duration_ms", "fault", "dependency", "request_id"].filter((k) => entry[k] != null).map((k) => `${k}=${entry[k]}`).join(" ");
  const title = `${entry.ts} ${level} ${entry.service ?? ""} ${entry.message ?? ""} ${extras}`.trim();
  return `<div class="log-row" title="${esc(title)}"><span class="log-time">${esc(fmtClock(entry.ts))}</span><span class="lvl-${esc(level)}">${esc(level)}</span><span class="log-svc">${esc(entry.service ?? "—")}</span><span>${esc(entry.message ?? "")}${extras ? ` <span class="log-meta">${esc(extras)}</span>` : ""}</span></div>`;
}

function renderLogs() {
  if (!state.logs) {
    setHtml("logs", pendingHtml("telemetry", 4));
    return;
  }
  const level = $("log-level").value;
  const search = $("log-search").value.trim().toLowerCase();
  const rows = state.logs.filter((e) => (!level || String(e.level ?? "").toLowerCase() === level) && (!search || JSON.stringify(e).toLowerCase().includes(search)));
  setText("log-count", String(rows.length));
  setHtml("logs", rows.length ? rows.map(logRowHtml).join("") : emptyHtml("No log lines", state.logs.length ? "Nothing matches the current filters." : "No structured logs are available from this control plane yet.", "telemetry"));
}

function renderTelemetry() {
  setHtml("tel-metrics", state.metrics ? metricsListHtml(state.metrics, {spark: true}) : pendingHtml("telemetry", 4));
  setHtml("tel-sources", state.ready ? `<ul class="health-list">${readyRows(state.ready).join("")}</ul>` : pendingHtml("telemetry", 3));
  renderLogs();
}

async function loadTelemetry() {
  const [metrics, ready, logs] = await Promise.all([getJson("/api/metrics"), fetchReady(), getJson(logUrl())]);
  state.metrics = metrics;
  state.ready = ready;
  state.logs = logs;
  recordSamples(metrics);
  delete state.errors.telemetry;
}

// ── Runbooks ───────────────────────────────────────────────────────────────────
function runbookRefs(slug) {
  return (state.incidents ?? []).filter((i) => (i.data?.investigation?.evidence ?? []).some((e) => e.source === "runbook" && e.label === slug));
}

function renderRunbooks() {
  if (!state.runbooks) {
    setHtml("runbooks", pendingHtml("runbooks", 3));
    return;
  }
  setText("rb-count", String(state.runbooks.length));
  if (!state.runbooks.length) {
    setHtml("runbooks", emptyHtml("No runbooks found", "Add Markdown files to the runbook directory and they appear here.", "runbooks"));
    return;
  }
  setHtml("runbooks", `<div class="runbook-grid">${state.runbooks.map((rb) => {
    const refs = runbookRefs(rb.slug);
    const links = refs.slice(0, 3).map((i) => `<li><a href="${incidentHref(i.id)}">${esc(i.title)}</a></li>`).join("");
    return `<article class="runbook"><h3>${esc(rb.title)}</h3><small>runbooks/${esc(rb.slug)}.md</small>
      ${refs.length ? `<small>Cited by ${refs.length} incident${refs.length === 1 ? "" : "s"}</small><ul>${links}</ul>` : "<small>Not cited by any incident yet</small>"}</article>`;
  }).join("")}</div>`);
}

async function loadRunbooks({poll}) {
  // The list is static between deploys; poll cycles only need it once.
  if (poll && state.runbooks) return;
  const [runbooks, list] = await Promise.all([getJson("/api/runbooks"), getJson(`/api/incidents?limit=${INCIDENT_LIMIT}`)]);
  state.runbooks = runbooks;
  state.incidents = sortIncidents(list.incidents);
  state.incidentsTotal = list.pagination.total;
  delete state.errors.runbooks;
}

// ── Audit log ──────────────────────────────────────────────────────────────────
const KNOWN_AUDIT_ACTIONS = ["approve", "batch_approve", "execute", "chaos_inject"];

function syncAuditActions(entries) {
  const select = $("audit-action");
  const known = new Set([...select.options].map((o) => o.value));
  for (const action of [...KNOWN_AUDIT_ACTIONS, ...entries.map((e) => e.action)]) {
    if (known.has(action)) continue;
    known.add(action);
    select.add(new Option(pretty(action), action));
  }
}

function auditRowHtml(entry) {
  const {action, at, incident_id: incidentId, approver, ...rest} = entry;
  const target = incidentId ? `<a href="${incidentHref(incidentId)}">${esc(incidentId)}</a>` : esc(rest.service ?? "—");
  const details = Object.entries(rest).filter(([k]) => k !== "service" || incidentId).map(([k, v]) => `<span class="chip">${esc(k)}=${esc(v)}</span>`).join("");
  return `<tr><td class="nowrap"><time datetime="${esc(at)}">${esc(fmtStamp(at))}</time></td><td><span class="badge">${esc(pretty(action))}</span></td><td>${esc(approver ?? "—")}</td><td>${target}</td><td><span class="kv">${details}</span></td></tr>`;
}

function renderAudit() {
  if (!state.audit) {
    setHtml("audit", pendingHtml("audit", 4));
    return;
  }
  const action = $("audit-action").value;
  const rows = state.audit.entries.filter((e) => !action || e.action === action);
  setText("audit-count", `${state.audit.total}`);
  setHtml("audit", rows.length
    ? `<div class="table-wrap"><table><caption class="sr-only">Audit log, newest first</caption><thead><tr><th scope="col">Time</th><th scope="col">Action</th><th scope="col">Approver</th><th scope="col">Target</th><th scope="col">Details</th></tr></thead><tbody>${rows.map(auditRowHtml).join("")}</tbody></table></div>`
    : emptyHtml("No audit entries", state.audit.entries.length ? "No entries match this action." : "Approvals, executions and fault injections are recorded here once they happen.", "audit"));
}

async function loadAudit() {
  const audit = await getJson(`/api/audit?limit=${encodeURIComponent($("audit-limit").value)}`, {headers: authHeaders()});
  state.audit = audit;
  syncAuditActions(audit.entries);
  delete state.errors.audit;
}

// ── Settings ───────────────────────────────────────────────────────────────────
function syncSettingsForm() {
  const key = $("api-key");
  const approver = $("approver");
  if (document.activeElement !== key) key.value = getApiKey();
  if (document.activeElement !== approver) approver.value = storageGet("aegis-approver");
  approver.placeholder = DEFAULT_APPROVER;
  setText("key-status", getApiKey() ? "A key is stored for this tab." : "No key stored.");
  $("auto-refresh").checked = state.autoRefresh;
}

function renderRunOnce() {
  const result = state.runOnce;
  if (!result) {
    setHtml("run-once-result", "");
    return;
  }
  const items = result.fired.map((i) => `<li><a href="${incidentHref(i.id)}">${esc(i.title)}</a> <span class="badge status-${esc(i.status)}">${esc(pretty(i.status))}</span></li>`).join("");
  setHtml("run-once-result", result.fired.length
    ? `<strong>${result.fired.length} rule${result.fired.length === 1 ? "" : "s"} fired at ${esc(fmtClock(result.at.toISOString()))}</strong><ul class="checks">${items}</ul>`
    : `<strong>No rules fired at ${esc(fmtClock(result.at.toISOString()))}.</strong> Everything is within thresholds.`);
}

function renderSettings() {
  setDisabled("run-once", state.busy !== null);
  renderRunOnce();
  if (!state.ready) {
    setHtml("set-health", pendingHtml("settings", 4));
    return;
  }
  const live = state.live ? healthRow("Liveness", true, "GET /healthz", "ok") : healthRow("Liveness", false, "GET /healthz", "down");
  setHtml("set-health", `<ul class="health-list">${live}${healthRow("Readiness", state.ready.status === "ok", "GET /readyz", state.ready.status)}${readyRows(state.ready).join("")}</ul>`);
}

async function loadSettings() {
  const [ready, live] = await Promise.all([fetchReady(), fetchLive()]);
  state.ready = ready;
  state.live = live;
  delete state.errors.settings;
}

function saveSettings(event) {
  event.preventDefault();
  const approver = $("approver").value.trim() || DEFAULT_APPROVER;
  if (!APPROVER_PATTERN.test(approver)) {
    toast("Approver name must start with a letter or digit and use letters, digits, space and . _ @ + - (2 to 80 characters).", "error");
    $("approver").focus();
    return;
  }
  const stored = storageSet("aegis-api-key", $("api-key").value.trim()) && storageSet("aegis-approver", approver === DEFAULT_APPROVER ? "" : approver);
  updateKeyChip();
  syncSettingsForm();
  if (stored) toast("Settings saved for this tab.");
  else toast("Could not store settings in this browser.", "error");
  refresh();
}

function clearKey() {
  storageSet("aegis-api-key", "");
  $("api-key").value = "";
  updateKeyChip();
  syncSettingsForm();
  toast("API key cleared.");
}

async function runEngineOnce() {
  await perform("run-once", async () => {
    const result = await post("/api/engine/run-once");
    state.runOnce = {at: new Date(), fired: result.fired};
    toast(result.fired.length ? `Engine ran: ${result.fired.length} rule${result.fired.length === 1 ? "" : "s"} fired.` : "Engine ran: no rules fired.");
  });
}

// ── Routing and refresh ────────────────────────────────────────────────────────
const VIEWS = {
  overview: {load: loadOverview, render: renderOverview},
  incidents: {load: loadIncidents, render: renderIncidents},
  chaos: {render: renderChaos},
  telemetry: {load: loadTelemetry, render: renderTelemetry},
  runbooks: {load: loadRunbooks, render: renderRunbooks},
  audit: {load: loadAudit, render: renderAudit},
  settings: {load: loadSettings, render: renderSettings},
};

const renderCurrent = () => VIEWS[state.route.name].render();

function parseRoute() {
  const [name, id] = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (!Object.hasOwn(ROUTES, name)) return {name: "overview", id: null};
  try {
    return {name, id: name === "incidents" && id ? decodeURIComponent(id) : null};
  } catch {
    return {name, id: null};
  }
}

function applyRoute(initial) {
  const previous = state.route;
  const next = parseRoute();
  state.route = next;
  if (next.name !== "incidents" || next.id !== state.detail.id) state.detail = {id: next.name === "incidents" ? next.id : null, incident: null};
  for (const name of Object.keys(ROUTES)) $(`view-${name}`).hidden = name !== next.name;
  for (const link of document.querySelectorAll(".nav a")) {
    if (link.dataset.route === next.name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  setText("page-title", ROUTES[next.name].title);
  setText("page-eyebrow", ROUTES[next.name].eyebrow);
  document.title = `${ROUTES[next.name].title} · Aegis`;
  if (next.name === "settings") syncSettingsForm();
  if (!initial) {
    if (previous.name !== next.name) $("page-title").focus({preventScroll: true});
    if (previous.name !== next.name || (next.id !== previous.id && matchMedia("(max-width: 900px)").matches)) window.scrollTo(0, 0);
  }
  renderCurrent();
  refresh();
}

function setConnection(ok) {
  setText("engine-status", ok ? "engine online" : "disconnected");
  setClass("engine-status", ok ? "pill" : "pill pill-bad");
  const now = new Date().toLocaleTimeString([], {hour12: false});
  setText("last-updated", ok ? `Updated ${now}` : `Failed ${now}`);
  if (state.connected === true && !ok) toast("Lost connection to the control plane.", "error");
  if (state.connected === false && ok) toast("Connection restored.");
  state.connected = ok;
}

let inFlight = null;
let queued = false;

function refresh({poll = false} = {}) {
  if (inFlight) {
    queued = true;
    return inFlight;
  }
  const name = state.route.name;
  inFlight = (async () => {
    try {
      await VIEWS[name].load?.({poll});
      setConnection(true);
    } catch (error) {
      state.errors[name] = error;
      // A 401 or 404 means the server answered; only transport and 5xx failures are an outage.
      setConnection(error.status > 0 && error.status < 500);
    }
    if (state.route.name === name) VIEWS[name].render();
  })().finally(() => {
    inFlight = null;
    if (queued) {
      queued = false;
      refresh();
    }
  });
  return inFlight;
}

// ── Events ─────────────────────────────────────────────────────────────────────
const ACTIONS = {
  refresh: () => refresh(),
  approve: ({id}) => approveIncident(id),
  execute: ({id}) => executeIncident(id),
  investigate: ({id}) => investigateIncident(id),
  "batch-approve": () => batchApprove(),
  export: ({format}) => exportIncidents(format),
  "run-once": () => runEngineOnce(),
  "clear-key": () => clearKey(),
  "prompt-key": async () => {
    if (await askForKey("The control plane requires an API key for this view.")) refresh();
  },
};

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target || target.disabled) return;
  const action = ACTIONS[target.dataset.action];
  if (!action) return;
  event.preventDefault();
  action(target.dataset);
});

$("chaos-form").addEventListener("submit", injectFault);
$("key-form").addEventListener("submit", saveSettings);
$("chaos-intensity").addEventListener("input", (event) => { event.target.dataset.touched = "1"; });
for (const radio of document.querySelectorAll('input[name="fault"]')) {
  radio.addEventListener("change", () => {
    const intensity = $("chaos-intensity");
    if (!intensity.dataset.touched) intensity.value = radio.value === "latency" ? "1.2" : "1";
  });
}
$("key-dialog-input").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  $("key-dialog").close("save");
});

for (const id of ["inc-search", "inc-status", "inc-severity"]) {
  $(id).addEventListener(id === "inc-search" ? "input" : "change", renderIncidentList);
}
for (const id of ["log-search", "log-level"]) $(id).addEventListener(id === "log-search" ? "input" : "change", renderLogs);
$("log-service").addEventListener("change", () => { state.logs = null; renderLogs(); refresh(); });
$("log-limit").addEventListener("change", () => refresh());
$("audit-action").addEventListener("change", renderAudit);
$("audit-limit").addEventListener("change", () => refresh());
$("auto-refresh").addEventListener("change", (event) => {
  state.autoRefresh = event.target.checked;
  storageSet("aegis-auto-refresh", state.autoRefresh ? "" : "off");
  toast(state.autoRefresh ? "Automatic refresh on." : "Automatic refresh paused. Use the refresh button to update.", "ok");
});

window.addEventListener("hashchange", () => applyRoute(false));
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.autoRefresh) refresh();
});

// ── Start ──────────────────────────────────────────────────────────────────────
state.autoRefresh = storageGet("aegis-auto-refresh") !== "off";
syncAuditActions([]);
updateKeyChip();
applyRoute(true);
setInterval(() => {
  if (!document.hidden && state.autoRefresh) refresh({poll: true});
}, POLL_MS);
