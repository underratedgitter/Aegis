let selectedIncident = null;
let allIncidents = [];
const TIMELINE_LIMIT = 20;

const $ = (id) => document.getElementById(id);

// The page re-renders on every 5 s poll. Replacing unchanged markup makes it flash and drops
// hover, focus, selection and scroll position, so write only what actually changed.
const renderedHtml = new WeakMap();

function syncAttributes(current, wanted) {
  for (const {name} of [...current.attributes]) if (!wanted.hasAttribute(name)) current.removeAttribute(name);
  for (const {name, value} of wanted.attributes) if (current.getAttribute(name) !== value) current.setAttribute(name, value);
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

function setHtml(id, html) {
  const el = $(id);
  if (renderedHtml.get(el) === html) return;
  const template = document.createElement("template");
  template.innerHTML = html;
  patchChildren(el, template.content);
  renderedHtml.set(el, html);
}

// Writing identical text or classes still queues DOM mutations; skip them.
function setText(id, text) {
  const el = $(id);
  if (el.textContent === text) return;
  // Update the existing text node in place instead of replacing it.
  if (el.firstChild?.nodeType === Node.TEXT_NODE && !el.firstChild.nextSibling) el.firstChild.data = text;
  else el.textContent = text;
}

function setClass(id, className) {
  const el = $(id);
  if (el.className !== className) el.className = className;
}

function setHidden(id, hidden) {
  const el = $(id);
  if (el.classList.contains("hidden") !== hidden) el.classList.toggle("hidden", hidden);
}
const fmt = (value) => value == null ? "—" : typeof value === "number" ? value.toFixed(value < 1 ? 3 : 1) : value;

// The key lives only in sessionStorage; storage can be blocked, so never let it throw.
function getApiKey() {
  try {
    return sessionStorage.getItem("aegis-api-key") || "";
  } catch {
    return "";
  }
}

function saveApiKey() {
  const key = $("api-key").value.trim();
  try {
    if (key) sessionStorage.setItem("aegis-api-key", key);
    else sessionStorage.removeItem("aegis-api-key");
  } catch {
    $("chaos-result").textContent = "Could not store the API key in this browser.";
  }
}

// Options for a state-changing POST; sends the bearer key when one is set.
function postOptions(body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const key = getApiKey();
  if (key) headers.Authorization = `Bearer ${key}`;
  return {method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body)};
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) throw new Error("API key required: enter the AEGIS_API_KEY in the API key box above and retry.");
  // A proxy error page or 5xx may not be JSON; keep the HTTP status as the message.
  const payload = await response.json().catch(() => ({detail: `HTTP ${response.status}`}));
  if (!response.ok) throw new Error(payload.detail || "Request failed");
  return payload;
}

async function refresh() {
  try {
    const [overview, metrics] = await Promise.all([getJson("/api/overview"), getJson("/api/metrics")]);
    setText("engine-status", "engine online");
    setClass("engine-status", "pill");
    setText("last-updated", `Updated ${new Date().toLocaleTimeString()}`);
    setText("open-incidents", String(overview.open_incidents));
    setText("mttr", overview.mttr_seconds == null ? "—" : `${overview.mttr_seconds}s`);
    const availableTelemetry = [overview.telemetry.prometheus.available, overview.telemetry.loki.available].filter(Boolean).length;
    setText("telemetry", `${availableTelemetry}/2`);
    setText("services", `${overview.services.filter((s) => s.available).length}/2`);
    const budget = overview.slos?.[0]?.error_budget_remaining;
    setText("error-budget", budget == null ? "—" : `${(budget * 100).toFixed(0)}%`);
    allIncidents = overview.incidents;
    // Re-apply the active search/filters; rendering the raw list wiped them every 5s poll.
    filterIncidents();
    renderMetrics(metrics);
    if (selectedIncident) await showIncident(selectedIncident);
  } catch (error) {
    setText("engine-status", "disconnected");
    setClass("engine-status", "pill muted");
    setText("last-updated", error.message);
  }
}

function renderIncidents(incidents) {
  setText("incident-count", String(incidents.length));
  if (!incidents.length) {
    setHtml("incident-list", `<div class="empty">No incidents found.<br><span>Try adjusting your filters or inject a fault.</span></div>`);
    return;
  }
  setHtml("incident-list", incidents.map((incident) => `
    <div class="incident-item ${selectedIncident === incident.id ? "selected" : ""}" onclick="showIncident('${incident.id}')">
      <span class="severity severity-${incident.severity}">${incident.severity} · ${escapeHtml(incident.root_cause_key)}</span>
      <h3>${escapeHtml(incident.title)}</h3>
      <p>${incident.status.replaceAll("_", " ")} · ${new Date(incident.last_seen).toLocaleTimeString()}</p>
    </div>
  `).join(""));
}

function renderMetrics(metrics) {
  setHtml("metrics", metrics.map((metric) => {
    const value = metric.value == null ? 0 : metric.value;
    const width = Math.min(100, Math.max(4, value * (metric.name.includes("rate") ? 100 : 70)));
    return `<div class="metric-row"><span>${metric.name.replaceAll("_", " ")}</span><span>${fmt(metric.value)}</span><div class="bar"><i style="width:${width}%"></i></div></div>`;
  }).join(""));
}

function filterIncidents() {
  const search = $("incident-search").value.toLowerCase();
  const status = $("incident-status-filter").value;
  const severity = $("incident-severity-filter").value;

  let filtered = allIncidents;
  if (search) {
    filtered = filtered.filter(i =>
      i.title.toLowerCase().includes(search) ||
      i.root_cause_key.toLowerCase().includes(search) ||
      i.id.toLowerCase().includes(search)
    );
  }
  if (status) filtered = filtered.filter(i => i.status === status);
  if (severity) filtered = filtered.filter(i => i.severity === severity);

  renderIncidents(filtered);
}

async function showIncident(id) {
  selectedIncident = id;
  const incident = await getJson(`/api/incidents/${id}`);
  setHidden("detail-empty", true);
  setHidden("detail", false);
  setHtml("detail-severity", `<span class="severity severity-${incident.severity}">${incident.severity} · ${escapeHtml(incident.root_cause_key)}</span>`);
  setText("detail-title", incident.title);
  setText("detail-meta", `${incident.id} · detected ${new Date(incident.first_seen).toLocaleString()}`);
  setText("detail-status", incident.status.replaceAll("_", " "));
  setClass("detail-status", `status status-${incident.status}`);

  const investigation = incident.data.investigation;
  const recommendation = incident.data.recommendation;

  setText("hypothesis", investigation?.hypothesis || "The agent is still collecting evidence…");
  setHtml("evidence", (investigation?.evidence || []).slice(0, 8).map((item) =>
    `<div class="evidence-item"><span>${escapeHtml(item.source)} · ${escapeHtml(item.label || "observation")}</span>${escapeHtml(item.detail || "")}</div>`
  ).join("") || `<div class="empty">No agent evidence yet.</div>`);

  // An open incident logs events every cycle; rendering them all makes the page grow on each poll.
  const events = incident.events.slice(-TIMELINE_LIMIT);
  const hidden = incident.events.length - events.length;
  setHtml("timeline", (hidden ? `<div class="timeline-more">${hidden} earlier events not shown</div>` : "") + events.map((event) =>
    `<div class="timeline-item"><small>${new Date(event.at).toLocaleTimeString()} · ${escapeHtml(event.kind)}</small><p>${escapeHtml(event.message)}</p></div>`
  ).join(""));

  if (recommendation) {
    const approved = incident.status === "approved";
    setHtml("recommendation-card", `
      <h3>▣ Proposed safe remediation</h3>
      <p><strong>${escapeHtml(recommendation.action)}</strong> on <strong>${escapeHtml(recommendation.target)}</strong> · ${escapeHtml(recommendation.reason || "")}</p>
      <div class="rec-actions">
        ${incident.status === "recommendation_pending" ? `<button onclick="approveIncident('${id}')">Approve</button>` : ""}
        ${approved ? `<button onclick="executeIncident('${id}')">Execute fix</button>` : ""}
        ${incident.status === "open" ? `<button class="secondary" onclick="investigateIncident('${id}')">Re-investigate</button>` : ""}
      </div>`);
  } else {
    setHtml("recommendation-card", "");
  }
}

// Surface API failures (409 conflict, 401 when AEGIS_API_KEY is set, service down)
// instead of dropping them as unhandled promise rejections.
async function runIncidentAction(url, body) {
  try {
    await getJson(url, postOptions(body));
  } catch (error) {
    $("chaos-result").textContent = error.message;
  }
  await refresh();
}

async function investigateIncident(id) {
  await runIncidentAction(`/api/incidents/${id}/investigate`);
}

async function approveIncident(id) {
  await runIncidentAction(`/api/incidents/${id}/approve`, {approver: "demo-operator"});
}

async function executeIncident(id) {
  await runIncidentAction(`/api/incidents/${id}/execute`, {approver: "demo-operator"});
}

async function batchApprove() {
  try {
    const result = await getJson("/api/incidents/batch/approve", postOptions({approver: "demo-operator"}));
    $("chaos-result").textContent = `Approved ${result.count} incident(s).`;
    await refresh();
  } catch (error) {
    $("chaos-result").textContent = error.message;
  }
}

function exportIncidents(format) {
  window.open(`/api/incidents/export?format=${format}`, "_blank");
}

$("inject").onclick = async () => {
  const result = $("chaos-result");
  result.textContent = "Injecting…";
  try {
    const payload = {
      service: $("chaos-service").value,
      fault: $("chaos-fault").value,
      duration_seconds: Number($("chaos-duration").value),
      intensity: $("chaos-fault").value === "latency" ? 1.2 : 1,
    };
    await getJson("/api/chaos", postOptions(payload));
    result.textContent = "Fault injected. Engine will evaluate within a few seconds.";
    setTimeout(refresh, 1500);
  } catch (error) {
    result.textContent = error.message;
  }
};

$("refresh").onclick = refresh;

$("api-key").value = getApiKey();
$("api-key").addEventListener("change", saveApiKey);

// Filter event listeners
$("incident-search")?.addEventListener("input", filterIncidents);
$("incident-status-filter")?.addEventListener("change", filterIncidents);
$("incident-severity-filter")?.addEventListener("change", filterIncidents);

setInterval(refresh, 5000);
refresh();

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  }[char]));
}
