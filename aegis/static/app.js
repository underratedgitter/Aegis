let selectedIncident = null;
let allIncidents = [];

const $ = (id) => document.getElementById(id);
const fmt = (value) => value == null ? "—" : typeof value === "number" ? value.toFixed(value < 1 ? 3 : 1) : value;

async function getJson(url, options) {
  const response = await fetch(url, options);
  // A proxy error page or 5xx may not be JSON; keep the HTTP status as the message.
  const payload = await response.json().catch(() => ({detail: `HTTP ${response.status}`}));
  if (!response.ok) throw new Error(payload.detail || "Request failed");
  return payload;
}

async function refresh() {
  try {
    const [overview, metrics] = await Promise.all([getJson("/api/overview"), getJson("/api/metrics")]);
    $("engine-status").textContent = "engine online";
    $("engine-status").className = "pill";
    $("last-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    $("open-incidents").textContent = overview.open_incidents;
    $("mttr").textContent = overview.mttr_seconds == null ? "—" : `${overview.mttr_seconds}s`;
    const availableTelemetry = [overview.telemetry.prometheus.available, overview.telemetry.loki.available].filter(Boolean).length;
    $("telemetry").textContent = `${availableTelemetry}/2`;
    $("services").textContent = `${overview.services.filter((s) => s.available).length}/2`;
    const budget = overview.slos?.[0]?.error_budget_remaining;
    $("error-budget").textContent = budget == null ? "—" : `${(budget * 100).toFixed(0)}%`;
    allIncidents = overview.incidents;
    // Re-apply the active search/filters; rendering the raw list wiped them every 5s poll.
    filterIncidents();
    renderMetrics(metrics);
    if (selectedIncident) await showIncident(selectedIncident);
  } catch (error) {
    $("engine-status").textContent = "disconnected";
    $("engine-status").className = "pill muted";
    $("last-updated").textContent = error.message;
  }
}

function renderIncidents(incidents) {
  $("incident-count").textContent = incidents.length;
  if (!incidents.length) {
    $("incident-list").innerHTML = `<div class="empty">No incidents found.<br><span>Try adjusting your filters or inject a fault.</span></div>`;
    return;
  }
  $("incident-list").innerHTML = incidents.map((incident) => `
    <div class="incident-item ${selectedIncident === incident.id ? "selected" : ""}" onclick="showIncident('${incident.id}')">
      <span class="severity severity-${incident.severity}">${incident.severity} · ${escapeHtml(incident.root_cause_key)}</span>
      <h3>${escapeHtml(incident.title)}</h3>
      <p>${incident.status.replaceAll("_", " ")} · ${new Date(incident.last_seen).toLocaleTimeString()}</p>
    </div>
  `).join("");
}

function renderMetrics(metrics) {
  $("metrics").innerHTML = metrics.map((metric) => {
    const value = metric.value == null ? 0 : metric.value;
    const width = Math.min(100, Math.max(4, value * (metric.name.includes("rate") ? 100 : 70)));
    return `<div class="metric-row"><span>${metric.name.replaceAll("_", " ")}</span><span>${fmt(metric.value)}</span><div class="bar"><i style="width:${width}%"></i></div></div>`;
  }).join("");
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
  $("detail-empty").classList.add("hidden");
  $("detail").classList.remove("hidden");
  $("detail-severity").innerHTML = `<span class="severity severity-${incident.severity}">${incident.severity} · ${escapeHtml(incident.root_cause_key)}</span>`;
  $("detail-title").textContent = incident.title;
  $("detail-meta").textContent = `${incident.id} · detected ${new Date(incident.first_seen).toLocaleString()}`;
  $("detail-status").textContent = incident.status.replaceAll("_", " ");
  $("detail-status").className = `status status-${incident.status}`;

  const investigation = incident.data.investigation;
  const recommendation = incident.data.recommendation;

  $("hypothesis").textContent = investigation?.hypothesis || "The agent is still collecting evidence…";
  $("evidence").innerHTML = (investigation?.evidence || []).slice(0, 8).map((item) =>
    `<div class="evidence-item"><span>${escapeHtml(item.source)} · ${escapeHtml(item.label || "observation")}</span>${escapeHtml(item.detail || "")}</div>`
  ).join("") || `<div class="empty">No agent evidence yet.</div>`;

  $("timeline").innerHTML = incident.events.map((event) =>
    `<div class="timeline-item"><small>${new Date(event.at).toLocaleTimeString()} · ${escapeHtml(event.kind)}</small><p>${escapeHtml(event.message)}</p></div>`
  ).join("");

  if (recommendation) {
    const approved = incident.status === "approved";
    $("recommendation-card").innerHTML = `
      <h3>▣ Proposed safe remediation</h3>
      <p><strong>${escapeHtml(recommendation.action)}</strong> on <strong>${escapeHtml(recommendation.target)}</strong> · ${escapeHtml(recommendation.reason || "")}</p>
      <div class="rec-actions">
        ${incident.status === "recommendation_pending" ? `<button onclick="approveIncident('${id}')">Approve</button>` : ""}
        ${approved ? `<button onclick="executeIncident('${id}')">Execute fix</button>` : ""}
        ${incident.status === "open" ? `<button class="secondary" onclick="investigateIncident('${id}')">Re-investigate</button>` : ""}
      </div>`;
  } else {
    $("recommendation-card").innerHTML = "";
  }
}

// Surface API failures (409 conflict, 401 when AEGIS_API_KEY is set, service down)
// instead of dropping them as unhandled promise rejections.
async function runIncidentAction(url, body) {
  try {
    await getJson(url, body === undefined ? {method: "POST"} : {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
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
    const result = await getJson("/api/incidents/batch/approve", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({approver: "demo-operator"}),
    });
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
    await getJson("/api/chaos", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    result.textContent = "Fault injected. Engine will evaluate within a few seconds.";
    setTimeout(refresh, 1500);
  } catch (error) {
    result.textContent = error.message;
  }
};

$("refresh").onclick = refresh;

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
