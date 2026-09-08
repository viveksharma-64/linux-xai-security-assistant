const $ = (selector) => document.querySelector(selector);

// Safe DOM construction. Every value goes in as textContent or a set attribute,
// never as parsed HTML, so a persisted string (an entity key, an explanation, a
// policy reason) can never become markup. This replaces the old innerHTML +
// escapeHtml string-concatenation paths wholesale: structure is built, not spliced.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

const replaceChildren = (node, ...children) => {
  node.replaceChildren(...children.filter((child) => child !== null && child !== undefined && child !== false));
};

// The API requires a bearer token; the static dashboard does not, because it holds
// no telemetry. The token is kept in sessionStorage rather than localStorage so it
// dies with the tab -- a shared workstation should not leave a working credential
// behind for the next person who opens the browser.
const TOKEN_KEY = "linuxXaiApiToken";
const apiToken = () => sessionStorage.getItem(TOKEN_KEY) || "";

function promptForToken(message) {
  const token = window.prompt(message || "API token:", "");
  if (token) sessionStorage.setItem(TOKEN_KEY, token.trim());
  return token ? token.trim() : "";
}

// Which finding the analyst has opened, remembered across background refreshes so a
// refresh re-applies the row highlight instead of silently dropping it. The detail
// pane itself is never rebuilt by a refresh, so an open investigation stays put.
let selectedFindingId = null;
// Server-side paging/filter/sort state; the dashboard never fetches-all-then-filters.
const pageState = { limit: 25, offset: 0, total: 0 };
// Last integrity verdict rendered, so the live region only announces on a change.
let lastIntegrityOk = null;
// The set of finding ids seen last refresh, to announce genuinely new findings.
let knownFindingIds = new Set();

// interactive is false for background refreshes. A periodic tick that meets a 401 must
// fail quietly rather than raising a token prompt on its own -- otherwise an
// auth-required instance would pop a dialog at the analyst on every interval.
async function apiFetch(url, { interactive = true, method = "GET", body = null } = {}) {
  const send = (token) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== null) headers["Content-Type"] = "application/json";
    return fetch(url, { method, headers, body: body !== null ? JSON.stringify(body) : undefined });
  };
  let response = await send(apiToken());
  if (response.status === 401) {
    if (!interactive) throw new Error("401");
    const token = promptForToken("This API requires a token. Paste it to continue:");
    if (token) response = await send(token);
  }
  return response;
}

const getJson = async (url, interactive = true) => {
  const response = await apiFetch(url, { interactive });
  if (!response.ok) throw new Error(`${response.status}`);
  return response.json();
};

function announce(message) {
  const region = $("#live-region");
  if (region) region.textContent = message;
}

// A dropped-event count on its own cannot tell an analyst whether telemetry is
// being lost right now or was lost once an hour ago -- and a gap in the evidence
// is only interpretable if you know when it happened. Queue occupancy is shown
// alongside so pressure is visible before it becomes loss.
function describeEventLoss(status) {
  const parts = [];
  if (status.last_drop_timestamp) parts.push(`last drop ${new Date(status.last_drop_timestamp * 1000).toLocaleString()}`);
  if (status.collector_backpressure_wait_count) parts.push(`backpressure waits: ${status.collector_backpressure_wait_count}`);
  if (status.collector_queue_capacity) parts.push(`queue ${status.collector_queue_depth ?? 0}/${status.collector_queue_capacity}, peak ${status.collector_queue_high_water_mark ?? 0}`);
  return parts.length ? ` (${parts.join("; ")})` : "";
}

// Kernel-side loss is rendered as its own clause rather than folded into the
// dropped count. A perf ring-buffer overrun means the collector could not drain
// the kernel fast enough; a dropped event means the ingestion consumer could not
// keep up with the collector. Adding them would give one number that points at
// neither cause. Omitted entirely when the column is absent or has never been
// written, because "unknown" must not read as "no loss".
function describeKernelLoss(status) {
  if (status.kernel_lost_event_count === null || status.kernel_lost_event_count === undefined) return "";
  const parts = [];
  if (status.first_kernel_loss_timestamp) parts.push(`first ${new Date(status.first_kernel_loss_timestamp * 1000).toLocaleString()}`);
  if (status.last_kernel_loss_timestamp) parts.push(`last ${new Date(status.last_kernel_loss_timestamp * 1000).toLocaleString()}`);
  return `; kernel-lost: ${status.kernel_lost_event_count}${parts.length ? ` (${parts.join("; ")})` : ""}`;
}

function renderStatus(status) {
  const cards = [
    ["Events", status.total_events],
    ["Last event", status.last_event_timestamp ? new Date(status.last_event_timestamp * 1000).toLocaleString() : "None"],
    ["Detections", status.total_detections],
    ["Baseline", String(status.baseline_status).replaceAll("_", " ")],
    ["Collector", status.collector_status],
    ["Data", status.stale_data ? "Stale" : "Current"],
  ].map(([label, value]) => el("div", { class: "status-card" },
    el("div", { class: "label", text: label }),
    el("div", { class: "value", text: String(value) }),
  ));
  replaceChildren($("#status-cards"), ...cards);

  $("#collector-detail").textContent = `${status.collector_detail} Processed: ${status.collector_processed_count}; malformed: ${status.collector_malformed_count}; dropped: ${status.dropped_event_count ?? "unavailable"}${describeEventLoss(status)}${describeKernelLoss(status)}; throughput: ${Number(status.collector_throughput || 0).toFixed(2)}/s${status.collector_error ? ` Error: ${status.collector_error}` : ""}`;

  const boxes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((severity) => el("div", { class: `severity-box ${severity}` },
    el("strong", { text: String(status.severity_counts[severity] || 0) }),
    el("span", { text: severity }),
  ));
  replaceChildren($("#severity-counts"), ...boxes);
}

const SOURCE_LABELS = {
  process_exec: "Process execution", system_health: "System health", tcp_network: "TCP / network",
  file_access: "File access", audit_auth: "Authentication / session", system_service: "System / service",
  pipes_streams: "Pipes / streams / IPC",
};

function renderTelemetry(status) {
  const rows = Object.entries(status.sources).map(([key, source]) => el("div", { class: "telemetry-row" },
    el("span", { text: SOURCE_LABELS[key] || key }),
    el("span", { class: `telemetry-status ${source.status === "verified" ? "verified" : "unverified"}`, text: source.status }),
  ));
  replaceChildren($("#telemetry-list"), ...rows);
  $("#health-badge").textContent = "Observed status";

  // Honest footer: reflect the sources actually reported as verified right now,
  // rather than a hardcoded "Live verified: ..." list that could drift from reality.
  const verified = Object.entries(status.sources).filter(([, s]) => s.status === "verified").map(([key]) => SOURCE_LABELS[key] || key);
  const footer = $("#source-footer");
  if (verified.length) {
    footer.textContent = `Observed verified sources: ${verified.join(", ")}.`;
  } else {
    footer.textContent = "No telemetry source is currently reporting as verified.";
  }
}

// Compact effective-triage label for the findings table.
function triageLabel(finding) {
  const parts = [];
  if (finding.triage_disposition) parts.push(finding.triage_disposition);
  if (finding.triage_acknowledged) parts.push("ack");
  if (finding.triage_suppressed) parts.push("suppressed");
  return parts.length ? parts.join(" · ") : "untriaged";
}

function findingRow(finding) {
  const meter = el("span", { class: "risk-meter" }, el("i", { style: `width:${Math.round(finding.risk_score * 100)}%` }));
  const row = el("tr", {
    role: "option",
    tabindex: "-1",
    "aria-selected": finding.id === selectedFindingId ? "true" : "false",
    dataset: { id: String(finding.id) },
  },
    el("td", { text: `#${finding.id}` }),
    el("td", { class: "severity", text: finding.severity }),
    el("td", {}, meter, document.createTextNode(finding.risk_score.toFixed(4))),
    el("td", { text: `${finding.entity_type}:${finding.entity_key}` }),
    el("td", { text: new Date(finding.window_end * 1000).toLocaleString() }),
    el("td", { class: "triage-cell", text: triageLabel(finding) }),
  );
  if (finding.id === selectedFindingId) row.classList.add("selected");
  row.addEventListener("click", () => selectFinding(finding.id, { focusDetail: true }));
  return row;
}

function renderFindings(findings) {
  $("#finding-count").textContent = `${pageState.total} match • showing ${findings.length}`;
  const body = $("#findings-body");
  if (findings.length) {
    replaceChildren(body, ...findings.map(findingRow));
    // The first row (or the open one) is the single roving-tabindex entry point.
    const active = body.querySelector('tr[data-id].selected') || body.querySelector("tr[data-id]");
    if (active) active.tabIndex = 0;
  } else {
    replaceChildren(body, el("tr", {}, el("td", { colspan: "6", class: "empty-state", text: "No persisted detection findings match this view." })));
  }

  // Announce genuinely new findings for assistive tech, without stealing focus.
  const currentIds = new Set(findings.map((f) => f.id));
  const fresh = [...currentIds].filter((id) => !knownFindingIds.has(id));
  if (knownFindingIds.size && fresh.length) announce(`${fresh.length} new detection finding(s).`);
  knownFindingIds = currentIds;

  // Pager.
  const shownEnd = pageState.offset + findings.length;
  $("#page-status").textContent = pageState.total
    ? `${pageState.offset + 1}–${shownEnd} of ${pageState.total}`
    : "0 of 0";
  $("#page-prev").disabled = pageState.offset <= 0;
  $("#page-next").disabled = shownEnd >= pageState.total;
}

// --- Keyboard navigation of the findings table (roving tabindex) -------------
function moveActiveRow(delta) {
  const rows = [...document.querySelectorAll("#findings-body tr[data-id]")];
  if (!rows.length) return;
  const currentIndex = rows.findIndex((row) => row.tabIndex === 0);
  const nextIndex = Math.max(0, Math.min(rows.length - 1, (currentIndex < 0 ? 0 : currentIndex) + delta));
  rows.forEach((row) => { row.tabIndex = -1; });
  rows[nextIndex].tabIndex = 0;
  rows[nextIndex].focus();
}

$("#findings-body").addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown") { event.preventDefault(); moveActiveRow(1); }
  else if (event.key === "ArrowUp") { event.preventDefault(); moveActiveRow(-1); }
  else if (event.key === "Enter" || event.key === " ") {
    const active = document.activeElement;
    if (active && active.dataset && active.dataset.id) {
      event.preventDefault();
      selectFinding(Number(active.dataset.id), { focusDetail: true });
    }
  }
});

// --- Triage controls ---------------------------------------------------------
function triageButton(label, handler) {
  return el("button", { type: "button", class: "triage-btn", onclick: handler }, label);
}

async function postTriage(id, action, body) {
  const response = await apiFetch(`/api/triage/${id}/${action}`, { method: "POST", body });
  if (!response.ok) {
    let detail = `${response.status}`;
    try { const data = await response.json(); if (data.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail); } catch (_) {}
    throw new Error(detail);
  }
  return response.json();
}

function renderTriageControls(id, state) {
  const controls = $("#triage-controls");
  const status = el("div", { class: "triage-status" },
    el("span", { text: `Disposition: ${state?.disposition || "none"}` }),
    el("span", { text: `Acknowledged: ${state?.acknowledged ? "yes" : "no"}` }),
    el("span", { text: `Suppressed (effective): ${state?.effective_suppressed ? "yes" : "no"}` }),
    el("span", { class: "muted", text: `Config suppressed: ${state?.config_suppressed ? "yes" : "no"} · annotations: ${state?.annotation_count ?? 0}` }),
  );

  const run = (action, bodyBuilder) => async () => {
    try {
      const body = bodyBuilder ? bodyBuilder() : {};
      if (body === null) return; // analyst cancelled a prompt
      await postTriage(id, action, body);
      announce(`Recorded ${action} on finding #${id}.`);
      // Re-fetch the opened finding + its triage, and refresh the list so the
      // triage column and effective state update in place -- no page reload.
      await selectFinding(id, { focusDetail: false });
      await load(false);
    } catch (error) {
      announce(`Triage ${action} failed: ${error.message}`);
      window.alert(`Triage ${action} failed: ${error.message}`);
    }
  };

  const actions = el("div", { class: "triage-actions" },
    triageButton("Acknowledge", run("acknowledge", () => ({}))),
    triageButton("Annotate", run("annotate", () => {
      const note = window.prompt("Annotation note:", "");
      return note && note.trim() ? { note: note.trim() } : null;
    })),
    triageButton("True positive", run("disposition", () => ({ disposition: "true-positive" }))),
    triageButton("False positive", run("disposition", () => ({ disposition: "false-positive" }))),
    triageButton("Benign", run("disposition", () => ({ disposition: "benign" }))),
    state?.effective_suppressed
      ? triageButton("Unsuppress", run("unsuppress", () => {
          const reason = window.prompt("Reason to unsuppress:", "");
          return reason && reason.trim() ? { reason: reason.trim() } : null;
        }))
      : triageButton("Suppress", run("suppress", () => {
          const reason = window.prompt("Reason to suppress (finding is never removed from the record):", "");
          return reason && reason.trim() ? { reason: reason.trim() } : null;
        })),
  );

  const note = el("p", { class: "triage-note muted", text: "Triage is append-only. Suppress is a presentation annotation; it never removes a finding from the record or the export." });
  replaceChildren(controls, status, actions, note);
  controls.hidden = false;
}

// --- Detail pane -------------------------------------------------------------
async function selectFinding(id, { focusDetail = true } = {}) {
  selectedFindingId = id;
  document.querySelectorAll("#findings-body tr[data-id]").forEach((row) => {
    const isSelected = Number(row.dataset.id) === id;
    row.classList.toggle("selected", isSelected);
    row.setAttribute("aria-selected", isSelected ? "true" : "false");
  });
  $("#selected-id").textContent = `Finding #${id}`;
  const detail = $("#detail-content");
  try {
    const [finding, explanation, assistant, policyDecisions, triage] = await Promise.all([
      getJson(`/api/detections/${id}`),
      getJson(`/api/explanations/${id}`).catch(() => null),
      getJson(`/api/assistant/${id}`).catch(() => null),
      getJson("/api/policy-decisions"),
      getJson(`/api/triage/${id}`).catch(() => null),
    ]);

    renderTriageControls(id, triage?.state);

    const factors = explanation?.contributing_factors || [];
    const blocks = [
      el("div", { class: "detail-content" },
        el("h3", { text: explanation?.summary || finding.explanation }),
        ...factors.map((factor) => el("div", { class: factor.label === "FACT" ? "fact" : "interpretation" },
          el("strong", { text: `${factor.label} · ${factor.factor}` }),
          el("br"),
          document.createTextNode(factor.statement),
        )),
        el("pre", { text: JSON.stringify(explanation?.calculation || finding.evidence, null, 2) }),
        el("div", { class: "muted", text: `Limitations: ${(explanation?.limitations || []).join(" ")}` }),
      ),
    ];

    const assistantResponse = assistant?.response;
    if (assistantResponse) {
      blocks.push(el("div", { class: "detail-content" },
        el("h3", { text: "AI analyst" }),
        el("div", { class: "fact" }, el("strong", { text: "SUMMARY" }), el("br"), document.createTextNode(assistantResponse.executive_summary)),
        el("div", { class: "interpretation" }, el("strong", { text: "RECOMMENDATION" }), el("br"), document.createTextNode(assistantResponse.recommended_action)),
        el("div", { class: "muted", text: `Provider: ${assistantResponse.provider} · Fallback: ${assistantResponse.fallback_used ? "Yes" : "No"}` }),
      ));
    }
    replaceChildren(detail, ...blocks);

    const policy = policyDecisions.find((item) => item.finding_id === id);
    if (policy) {
      replaceChildren($("#policy-content"), el("div", { class: "detail-content" },
        el("h3", { text: policy.decision }),
        el("div", { text: policy.reason }),
        el("div", {}, el("strong", { text: "Approval: " }), document.createTextNode(policy.required_approval ? "Required" : "Not required")),
        el("div", {}, el("strong", { text: "Dry run: " }), document.createTextNode(policy.dry_run ? "Yes" : "No")),
        el("div", { class: "muted", text: policy.proposed_action }),
      ));
    } else {
      replaceChildren($("#policy-content"), el("div", { class: "empty-state", text: "No persisted policy decision for this finding." }));
    }

    // Opening a finding is an explicit analyst action, so it is allowed to move
    // focus to the detail pane. A background refresh passes focusDetail=false and
    // never moves focus.
    if (focusDetail) $("#detail-panel").focus();
  } catch (error) {
    detail.textContent = "Unable to load persisted finding detail.";
  }
}

// --- Integrity alarm ---------------------------------------------------------
function renderIntegrity(integrity) {
  const banner = $("#integrity-banner");
  const chains = ["findings", "policy", "triage"];
  const broken = chains.filter((name) => integrity[name] && integrity[name].ok === false);
  if (!broken.length) {
    banner.hidden = true;
    replaceChildren(banner);
    if (lastIntegrityOk === false) announce("Evidence integrity restored: all chains verify.");
    lastIntegrityOk = true;
    return;
  }
  const details = broken.map((name) => {
    const verdict = integrity[name];
    return el("li", { text: `${name} chain broken at seq ${verdict.break_seq ?? "?"}: ${verdict.reason || "verification failed"}` });
  });
  replaceChildren(banner,
    el("strong", { text: "⚠ EVIDENCE INTEGRITY ALARM" }),
    el("ul", {}, ...details),
    el("div", { class: "muted", text: "A chain failed to verify. The record may have been tampered with, reordered, or truncated. Investigate before trusting these findings." }),
  );
  banner.hidden = false;
  if (lastIntegrityOk !== false) announce("Evidence integrity alarm: a hash chain failed to verify.");
  lastIntegrityOk = false;
}

// --- Last-updated / stale badge ---------------------------------------------
function markUpdated() {
  const now = new Date();
  const badge = $("#last-updated");
  badge.classList.remove("stale");
  badge.textContent = `Updated ${now.toLocaleTimeString()}`;
  badge.title = now.toLocaleString();
}

function markStale() {
  const badge = $("#last-updated");
  badge.classList.add("stale");
  badge.textContent = "Disconnected — showing last known data";
}

// --- Load --------------------------------------------------------------------
function detectionsQuery() {
  const params = new URLSearchParams();
  params.set("limit", String(pageState.limit));
  params.set("offset", String(pageState.offset));
  const severity = $("#filter-severity").value;
  const disposition = $("#filter-disposition").value;
  params.set("sort", $("#sort-field").value);
  params.set("order", $("#sort-order").value);
  if (severity) params.set("severity", severity);
  if (disposition) params.set("disposition", disposition);
  return `/api/detections?${params.toString()}`;
}

async function loadFindings(interactive) {
  const response = await apiFetch(detectionsQuery(), { interactive });
  if (!response.ok) throw new Error(`${response.status}`);
  pageState.total = Number(response.headers.get("X-Total-Count") || 0);
  const findings = await response.json();
  renderFindings(findings);
}

async function load(interactive = true) {
  try {
    const [status, telemetry, integrity] = await Promise.all([
      getJson("/api/status", interactive),
      getJson("/api/telemetry/status", interactive),
      getJson("/api/integrity", interactive),
    ]);
    renderStatus(status);
    renderTelemetry(telemetry);
    renderIntegrity(integrity);
    await loadFindings(interactive);
    markUpdated();
  } catch (error) {
    $("#health-badge").textContent = "API unavailable";
    markStale();
    // Only claim the detail pane on the first, interactive load; a transient failure
    // during a background refresh must not wipe an open investigation.
    if (interactive) $("#detail-content").textContent = "The read-only API is unavailable.";
  }
}

// Filter/sort changes reset to the first page and reload server-side.
["#filter-severity", "#filter-disposition", "#sort-field", "#sort-order"].forEach((selector) => {
  $(selector).addEventListener("change", () => { pageState.offset = 0; load(true); });
});
$("#page-prev").addEventListener("click", () => { pageState.offset = Math.max(0, pageState.offset - pageState.limit); load(true); });
$("#page-next").addEventListener("click", () => { pageState.offset = pageState.offset + pageState.limit; load(true); });

// The API re-queries SQLite on every request, so re-running load() surfaces the rows
// the collector has persisted since the last tick -- the dashboard tails the evidence
// record without a manual reload. Background ticks are non-interactive (never prompt)
// and are paused while the tab is hidden, so a backgrounded dashboard issues no
// requests; returning to the tab refreshes immediately.
const REFRESH_INTERVAL_MS = 10000;
load();
setInterval(() => { if (document.visibilityState === "visible") load(false); }, REFRESH_INTERVAL_MS);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") load(false); });
