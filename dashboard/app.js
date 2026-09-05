const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[char]));
const getJson = async (url) => { const response = await fetch(url); if (!response.ok) throw new Error(`${response.status}`); return response.json(); };

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
  $("#status-cards").innerHTML = [
    ["Events", status.total_events],
    ["Last event", status.last_event_timestamp ? new Date(status.last_event_timestamp * 1000).toLocaleString() : "None"],
    ["Detections", status.total_detections],
    ["Baseline", status.baseline_status.replaceAll("_", " ")],
    ["Collector", status.collector_status],
    ["Data", status.stale_data ? "Stale" : "Current"],
  ].map(([label, value]) => `<div class="status-card"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div></div>`).join("");
  $("#collector-detail").textContent = `${status.collector_detail} Processed: ${status.collector_processed_count}; malformed: ${status.collector_malformed_count}; dropped: ${status.dropped_event_count ?? "unavailable"}${describeEventLoss(status)}${describeKernelLoss(status)}; throughput: ${Number(status.collector_throughput || 0).toFixed(2)}/s${status.collector_error ? ` Error: ${status.collector_error}` : ""}`;
  $("#severity-counts").innerHTML = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((severity) => `<div class="severity-box ${severity}"><strong>${status.severity_counts[severity] || 0}</strong><span>${severity}</span></div>`).join("");
}

function renderTelemetry(status) {
  const labels = { process_exec: "Process execution", system_health: "System health", tcp_network: "TCP / network", file_access: "File access", audit_auth: "Authentication / session", system_service: "System / service", pipes_streams: "Pipes / streams / IPC" };
  $("#telemetry-list").innerHTML = Object.entries(status.sources).map(([key, source]) => `<div class="telemetry-row"><span>${escapeHtml(labels[key] || key)}</span><span class="telemetry-status ${source.status === "verified" ? "verified" : "unverified"}">${escapeHtml(source.status)}</span></div>`).join("");
  $("#health-badge").textContent = "Observed status";
}

function renderFindings(findings) {
  $("#finding-count").textContent = `${findings.length} persisted`;
  $("#findings-body").innerHTML = findings.length ? findings.map((finding) => `<tr data-id="${finding.id}"><td>#${finding.id}</td><td class="severity">${escapeHtml(finding.severity)}</td><td><span class="risk-meter"><i style="width:${Math.round(finding.risk_score * 100)}%"></i></span>${finding.risk_score.toFixed(4)}</td><td>${escapeHtml(finding.entity_type)}:${escapeHtml(finding.entity_key)}</td><td>${new Date(finding.window_end * 1000).toLocaleString()}</td></tr>`).join("") : `<tr><td colspan="5" class="empty-state">No persisted detection findings.</td></tr>`;
  document.querySelectorAll("#findings-body tr[data-id]").forEach((row) => row.addEventListener("click", () => selectFinding(Number(row.dataset.id), row)));
}

async function selectFinding(id, row) {
  document.querySelectorAll("#findings-body tr").forEach((item) => item.classList.remove("selected")); row.classList.add("selected");
  $("#selected-id").textContent = `Finding #${id}`;
  try {
    const [finding, explanation, assistant, policyDecisions] = await Promise.all([getJson(`/api/detections/${id}`), getJson(`/api/explanations/${id}`).catch(() => null), getJson(`/api/assistant/${id}`).catch(() => null), getJson("/api/policy-decisions")]);
    const factors = explanation?.contributing_factors || [];
    $("#detail-content").innerHTML = `<div class="detail-content"><h3>${escapeHtml(explanation?.summary || finding.explanation)}</h3>${factors.map((factor) => `<div class="${factor.label === "FACT" ? "fact" : "interpretation"}"><strong>${escapeHtml(factor.label)} · ${escapeHtml(factor.factor)}</strong><br>${escapeHtml(factor.statement)}</div>`).join("")}<pre>${escapeHtml(JSON.stringify(explanation?.calculation || finding.evidence, null, 2))}</pre><div class="muted">Limitations: ${escapeHtml((explanation?.limitations || []).join(" "))}</div></div>`;
    const assistantResponse = assistant?.response;
    $("#detail-content").innerHTML += assistantResponse ? `<div class="detail-content"><h3>AI analyst</h3><div class="fact"><strong>SUMMARY</strong><br>${escapeHtml(assistantResponse.executive_summary)}</div><div class="interpretation"><strong>RECOMMENDATION</strong><br>${escapeHtml(assistantResponse.recommended_action)}</div><div class="muted">Provider: ${escapeHtml(assistantResponse.provider)} · Fallback: ${assistantResponse.fallback_used ? "Yes" : "No"}</div></div>` : "";
    const policy = policyDecisions.find((item) => item.finding_id === id);
    $("#policy-content").innerHTML = policy ? `<div class="detail-content"><h3>${escapeHtml(policy.decision)}</h3><div>${escapeHtml(policy.reason)}</div><div><strong>Approval:</strong> ${policy.required_approval ? "Required" : "Not required"}</div><div><strong>Dry run:</strong> ${policy.dry_run ? "Yes" : "No"}</div><div class="muted">${escapeHtml(policy.proposed_action)}</div></div>` : `<div class="empty-state">No persisted policy decision for this finding.</div>`;
  } catch (error) { $("#detail-content").textContent = "Unable to load persisted finding detail."; }
}

async function load() {
  try {
    const [status, telemetry, findings] = await Promise.all([getJson("/api/status"), getJson("/api/telemetry/status"), getJson("/api/detections")]);
    renderStatus(status); renderTelemetry(telemetry); renderFindings(findings);
  } catch (error) {
    $("#health-badge").textContent = "API unavailable";
    $("#detail-content").textContent = "The read-only API is unavailable.";
  }
}
load();
