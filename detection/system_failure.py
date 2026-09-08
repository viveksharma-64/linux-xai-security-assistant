"""
System-failure scorer: surface availability-impacting host and service conditions
as first-class findings, without performing any response or remediation.

Design constraints (hard scope boundaries)
-------------------------------------------
* DETECTION ONLY. No termination, restart, process kill, freeze, block, firewall
  change, or any active/destructive action is performed or laid groundwork for.
  Failures surface as findings; all response is left to human operators.
* Missing or partial telemetry is treated as "unknown", never as healthy and
  never as a failure. A null cpu_percent or disk_percent yields no annotation
  and no finding for that dimension; a window with no health events at all
  produces no finding.
* Severity mapping is documented below and configurable via Settings.
* Hysteresis: a condition must breach the threshold in N consecutive windows
  before a finding is emitted; it clears only when it drops below a distinct
  (lower) clear threshold in M consecutive windows. The counters are
  WINDOW-IDEMPOTENT: one 300s window spans many ingestion batches, so a counter
  advances at most once per distinct, strictly increasing window_start. Repeats
  of a window already observed (and windows older than the last one seen) are
  ignored, so "consecutive windows" means wall-clock time, not batch count.
* No ATT&CK mappings are asserted. T1489/T1499 are possible INTERPRETATION
  possibilities only, noted in the explainer. The category is "availability".

Payload schemas consumed (from pipeline/event_stream.py)
---------------------------------------------------------
SYSTEM_HEALTH payload:
    cpu_percent      – float | None   (null in most collector variants)
    mem_percent      – float | None   (populated by all variants)
    disk_percent     – float | None   (populated by telemetry_collector only)
    mem_available_mb – int   | None   (populated by all variants)

SERVICE_STATE payload:
    unit          – str | None
    reporter_unit – str | None
    action        – "started" | "stopped" | "failed" | None
    result        – "success" | "failure" | None

Severity mapping (documented)
------------------------------
HIGH   – disk ≥ failure_disk_full_pct sustained (default 99 %), OR a service
         unit entered the failed state (single failure or crash loop)
MEDIUM – mem_percent ≥ failure_memory_high_pct sustained (default 90 %)
         mem_available_mb ≤ failure_memory_min_available_mb sustained (default 128 MB)
         cpu_percent ≥ failure_cpu_high_pct sustained (default 95 %) when available
LOW    – mem_percent ≥ failure_memory_medium_pct (default 80 %) sustained
"""

import hashlib
import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from observability.config import Settings
from pipeline.event_stream import Event, EventType
from storage.sqlite_store import SQLiteEventStore

# Detector version string written into every failure finding.
FAILURE_DETECTOR_VERSION = "system_failure.v1"

# Fixed tumbling-window width, epoch-aligned. Matches the behaviour analyzer's
# window_seconds (baseline/behavior_analyzer.py) so failure windows line up with
# behaviour windows and a single wall-clock interval maps to one window key.
WINDOW_SECONDS = 300.0


def _window_start_for(ts: float) -> float:
    """Epoch-aligned start of the 300s window containing ``ts``."""
    return float(int(ts // WINDOW_SECONDS) * int(WINDOW_SECONDS))


# ---------------------------------------------------------------------------
# Configurable thresholds (all read from Settings; see observability/config.py)
# ---------------------------------------------------------------------------

def _thresholds(settings: Settings) -> Dict[str, Any]:
    """Return all failure thresholds as a plain dict for evidence embedding."""
    return {
        "failure_memory_high_pct": settings.failure_memory_high_pct,
        "failure_memory_medium_pct": settings.failure_memory_medium_pct,
        "failure_memory_min_available_mb": settings.failure_memory_min_available_mb,
        "failure_cpu_high_pct": settings.failure_cpu_high_pct,
        "failure_disk_full_pct": settings.failure_disk_full_pct,
        "failure_consecutive_windows": settings.failure_consecutive_windows,
        "failure_clear_windows": settings.failure_clear_windows,
        "failure_clear_ratio": settings.failure_clear_ratio,
        "failure_crash_loop_threshold": settings.failure_crash_loop_threshold,
        "failure_crash_loop_window_seconds": settings.failure_crash_loop_window_seconds,
    }


# ---------------------------------------------------------------------------
# Dead-band helpers
# ---------------------------------------------------------------------------
#
# A "dead band" separates the breach threshold from the (lower) clear threshold
# so a value oscillating around a single threshold does not flap between fired
# and cleared. For an upper-bound condition (breach when value is HIGH) the
# clear threshold sits below the breach threshold; for a lower-bound condition
# (breach when value is LOW, e.g. free memory) it sits above. Both take the
# current active state so a fired condition stays fired until the value crosses
# the clear threshold, not merely dips back under the breach threshold.

def _breach_high(active: bool, value: float, threshold: float, clear_ratio: float) -> bool:
    """Upper-bound breach with dead band. clear_thr = threshold * clear_ratio."""
    if active:
        return value >= threshold * clear_ratio
    return value >= threshold


def _breach_low(active: bool, value: float, threshold: float, clear_ratio: float) -> bool:
    """Lower-bound breach with dead band. clear_thr = threshold / clear_ratio."""
    if active:
        # clear_ratio ∈ (0,1] so dividing raises the clear threshold above the
        # breach threshold: free memory must recover past threshold/ratio to clear.
        return value <= threshold / clear_ratio
    return value <= threshold


# ---------------------------------------------------------------------------
# Hysteresis state tracker (in-process; not persisted across restarts)
# ---------------------------------------------------------------------------

class _HysteresisCounter:
    """
    Track consecutive-window counts for both trigger and clear conditions.

    A condition becomes active only after ``in_breach`` has been True in
    ``breach_needed`` consecutive windows, and clears only after it has been
    False in ``clear_needed`` consecutive windows.

    Window-idempotent: ``observe`` takes the window_start it is reporting on and
    advances the counters at most once per distinct, strictly increasing window.
    A repeat of the current window (another batch landing in the same 300s slice)
    or a stale, earlier window is ignored — it returns the current state without
    advancing. This makes "N consecutive windows" mean N wall-clock intervals,
    independent of how many ingestion batches fell inside each one.
    """

    def __init__(self, breach_needed: int, clear_needed: int) -> None:
        self._breach_needed = max(1, breach_needed)
        self._clear_needed = max(1, clear_needed)
        self._breach_count: int = 0
        self._clear_count: int = 0
        self._active: bool = False
        self._last_window: Optional[float] = None

    def observe(self, in_breach: bool, window_start: float) -> Tuple[bool, bool]:
        """
        Record one window observation.

        Returns (now_active, just_cleared):
          now_active   — True when the condition is in force after this window
          just_cleared — True when this window caused the condition to clear
        """
        # Ignore repeats of, or windows earlier than, the last one advanced.
        if self._last_window is not None and window_start <= self._last_window:
            return self._active, False
        self._last_window = window_start

        if in_breach:
            self._breach_count += 1
            self._clear_count = 0
            if not self._active and self._breach_count >= self._breach_needed:
                self._active = True
        else:
            self._clear_count += 1
            self._breach_count = 0
            if self._active and self._clear_count >= self._clear_needed:
                self._active = False
                return False, True
        return self._active, False

    @property
    def active(self) -> bool:
        return self._active

    @property
    def breach_count(self) -> int:
        return self._breach_count


class _HostState:
    """Per-host hysteresis trackers."""

    def __init__(self, breach: int, clear: int) -> None:
        self.mem_high = _HysteresisCounter(breach, clear)
        self.mem_medium = _HysteresisCounter(breach, clear)
        self.mem_available = _HysteresisCounter(breach, clear)
        self.cpu_high = _HysteresisCounter(breach, clear)
        self.disk_full = _HysteresisCounter(breach, clear)


class _ServiceState:
    """Per-unit crash-loop tracking: unit → list of 'failed' event timestamps."""

    def __init__(self) -> None:
        self._failures: Dict[str, List[float]] = defaultdict(list)

    def record_failure(self, unit: str, timestamp: float) -> None:
        self._failures[unit].append(timestamp)

    def failure_count_in_window(self, unit: str, window_seconds: float, now: float) -> int:
        cutoff = now - window_seconds
        self._failures[unit] = [t for t in self._failures[unit] if t >= cutoff]
        return len(self._failures[unit])


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

class SystemFailureScorer:
    """
    Score system_health and service_state events into availability findings.

    This scorer is DETECTION ONLY. It calls store.write_detection_finding()
    for persistence and returns the written findings. It never restarts
    services, kills processes, changes firewall rules, or takes any active
    system action.
    """

    def __init__(self, store: SQLiteEventStore, settings: Optional[Settings] = None) -> None:
        self.store = store
        self._settings: Optional[Settings] = settings
        # Per-host hysteresis state — keyed by host_id (falls back to "unknown")
        self._host_states: Dict[str, _HostState] = {}
        # Per-unit crash-loop tracking
        self._service_state = _ServiceState()

    def _s(self) -> Settings:
        """Lazily load settings so tests can inject them via the constructor."""
        if self._settings is not None:
            return self._settings
        from observability.config import settings as _global
        return _global()

    def _host_state(self, host_id: str) -> _HostState:
        if host_id not in self._host_states:
            s = self._s()
            self._host_states[host_id] = _HostState(
                breach=s.failure_consecutive_windows,
                clear=s.failure_clear_windows,
            )
        return self._host_states[host_id]

    # ------------------------------------------------------------------
    # Provenance hash (same structure as detector.py but failure-specific)
    # ------------------------------------------------------------------

    def _provenance_hash(self, finding: Dict[str, Any]) -> str:
        # The hash pins the identity of a finding for dedup. It intentionally
        # covers only the STABLE identity of the condition — detector, window,
        # entity, and the condition/severity — not the fluctuating observed
        # sample values or breach counts. Two batches landing in the same 300s
        # window with the same breached condition therefore dedup to one row,
        # matching the window-idempotent hysteresis above.
        material = {
            "detector_version": FAILURE_DETECTOR_VERSION,
            "window_start": finding["window_start"],
            "window_end": finding["window_end"],
            "entity_type": finding["entity_type"],
            "entity_key": finding["entity_key"],
            "condition": finding["evidence"][0]["condition"],
            "severity": finding["severity"],
        }
        encoded = json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    # ------------------------------------------------------------------
    # Score helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity(risk_score: float) -> str:
        # disk full or service failed → HIGH (risk 0.85); memory/CPU sustained
        # above the high threshold → MEDIUM (risk 0.65); medium memory → LOW.
        if risk_score >= 0.80:
            return "HIGH"
        if risk_score >= 0.50:
            return "MEDIUM"
        return "LOW"

    def _build_finding(
        self,
        window_start: float,
        window_end: float,
        entity_type: str,
        entity_key: str,
        risk_score: float,
        condition: str,
        detail: str,
        threshold_context: Dict[str, Any],
        consecutive_windows: int,
    ) -> Dict[str, Any]:
        """Construct a failure finding dict ready for write_detection_finding."""
        severity = self._severity(risk_score)
        evidence = [
            {
                "signal": "system_failure",
                "condition": condition,
                "detail": detail,
                "risk_score": round(risk_score, 4),
                "consecutive_windows": consecutive_windows,
                "threshold_context": threshold_context,
            }
        ]
        explanation = (
            f"system_failure={condition}; risk={risk_score:.4f}; "
            f"entity={entity_type}:{entity_key}; "
            f"consecutive_windows={consecutive_windows}"
        )
        finding: Dict[str, Any] = {
            "detector_version": FAILURE_DETECTOR_VERSION,
            "source_risk_id": None,
            "window_start": window_start,
            "window_end": window_end,
            "entity_type": entity_type,
            "entity_key": entity_key,
            "risk_score": round(risk_score, 4),
            "severity": severity,
            "behavior_score": 0.0,
            "rule_score": 0.0,
            "context_score": 0.0,
            "evidence": evidence,
            "explanation": explanation,
            "mode": "system_failure",
            "fusion_formula": "risk_score set directly by system_failure scorer",
            "correlation_id": None,
            "suppressed": False,
            "suppression_reason": None,
        }
        finding["provenance_hash"] = self._provenance_hash(finding)
        return finding

    # ------------------------------------------------------------------
    # Batch entry point: group events into epoch-aligned 300s windows
    # ------------------------------------------------------------------

    def score_batch(
        self,
        events: Sequence[Event],
        persist: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Group SYSTEM_HEALTH and SERVICE_STATE events into epoch-aligned 300s
        windows and score each window in increasing window order.

        This is the pipeline entry point. It mirrors the behaviour analyzer's
        fixed-window model: events are bucketed by ``int(ts // 300) * 300`` and
        each bucket scored once. Because a live batch can straddle a window
        boundary, windows are scored in ascending order so the hysteresis
        counters advance monotonically.
        """
        by_window: Dict[float, List[Event]] = defaultdict(list)
        for event in events:
            if event.event_type not in (EventType.SYSTEM_HEALTH, EventType.SERVICE_STATE):
                continue
            ws = _window_start_for(float(event.timestamp))
            by_window[ws].append(event)

        findings: List[Dict[str, Any]] = []
        for ws in sorted(by_window):
            findings.extend(
                self.score(by_window[ws], ws, ws + WINDOW_SECONDS, persist=persist)
            )
        return findings

    # ------------------------------------------------------------------
    # Score one window of events
    # ------------------------------------------------------------------

    def score(
        self,
        events: Sequence[Event],
        window_start: float,
        window_end: float,
        persist: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Score a single window of events for system failures.

        Events outside [window_start, window_end) are ignored. Only
        SYSTEM_HEALTH and SERVICE_STATE events are considered; all other
        event types are silently skipped.

        Returns a (possibly empty) list of finding dicts. When persist=True,
        each finding is written to the store via write_detection_finding()
        and gets an ``id`` field. When persist=False the findings are
        returned in-memory only.
        """
        s = self._s()

        # Partition by type within this window
        health_events: List[Event] = []
        service_events: List[Event] = []
        for event in events:
            ts = float(event.timestamp)
            if not (window_start <= ts < window_end):
                continue
            if event.event_type == EventType.SYSTEM_HEALTH:
                health_events.append(event)
            elif event.event_type == EventType.SERVICE_STATE:
                service_events.append(event)

        findings: List[Dict[str, Any]] = []
        findings.extend(
            self._score_health(health_events, window_start, window_end, s, persist)
        )
        findings.extend(
            self._score_service(service_events, window_start, window_end, s, persist)
        )
        return findings

    # ------------------------------------------------------------------
    # Health scoring
    # ------------------------------------------------------------------

    def _score_health(
        self,
        events: List[Event],
        window_start: float,
        window_end: float,
        s: Settings,
        persist: bool,
    ) -> List[Dict[str, Any]]:
        if not events:
            return []

        # Group by host_id; fall back to "unknown" if absent
        by_host: Dict[str, List[Event]] = defaultdict(list)
        for event in events:
            host_id = event.host_id or "unknown"
            by_host[host_id].append(event)

        findings: List[Dict[str, Any]] = []
        for host_id, host_events in by_host.items():
            findings.extend(
                self._score_host(host_id, host_events, window_start, window_end, s, persist)
            )
        return findings

    def _score_host(
        self,
        host_id: str,
        events: List[Event],
        window_start: float,
        window_end: float,
        s: Settings,
        persist: bool,
    ) -> List[Dict[str, Any]]:
        # Use the last sample in the window as representative (most recent).
        rep = max(events, key=lambda e: float(e.timestamp))
        payload = rep.payload or {}

        mem_percent = payload.get("mem_percent")       # float | None
        mem_avail = payload.get("mem_available_mb")     # int | None
        cpu_percent = payload.get("cpu_percent")        # float | None (often None)
        disk_percent = payload.get("disk_percent")      # float | None

        state = self._host_state(host_id)
        thresholds = _thresholds(s)
        ratio = s.failure_clear_ratio
        findings: List[Dict[str, Any]] = []

        # --- disk full (HIGH) ---
        # A None reading is "unknown": we do NOT observe the counter, so a gap in
        # disk telemetry neither advances a breach nor counts toward a clear.
        if disk_percent is not None:
            disk_val = float(disk_percent)
            breach = _breach_high(state.disk_full.active, disk_val, s.failure_disk_full_pct, ratio)
            active, _ = state.disk_full.observe(breach, window_start)
            if active:
                findings.append(self._persist_maybe(self._build_finding(
                    window_start, window_end,
                    entity_type="host",
                    entity_key=host_id,
                    risk_score=0.85,
                    condition="disk_full",
                    detail=(
                        f"Disk usage {disk_val:.1f}% >= threshold "
                        f"{s.failure_disk_full_pct:.1f}%"
                    ),
                    threshold_context={**thresholds, "observed_disk_percent": disk_val},
                    consecutive_windows=state.disk_full.breach_count,
                ), persist))

        # --- memory pressure (MEDIUM high / LOW medium) ---
        # Observe BOTH counters every window so the medium counter keeps its
        # consecutive-window history even while high is quiet. Emit the high
        # finding when active, else the medium finding when active — never both.
        if mem_percent is not None:
            mem_pct = float(mem_percent)
            high_breach = _breach_high(
                state.mem_high.active, mem_pct, s.failure_memory_high_pct, ratio
            )
            med_breach = _breach_high(
                state.mem_medium.active, mem_pct, s.failure_memory_medium_pct, ratio
            )
            active_high, _ = state.mem_high.observe(high_breach, window_start)
            active_med, _ = state.mem_medium.observe(med_breach, window_start)
            if active_high:
                findings.append(self._persist_maybe(self._build_finding(
                    window_start, window_end,
                    entity_type="host",
                    entity_key=host_id,
                    risk_score=0.65,
                    condition="memory_pressure_high",
                    detail=(
                        f"mem_percent {mem_pct:.1f}% >= threshold "
                        f"{s.failure_memory_high_pct:.1f}%"
                    ),
                    threshold_context={**thresholds, "observed_mem_percent": mem_pct},
                    consecutive_windows=state.mem_high.breach_count,
                ), persist))
            elif active_med:
                findings.append(self._persist_maybe(self._build_finding(
                    window_start, window_end,
                    entity_type="host",
                    entity_key=host_id,
                    risk_score=0.40,
                    condition="memory_pressure_medium",
                    detail=(
                        f"mem_percent {mem_pct:.1f}% >= threshold "
                        f"{s.failure_memory_medium_pct:.1f}%"
                    ),
                    threshold_context={**thresholds, "observed_mem_percent": mem_pct},
                    consecutive_windows=state.mem_medium.breach_count,
                ), persist))

        # --- memory available floor (MEDIUM) — independent of percent ---
        if mem_avail is not None:
            avail_val = float(mem_avail)
            breach = _breach_low(
                state.mem_available.active, avail_val,
                float(s.failure_memory_min_available_mb), ratio,
            )
            active, _ = state.mem_available.observe(breach, window_start)
            if active:
                findings.append(self._persist_maybe(self._build_finding(
                    window_start, window_end,
                    entity_type="host",
                    entity_key=host_id,
                    risk_score=0.65,
                    condition="memory_available_low",
                    detail=(
                        f"mem_available_mb {int(mem_avail)} MB <= threshold "
                        f"{s.failure_memory_min_available_mb} MB"
                    ),
                    threshold_context={**thresholds, "observed_mem_available_mb": mem_avail},
                    consecutive_windows=state.mem_available.breach_count,
                ), persist))

        # --- CPU pressure (MEDIUM) — only when the field is present ---
        if cpu_percent is not None:
            cpu_pct = float(cpu_percent)
            breach = _breach_high(state.cpu_high.active, cpu_pct, s.failure_cpu_high_pct, ratio)
            active, _ = state.cpu_high.observe(breach, window_start)
            if active:
                findings.append(self._persist_maybe(self._build_finding(
                    window_start, window_end,
                    entity_type="host",
                    entity_key=host_id,
                    risk_score=0.65,
                    condition="cpu_pressure_high",
                    detail=(
                        f"cpu_percent {cpu_pct:.1f}% >= threshold "
                        f"{s.failure_cpu_high_pct:.1f}%"
                    ),
                    threshold_context={**thresholds, "observed_cpu_percent": cpu_pct},
                    consecutive_windows=state.cpu_high.breach_count,
                ), persist))

        return findings

    # ------------------------------------------------------------------
    # Service-state scoring
    # ------------------------------------------------------------------

    def _score_service(
        self,
        events: List[Event],
        window_start: float,
        window_end: float,
        s: Settings,
        persist: bool,
    ) -> List[Dict[str, Any]]:
        # Aggregate to at most one finding per unit per window. A window may
        # carry several 'failed' reports for one unit (repeated restarts); they
        # collapse into a single finding whose crash-loop count reflects the
        # rolling window. The most recent failure timestamp in the window drives
        # the crash-loop lookback.
        failed_ts_by_unit: Dict[str, List[float]] = defaultdict(list)
        last_action_by_unit: Dict[str, Optional[str]] = {}
        last_result_by_unit: Dict[str, Optional[str]] = {}

        for event in events:
            payload = event.payload or {}
            unit = payload.get("unit")
            if not unit:
                continue  # unit name unknown → treat as unknown, skip
            action = payload.get("action")
            result = payload.get("result")
            if action == "failed" or result == "failure":
                failed_ts_by_unit[unit].append(float(event.timestamp))
                last_action_by_unit[unit] = action
                last_result_by_unit[unit] = result

        findings: List[Dict[str, Any]] = []
        for unit in sorted(failed_ts_by_unit):
            timestamps = sorted(failed_ts_by_unit[unit])
            # Record every failure so the rolling crash-loop window spans batches,
            # then evaluate the loop count as of the latest failure in this window.
            for ts in timestamps:
                self._service_state.record_failure(unit, ts)
            latest = timestamps[-1]
            crash_count = self._service_state.failure_count_in_window(
                unit, s.failure_crash_loop_window_seconds, latest
            )
            if crash_count >= s.failure_crash_loop_threshold:
                condition = "service_crash_loop"
                detail = (
                    f"Unit {unit!r} failed {crash_count} times in "
                    f"{s.failure_crash_loop_window_seconds:.0f}s"
                )
            else:
                condition = "service_unit_failed"
                detail = f"Unit {unit!r} entered failed state"

            findings.append(self._persist_maybe(self._build_finding(
                window_start, window_end,
                entity_type="systemd_unit",
                entity_key=unit,
                risk_score=0.85,
                condition=condition,
                detail=detail,
                threshold_context={
                    **_thresholds(s),
                    "observed_action": last_action_by_unit.get(unit),
                    "observed_result": last_result_by_unit.get(unit),
                    "failures_in_this_window": len(timestamps),
                    "failure_count_in_crash_loop_window": crash_count,
                },
                consecutive_windows=1,
            ), persist))

        return findings

    # ------------------------------------------------------------------
    # Persistence helper
    # ------------------------------------------------------------------

    def _persist_maybe(self, finding: Dict[str, Any], persist: bool) -> Dict[str, Any]:
        if persist:
            finding["id"] = self.store.write_detection_finding(finding)
        return finding
