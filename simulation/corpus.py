"""
Seeded, labeled detection-efficacy corpus.

This is a *read-only attack simulation*: every window is a list of synthetic
canonical ``Event``s built through ``pipeline.event_stream.Event.from_raw_json``,
so they satisfy the exact contract the live pipeline produces. Nothing is
executed on the host, no exploit is run -- the "attack" is entirely in the shape
of the synthesized telemetry, matching the project's observation-only boundary.

Two window kinds, each labeled 0 (benign) or 1 (attack):

  * **benign** (label 0) -- ordinary uid 1000 interactive/developer activity
    over baselined commands, plus a small, deliberately HONEST set of
    privileged-maintenance windows (root running a non-allowlisted admin command)
    that trip the privileged-execution rule. Those are *known false positives*:
    the corpus does not pretend precision is 1.0, and these are exactly the
    windows an operator suppression spec or a threshold revision would address.
  * **attack** (label 1) -- one scenario per window, each documented with the
    MITRE ATT&CK technique it simulates and the detection signal (a specific rule
    and/or a behavioural anomaly) it is designed to trip.

Determinism
-----------
The corpus is fully determined by ``seed``. Window ``i`` occupies
``[CORPUS_EPOCH + i*WINDOW_SECONDS, CORPUS_EPOCH + i*WINDOW_SECONDS +
WINDOW_SECONDS)``. ``CORPUS_EPOCH`` is a multiple of ``WINDOW_SECONDS`` and far
from the baseline timestamps, so a scored window never collides with the
baseline or with its neighbours.

Timing invariant (load-bearing)
--------------------------------
The behavioural scorer's ``burst_ratio`` compares the *scored window's* peak
per-60-second bucket against the baseline's. Benign windows therefore spread
their executions evenly across the full 300 s (distinct seconds, low per-bucket
peak) so they never manufacture a phantom burst. Only the ``execution_burst``
attack concentrates executions into a single second.
"""

from dataclasses import dataclass, field
import random
from typing import Any, Dict, List, Optional

from pipeline.event_stream import Event

# --------------------------------------------------------------------------- #
# Corpus geometry
# --------------------------------------------------------------------------- #

WINDOW_SECONDS = 300
# 3_000_000 / 300 == 10_000 exactly: window bases stay aligned to the analyzer's
# floor(ts / 300) * 300 windowing, and sit ~2M seconds above the baseline base.
CORPUS_EPOCH = 3_000_000
BASELINE_BASE = 1_000_000
DEFAULT_SEED = 1337
DEFAULT_BASELINE_EXECS = 600
DEFAULT_BENIGN_CLEAN_WINDOWS = 48

# Clean benign windows draw only from these commands. Each is present in the
# baseline with a healthy frequency and is run by the baselined uid 1000, so a
# clean window's peak entity score stays below the 0.45 behavioural gate. git and
# sed exist in the baseline for vocabulary breadth but are intentionally not
# exercised in monitored benign windows -- their low baseline frequency would put
# a benign window uncomfortably close to the gate, and the corpus should measure
# a clear separation, not a coin-flip.
_BENIGN_COMMANDS = ("bash", "ls", "cat", "grep", "python3")

# Baseline composition (verified-normal *stand-in*, built only for this harness).
# (comm, uid, gid, ppid, weight); weights sum to 600. uid 1000 is the interactive
# user under one login shell (ppid 1000); uid 0 is the small, normal daemon
# presence (systemd/sshd, both on the rule allowlist) so that "root" is not by
# itself treated as unseen.
_BASELINE_MIX = (
    ("bash", 1000, 1000, 1000, 140),
    ("ls", 1000, 1000, 1000, 120),
    ("cat", 1000, 1000, 1000, 90),
    ("grep", 1000, 1000, 1000, 80),
    ("python3", 1000, 1000, 1000, 80),
    ("git", 1000, 1000, 1000, 40),
    ("sed", 1000, 1000, 1000, 20),
    ("systemd", 0, 0, 1, 20),
    ("sshd", 0, 0, 1, 10),
)


@dataclass
class LabeledWindow:
    """One evaluation unit: a labeled 5-minute window of canonical events."""

    name: str
    label: int  # 1 == attack, 0 == benign
    kind: str  # "attack" | "benign"
    events: List[Event]
    description: str = ""
    # Present only for attack windows: the ATT&CK mapping and the signal the
    # scenario is designed to trip. Purely descriptive -- the harness measures
    # the actual outcome, it never trusts this field.
    attack: Optional[Dict[str, Any]] = field(default=None)


class _Pid:
    """Monotonic pid source so synthesized events have distinct, stable pids."""

    def __init__(self, start: int) -> None:
        self._next = start

    def next(self) -> int:
        value = self._next
        self._next += 1
        return value


def _exec(
    timestamp: float,
    comm: str,
    uid: int,
    *,
    gid: int,
    ppid: int,
    pid: int,
    executable: Optional[str] = None,
) -> Event:
    """
    Build one PROCESS_EXEC ``Event`` through the canonical factory.

    Routing the dict through ``Event.from_raw_json`` (rather than constructing an
    ``Event`` directly) keeps the corpus honest to the real ingestion contract:
    the same field handling that live telemetry gets -- including
    ``executable = executable or filename`` -- applies here too.
    """
    path = executable or f"/usr/bin/{comm}"
    return Event.from_raw_json(
        {
            "event_type": "process_exec",
            "timestamp": float(timestamp),
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "gid": gid,
            "comm": comm,
            "filename": path,
            "executable": path,
        }
    )


def _spread_seconds(count: int) -> List[int]:
    """
    Distinct second-offsets spread evenly across the full window.

    ``int(k * WINDOW_SECONDS / count)`` keeps at most ``ceil(count/5)`` events in
    any 60 s bucket and one event per second, so a benign window's peak stays well
    under the baseline peak (no phantom burst) and never trips the burst rule.
    """
    return [int(k * WINDOW_SECONDS / count) for k in range(count)]


# --------------------------------------------------------------------------- #
# Baseline (throwaway verified-normal stand-in)
# --------------------------------------------------------------------------- #

def build_baseline_events(count: int = DEFAULT_BASELINE_EXECS, seed: int = DEFAULT_SEED) -> List[Event]:
    """
    Synthesize ``count`` normal PROCESS_EXEC events for a *throwaway* baseline.

    This is fed to ``BehaviorAnalyzer.learn_normal(..., verified_normal=True)`` to
    promote an in-memory baseline for the harness. It is emphatically **not** the
    verified-normal ML corpus: it is never written through ``ml/training.py`` and
    never touches the ``ml_datasets`` / ``ml_training_windows`` tables. The
    efficacy test asserts exactly that (contamination guard).

    Events are distributed round-robin across 60 one-minute buckets so the
    baseline's peak-per-bucket is ``count // 60`` (10 at the default 600) -- high
    enough that evenly-spread benign windows never look bursty, low enough that a
    real single-second burst does.
    """
    rng = random.Random(seed ^ 0xB00)
    pid = _Pid(5000)
    total_weight = sum(weight for *_, weight in _BASELINE_MIX)

    population: List[tuple] = []
    for comm, uid, gid, ppid, weight in _BASELINE_MIX:
        scaled = round(weight * count / total_weight)
        population.extend([(comm, uid, gid, ppid)] * scaled)
    # Correct any rounding drift so len(population) == count exactly.
    while len(population) < count:
        population.append(population[-1])
    population = population[:count]
    rng.shuffle(population)

    buckets = 60
    per_bucket = max(1, count // buckets)
    step = max(1, 60 // per_bucket)
    events: List[Event] = []
    for index, (comm, uid, gid, ppid) in enumerate(population):
        bucket = index % buckets
        slot = index // buckets
        second = min(59, slot * step)
        timestamp = BASELINE_BASE + bucket * 60 + second
        events.append(_exec(timestamp, comm, uid, gid=gid, ppid=ppid, pid=pid.next()))
    return events


# --------------------------------------------------------------------------- #
# Benign windows
# --------------------------------------------------------------------------- #

def _benign_clean_window(name: str, base_ts: int, rng: random.Random, pid: _Pid) -> LabeledWindow:
    """A clean uid-1000 activity window over baselined commands (true negative)."""
    count = rng.randint(8, 24)
    seconds = _spread_seconds(count)
    events = []
    for offset, second in zip(range(count), seconds):
        comm = rng.choice(_BENIGN_COMMANDS)
        events.append(
            _exec(base_ts + second, comm, uid=1000, gid=1000, ppid=1000, pid=pid.next())
        )
    return LabeledWindow(
        name=name,
        label=0,
        kind="benign",
        events=events,
        description="ordinary uid 1000 interactive/developer activity over baselined commands",
    )


def _benign_priv_maintenance_window(name: str, base_ts: int, command: str, pid: _Pid) -> LabeledWindow:
    """
    Root maintenance over a non-allowlisted admin command -- a KNOWN false positive.

    Legitimate but privileged: it trips ``privileged_unusual_execution`` and fuses
    to HIGH. Labeled benign on purpose. These windows are the honest cost of a
    conservative privileged-execution rule and the concrete motivation for
    operator suppression (Deliverable 4) and the threshold review (Deliverable 2).
    """
    count = 12
    seconds = _spread_seconds(count)
    events = [
        _exec(base_ts + second, command, uid=0, gid=0, ppid=1, pid=pid.next())
        for second in seconds
    ]
    return LabeledWindow(
        name=name,
        label=0,
        kind="benign",
        events=events,
        description=f"root maintenance running '{command}' (non-allowlisted); known false positive",
    )


# --------------------------------------------------------------------------- #
# Attack windows
# --------------------------------------------------------------------------- #

def _attack_reverse_shell(base_ts: int, pid: _Pid) -> LabeledWindow:
    commands = ("nc", "socat")
    count = 10
    seconds = _spread_seconds(count)
    events = [
        _exec(base_ts + second, commands[i % len(commands)], uid=0, gid=0, ppid=31337, pid=pid.next())
        for i, second in enumerate(seconds)
    ]
    return LabeledWindow(
        name="attack_reverse_shell",
        label=1,
        kind="attack",
        events=events,
        description="root spawns netcat/socat to stage an interactive channel",
        attack={
            "scenario": "reverse_shell",
            "mitre_tactic": "TA0011 Command and Control",
            "mitre_technique": "T1105 Ingress Tool Transfer",
            "expected_signal": (
                "privileged_unusual_execution + suspicious_utility_activity; "
                "unseen root command with privileged context"
            ),
        },
    )


def _attack_dualuse_exfil(base_ts: int, pid: _Pid) -> LabeledWindow:
    commands = ("curl", "wget")
    count = 12
    seconds = _spread_seconds(count)
    events = [
        _exec(base_ts + second, commands[i % len(commands)], uid=1000, gid=1000, ppid=31338, pid=pid.next())
        for i, second in enumerate(seconds)
    ]
    return LabeledWindow(
        name="attack_dualuse_exfil",
        label=1,
        kind="attack",
        events=events,
        description="uid 1000 uses curl/wget as dual-use transfer tools",
        attack={
            "scenario": "dualuse_exfil",
            "mitre_tactic": "TA0011 Command and Control",
            "mitre_technique": "T1105 Ingress Tool Transfer",
            "expected_signal": "suspicious_utility_activity; unseen transfer utility for a normal user",
        },
    )


def _attack_execution_burst(base_ts: int, pid: _Pid) -> LabeledWindow:
    # 60 executions concentrated into a single second: the one window that is
    # SUPPOSED to look bursty (peak/sec and per-bucket peak both spike).
    count = 60
    events = [
        _exec(base_ts + 2, "python3", uid=1000, gid=1000, ppid=31339, pid=pid.next())
        for _ in range(count)
    ]
    return LabeledWindow(
        name="attack_execution_burst",
        label=1,
        kind="attack",
        events=events,
        description="script-driven burst of process creation in a single second",
        attack={
            "scenario": "execution_burst",
            "mitre_tactic": "TA0002 Execution",
            "mitre_technique": "T1059.004 Unix Shell",
            "expected_signal": "execution_burst; high per-second peak over minimum window volume",
        },
    )


def _attack_multi_uid(base_ts: int, pid: _Pid) -> LabeledWindow:
    uids = (1000, 33, 48, 113)  # user + www-data + messagebus + a service acct
    count = 16
    seconds = _spread_seconds(count)
    events = [
        _exec(base_ts + second, "perl", uid=uids[i % len(uids)], gid=uids[i % len(uids)], ppid=31340, pid=pid.next())
        for i, second in enumerate(seconds)
    ]
    return LabeledWindow(
        name="attack_multi_uid",
        label=1,
        kind="attack",
        events=events,
        description="one command executed across several distinct user identities",
        attack={
            "scenario": "multi_uid",
            "mitre_tactic": "TA0005 Defense Evasion",
            "mitre_technique": "T1078 Valid Accounts",
            "expected_signal": "multi_uid_activity; >=3 distinct uids in one window (no root)",
        },
    )


def _attack_privileged_recon(base_ts: int, pid: _Pid) -> LabeledWindow:
    commands = ("unshare", "nsenter", "id", "whoami", "chattr")
    count = 12
    seconds = _spread_seconds(count)
    events = [
        _exec(base_ts + second, commands[i % len(commands)], uid=0, gid=0, ppid=31341, pid=pid.next())
        for i, second in enumerate(seconds)
    ]
    return LabeledWindow(
        name="attack_privileged_recon",
        label=1,
        kind="attack",
        events=events,
        description="root runs unseen recon/namespace utilities",
        attack={
            "scenario": "privileged_recon",
            "mitre_tactic": "TA0002 Execution",
            "mitre_technique": "T1059 Command and Scripting Interpreter",
            "expected_signal": "privileged_unusual_execution; unseen root commands with privileged context",
        },
    )


_ATTACK_BUILDERS = (
    _attack_reverse_shell,
    _attack_dualuse_exfil,
    _attack_execution_burst,
    _attack_multi_uid,
    _attack_privileged_recon,
)

# Non-allowlisted commands used by the honest privileged-maintenance FPs.
_PRIV_MAINTENANCE_COMMANDS = ("apt-get", "dpkg")


def labeled_windows(
    seed: int = DEFAULT_SEED,
    benign_clean: int = DEFAULT_BENIGN_CLEAN_WINDOWS,
) -> List[LabeledWindow]:
    """
    Build the full labeled corpus: attacks, honest FPs, then clean benign windows.

    Window order is irrelevant to measurement (each window is scored in isolation),
    but is fixed for a stable, diffable manifest. Every window base is
    ``CORPUS_EPOCH + i * WINDOW_SECONDS``.
    """
    rng = random.Random(seed)
    pid = _Pid(100_000)
    windows: List[LabeledWindow] = []

    for builder in _ATTACK_BUILDERS:
        base_ts = CORPUS_EPOCH + len(windows) * WINDOW_SECONDS
        windows.append(builder(base_ts, pid))

    for i, command in enumerate(_PRIV_MAINTENANCE_COMMANDS):
        base_ts = CORPUS_EPOCH + len(windows) * WINDOW_SECONDS
        windows.append(
            _benign_priv_maintenance_window(f"benign_priv_maintenance_{i}", base_ts, command, pid)
        )

    for i in range(benign_clean):
        base_ts = CORPUS_EPOCH + len(windows) * WINDOW_SECONDS
        windows.append(_benign_clean_window(f"benign_clean_{i:02d}", base_ts, rng, pid))

    return windows


def manifest(seed: int = DEFAULT_SEED, benign_clean: int = DEFAULT_BENIGN_CLEAN_WINDOWS) -> Dict[str, Any]:
    """A serializable description of the corpus, for the published docs."""
    windows = labeled_windows(seed=seed, benign_clean=benign_clean)
    attacks = [w for w in windows if w.kind == "attack"]
    benign = [w for w in windows if w.kind == "benign"]
    known_fp = [w for w in benign if "known false positive" in w.description]
    return {
        "seed": seed,
        "window_seconds": WINDOW_SECONDS,
        "corpus_epoch": CORPUS_EPOCH,
        "total_windows": len(windows),
        "attack_windows": len(attacks),
        "benign_windows": len(benign),
        "benign_clean_windows": len(benign) - len(known_fp),
        "known_false_positive_windows": len(known_fp),
        "baseline_exec_default": DEFAULT_BASELINE_EXECS,
        "attack_scenarios": [
            {
                "name": w.name,
                "description": w.description,
                "event_count": len(w.events),
                **(w.attack or {}),
            }
            for w in attacks
        ],
        "known_false_positives": [
            {"name": w.name, "description": w.description, "event_count": len(w.events)}
            for w in known_fp
        ],
    }
