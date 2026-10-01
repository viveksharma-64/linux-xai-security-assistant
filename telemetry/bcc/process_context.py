"""Best-effort userspace process context enrichment for exec events."""

from pathlib import Path
from typing import Any


def _read_identity(pid: int) -> dict[str, Any] | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
        values = {}
        for line in status:
            name, separator, value = line.partition(":")
            if separator:
                values[name] = value.strip()
        uid = int(values["Uid"].split()[0])
        gid = int(values["Gid"].split()[0])
        starttime = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[19]
        return {"comm": values.get("Name"), "uid": uid, "gid": gid, "starttime": starttime}
    except (OSError, UnicodeError, KeyError, IndexError, ValueError):
        return None


def _read_status_value(pid: int, key: str) -> str | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition(":")
            if separator and name == key:
                return value.strip()
    except (OSError, UnicodeError):
        return None
    return None


def _read_ppid(pid: int) -> int | None:
    value = _read_status_value(pid, "PPid")
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _read_comm(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        return value or None
    except (OSError, UnicodeError):
        return None


def read_process_context(
    pid: int,
    max_ancestry: int = 16,
    expected_comm: str | None = None,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    """Read stable parent context; executable must come from authoritative kernel data."""
    if pid <= 0 or max_ancestry <= 0:
        return {"ppid": None, "executable": executable, "parent_comm": None, "ancestry": []}

    identity_before = _read_identity(pid)
    if identity_before is None:
        return {"ppid": None, "executable": executable, "parent_comm": None, "ancestry": []}
    if expected_comm is not None and identity_before["comm"] != expected_comm:
        return {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}
    if expected_uid is not None and identity_before["uid"] != expected_uid:
        return {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}
    if expected_gid is not None and identity_before["gid"] != expected_gid:
        return {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}

    ppid = _read_ppid(pid)
    ancestry: list[dict[str, Any]] = []
    current_pid = ppid
    visited = {pid}
    while current_pid and current_pid not in visited and len(ancestry) < max_ancestry:
        visited.add(current_pid)
        parent_identity = _read_identity(current_pid)
        if parent_identity is None or parent_identity["comm"] is None:
            break
        parent_ppid = _read_ppid(current_pid)
        ancestry.append({
            "pid": current_pid,
            "comm": parent_identity["comm"],
            "ppid": parent_ppid,
        })
        current_pid = parent_ppid

    identity_after = _read_identity(pid)
    if identity_after is None or identity_after["starttime"] != identity_before["starttime"]:
        return {"ppid": None, "executable": None, "parent_comm": None, "ancestry": []}

    parent_identity = _read_identity(ppid) if ppid else None

    return {
        "ppid": ppid,
        "executable": executable,
        "parent_comm": parent_identity["comm"] if parent_identity else None,
        "ancestry": ancestry,
    }
