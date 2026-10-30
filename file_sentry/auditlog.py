"""A tamper-evident audit log: every entry chains to the one before it, so editing or deleting a past
entry (to hide what really changed) breaks the chain and `verify_log` catches it. This is the same idea
as a blockchain's hash-linking, applied to a plain append-only log file instead.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass
class LogEntry:
    seq: int
    timestamp: str
    event_type: str
    data: dict[str, Any]
    prev_hash: str
    entry_hash: str


def _entry_hash(seq: int, timestamp: str, event_type: str, data: dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps(
        {"seq": seq, "timestamp": timestamp, "event_type": event_type, "data": data, "prev_hash": prev_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _last_entry(log_path: Path) -> LogEntry | None:
    if not log_path.exists():
        return None
    last_line = None
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return None
    raw = json.loads(last_line)
    return LogEntry(**raw)


def append_event(log_path: Path, event_type: str, data: dict[str, Any]) -> LogEntry:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_entry(log_path)
    seq = (prev.seq + 1) if prev else 0
    prev_hash = prev.entry_hash if prev else GENESIS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    entry_hash = _entry_hash(seq, timestamp, event_type, data, prev_hash)
    entry = LogEntry(seq=seq, timestamp=timestamp, event_type=event_type, data=data,
                      prev_hash=prev_hash, entry_hash=entry_hash)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry.__dict__, sort_keys=True, separators=(",", ":")) + "\n")
    return entry


@dataclass
class VerifyResult:
    ok: bool
    entries_checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def verify_log(log_path: Path) -> VerifyResult:
    """Replays the whole chain and checks every link. Any edit, deletion, reorder or truncation of a past
    entry changes a hash somewhere in the chain and is reported here, with the entry where it was first
    detected (truncation surfaces as the gap; a value in the middle changing surfaces there).
    """
    if not log_path.exists():
        return VerifyResult(ok=True, entries_checked=0)

    expected_prev = GENESIS_HASH
    expected_seq = 0
    checked = 0
    with open(log_path, "r") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(ok=False, entries_checked=checked, broken_at_seq=None,
                                     reason=f"line {lineno} is not valid JSON")
            entry = LogEntry(**raw)
            if entry.seq != expected_seq:
                return VerifyResult(ok=False, entries_checked=checked, broken_at_seq=entry.seq,
                                     reason=f"expected sequence {expected_seq}, found {entry.seq} (entries missing or reordered)")
            if entry.prev_hash != expected_prev:
                return VerifyResult(ok=False, entries_checked=checked, broken_at_seq=entry.seq,
                                     reason="prev_hash does not match the previous entry (the chain was broken)")
            recomputed = _entry_hash(entry.seq, entry.timestamp, entry.event_type, entry.data, entry.prev_hash)
            if recomputed != entry.entry_hash:
                return VerifyResult(ok=False, entries_checked=checked, broken_at_seq=entry.seq,
                                     reason="entry_hash does not match its own contents (the entry was edited)")
            expected_prev = entry.entry_hash
            expected_seq += 1
            checked += 1
    return VerifyResult(ok=True, entries_checked=checked)


def read_entries(log_path: Path, limit: int | None = None) -> list[LogEntry]:
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(LogEntry(**json.loads(line)))
    return entries[-limit:] if limit else entries
