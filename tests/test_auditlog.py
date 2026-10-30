import json
from pathlib import Path

from file_sentry.auditlog import GENESIS_HASH, _entry_hash, append_event, read_entries, verify_log


def test_empty_log_is_valid(tmp_path: Path):
    result = verify_log(tmp_path / "nope.log")
    assert result.ok and result.entries_checked == 0


def test_single_entry_verifies(tmp_path: Path):
    log = tmp_path / "audit.log"
    append_event(log, "baseline_created", {"file_count": 3})
    result = verify_log(log)
    assert result.ok
    assert result.entries_checked == 1


def test_entries_chain_in_sequence(tmp_path: Path):
    log = tmp_path / "audit.log"
    e1 = append_event(log, "scan", {"n": 1})
    e2 = append_event(log, "scan", {"n": 2})
    assert e2.seq == e1.seq + 1
    assert e2.prev_hash == e1.entry_hash
    result = verify_log(log)
    assert result.ok and result.entries_checked == 2


def test_editing_a_past_entrys_data_is_detected(tmp_path: Path):
    """The classic attack: someone who modified a file edits the log afterward to hide it."""
    log = tmp_path / "audit.log"
    append_event(log, "change_modified", {"path": "secret.txt", "old_hash": "aaa", "new_hash": "bbb"})
    append_event(log, "scan", {"n": 2})
    append_event(log, "scan", {"n": 3})

    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["data"] = {"path": "secret.txt", "old_hash": "aaa", "new_hash": "aaa"}  # pretend nothing changed
    lines[0] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n")

    result = verify_log(log)
    assert not result.ok
    assert result.broken_at_seq == 0


def test_deleting_a_past_entry_is_detected(tmp_path: Path):
    log = tmp_path / "audit.log"
    append_event(log, "scan", {"n": 1})
    append_event(log, "change_removed", {"path": "evidence.txt"})
    append_event(log, "scan", {"n": 3})

    lines = log.read_text().splitlines()
    del lines[1]  # remove the "evidence" entry
    log.write_text("\n".join(lines) + "\n")

    result = verify_log(log)
    assert not result.ok


def test_truncating_the_tail_is_detected_by_the_caller_comparing_counts(tmp_path: Path):
    """Removing entries off the END doesn't break any single link (each remaining entry still points
    correctly to the one before it) — the chain looks perfectly valid. This is a real limitation,
    documented in SECURITY.md: the count itself, or a copy of the last known hash kept elsewhere, is
    what catches truncation. This test demonstrates exactly that gap, on purpose.
    """
    log = tmp_path / "audit.log"
    for i in range(5):
        append_event(log, "scan", {"n": i})
    full_count = verify_log(log).entries_checked

    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:3]) + "\n")  # drop the last 2 entries
    truncated = verify_log(log)

    assert truncated.ok  # the remaining chain is internally consistent...
    assert truncated.entries_checked < full_count  # ...but an external record of the count would catch this


def test_forged_entry_with_skipped_sequence_is_detected_even_with_a_self_consistent_hash(tmp_path: Path):
    """The sequence check and the hash-chain check are independent layers, not one check wearing two hats.
    This builds a forged entry that is internally self-consistent (its own entry_hash correctly matches
    its own seq/timestamp/data/prev_hash) and correctly chained to the real previous entry, but skips a
    sequence number — the kind of forgery someone could produce if they could append whatever they liked
    but didn't control existing entries. Only the sequence check catches this one.
    """
    log = tmp_path / "audit.log"
    append_event(log, "scan", {"n": 0})  # seq 0
    real = append_event(log, "scan", {"n": 1})  # seq 1

    forged_seq = 5  # skips 2, 3, 4
    forged_data = {"n": "forged"}
    forged_timestamp = "2026-01-01T00:00:00+00:00"
    forged_hash = _entry_hash(forged_seq, forged_timestamp, "scan", forged_data, real.entry_hash)
    forged_line = json.dumps({
        "seq": forged_seq, "timestamp": forged_timestamp, "event_type": "scan",
        "data": forged_data, "prev_hash": real.entry_hash, "entry_hash": forged_hash,
    })
    with open(log, "a") as f:
        f.write(forged_line + "\n")

    result = verify_log(log)
    assert not result.ok
    assert result.broken_at_seq == forged_seq
    assert "sequence" in result.reason


def test_forged_entry_with_wrong_prev_hash_is_detected_even_with_correct_sequence(tmp_path: Path):
    """The mirror case: a forged entry with the *correct* next sequence number but a prev_hash that
    doesn't actually point to the real preceding entry (as if an attacker forked the log's history from
    an earlier point and grafted a new entry onto it). The entry is still self-consistent on its own —
    only the chain-linkage check catches that it doesn't connect to what's really there.
    """
    log = tmp_path / "audit.log"
    append_event(log, "scan", {"n": 0})  # seq 0
    append_event(log, "scan", {"n": 1})  # seq 1, the real entry at this position

    forged_seq = 2
    forged_data = {"n": "forged"}
    forged_timestamp = "2026-01-01T00:00:00+00:00"
    fake_prev_hash = GENESIS_HASH  # does not match the real entry at seq 1
    forged_hash = _entry_hash(forged_seq, forged_timestamp, "scan", forged_data, fake_prev_hash)
    forged_line = json.dumps({
        "seq": forged_seq, "timestamp": forged_timestamp, "event_type": "scan",
        "data": forged_data, "prev_hash": fake_prev_hash, "entry_hash": forged_hash,
    })
    with open(log, "a") as f:
        f.write(forged_line + "\n")

    result = verify_log(log)
    assert not result.ok
    assert result.broken_at_seq == forged_seq
    assert "prev_hash" in result.reason


def test_reordering_entries_is_detected(tmp_path: Path):
    log = tmp_path / "audit.log"
    append_event(log, "scan", {"n": 1})
    append_event(log, "scan", {"n": 2})
    append_event(log, "scan", {"n": 3})

    lines = log.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log.write_text("\n".join(lines) + "\n")

    result = verify_log(log)
    assert not result.ok


def test_corrupted_json_line_is_reported_not_crashed_on(tmp_path: Path):
    log = tmp_path / "audit.log"
    append_event(log, "scan", {"n": 1})
    with open(log, "a") as f:
        f.write("{not valid json\n")

    result = verify_log(log)
    assert not result.ok
    assert "JSON" in result.reason


def test_read_entries_respects_limit(tmp_path: Path):
    log = tmp_path / "audit.log"
    for i in range(10):
        append_event(log, "scan", {"n": i})
    assert len(read_entries(log)) == 10
    last_three = read_entries(log, limit=3)
    assert len(last_three) == 3
    assert [e.data["n"] for e in last_three] == [7, 8, 9]


def test_entry_hash_depends_on_every_field(tmp_path: Path):
    """Two entries with the same data but a different event_type (or vice versa) must hash differently —
    otherwise an attacker could swap one kind of event for another without detection.
    """
    log1, log2 = tmp_path / "a.log", tmp_path / "b.log"
    append_event(log1, "change_added", {"path": "x"})
    append_event(log2, "change_removed", {"path": "x"})
    h1 = read_entries(log1)[0].entry_hash
    h2 = read_entries(log2)[0].entry_hash
    assert h1 != h2
