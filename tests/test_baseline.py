from pathlib import Path

from file_sentry.baseline import has_baseline, load_baseline, save_baseline
from file_sentry.records import FileRecord


def rec(path, hash="h1") -> FileRecord:
    return FileRecord(path=path, hash=hash, size=1, mtime=0.0, mode=0o644, is_symlink=False, symlink_target=None)


def test_no_database_file_means_no_baseline(tmp_path: Path):
    db = tmp_path / "nope.db"
    assert not has_baseline(db)
    assert load_baseline(db) == {}


def test_save_then_load_roundtrips(tmp_path: Path):
    db = tmp_path / "state" / "baseline.db"
    records = {"a.txt": rec("a.txt", "h1"), "b/c.txt": rec("b/c.txt", "h2")}
    save_baseline(db, records)
    assert has_baseline(db)
    loaded = load_baseline(db)
    assert loaded == records


def test_save_replaces_the_whole_baseline(tmp_path: Path):
    db = tmp_path / "baseline.db"
    save_baseline(db, {"a.txt": rec("a.txt")})
    save_baseline(db, {"b.txt": rec("b.txt")})
    loaded = load_baseline(db)
    assert set(loaded) == {"b.txt"}


def test_symlink_fields_roundtrip(tmp_path: Path):
    db = tmp_path / "baseline.db"
    link = FileRecord(path="l", hash="h", size=4, mtime=0.0, mode=0o777, is_symlink=True, symlink_target="target")
    save_baseline(db, {"l": link})
    loaded = load_baseline(db)
    assert loaded["l"].is_symlink is True
    assert loaded["l"].symlink_target == "target"
