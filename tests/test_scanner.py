import os
from pathlib import Path

from file_sentry.config import load_config
from file_sentry.scanner import scan


def test_basic_scan_finds_all_files(tmp_path: Path, config_file, watched_dir):
    (watched_dir / "a.txt").write_text("hello")
    (watched_dir / "sub").mkdir()
    (watched_dir / "sub" / "b.txt").write_text("world")
    config = load_config(config_file())
    records = scan(config)
    assert set(records) == {"a.txt", "sub/b.txt"}


def test_scan_detects_add_remove_modify(tmp_path: Path, config_file, watched_dir):
    (watched_dir / "a.txt").write_text("v1")
    (watched_dir / "b.txt").write_text("keep")
    config = load_config(config_file())
    before = scan(config)

    (watched_dir / "a.txt").write_text("v2")  # modify
    (watched_dir / "b.txt").unlink()  # remove
    (watched_dir / "c.txt").write_text("new")  # add

    after = scan(config)
    from file_sentry.records import diff_states
    diff = diff_states(before, after)
    assert [r.path for r in diff.added] == ["c.txt"]
    assert [r.path for r in diff.removed] == ["b.txt"]
    assert [new.path for old, new in diff.modified] == ["a.txt"]


def test_permission_change_is_detected(tmp_path: Path, config_file, watched_dir):
    f = watched_dir / "a.txt"
    f.write_text("hello")
    f.chmod(0o644)
    config = load_config(config_file())
    before = scan(config)
    f.chmod(0o600)
    after = scan(config)
    from file_sentry.records import diff_states
    diff = diff_states(before, after)
    assert len(diff.permission_changed) == 1


def test_excluded_directory_is_not_descended_into(tmp_path: Path, config_file, watched_dir):
    excluded = watched_dir / "node_modules"
    excluded.mkdir()
    (excluded / "pkg.js").write_text("should not be scanned")
    (watched_dir / "real.txt").write_text("keep")

    config = load_config(config_file())
    records = scan(config)
    assert "real.txt" in records
    assert not any("node_modules" in p for p in records)


def test_huge_excluded_subtree_is_never_walked(tmp_path: Path, config_file, watched_dir, monkeypatch):
    excluded = watched_dir / "node_modules"
    excluded.mkdir()
    for i in range(50):
        (excluded / f"file{i}.txt").write_text("x")
    (watched_dir / "real.txt").write_text("keep")

    visited = []
    real_walk = os.walk

    def spy_walk(top, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, **kwargs):
            visited.append(dirpath)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(os, "walk", spy_walk)
    config = load_config(config_file())
    scan(config)
    assert not any("node_modules" in v for v in visited)


def test_symlink_not_followed_by_default_records_target_string(tmp_path: Path, config_file, watched_dir):
    target = watched_dir / "real.txt"
    target.write_text("hello")
    link = watched_dir / "link.txt"
    link.symlink_to(target)

    config = load_config(config_file())
    records = scan(config)
    assert records["link.txt"].is_symlink
    assert records["link.txt"].symlink_target == str(target)


def test_broken_symlink_is_still_recorded_not_crashed_on(tmp_path: Path, config_file, watched_dir):
    link = watched_dir / "broken.txt"
    link.symlink_to(watched_dir / "does-not-exist.txt")

    config = load_config(config_file())
    records = scan(config)
    assert records["broken.txt"].is_symlink


def test_symlinked_directory_is_recorded_but_not_walked_when_not_following(tmp_path: Path, config_file, watched_dir):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("hidden")
    link_dir = watched_dir / "linked_dir"
    link_dir.symlink_to(outside)

    config = load_config(config_file())
    records = scan(config)
    assert "linked_dir" in records
    assert records["linked_dir"].is_symlink
    assert not any(p.startswith("linked_dir/") for p in records)


def test_relative_keys_are_correct_across_multiple_watched_roots(tmp_path: Path, config_file):
    root1 = tmp_path / "root1"
    root2 = tmp_path / "root2"
    root1.mkdir()
    root2.mkdir()
    (root1 / "a.txt").write_text("a")
    (root2 / "b.txt").write_text("b")

    config = load_config(config_file(paths=["root1", "root2"]))
    records = scan(config)
    assert set(records) == {"a.txt", "b.txt"}
