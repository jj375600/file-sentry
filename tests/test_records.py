from file_sentry.records import FileRecord, diff_states


def rec(path, hash="h1", mode=0o644, size=10, mtime=0.0, is_symlink=False, target=None) -> FileRecord:
    return FileRecord(path=path, hash=hash, size=size, mtime=mtime, mode=mode,
                       is_symlink=is_symlink, symlink_target=target)


def test_identical_states_produce_no_diff():
    state = {"a.txt": rec("a.txt")}
    diff = diff_states(state, dict(state))
    assert diff.is_clean
    assert diff.total_changes == 0


def test_new_file_is_added():
    diff = diff_states({}, {"a.txt": rec("a.txt")})
    assert [r.path for r in diff.added] == ["a.txt"]
    assert not diff.removed and not diff.modified and not diff.permission_changed


def test_deleted_file_is_removed():
    diff = diff_states({"a.txt": rec("a.txt")}, {})
    assert [r.path for r in diff.removed] == ["a.txt"]


def test_changed_content_is_modified_not_permission_changed():
    old = {"a.txt": rec("a.txt", hash="h1")}
    new = {"a.txt": rec("a.txt", hash="h2")}
    diff = diff_states(old, new)
    assert len(diff.modified) == 1
    assert diff.modified[0][0].hash == "h1" and diff.modified[0][1].hash == "h2"
    assert not diff.permission_changed


def test_mode_change_alone_is_permission_changed_not_modified():
    old = {"a.txt": rec("a.txt", hash="h1", mode=0o644)}
    new = {"a.txt": rec("a.txt", hash="h1", mode=0o777)}
    diff = diff_states(old, new)
    assert not diff.modified
    assert len(diff.permission_changed) == 1
    assert diff.permission_changed[0][1].mode == 0o777


def test_content_and_mode_both_changed_counts_as_modified_only():
    """A content change takes priority in the report: the file is flagged MODIFIED (which is the more
    serious finding), not reported twice.
    """
    old = {"a.txt": rec("a.txt", hash="h1", mode=0o644)}
    new = {"a.txt": rec("a.txt", hash="h2", mode=0o777)}
    diff = diff_states(old, new)
    assert len(diff.modified) == 1
    assert not diff.permission_changed


def test_mtime_only_change_is_not_reported():
    """Touching a file (changing its mtime) without changing its bytes or permissions is not a finding —
    that would make every backup or checkout tool trigger false alarms.
    """
    old = {"a.txt": rec("a.txt", hash="h1", mtime=100.0)}
    new = {"a.txt": rec("a.txt", hash="h1", mtime=200.0)}
    assert diff_states(old, new).is_clean


def test_multiple_changes_at_once_are_all_reported_and_sorted():
    old = {"a.txt": rec("a.txt", hash="h1"), "b.txt": rec("b.txt", hash="h1"), "c.txt": rec("c.txt", hash="h1")}
    new = {"a.txt": rec("a.txt", hash="h1"), "c.txt": rec("c.txt", hash="h2"), "d.txt": rec("d.txt", hash="h1")}
    diff = diff_states(old, new)
    assert [r.path for r in diff.added] == ["d.txt"]
    assert [r.path for r in diff.removed] == ["b.txt"]
    assert [new.path for old, new in diff.modified] == ["c.txt"]
    assert diff.total_changes == 3


def test_permissions_string_matches_stat_style():
    r = rec("a.txt", mode=0o640)
    assert r.permissions() == "rw-r-----"
