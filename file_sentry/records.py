"""The shape of one watched file's state, and the result of comparing two sets of them."""
from __future__ import annotations

import stat
from dataclasses import dataclass


@dataclass(frozen=True)
class FileRecord:
    path: str  # posix-style, relative to the config file's directory
    hash: str  # sha256 hex; for a symlink, the hash of its target string, not its contents
    size: int
    mtime: float
    mode: int  # the permission bits (stat().st_mode & 0o7777)
    is_symlink: bool
    symlink_target: str | None

    def permissions(self) -> str:
        return stat.filemode(stat.S_IFREG | self.mode)[1:]  # drop the leading file-type character


@dataclass
class Diff:
    added: list[FileRecord]
    removed: list[FileRecord]
    modified: list[tuple[FileRecord, FileRecord]]  # (old, new) — hash differs
    permission_changed: list[tuple[FileRecord, FileRecord]]  # (old, new) — same hash, different mode

    @property
    def is_clean(self) -> bool:
        return not (self.added or self.removed or self.modified or self.permission_changed)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified) + len(self.permission_changed)


def diff_states(baseline: dict[str, FileRecord], current: dict[str, FileRecord]) -> Diff:
    added, removed, modified, perm_changed = [], [], [], []
    for path, new in current.items():
        old = baseline.get(path)
        if old is None:
            added.append(new)
        elif old.hash != new.hash:
            modified.append((old, new))
        elif old.mode != new.mode:
            perm_changed.append((old, new))
    for path, old in baseline.items():
        if path not in current:
            removed.append(old)
    added.sort(key=lambda r: r.path)
    removed.sort(key=lambda r: r.path)
    modified.sort(key=lambda pair: pair[1].path)
    perm_changed.sort(key=lambda pair: pair[1].path)
    return Diff(added=added, removed=removed, modified=modified, permission_changed=perm_changed)
