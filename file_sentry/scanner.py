"""Walks the watched paths and builds the current state: one FileRecord per file (and per symlink)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .config import Config
from .hashing import hash_bytes, hash_file
from .records import FileRecord


def _relative_key(config: Config, abs_path: Path) -> str:
    """A stable, posix-style identifier for a file, used as its row key and shown in reports."""
    for root in config.paths:
        base = root if root.is_dir() else root.parent
        try:
            return abs_path.relative_to(base).as_posix() if root.is_dir() else abs_path.name
        except ValueError:
            continue
    try:
        return abs_path.relative_to(config.config_path.parent).as_posix()
    except ValueError:
        return abs_path.as_posix()


def _record_for(config: Config, abs_path: Path) -> FileRecord | None:
    try:
        st = abs_path.lstat()
    except OSError:
        return None  # vanished between listing and stat-ing; the next scan will record it as removed

    key = _relative_key(config, abs_path)
    is_symlink = stat.S_ISLNK(st.st_mode)

    if is_symlink and not config.follow_symlinks:
        target = os.readlink(abs_path)
        return FileRecord(
            path=key, hash=hash_bytes(target.encode()), size=len(target), mtime=st.st_mtime,
            mode=stat.S_IMODE(st.st_mode), is_symlink=True, symlink_target=target,
        )

    if is_symlink:
        try:
            st = abs_path.stat()  # follow it
        except OSError:
            return None  # broken symlink

    if not stat.S_ISREG(st.st_mode):
        return None  # a device, socket, etc. — not meaningful to hash

    try:
        digest = hash_file(abs_path)
    except OSError:
        return None  # unreadable (permissions, vanished mid-scan)

    return FileRecord(
        path=key, hash=digest, size=st.st_size, mtime=st.st_mtime,
        mode=stat.S_IMODE(st.st_mode), is_symlink=False, symlink_target=None,
    )


def scan(config: Config) -> dict[str, FileRecord]:
    """Walks every configured path and returns {relative_path: FileRecord} for everything not excluded."""
    results: dict[str, FileRecord] = {}

    def visit_file(abs_path: Path, rel_to_root: str) -> None:
        if config.is_excluded(rel_to_root):
            return
        record = _record_for(config, abs_path)
        if record is not None:
            results[record.path] = record

    for root in config.paths:
        if root.is_file():
            visit_file(root, root.name)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=config.follow_symlinks):
            dirpath_p = Path(dirpath)
            rel_dir = dirpath_p.relative_to(root).as_posix()
            # Prune excluded directories before descending, so we never walk into node_modules/.git/etc.
            dirnames[:] = [
                d for d in dirnames
                if not config.is_excluded(f"{rel_dir}/{d}".lstrip("./"))
            ]
            for name in filenames:
                rel = f"{rel_dir}/{name}".lstrip("./")
                visit_file(dirpath_p / name, rel)
            # Symlinked directories aren't walked into when follow_symlinks is False, but are still recorded.
            if not config.follow_symlinks:
                for d in list(dirnames):
                    full = dirpath_p / d
                    if full.is_symlink():
                        rel = f"{rel_dir}/{d}".lstrip("./")
                        if not config.is_excluded(rel):
                            record = _record_for(config, full)
                            if record is not None:
                                results[record.path] = record
                        dirnames.remove(d)
    return results
