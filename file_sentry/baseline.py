"""The baseline: the last-known-good state of every watched file, kept in a small SQLite database."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .records import FileRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime REAL NOT NULL,
    mode INTEGER NOT NULL,
    is_symlink INTEGER NOT NULL,
    symlink_target TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def load_baseline(db_path: Path) -> dict[str, FileRecord]:
    """Returns {} if no baseline has been created yet (the database or table is empty)."""
    if not db_path.exists():
        return {}
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT path, hash, size, mtime, mode, is_symlink, symlink_target FROM files").fetchall()
    return {
        row[0]: FileRecord(
            path=row[0], hash=row[1], size=row[2], mtime=row[3], mode=row[4],
            is_symlink=bool(row[5]), symlink_target=row[6],
        )
        for row in rows
    }


def save_baseline(db_path: Path, records: dict[str, FileRecord]) -> None:
    """Replaces the entire baseline with the given records, atomically (one transaction)."""
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM files")
        conn.executemany(
            "INSERT INTO files (path, hash, size, mtime, mode, is_symlink, symlink_target) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (r.path, r.hash, r.size, r.mtime, r.mode, int(r.is_symlink), r.symlink_target)
                for r in records.values()
            ],
        )
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('baseline_count', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(len(records)),),
        )


def has_baseline(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with _connect(db_path) as conn:
        row = conn.execute("SELECT 1 FROM meta WHERE key = 'baseline_count'").fetchone()
    return row is not None
