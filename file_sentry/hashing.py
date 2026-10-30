"""Streaming SHA-256 hashing, so a multi-gigabyte file never has to fit in memory."""
from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def hash_file(path: Path) -> str:
    """Returns the SHA-256 digest of a file's contents, as lowercase hex, reading it in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Hashes an in-memory value, such as a symlink's target path. Used where there is no file to stream."""
    return hashlib.sha256(data).hexdigest()
