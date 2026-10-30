import hashlib
import os
from pathlib import Path

from file_sentry.hashing import hash_bytes, hash_file


def test_hash_file_matches_direct_hashlib(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("hello world")
    assert hash_file(f) == hashlib.sha256(b"hello world").hexdigest()


def test_hash_file_streams_across_chunk_boundaries(tmp_path: Path):
    """A file bigger than one chunk must hash the same as hashing it all in memory at once —
    this is the thing that would break silently if the streaming loop had an off-by-one.
    """
    from file_sentry.hashing import CHUNK_SIZE
    f = tmp_path / "big.bin"
    data = os.urandom(CHUNK_SIZE * 2 + 137)
    f.write_bytes(data)
    assert hash_file(f) == hashlib.sha256(data).hexdigest()


def test_empty_file_hashes_to_the_known_empty_sha256(tmp_path: Path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    assert hash_file(f) == hashlib.sha256(b"").hexdigest()


def test_hash_bytes_matches_hashlib():
    assert hash_bytes(b"target/path") == hashlib.sha256(b"target/path").hexdigest()


def test_different_content_different_hash(tmp_path: Path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("one")
    b.write_text("two")
    assert hash_file(a) != hash_file(b)
