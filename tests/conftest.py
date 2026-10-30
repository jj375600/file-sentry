from pathlib import Path

import pytest
import yaml


@pytest.fixture
def watched_dir(tmp_path: Path) -> Path:
    d = tmp_path / "watched"
    d.mkdir()
    return d


@pytest.fixture
def config_file(tmp_path: Path, watched_dir: Path):
    """Writes a minimal config watching `watched_dir`, with state kept alongside it. Returns its path."""
    def _write(**overrides):
        cfg = {
            "paths": [str(watched_dir)],
            "excludes": [],
            "follow_symlinks": False,
            "state_dir": str(tmp_path / ".file-sentry"),
        }
        cfg.update(overrides)
        path = tmp_path / "file-sentry.yml"
        path.write_text(yaml.safe_dump(cfg))
        return path
    return _write


def write(path: Path, content: str = "hello") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
