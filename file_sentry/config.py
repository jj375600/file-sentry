"""Loads and validates a file-sentry config file (YAML)."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_EXCLUDES = [
    ".git/*", ".git",
    "__pycache__/*", "__pycache__", "*.pyc",
    "node_modules/*", "node_modules",
    ".DS_Store",
    "*.swp", "*.tmp",
    ".file-sentry/*", ".file-sentry",  # the tool's own database and log live here by default
]


class ConfigError(ValueError):
    """The config file is missing, malformed, or names a path that doesn't exist."""


@dataclass
class WebhookAlert:
    url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    paths: list[Path]
    excludes: list[str]
    follow_symlinks: bool
    state_dir: Path
    webhook: WebhookAlert | None
    config_path: Path

    def is_excluded(self, relative_path: str) -> bool:
        """relative_path uses forward slashes, relative to the nearest watched root."""
        parts = relative_path.split("/")
        for pattern in self.excludes:
            if fnmatch.fnmatch(relative_path, pattern):
                return True
            # a pattern like "node_modules/*" or a bare dir name should also match at any depth
            if any(fnmatch.fnmatch(part, pattern.rstrip("/*")) for part in parts):
                return True
        return False


def load_config(path: Path) -> Config:
    if not path.exists():
        raise ConfigError(f"No config file at {path}. Run 'file-sentry init' first.")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} is not valid YAML: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level.")

    raw_paths = raw.get("paths")
    if not raw_paths or not isinstance(raw_paths, list):
        raise ConfigError("config must list at least one path under 'paths:'.")

    base = path.parent
    paths = []
    for p in raw_paths:
        resolved = (base / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
        if not resolved.exists():
            raise ConfigError(f"watched path does not exist: {resolved}")
        paths.append(resolved)

    excludes = list(DEFAULT_EXCLUDES) + list(raw.get("excludes", []) or [])
    follow_symlinks = bool(raw.get("follow_symlinks", False))

    state_dir_raw = raw.get("state_dir", ".file-sentry")
    state_dir = (base / state_dir_raw).resolve() if not Path(state_dir_raw).is_absolute() else Path(state_dir_raw)

    webhook = None
    wh_raw = raw.get("webhook")
    if wh_raw:
        if not isinstance(wh_raw, dict) or not wh_raw.get("url"):
            raise ConfigError("'webhook:' must be a mapping with at least a 'url' key.")
        webhook = WebhookAlert(url=wh_raw["url"], headers=wh_raw.get("headers", {}) or {})

    return Config(
        paths=paths,
        excludes=excludes,
        follow_symlinks=follow_symlinks,
        state_dir=state_dir,
        webhook=webhook,
        config_path=path,
    )
