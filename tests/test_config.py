from pathlib import Path

import pytest
import yaml

from file_sentry.config import ConfigError, load_config


def test_missing_config_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError, match="No config file"):
        load_config(tmp_path / "nope.yml")


def test_invalid_yaml_raises(tmp_path: Path):
    f = tmp_path / "cfg.yml"
    f.write_text("paths: [unterminated")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(f)


def test_non_mapping_top_level_raises(tmp_path: Path):
    f = tmp_path / "cfg.yml"
    f.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(f)


def test_missing_paths_key_raises(tmp_path: Path):
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"excludes": []}))
    with pytest.raises(ConfigError, match="paths"):
        load_config(f)


def test_nonexistent_watched_path_raises(tmp_path: Path):
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["does-not-exist"]}))
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(f)


def test_relative_paths_resolve_against_config_directory(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"]}))
    config = load_config(f)
    assert config.paths == [(tmp_path / "data").resolve()]


def test_default_excludes_are_always_present(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"]}))
    config = load_config(f)
    assert config.is_excluded(".git")
    assert config.is_excluded("sub/.git")
    assert config.is_excluded("node_modules/pkg/index.js")


def test_custom_excludes_are_added_not_replaced(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"], "excludes": ["*.log"]}))
    config = load_config(f)
    assert config.is_excluded("debug.log")
    assert config.is_excluded(".git")  # the default is still there


def test_exclude_does_not_match_unrelated_files(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"], "excludes": ["*.log"]}))
    config = load_config(f)
    assert not config.is_excluded("keep.txt")


def test_webhook_without_url_raises(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"], "webhook": {"headers": {}}}))
    with pytest.raises(ConfigError, match="webhook"):
        load_config(f)


def test_webhook_url_is_parsed(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"], "webhook": {"url": "https://example.test/hook"}}))
    config = load_config(f)
    assert config.webhook is not None
    assert config.webhook.url == "https://example.test/hook"


def test_follow_symlinks_defaults_false(tmp_path: Path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "cfg.yml"
    f.write_text(yaml.safe_dump({"paths": ["data"]}))
    assert load_config(f).follow_symlinks is False
