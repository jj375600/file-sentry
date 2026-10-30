import json
import os
from contextlib import contextmanager
from pathlib import Path

from click.testing import CliRunner

from file_sentry.cli import main


@contextmanager
def _cwd(path: Path):
    """Runs a block with the process cwd temporarily changed to `path`.

    Each CLI command here reads/writes files relative to the current directory
    (file-sentry.yml, the state dir), so tests need a real cwd change — this
    replaces click.testing's now-deprecated `isolated_filesystem`.
    """
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield path
    finally:
        os.chdir(previous)


def test_init_creates_config_and_baseline(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")

    with _cwd(tmp_path):
        result = runner.invoke(main, ["init", str(watched)])
        assert result.exit_code == 0, result.output
        assert Path("file-sentry.yml").exists()
        assert "Baseline recorded: 1 files" in result.output


def test_init_refuses_to_rebuild_without_force(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")

    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 1
        assert "already exists" in result.output

        result = runner.invoke(main, ["init", "--force"])
        assert result.exit_code == 0
        assert "Baseline recorded" in result.output


def test_scan_without_baseline_fails(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    with _cwd(tmp_path):
        Path("file-sentry.yml").write_text(f"paths: [{watched}]\n")
        result = runner.invoke(main, ["scan"])
        assert result.exit_code == 2


def test_scan_clean_exits_zero(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        result = runner.invoke(main, ["scan"])
        assert result.exit_code == 0
        assert "No changes" in result.output


def test_scan_dirty_exits_one(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("v1")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        (watched / "a.txt").write_text("v2")
        result = runner.invoke(main, ["scan"])
        assert result.exit_code == 1
        assert "change(s) detected" in result.output


def test_scan_accept_updates_baseline(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("v1")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        (watched / "a.txt").write_text("v2")
        result = runner.invoke(main, ["scan", "--accept"])
        assert result.exit_code == 1  # still reports the change this run
        assert "Baseline updated" in result.output

        result_again = runner.invoke(main, ["scan"])
        assert result_again.exit_code == 0  # but is now clean


def test_scan_json_output(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("v1")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        (watched / "a.txt").write_text("v2")
        result = runner.invoke(main, ["scan", "--json"])
        payload = json.loads(result.output)
        assert payload["clean"] is False
        assert len(payload["changes"]) == 1


def test_status_reports_intact_chain(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "intact" in result.output


def test_status_reports_tampered_chain(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        log = Path(".file-sentry") / "audit.log"
        lines = log.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["data"]["file_count"] = 999
        log.write_text(json.dumps(entry) + "\n")

        result = runner.invoke(main, ["status"])
        assert result.exit_code == 1
        assert "BROKEN" in result.output


def test_report_shows_entries(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        result = runner.invoke(main, ["report"])
        assert result.exit_code == 0
        assert "baseline_created" in result.output


def test_report_with_no_entries(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    with _cwd(tmp_path):
        Path("file-sentry.yml").write_text(f"paths: [{watched}]\n")
        result = runner.invoke(main, ["report"])
        assert "No audit log entries yet" in result.output


def test_verify_log_ok(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        result = runner.invoke(main, ["verify-log"])
        assert result.exit_code == 0
        assert "OK" in result.output


def test_verify_log_tampered(tmp_path: Path):
    runner = CliRunner()
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("hello")
    with _cwd(tmp_path):
        runner.invoke(main, ["init", str(watched)])
        log = Path(".file-sentry") / "audit.log"
        with open(log, "a") as f:
            f.write("{not json\n")
        result = runner.invoke(main, ["verify-log"])
        assert result.exit_code == 1
        assert "TAMPERED" in result.output
