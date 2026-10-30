"""The file-sentry command line: init, scan, watch, status, report, verify-log."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import click
import yaml

from . import __version__, auditlog
from .alerts import format_diff
from .baseline import has_baseline
from .config import Config, ConfigError, load_config
from .engine import db_path, init_baseline, log_path, run_check
from .watcher import watch as watch_loop

DEFAULT_CONFIG = "file-sentry.yml"


def _load(config_path: str) -> Config:
    try:
        return load_config(Path(config_path))
    except ConfigError as e:
        click.secho(f"error: {e}", fg="red", err=True)
        sys.exit(2)


@click.group()
@click.version_option(__version__, prog_name="file-sentry")
def main() -> None:
    """A file-integrity monitor: baseline a directory, then detect what changes."""


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
@click.option("--force", is_flag=True, help="Rebuild the baseline even if one already exists.")
def init(paths: tuple[str, ...], config_path: str, force: bool) -> None:
    """Create a config file (if one doesn't exist) and record the current state as the baseline."""
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        watch_paths = list(paths) or ["."]
        cfg_file.write_text(yaml.safe_dump({
            "paths": watch_paths,
            "excludes": [],
            "follow_symlinks": False,
            "state_dir": ".file-sentry",
        }, sort_keys=False))
        click.echo(f"Wrote {cfg_file} watching: {', '.join(watch_paths)}")
    elif paths:
        click.secho(f"{cfg_file} already exists; ignoring the paths given here. Edit it directly to change what's watched.",
                    fg="yellow")

    config = _load(config_path)
    if has_baseline(db_path(config)) and not force:
        click.secho("A baseline already exists. Pass --force to replace it (any un-reviewed changes since "
                     "the last scan will be accepted as the new normal).", fg="yellow")
        sys.exit(1)

    count = init_baseline(config)
    click.secho(f"Baseline recorded: {count} files.", fg="green")


@main.command()
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
@click.option("--accept", "-a", is_flag=True, help="Treat the current state as the new baseline after reporting it.")
@click.option("--json", "as_json", is_flag=True, help="Print the diff as JSON instead of text.")
def scan(config_path: str, accept: bool, as_json: bool) -> None:
    """Compare the filesystem now against the baseline, once, and report what differs.

    Exits 0 if nothing changed, 1 if something did (so this is safe to use in a cron job or CI step).
    """
    config = _load(config_path)
    if not has_baseline(db_path(config)):
        click.secho("No baseline yet. Run 'file-sentry init' first.", fg="red", err=True)
        sys.exit(2)

    diff, webhook_result = run_check(config, update_baseline=accept)

    if as_json:
        import json

        from .alerts import diff_to_events
        click.echo(json.dumps({"clean": diff.is_clean, "changes": diff_to_events(diff)}, indent=2))
    elif diff.is_clean:
        click.secho("No changes.", fg="green")
    else:
        for line in format_diff(diff):
            click.secho(line, fg="yellow")
        click.secho(f"{diff.total_changes} change(s) detected.", fg="red" if not accept else "yellow")
        if accept:
            click.echo("Baseline updated to match.")
        if webhook_result and not webhook_result.sent:
            click.secho(f"webhook failed: {webhook_result.error}", fg="red", err=True)

    sys.exit(0 if diff.is_clean else 1)


@main.command()
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
@click.option("--debounce", default=1.0, show_default=True, help="Seconds to wait after activity settles before checking.")
def watch(config_path: str, debounce: float) -> None:
    """Watch the configured paths continuously and report changes as they happen. Ctrl+C to stop."""
    config = _load(config_path)
    if not has_baseline(db_path(config)):
        click.secho("No baseline yet. Run 'file-sentry init' first.", fg="red", err=True)
        sys.exit(2)

    click.echo(f"Watching {len(config.paths)} path(s). Press Ctrl+C to stop.")

    def on_diff(diff) -> None:
        if diff.is_clean:
            return
        for line in format_diff(diff):
            click.secho(line, fg="yellow")

    stop_event = threading.Event()
    try:
        watch_loop(config, on_diff, debounce=debounce, stop_event=stop_event)
    except KeyboardInterrupt:
        stop_event.set()
        click.echo("\nStopped.")


@main.command()
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
def status(config_path: str) -> None:
    """A quick health check: baseline size, audit log size, and whether the log's chain is intact."""
    config = _load(config_path)
    db = db_path(config)
    log = log_path(config)
    if not has_baseline(db):
        click.secho("No baseline yet. Run 'file-sentry init' first.", fg="red")
        sys.exit(2)
    from .baseline import load_baseline
    baseline = load_baseline(db)
    result = auditlog.verify_log(log)
    click.echo(f"Baseline:    {len(baseline)} files, watching {len(config.paths)} path(s)")
    click.echo(f"Audit log:   {result.entries_checked} entries")
    if result.ok:
        click.secho("Log chain:   intact", fg="green")
    else:
        click.secho(f"Log chain:   BROKEN at entry {result.broken_at_seq} ({result.reason})", fg="red")
        sys.exit(1)


@main.command()
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
@click.option("--limit", default=20, show_default=True)
def report(config_path: str, limit: int) -> None:
    """Show the most recent audit log entries."""
    config = _load(config_path)
    entries = auditlog.read_entries(log_path(config), limit=limit)
    if not entries:
        click.echo("No audit log entries yet.")
        return
    for e in entries:
        click.echo(f"#{e.seq:<6} {e.timestamp}  {e.event_type:<20} {e.data}")


@main.command("verify-log")
@click.option("--config", "-c", "config_path", default=DEFAULT_CONFIG, show_default=True)
def verify_log_cmd(config_path: str) -> None:
    """Replay the audit log's hash chain end to end and confirm no entry was edited, removed or reordered."""
    config = _load(config_path)
    result = auditlog.verify_log(log_path(config))
    if result.ok:
        click.secho(f"OK: {result.entries_checked} entries, chain intact.", fg="green")
        sys.exit(0)
    click.secho(f"TAMPERED: break detected at entry {result.broken_at_seq}: {result.reason}", fg="red")
    sys.exit(1)


if __name__ == "__main__":
    main()
