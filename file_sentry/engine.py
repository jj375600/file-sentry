"""Ties the pieces together: scan the filesystem, compare to the baseline, record what changed, alert."""
from __future__ import annotations

from pathlib import Path

from . import auditlog
from .alerts import WebhookResult, diff_to_events, send_webhook
from .baseline import load_baseline, save_baseline
from .config import Config
from .records import Diff
from .scanner import scan


def db_path(config: Config) -> Path:
    return config.state_dir / "baseline.db"


def log_path(config: Config) -> Path:
    return config.state_dir / "audit.log"


def init_baseline(config: Config) -> int:
    """Creates the first baseline from the current state of disk. Returns how many files were recorded."""
    current = scan(config)
    save_baseline(db_path(config), current)
    auditlog.append_event(log_path(config), "baseline_created", {"file_count": len(current)})
    return len(current)


def run_check(config: Config, update_baseline: bool = True) -> tuple[Diff, WebhookResult | None]:
    """One scan-and-compare cycle: always logs that a scan happened, logs each individual change, and
    (if a webhook is configured and something changed) posts the batch. Returns the diff and, if a webhook
    fired, its result.
    """
    db = db_path(config)
    log = log_path(config)
    baseline = load_baseline(db)
    current = scan(config)
    from .records import diff_states
    diff = diff_states(baseline, current)

    auditlog.append_event(log, "scan", {"file_count": len(current), "changes": diff.total_changes})

    webhook_result = None
    if not diff.is_clean:
        events = diff_to_events(diff)
        for event in events:
            auditlog.append_event(log, f"change_{event['kind']}", event)
        if config.webhook:
            webhook_result = send_webhook(config.webhook, events)
            auditlog.append_event(log, "webhook_sent", {
                "sent": webhook_result.sent, "status": webhook_result.status, "error": webhook_result.error,
            })

    if update_baseline:
        save_baseline(db, current)

    return diff, webhook_result
