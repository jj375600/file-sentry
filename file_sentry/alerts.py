"""Turns a Diff into human-readable lines, and optionally posts it to a webhook."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import WebhookAlert
from .records import Diff

LABELS = {
    "added": "ADDED", "removed": "REMOVED", "modified": "MODIFIED", "permission_changed": "PERMISSIONS",
}


def format_diff(diff: Diff, root_label: str = "") -> list[str]:
    prefix = f"[{root_label}] " if root_label else ""
    lines: list[str] = []
    for r in diff.added:
        lines.append(f"{prefix}{LABELS['added']}  {r.path}  ({r.permissions()}, {r.size} bytes)")
    for r in diff.removed:
        lines.append(f"{prefix}{LABELS['removed']}  {r.path}")
    for old, new in diff.modified:
        lines.append(f"{prefix}{LABELS['modified']}  {new.path}  {old.hash[:12]} -> {new.hash[:12]}")
    for old, new in diff.permission_changed:
        lines.append(f"{prefix}{LABELS['permission_changed']}  {new.path}  {old.permissions()} -> {new.permissions()}")
    return lines


def diff_to_events(diff: Diff) -> list[dict]:
    """One small dict per change, suitable for the audit log or a webhook payload."""
    events: list[dict] = []
    for r in diff.added:
        events.append({"kind": "added", "path": r.path, "hash": r.hash, "mode": r.permissions()})
    for r in diff.removed:
        events.append({"kind": "removed", "path": r.path, "hash": r.hash})
    for old, new in diff.modified:
        events.append({"kind": "modified", "path": new.path, "old_hash": old.hash, "new_hash": new.hash})
    for old, new in diff.permission_changed:
        events.append({
            "kind": "permission_changed", "path": new.path,
            "old_mode": old.permissions(), "new_mode": new.permissions(),
        })
    return events


@dataclass
class WebhookResult:
    sent: bool
    status: int | None = None
    error: str | None = None


def send_webhook(webhook: WebhookAlert, events: list[dict], timeout: float = 5.0) -> WebhookResult:
    """POSTs {"events": [...]} as JSON. Never raises: a webhook failure must not stop monitoring, so the
    caller just logs the result.
    """
    body = json.dumps({"events": events}).encode()
    req = urllib.request.Request(
        webhook.url, data=body, method="POST",
        headers={"Content-Type": "application/json", **webhook.headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return WebhookResult(sent=True, status=resp.status)
    except urllib.error.HTTPError as e:
        return WebhookResult(sent=False, status=e.code, error=str(e))
    except urllib.error.URLError as e:
        return WebhookResult(sent=False, error=str(e.reason))
    except OSError as e:
        return WebhookResult(sent=False, error=str(e))
