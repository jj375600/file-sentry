import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from file_sentry import engine
from file_sentry.auditlog import read_entries
from file_sentry.config import load_config


class _CapturingHandler(BaseHTTPRequestHandler):
    received: ClassVar[list] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CapturingHandler.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


def test_init_baseline_creates_baseline_and_logs_event(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("hello")
    config = load_config(config_file())
    count = engine.init_baseline(config)
    assert count == 1
    entries = read_entries(engine.log_path(config))
    assert entries[-1].event_type == "baseline_created"


def test_run_check_clean_logs_scan_only(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("hello")
    config = load_config(config_file())
    engine.init_baseline(config)

    diff, webhook_result = engine.run_check(config)
    assert diff.is_clean
    assert webhook_result is None
    entries = read_entries(engine.log_path(config))
    assert entries[-1].event_type == "scan"


def test_run_check_dirty_logs_change_events(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("v1")
    config = load_config(config_file())
    engine.init_baseline(config)

    (watched_dir / "a.txt").write_text("v2")
    diff, _ = engine.run_check(config)
    assert not diff.is_clean
    event_types = [e.event_type for e in read_entries(engine.log_path(config))]
    # order: baseline_created, then scan (always logged), then the individual change event
    assert event_types == ["baseline_created", "scan", "change_modified"]


def test_run_check_without_update_baseline_leaves_baseline_unchanged(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("v1")
    config = load_config(config_file())
    engine.init_baseline(config)

    (watched_dir / "a.txt").write_text("v2")
    engine.run_check(config, update_baseline=False)

    # second check should still show the same modification since baseline wasn't updated
    diff_again, _ = engine.run_check(config, update_baseline=False)
    assert not diff_again.is_clean


def test_run_check_with_update_baseline_true_clears_the_diff_on_next_run(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("v1")
    config = load_config(config_file())
    engine.init_baseline(config)

    (watched_dir / "a.txt").write_text("v2")
    engine.run_check(config, update_baseline=True)

    diff_again, _ = engine.run_check(config, update_baseline=True)
    assert diff_again.is_clean


def test_webhook_is_sent_on_dirty_check_and_result_logged(tmp_path: Path, config_file, watched_dir):
    srv, thread = _server()
    try:
        port = srv.server_address[1]
        config = load_config(config_file(webhook={"url": f"http://127.0.0.1:{port}/hook"}))
        (watched_dir / "a.txt").write_text("v1")
        engine.init_baseline(config)
        (watched_dir / "a.txt").write_text("v2")

        diff, webhook_result = engine.run_check(config)
        assert not diff.is_clean
        assert webhook_result is not None
        assert webhook_result.sent

        event_types = [e.event_type for e in read_entries(engine.log_path(config))]
        assert "webhook_sent" in event_types
        assert len(_CapturingHandler.received) == 1
        assert _CapturingHandler.received[0]["events"]
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        _CapturingHandler.received.clear()


def test_webhook_failure_is_caught_logged_and_never_raises(config_file, watched_dir):
    """A dead or unreachable webhook endpoint must not stop monitoring: run_check should return normally,
    with a WebhookResult recording the failure, and the failure itself should be written to the audit log.
    """
    config = load_config(config_file(webhook={"url": "http://127.0.0.1:1/unreachable"}))
    (watched_dir / "a.txt").write_text("v1")
    engine.init_baseline(config)
    (watched_dir / "a.txt").write_text("v2")

    diff, webhook_result = engine.run_check(config)
    assert not diff.is_clean
    assert webhook_result is not None
    assert webhook_result.sent is False
    assert webhook_result.error

    entries = read_entries(engine.log_path(config))
    webhook_entry = next(e for e in entries if e.event_type == "webhook_sent")
    assert webhook_entry.data["sent"] is False


def test_webhook_is_not_sent_when_clean(config_file, watched_dir):
    srv, thread = _server()
    try:
        port = srv.server_address[1]
        config = load_config(config_file(webhook={"url": f"http://127.0.0.1:{port}/hook"}))
        (watched_dir / "a.txt").write_text("v1")
        engine.init_baseline(config)

        diff, webhook_result = engine.run_check(config)
        assert diff.is_clean
        assert webhook_result is None
        assert len(_CapturingHandler.received) == 0
    finally:
        srv.shutdown()
        thread.join(timeout=5)
        _CapturingHandler.received.clear()
