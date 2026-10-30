import threading
import time

from file_sentry.config import load_config
from file_sentry.engine import init_baseline
from file_sentry.watcher import watch


def _run_watch_for(config, duration=3.0, debounce=0.3):
    diffs = []
    stop_event = threading.Event()

    def on_diff(diff):
        diffs.append(diff)

    thread = threading.Thread(target=watch, args=(config, on_diff), kwargs={"debounce": debounce, "stop_event": stop_event})
    thread.start()
    return diffs, stop_event, thread


def test_watch_detects_a_new_file(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("hello")
    config = load_config(config_file())
    init_baseline(config)

    diffs, stop_event, thread = _run_watch_for(config)
    try:
        time.sleep(0.5)  # let the observer start polling
        (watched_dir / "b.txt").write_text("new file")
        deadline = time.time() + 10
        while time.time() < deadline and not diffs:
            time.sleep(0.2)
    finally:
        stop_event.set()
        thread.join(timeout=10)

    assert diffs, "expected at least one diff to be reported"
    assert any(r.path == "b.txt" for d in diffs for r in d.added)


def test_watch_debounces_rapid_bursts_into_one_callback(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("v0")
    config = load_config(config_file())
    init_baseline(config)

    diffs, stop_event, thread = _run_watch_for(config, debounce=1.0)
    try:
        time.sleep(0.5)
        for i in range(5):
            (watched_dir / "a.txt").write_text(f"v{i}")
            time.sleep(0.05)
        # wait past the debounce window for the single settled callback
        deadline = time.time() + 10
        while time.time() < deadline and not diffs:
            time.sleep(0.2)
        time.sleep(1.5)  # make sure no second callback trickles in
    finally:
        stop_event.set()
        thread.join(timeout=10)

    assert len(diffs) == 1


def test_watch_stops_cleanly_on_stop_event(config_file, watched_dir):
    (watched_dir / "a.txt").write_text("hello")
    config = load_config(config_file())
    init_baseline(config)

    _diffs, stop_event, thread = _run_watch_for(config)
    time.sleep(0.5)
    stop_event.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
