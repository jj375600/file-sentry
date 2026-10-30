"""Continuous monitoring: watches the configured paths with the OS's native file-event API (via the
`watchdog` library) and re-checks against the baseline a short moment after things go quiet, rather than
on every single event — editors often touch a file several times in one save.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

# A polling observer (rather than the OS-native inotify/FSEvents one) trades a little latency for working
# the same way everywhere: inside containers, over network filesystems, and in CI sandboxes where the
# native watcher's event source isn't always available.
from .config import Config
from .engine import run_check
from .records import Diff

DEBOUNCE_SECONDS = 1.0


class _DebouncedHandler(FileSystemEventHandler):
    def __init__(self, on_settled: Callable[[], None], debounce: float) -> None:
        self._on_settled = on_settled
        self._debounce = debounce
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        self._on_settled()

    def stop(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()


def watch(
    config: Config,
    on_diff: Callable[[Diff], None],
    debounce: float = DEBOUNCE_SECONDS,
    stop_event: threading.Event | None = None,
) -> None:
    """Blocks until `stop_event` is set (or forever, if none is given). Calls `on_diff` once per settled
    burst of changes, even when nothing turned out to differ (so the caller can print "no changes" too).
    """
    stop_event = stop_event or threading.Event()

    def settled() -> None:
        diff, _ = run_check(config, update_baseline=True)
        on_diff(diff)

    handler = _DebouncedHandler(settled, debounce)
    observer = PollingObserver(timeout=0.3)
    watched_dirs: set[Path] = set()
    for root in config.paths:
        d = root if root.is_dir() else root.parent
        if d not in watched_dirs:
            observer.schedule(handler, str(d), recursive=True)
            watched_dirs.add(d)

    observer.start()
    try:
        while not stop_event.is_set():
            time.sleep(0.2)
    finally:
        handler.stop()
        observer.stop()
        observer.join(timeout=5)
