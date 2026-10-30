# file-sentry

A file-integrity monitor (FIM): it records a cryptographic baseline of a
directory tree, then tells you exactly what changed — added, removed,
modified content, or modified permissions — either on demand (`scan`) or
continuously (`watch`). Every check is written to a tamper-evident audit
log, so the monitoring itself leaves a trail that's hard to quietly erase.

This is the kind of control real security tooling (Tripwire, OSSEC, AIDE,
AWS Config rules, Wazuh's FIM module) is built around: configuration
drift, unauthorized changes to binaries or config files, and "did someone
touch this while I wasn't looking" are all the same underlying question —
*does the current state of this directory match the state I last approved?*

## How it works

```
                 ┌──────────────┐
  file-sentry.yml│   config.py  │  paths, excludes, state dir, webhook
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐
                 │  scanner.py  │  walks the tree, skips excludes,
                 │              │  hashes every file (SHA-256)
                 └──────┬───────┘
                        │ {relative_path: FileRecord}
                 ┌──────▼───────┐        ┌────────────────┐
                 │ baseline.py  │◄──────►│ baseline.db     │  SQLite —
                 │ load/save    │        │ (state_dir)     │  atomic replace
                 └──────┬───────┘        └────────────────┘
                        │
                 ┌──────▼───────┐
                 │ records.py   │  diff_states(old, new) → Diff
                 │ diff_states  │  added / removed / modified / perm-changed
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐        ┌────────────────┐
                 │  engine.py   │───────►│ audit.log       │  append-only,
                 │  run_check   │        │ (state_dir)     │  hash-chained
                 └──────┬───────┘        └────────────────┘
                        │ (if configured and dirty)
                 ┌──────▼───────┐
                 │  alerts.py   │  POSTs the diff as JSON
                 │ send_webhook │  (never raises — a dead webhook must
                 └──────────────┘   not stop monitoring)
```

`watcher.py` wraps this in a loop: it watches the filesystem for activity,
waits for a short quiet period (debounce), then calls the same `run_check`
a one-off `scan` would call. Watch mode and scan mode share one code path
on purpose — there's exactly one place that decides what counts as a
change.

### Why baseline-and-diff, not "hash everything in real time"

A naive FIM re-hashes files the instant it sees an OS-level write event.
That sounds more responsive, but it means every detector run depends on
catching every single event correctly, with no second chance. This tool
instead keeps one source of truth — the baseline — and treats every scan
(scheduled, on-demand, or watch-triggered) as the same operation: "compute
the current state, diff it against what was last approved." That makes
the tool trivially testable (a scan is a pure function of two directory
states) and means a missed filesystem event just means the *next* scan
catches it, rather than the change vanishing forever.

### Why `PollingObserver`, not the native OS watcher

`watch` mode uses `watchdog`'s `PollingObserver` instead of its default,
OS-native backend (inotify on Linux, FSEvents on macOS). The native
backends aren't reliably available everywhere this tool might run —
containers, CI runners, and network filesystems are common places where
they're missing, rate-limited, or simply lie. Polling is slightly less
immediate, but it works the same way everywhere, which matters more for a
security tool than shaving a few hundred milliseconds off detection time.

### The audit log: a hash chain over a plain text file

Every event `file-sentry` logs — baseline created, scan run, each
individual change, each webhook attempt — becomes one line of JSON in
`audit.log`. Each line's hash is computed over its own contents *and* the
previous line's hash, the same linking idea a blockchain uses, applied to
a boring append-only log file instead of a distributed ledger. That means:

- **Editing a past entry** (e.g. changing a logged `modified` event back to
  look clean) breaks that entry's own hash.
- **Deleting or reordering entries** breaks the `prev_hash` link to the
  entry that used to follow them.
- `file-sentry verify-log` replays the whole chain and reports the exact
  entry where it breaks, if it does.

This is **not** a substitute for file permissions or backups — if an
attacker has write access to `audit.log`, they can still truncate the
*end* of it (see the honest limitation in `SECURITY.md`). What it buys you
is: any edit to the *history* of what already happened is detectable,
which is the harder property to fake.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# First-time setup: watch one or more paths, record the baseline.
file-sentry init /etc /usr/local/bin

# Check once. Exit code 0 = clean, 1 = changes found — safe for cron or CI.
file-sentry scan

# Check once and accept whatever you find as the new normal.
file-sentry scan --accept

# Get the diff as JSON (for piping into another tool).
file-sentry scan --json

# Watch continuously; reports each settled burst of changes.
file-sentry watch

# Quick health check: baseline size, audit log size, chain integrity.
file-sentry status

# See the last N audit log entries.
file-sentry report --limit 50

# Verify the audit log's hash chain end to end.
file-sentry verify-log
```

### Configuration (`file-sentry.yml`)

```yaml
paths:
  - /etc
  - /usr/local/bin
excludes:
  - "*.log"          # merged with built-in defaults (.git, __pycache__, node_modules, ...)
follow_symlinks: false
state_dir: .file-sentry   # where baseline.db and audit.log live
webhook:
  url: https://example.com/alerts
  headers:
    Authorization: "Bearer ..."
```

## Testing

```bash
pytest                 # 75 tests
mypy file_sentry        # static types
ruff check .             # lint

# Sabotage testing: deliberately breaks the code in 14 different specific places
# (one at a time) and confirms the test suite actually fails for each one, then
# restores the original file. A test suite that never fails is as suspicious as
# code that never breaks.
bash scripts/sabotage.sh
```

The test suite is built the same way as my other projects: real files on
a real (temporary) disk, not mocked filesystems — `scanner`, `baseline`,
and `watcher` are all tested by actually creating, editing, and deleting
files under `tmp_path` and checking what the tool reports, because a
mocked `os.walk` can tell you your code calls the right function without
ever proving it finds the right *files*.

The audit log gets special attention: `tests/test_auditlog.py` doesn't
just check that a clean log verifies — it actively attacks its own log
(editing an entry's data, deleting a line, reordering two lines, corrupting
a line's JSON) and asserts `verify_log` catches each one. One of those
tests (`test_truncating_the_tail_...`) is written to *pass* while
demonstrating a real gap: dropping the last few entries doesn't break the
chain. That's intentional — it's there so the limitation is proven, not
just described. See `SECURITY.md`.

## Design decisions

- **SQLite for the baseline, not a flat file.** Replacing the whole
  baseline is one transaction (`DELETE` + bulk `INSERT`, committed
  together), so a crash mid-save can't leave a half-written baseline that
  silently drops files from future comparisons.
- **Content changes outrank permission changes in reporting.** A file that
  changed both content and mode is reported once, as `modified` — the more
  serious finding — not twice.
- **`mtime` is never, on its own, a finding.** Checking out a branch,
  restoring a backup, or `touch`-ing a file all change mtimes without
  changing content; treating that as a security event would make the tool
  useless within a day.
- **A webhook failure is swallowed, not raised.** `send_webhook` always
  returns a result object instead of throwing, because a dead alerting
  endpoint should never be the reason file monitoring itself stops.

## Limitations

See `SECURITY.md` for the full threat model. The short version: this tool
detects *what* changed on disk between two points in time, assuming
something else (the OS's own file permissions, at minimum) keeps the
attacker from also rewriting `file-sentry`'s own state directory. It is a
detection tool, not a prevention one.
