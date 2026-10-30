# Security model

`file-sentry` is a detection tool: it tells you what changed on disk
between two points in time, and keeps a tamper-evident record of its own
findings. It is **not** a prevention tool — it cannot stop a change from
happening, only notice and report it. Being clear about that boundary is
the point of this document.

## Threat model

| Threat | Detected? | How |
|---|---|---|
| A file's content is modified | Yes | SHA-256 hash mismatch against the baseline |
| A file is added or deleted | Yes | Key present/absent in the current scan vs. baseline |
| A file's permission bits change (content unchanged) | Yes | `mode` mismatch, reported separately from content changes |
| A symlink's target is changed | Yes | The target path string is hashed and compared like file content |
| Someone edits a *past* audit log entry to hide what it recorded | Yes | Breaks that entry's own `entry_hash` |
| Someone deletes or reorders a *past* audit log entry | Yes | Breaks the `prev_hash` link to/from the adjacent entry |
| Someone truncates the *end* of the audit log (drops the most recent N entries) | **No, not by `verify_log` alone** | See "Known limitation" below |
| A root-privileged attacker directly edits `baseline.db` to match their changes, instead of tampering with the log | **No** | `file-sentry` trusts its own baseline file; see "Out of scope" |
| An attacker races the scan (modifies a file, then reverts it, between two scans) | **No** | Only the state *at scan time* is ever compared; a change-then-revert between scans is invisible by design — this is a point-in-time tool, not continuous byte-level auditing |
| The watch-mode webhook endpoint is down or rejects the request | Detected and logged, not silently lost | `send_webhook` never raises; a failed delivery is still written to the audit log as a `webhook_sent` event with `sent: false` |
| A change happens while `watch` isn't running (process killed, host rebooted) | Detected on the next `scan` or `watch` startup | The baseline is the source of truth, not "events seen while running" |

## Known limitation: tail truncation of the audit log

The hash chain links each entry to the one before it. That means editing,
deleting, or reordering an entry *in the middle* of the log breaks a link
and is caught by `verify_log`. But deleting the **most recent** entries —
truncating the file's tail — breaks nothing: every entry that's left still
correctly points to the entry before it. The chain looks perfectly intact,
because it is; it's just shorter than it used to be.

This is proven directly in the test suite
(`tests/test_auditlog.py::test_truncating_the_tail_is_detected_by_the_caller_comparing_counts`),
which deliberately drops the last two of five entries and asserts that
`verify_log` still reports `ok=True` — on a shorter log.

**Mitigation:** `verify_log`'s result includes `entries_checked`. If you
keep an independent record of the expected count (or the hash of the last
known-good entry) outside of this tool — a value shipped to a separate
logging pipeline, a SIEM, write-once storage, or even just a number
written down after a trusted scan — a truncation becomes detectable by
comparing that external count against what `status`/`verify-log` reports
now. `file-sentry` deliberately doesn't try to solve this internally,
because anything it could write to "remember the last count" lives on the
same disk the attacker already has write access to, and so is just as
truncatable as the log itself. Solving it for real means writing the count
somewhere the attacker in this threat model *doesn't* have access to —
which is a deployment decision, not something a single-host CLI tool can
guarantee on its own.

## Out of scope

- **Compromise of the host running `file-sentry` itself.** If an attacker
  has write access to `baseline.db`, they can simply update it to match
  whatever they changed, and no diff will ever be reported. Protecting
  `state_dir` (file permissions, a separate user, a read-only mount after
  the baseline is written) is the operator's responsibility, the same way
  it is for Tripwire, AIDE, or any other local FIM.
- **Confidentiality.** `file-sentry` tells you a file's *hash* changed; it
  does not tell you what the new content is, and the audit log doesn't
  store file contents.
- **Real-time, sub-second detection.** `watch` mode uses polling for
  portability (see the README), with a configurable debounce. This is a
  drift detector on a scale of seconds, not an intrusion-prevention system.
- **Protecting the webhook endpoint or its secrets.** Webhook URLs and
  headers are stored in plain YAML in the config file; treat that file
  with the same care as any other file containing credentials.

## Reporting a vulnerability

This is a portfolio project, not a maintained service. If you find a
genuine security issue, please open a GitHub issue describing it.
