#!/bin/bash
# Sabotage testing: deliberately break the code in specific places and confirm the test suite
# catches each one. Run from the project root with the venv active. Each case backs up the file,
# applies a one-line break, runs pytest, records pass/fail, then restores the original.
set -u
cd "$(dirname "$0")/.."
. .venv/bin/activate

pass=0
fail=0

run_case() {
  local name="$1" file="$2" from="$3" to="$4"
  cp "$file" "$file.orig"
  python3 - "$file" "$from" "$to" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if old not in text:
    print(f"  !! pattern not found in {path}: {old!r}")
    sys.exit(1)
open(path, "w").write(text.replace(old, new, 1))
PYEOF
  if [ $? -ne 0 ]; then
    echo "[$name] SKIPPED (pattern not found)"
    cp "$file.orig" "$file"
    rm "$file.orig"
    return
  fi
  if python -m pytest -q >/tmp/sabotage_out.txt 2>&1; then
    echo "[$name] NOT CAUGHT  <-- tests still passed with this bug in place!"
    fail=$((fail+1))
  else
    echo "[$name] caught ($(grep -c 'FAILED' /tmp/sabotage_out.txt) test(s) failed)"
    pass=$((pass+1))
  fi
  cp "$file.orig" "$file"
  rm "$file.orig"
}

echo "=== Sabotage testing: breaking file_sentry on purpose, one change at a time ==="

run_case "S1: skip entry_hash verification in verify_log" \
  "file_sentry/auditlog.py" \
  'if recomputed != entry.entry_hash:' \
  'if False and recomputed != entry.entry_hash:'

run_case "S2: skip prev_hash chain check in verify_log" \
  "file_sentry/auditlog.py" \
  'if entry.prev_hash != expected_prev:' \
  'if False and entry.prev_hash != expected_prev:'

run_case "S3: skip sequence check in verify_log" \
  "file_sentry/auditlog.py" \
  'if entry.seq != expected_seq:' \
  'if False and entry.seq != expected_seq:'

run_case "S4: permission changes never reported (records.py)" \
  "file_sentry/records.py" \
  'elif old.mode != new.mode:' \
  'elif False and old.mode != new.mode:'

run_case "S5: content changes no longer take priority over permission changes" \
  "file_sentry/records.py" \
  'elif old.hash != new.hash:' \
  'elif False and old.hash != new.hash:'

run_case "S6: mtime differences wrongly trigger a finding" \
  "file_sentry/records.py" \
  'elif old.mode != new.mode:' \
  'elif old.mode != new.mode or old.mtime != new.mtime:'

run_case "S7: excluded directories are no longer pruned (still walked)" \
  "file_sentry/scanner.py" \
  'if not config.is_excluded(f"{rel_dir}/{d}".lstrip("./"))' \
  'if True'

run_case "S8: save_baseline no longer replaces old rows (DELETE removed)" \
  "file_sentry/baseline.py" \
  'conn.execute("DELETE FROM files")' \
  'pass  # conn.execute("DELETE FROM files")'

run_case "S9: hash_file stops reading after the first chunk" \
  "file_sentry/hashing.py" \
  'while chunk := f.read(CHUNK_SIZE):' \
  'while False and (chunk := f.read(CHUNK_SIZE)):'

run_case "S10: send_webhook stops wrapping the payload in {\"events\": [...]}" \
  "file_sentry/alerts.py" \
  'body = json.dumps({"events": events}).encode()' \
  'body = json.dumps(events).encode()'

run_case "S11: run_check stops logging the scan event when clean" \
  "file_sentry/engine.py" \
  'auditlog.append_event(log, "scan", {"file_count": len(current), "changes": diff.total_changes})' \
  'pass  # scan event no longer logged'

run_case "S12: scan() no longer records symlinks distinctly" \
  "file_sentry/scanner.py" \
  'if is_symlink and not config.follow_symlinks:' \
  'if False and is_symlink and not config.follow_symlinks:'

run_case "S13: CLI scan always exits 0 regardless of diff" \
  "file_sentry/cli.py" \
  'sys.exit(0 if diff.is_clean else 1)' \
  'sys.exit(0)'

run_case "S14: CLI init no longer refuses to rebuild without --force" \
  "file_sentry/cli.py" \
  'if has_baseline(db_path(config)) and not force:' \
  'if False and has_baseline(db_path(config)) and not force:'

echo "=== Done: $pass caught, $fail NOT caught ==="
[ "$fail" -eq 0 ]
