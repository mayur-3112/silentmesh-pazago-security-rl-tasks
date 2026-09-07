#!/usr/bin/env bash
# Grader entrypoint. Emits a FRACTIONAL reward (fraction of the 16 independent
# verifier items that pass) so partial credit -> non-zero reward variance, as the
# acceptance model requires. Works whether the tests are mounted at /app/tests
# (Terminal-Bench) or /tests (Harbor). Deliberately does NOT use `set -e` around the
# pytest call, so a partial (failing) run still records its fraction rather than
# aborting before the reward is written.
set -uo pipefail
pip install --no-cache-dir "pytest==8.2.0" >/dev/null 2>&1 || true
mkdir -p /logs/verifier 2>/dev/null || true
cd /app

TESTF=/app/tests/test_outputs.py
[ -f "$TESTF" ] || TESTF=/tests/test_outputs.py

out=$(pytest -q --no-header -rN -p no:cacheprovider -o cache_dir=/tmp/pc "$TESTF" 2>&1) || true
echo "$out" | tail -4

passed=$(printf '%s\n' "$out" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1); passed=${passed:-0}
failed=$(printf '%s\n' "$out" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' | head -1); failed=${failed:-0}
total=$((passed + failed))
if [ "$total" -gt 0 ]; then
    reward=$(python3 -c "print('%.6f' % ($passed/$total))")
else
    reward=0
fi
echo "REWARD = ${passed}/${total} = ${reward}"
echo "$reward" > /logs/verifier/reward.txt 2>/dev/null || true
# Exit 0 iff every item passed (full reward); the numeric reward above is the signal.
[ "$failed" -eq 0 ] && [ "$total" -gt 0 ]
