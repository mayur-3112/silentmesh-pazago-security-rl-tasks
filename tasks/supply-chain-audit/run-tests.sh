#!/usr/bin/env bash
# Grader entrypoint. This task is accepted on the BINARY route (PDF: "Binary rewards work
# too ... frontier model pass rate <= 0.5"; security category: frontier pass@5 < 0.4), so
# the emitted reward is BINARY: 1.0 iff every independent verifier item passes (a complete,
# correct triage + remediation), else 0.0. The fractional pass fraction is still computed
# and logged for the org's failure-mode analysis / difficulty profiling. Works whether the
# tests are mounted at /app/tests (Terminal-Bench) or /tests (Harbor). Deliberately avoids
# `set -e` around pytest so a partial (failing) run still records a 0 reward.
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
    frac=$(python3 -c "print('%.6f' % ($passed/$total))")
else
    frac=0
fi
# Binary reward: full solve only.
if [ "$failed" -eq 0 ] && [ "$total" -gt 0 ]; then
    reward=1.0
else
    reward=0.0
fi
echo "PASS_FRACTION = ${passed}/${total} = ${frac}   (reference only)"
echo "REWARD = ${reward}   (binary: 1.0 iff full solve)"
echo "$reward" > /logs/verifier/reward.txt 2>/dev/null || true
# Exit 0 iff the binary reward is 1.0.
[ "$failed" -eq 0 ] && [ "$total" -gt 0 ]
