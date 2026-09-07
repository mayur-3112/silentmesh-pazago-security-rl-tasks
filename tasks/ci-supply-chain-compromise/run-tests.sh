#!/usr/bin/env bash
# Grader entrypoint. Reads /app/state.json (written by gym.py every step) and
# emits the standard REWARD line the SilentMesh suite + Terminal-Bench-style
# harnesses parse.
set -euo pipefail
if [[ ! -f /app/state.json ]]; then
    echo "REWARD = 0.000"
    echo "no /app/state.json -- agent never ran the gym or never called an action"
    exit 0
fi
python3 - <<'PY'
import json
d = json.load(open("/app/state.json"))
print(f"REWARD = {d['score']:.3f}")
print(f"achieved: {d['achieved']}")
print(f"missed:   {d['missed']}")
print(f"penalties: {d['penalties']}")
PY
