#!/usr/bin/env bash
set -euo pipefail
pip install --no-cache-dir "pytest==8.2.0" >/dev/null 2>&1 || true
cd /app
# Reward = fraction of passing test items; harness reads pytest exit + count.
pytest -q /app/tests/test_outputs.py -o cache_dir=/tmp/pc
