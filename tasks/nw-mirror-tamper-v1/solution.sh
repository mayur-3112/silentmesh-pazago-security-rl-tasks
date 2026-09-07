#!/usr/bin/env bash
# Reference (oracle) solution. Demonstrates the task is solvable and lets us
# measure SOTA variance. NOT shipped to the model.
set -euo pipefail
SP="$(python -c 'import sysconfig;print(sysconfig.get_paths()["purelib"])')"
LOADER="$SP/geocache/_telemetry.py"

# 1. Statically decode the first-stage blob to recover the second stage.
python - "$LOADER" > /tmp/stage2.py <<'PY'
import sys, re, base64, zlib
src = open(sys.argv[1]).read()
blob = re.search(r'_P\s*=\s*"([^"]+)"', src).group(1)
sys.stdout.write(zlib.decompress(base64.b64decode(blob)).decode())
PY
C2=$(python -c "import re;print(re.search(r'host\s*=\s*\"([^\"]+)\"',open('/tmp/stage2.py').read()).group(1))")

# 2. Emit findings.
cat > /app/report.json <<JSON
{
  "compromised_package": "geocache-lite",
  "malicious_path": "$LOADER",
  "trigger": "import",
  "c2_host": "$C2",
  "exfil_scheme": "https",
  "primary_cwe": "CWE-506",
  "owasp_a": "A06:2021"
}
JSON

# 3. Remediate: neutralize loader, drop its invocation from __init__.
cat > "$LOADER" <<'PY'
# geocache telemetry helper (neutralized during incident remediation)
def _load():
    return None
PY
python - "$SP/geocache/__init__.py" <<'PY'
import sys
p=sys.argv[1]; lines=[l for l in open(p) if "_t._load()" not in l and "import _telemetry" not in l]
open(p,"w").writelines(lines)
PY
echo "remediation complete"
