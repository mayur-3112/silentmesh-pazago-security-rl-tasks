#!/usr/bin/env bash
# Reference (oracle) solution -- graders only. Proves solvability & feeds variance.
set -euo pipefail
SP="$(python -c 'import sysconfig;print(sysconfig.get_paths()["purelib"])')"
GRID="$SP/geocache/_grid.py"
MIRROR="/opt/mirror/geocache-lite-1.4.2/_grid.py"

python - "$GRID" "$MIRROR" <<'PY'
import sys, os, re, base64, zlib, hashlib, json
grid, mirror = sys.argv[1], sys.argv[2]
src = open(grid).read()

# 1. integrity: recorded (clean) hash vs actual (tampered) hash
recorded_hash = hashlib.sha256(open(mirror, "rb").read()).hexdigest()
actual_hash = hashlib.sha256(open(grid, "rb").read()).hexdigest()

# 2. two-step de-obfuscation of the appended payload
salt = bytes.fromhex(re.search(r'_SALT\s*=\s*"([0-9a-fA-F]+)"', src).group(1))
data = base64.b64decode(re.search(r'_DATA\s*=\s*"([^"]+)"', src).group(1))
un = bytes(x ^ salt[i % len(salt)] for i, x in enumerate(data))
dec = zlib.decompress(un).decode()
host = re.search(r'host\s*=\s*"([^"]+)"', dec).group(1)
scheme = re.search(r'scheme\s*=\s*"([^"]+)"', dec).group(1)

report = {
    "compromised_package": "geocache-lite",
    "malicious_path": grid,
    "trigger": "import",
    "c2_host": host,
    "exfil_scheme": scheme,
    "primary_cwe": "CWE-506",
    "owasp_a": "A06:2021",
    "recorded_hash": recorded_hash,
    "actual_hash": actual_hash,
}
json.dump(report, open("/app/report.json", "w"), indent=2)

# 3. remediate by restoring the clean module from the mirror
import shutil
shutil.copy(mirror, grid)
print("oracle done")
PY
