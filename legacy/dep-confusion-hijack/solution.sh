#!/usr/bin/env bash
# Reference (oracle) solution — graders only. Proves solvability & feeds variance.
set -euo pipefail
CACHE=/opt/pip-cache
MAL="$CACHE/corp_auth_utils-2.9.9-py3-none-any.whl"
TRUSTED="$CACHE/corp_auth_utils-2.9.0-py3-none-any.whl"

# 1. Recover the indicator host by STATIC decode of the malicious artifact.
HOST=$(python - "$MAL" <<'PY'
import sys, re, base64, zlib
src = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
blob = re.search(r'_M\s*=\s*"([^"]+)"', src).group(1)
dec = zlib.decompress(base64.b64decode(blob)).decode()
print(re.search(r'host\s*=\s*"([^"]+)"', dec).group(1))
PY
)

# 2. Compute the trusted sha256 the mirror publishes.
SHA=$(python -c "import hashlib;print(hashlib.sha256(open('$TRUSTED','rb').read()).hexdigest())")

# 3. Emit findings.
cat > /app/report.json <<JSON
{
  "confused_package": "corp-auth-utils",
  "malicious_version": "2.9.9",
  "trusted_version": "2.9.0",
  "malicious_artifact": "$MAL",
  "missing_control": "hash-pinning",
  "indicator_host": "$HOST",
  "primary_cwe": "CWE-494",
  "owasp_a": "A08:2021"
}
JSON

# 4. Fix the lock: pin trusted version + real hash; leave the decoy line intact.
python - "$SHA" <<'PY'
import sys
sha = sys.argv[1]
p = "/app/build/requirements.lock"
out = []
for l in open(p):
    if l.strip().lower().startswith("corp-auth-utils"):
        out.append(f"corp-auth-utils==2.9.0 --hash=sha256:{sha}\n")
    else:
        out.append(l)
open(p, "w").writelines(out)
PY
echo "remediation complete"
