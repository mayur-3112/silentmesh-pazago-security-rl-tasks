#!/usr/bin/env bash
# Reference oracle -- graders only. Proves solvability & feeds variance.
set -euo pipefail
PKL=/app/service/cache/policy.pkl
SVC=/app/service/src/svc/config.py

python - "$PKL" <<'PY'
import sys, re, base64, zlib, json
raw = open(sys.argv[1], "rb").read().decode("latin-1")
key = bytes.fromhex(re.search(r'_K\s*=\s*bytes\.fromhex\("([0-9a-f]+)"\)', raw).group(1))
d = re.search(r'_D\s*=\s*"([A-Za-z0-9+/=]+)"', raw).group(1)
src = (lambda raw,key: zlib.decompress(bytes([raw[i] ^ key[i%len(key)] for i in range(len(raw))])).decode())(base64.b64decode(d), key)
host = re.search(r'host="([^"]+)"', src).group(1)
nonce = re.search(r'nonce="([^"]+)"', src).group(1)
json.dump({
    "vulnerable_call": "pickle.load",
    "artifact_path": "/app/service/cache/policy.pkl",
    "trigger": "deserialization",
    "c2_host": host,
    "exfil_scheme": "https",
    "indicator_nonce": nonce,
    "primary_cwe": "CWE-502",
    "owasp_a": "A08:2021",
}, open("/app/report.json", "w"), indent=2)
PY

# remediate: load the safe JSON policy from the mirror; no code execution
cat > "$SVC" <<'PY'
import json
SAFE = "/opt/mirror/policy.json"
def get():
    with open(SAFE) as f:
        return json.load(f)
PY
echo "oracle done"
