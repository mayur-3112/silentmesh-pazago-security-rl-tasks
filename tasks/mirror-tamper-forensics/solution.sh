#!/usr/bin/env bash
# Reference (oracle) solution -- graders only. Proves solvability and feeds reward
# variance. Performs the full forensic chain: localise via the RECORD manifest, decode
# the four-stage payload statically, write the findings report, then remediate by
# restoring the clean package from the mirror.
set -euo pipefail

python - <<'PY'
import os, re, base64, zlib, marshal, hashlib, json, shutil, sysconfig

SP = sysconfig.get_paths()["purelib"]
MIRROR = "/opt/mirror"
pkg = os.path.join(SP, "geocache")

def _b64(d):
    return base64.urlsafe_b64encode(d).decode().rstrip("=")

# 1. localise: the file whose installed hash no longer matches the RECORD manifest
record = os.path.join(SP, "geocache-2.3.1.dist-info", "RECORD")
malicious = None
for line in open(record):
    p = line.strip().split(",")
    if len(p) >= 2 and p[0].startswith("geocache/") and p[1]:
        fp = os.path.join(SP, p[0])
        if os.path.exists(fp):
            cur = _b64(hashlib.sha256(open(fp, "rb").read()).digest())
            if cur != p[1].split("=", 1)[1]:
                malicious = fp
assert malicious, "no manifest mismatch found"

# 2. integrity evidence
clean_src = os.path.join(MIRROR, "geocache-2.3.1", "geocache", "_cache.py")
recorded_hash = hashlib.sha256(open(clean_src, "rb").read()).hexdigest()
actual_hash = hashlib.sha256(open(malicious, "rb").read()).hexdigest()

# 3. four-stage static decode: base85 -> XOR(key) -> zlib -> marshal
res = os.path.join(os.path.dirname(malicious), "_resources")
blob = open(os.path.join(res, "grid.tbl"), "rb").read().split(b"\n#IDX1\n", 1)[1]
key_hex = open(os.path.join(res, ".buildcache")).read().strip()
key = bytes.fromhex(key_hex)
raw = base64.b85decode(blob)
dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
code = marshal.loads(zlib.decompress(dec))

strs, ints, byts = [], [], []
def _walk(c):
    for k in c.co_consts:
        if isinstance(k, str):
            strs.append(k)
        elif isinstance(k, bool):
            pass
        elif isinstance(k, int):
            ints.append(k)
        elif isinstance(k, bytes):
            byts.append(k)
        elif hasattr(k, "co_consts"):
            _walk(k)
_walk(code)
# the host is XOR-encrypted; the payload derives its key at runtime from the env var
# $GC_BUILD_SIG (unset in the sandbox, so it never contacts the real host). The key is
# the module's recorded build signature -- the RECORD manifest's recorded (clean) hash.
key16 = bytes.fromhex(recorded_hash)[:16]
host = None
for bc in byts:
    try:
        cand = bytes(x ^ key16[i % 16] for i, x in enumerate(bc)).decode()
    except Exception:
        continue
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", cand):
        host = cand
assert host, "host not recovered from payload"
endpoint = next(s for s in strs if s.startswith("/"))
port = next(i for i in ints if 1024 < i < 65536)

report = {
    "compromised_package": "geocache",
    "malicious_path": malicious,
    "trigger": "import",
    "c2_host": host,
    "c2_port": port,
    "exfil_endpoint": endpoint,
    "decode_key": key_hex,
    "primary_cwe": "CWE-506",
    "owasp_a": "A08:2021",
    "recorded_hash": recorded_hash,
    "actual_hash": actual_hash,
}
os.makedirs("/app", exist_ok=True)
json.dump(report, open("/app/report.json", "w"), indent=2)

# 4. remediate: restore the clean modules from the mirror and drop the rogue resources
src = os.path.join(MIRROR, "geocache-2.3.1", "geocache")
for f in ("__init__.py", "_grid.py", "_cache.py"):
    shutil.copy(os.path.join(src, f), os.path.join(pkg, f))
shutil.rmtree(res, ignore_errors=True)
print("oracle done:", host, port, endpoint)
PY
