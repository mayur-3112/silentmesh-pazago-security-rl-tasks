#!/usr/bin/env bash
# Reference (oracle) solution -- graders only. Proves solvability and feeds reward
# variance. Performs the full chain: identify the confused package and its two cached
# artifacts from the resolver log + mirror index, RECOMPUTE the trusted wheel's
# integrity hash, statically decode the four-stage payload (base85 -> XOR -> zlib ->
# marshal) to read the C2 indicators, write the findings report, then remediate by
# re-pinning the lock to the trusted build and byte-restoring the installed package.
set -euo pipefail

python - <<'PY'
import os, re, json, base64, zlib, marshal, hashlib, shutil, sysconfig, zipfile

SP = sysconfig.get_paths()["purelib"]
CACHE = "/opt/pip-cache"
MIRROR = "/opt/mirror"
BUILD = "/app/build"
pkg = os.path.join(SP, "corp_auth_utils")

# 1. the internal mirror names the trusted build; identify both cached artifacts
index = json.load(open(os.path.join(MIRROR, "index.json")))
entry = index["packages"]["corp-auth-utils"]
trusted_version = entry["trusted_version"]
trusted_wheel = os.path.join(CACHE, entry["wheel"])
# the malicious artifact is the OTHER cached corp_auth_utils wheel (the installed one)
cand = sorted(f for f in os.listdir(CACHE)
              if f.startswith("corp_auth_utils-") and f.endswith(".whl"))
mal_name = next(f for f in cand if entry["wheel"] not in f)
malicious_wheel = os.path.join(CACHE, mal_name)
malicious_version = mal_name.split("-")[1]

# 2. RECOMPUTE the trusted wheel's sha256 (the mirror publishes it nowhere)
trusted_sha = hashlib.sha256(open(trusted_wheel, "rb").read()).hexdigest()

# 3. four-stage static decode of the installed payload -> C2 indicators
res = os.path.join(pkg, "_resources")
blob = open(os.path.join(res, "vendor.dat"), "rb").read().split(b"\n#VBC1\n", 1)[1]
key = bytes.fromhex(open(os.path.join(res, "cachekey.bin")).read().strip())
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
# the host is XOR-encrypted; the payload reads its decrypt key at runtime from an env var
# (unset here, so a naive detonation decrypts to garbage). The real key is the trusted
# build's signing-module hash -- recompute it from the clean _signing.py inside the
# trusted wheel, then decrypt statically.
_signing_bytes = None
with zipfile.ZipFile(trusted_wheel) as _zf:
    for _n in _zf.namelist():
        if _n.endswith("_signing.py"):
            _signing_bytes = _zf.read(_n)
key16 = bytes.fromhex(hashlib.sha256(_signing_bytes).hexdigest())[:16]
host = None
for bc in byts:
    try:
        cand = bytes(x ^ key16[i % 16] for i, x in enumerate(bc)).decode()
    except Exception:
        continue
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", cand):
        host = cand
assert host, "host not recovered from payload"
port = next(i for i in ints if 1024 < i < 65536)

report = {
    "confused_package": "corp-auth-utils",
    "malicious_version": malicious_version,
    "trusted_version": trusted_version,
    "malicious_artifact": malicious_wheel,
    "trusted_artifact": trusted_wheel,
    "trusted_sha256": trusted_sha,
    "missing_control": "hash-pinning",
    "indicator_host": host,
    "indicator_port": port,
    "primary_cwe": "CWE-494",
    "owasp_a": "A08:2021",
}
os.makedirs("/app", exist_ok=True)
json.dump(report, open("/app/report.json", "w"), indent=2)

# 4a. remediate the lock: pin the trusted version + recomputed hash; leave the rest
lock = os.path.join(BUILD, "requirements.lock")
out = []
for line in open(lock).read().splitlines():
    if line.startswith("corp-auth-utils=="):
        out.append("corp-auth-utils==%s --hash=sha256:%s" % (trusted_version, trusted_sha))
    else:
        out.append(line)
with open(lock, "w", newline="") as f:
    f.write("\n".join(out) + "\n")

# 4b. remediate the install: byte-restore corp_auth_utils from the trusted wheel
shutil.rmtree(pkg, ignore_errors=True)
with zipfile.ZipFile(trusted_wheel) as zf:
    for name in zf.namelist():
        if name.startswith("corp_auth_utils/") and not name.endswith("/"):
            dst = os.path.join(SP, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(zf.read(name))

print("oracle done:", host, port, "trusted_sha", trusted_sha[:12])
PY
