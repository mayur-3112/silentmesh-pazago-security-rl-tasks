#!/usr/bin/env bash
# Reference (oracle) solution -- graders only. Proves solvability and feeds reward
# variance. Performs the full forensic chain: localise the injected .pth and the loader
# module it imports (a file absent from the dist-info RECORD), decode the four-stage
# payload statically, write the findings report, then remediate by removing the .pth,
# the loader module, and the obfuscated resources.
set -euo pipefail

python - <<'PY'
import os, re, glob, base64, zlib, marshal, hashlib, json, shutil, sysconfig

SP = sysconfig.get_paths()["purelib"]


def record_files(top):
    """Return the set of RECORD-listed rel paths for distribution <top>, or None."""
    for d in glob.glob(os.path.join(SP, top + "-*.dist-info")):
        rec = os.path.join(d, "RECORD")
        if os.path.exists(rec):
            out = set()
            for line in open(rec):
                p = line.strip().split(",")
                if p and p[0]:
                    out.add(p[0])
            return out
    return None


# 1. localise: a .pth whose 'import' line loads a module that is NOT listed in its
#    distribution's RECORD manifest -- an injected loader that runs at every startup.
pth_file = loader_module = None
for pth in sorted(glob.glob(os.path.join(SP, "*.pth"))):
    for line in open(pth, errors="replace"):
        s = line.strip()
        if s.startswith(("import ", "import\t")) and "." in s:
            mod = s.split(None, 1)[1].strip().split()[0]
            top = mod.split(".")[0]
            rel = mod.replace(".", "/") + ".py"
            fp = os.path.join(SP, rel)
            listed = record_files(top)
            if os.path.exists(fp) and listed is not None and rel not in listed:
                pth_file, loader_module = pth, fp
assert pth_file and loader_module, "no injected .pth/loader found"
compromised = os.path.basename(os.path.dirname(loader_module))

# 2. four-stage static decode: base85 -> XOR(key) -> zlib -> marshal
res = os.path.join(os.path.dirname(loader_module), "_resources")
blob = open(os.path.join(res, "table.bin"), "rb").read().split(b"\n#SEG2\n", 1)[1]
key_hex = open(os.path.join(res, ".keycache")).read().strip()
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
# the host is XOR-encrypted; the payload reads its decrypt key from an env var (unset here):
# reverse it statically -- for each bytes const and each single-byte key, xor and match
# a hostname regex (no plaintext host constant exists to read).
# host is XOR-encrypted; the payload reads its decrypt key at runtime from an env var
# (unset here, so a naive startup decrypts to garbage). The real key is the build
# signature: sha256 of the clean metricslib/_stats.py (its hash is in the RECORD manifest).
key16 = bytes.fromhex(hashlib.sha256(
    open(os.path.join(SP, "metricslib", "_stats.py"), "rb").read()).hexdigest())[:16]
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
    "compromised_package": compromised,
    "pth_file": pth_file,
    "loader_module": loader_module,
    "trigger": "interpreter-startup",
    "c2_host": host,
    "c2_port": port,
    "exfil_endpoint": endpoint,
    "decode_key": key_hex,
    "primary_cwe": "CWE-506",
    "owasp_a": "A06:2021",
}
os.makedirs("/app", exist_ok=True)
json.dump(report, open("/app/report.json", "w"), indent=2)

# 3. remediate: remove the malicious .pth, the injected loader, and the obfuscated
#    resources, leaving the legitimate package files (which still match the manifest).
os.remove(pth_file)
os.remove(loader_module)
shutil.rmtree(res, ignore_errors=True)
print("oracle done:", host, port, endpoint)
PY
