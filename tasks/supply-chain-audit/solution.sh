#!/usr/bin/env bash
# Reference (oracle) solution -- graders only. Proves the task is solvable end to end and
# feeds reward variance. Triages the installed tree, writes the findings report with every
# indicator recovered from disk, then remediates each compromise by its correct means
# (restore from mirror / repin to the trusted build / remove) while leaving the benign
# distributions in place and keeping the service importable.
set -euo pipefail

python - <<'PY'
import os, re, json, base64, shutil

SP = "/opt/service/venv/lib/python3.11/site-packages"
MIRROR = "/opt/mirror"
APP = "/app"

# ---- recover the encoded indicators straight from disk ----
def _read(p):
    with open(p) as f:
        return f.read()

_b64pat = r"b64decode\(\s*['\"]([^'\"]+)['\"]"
ind = {}
g = _read(os.path.join(SP, "geoindex", "_grid.py"))
ind["geoindex"] = base64.b64decode(re.search(_b64pat, g).group(1)).decode()

agg = _read(os.path.join(SP, "metricslib", "_agg.py"))
_h = re.search(r'_H = bytes\.fromhex\((.+?)\)', agg).group(1).strip().strip("'\"")
_k = re.search(r"_K = (.+?)\.encode", agg).group(1).strip().strip("'\"")
_hb, _kb = bytes.fromhex(_h), _k.encode()
ind["metricslib"] = bytes(b ^ _kb[i % len(_kb)] for i, b in enumerate(_hb)).decode()

ct = _read(os.path.join(SP, "corp_telemetry", "__init__.py"))
ind["corp-telemetry"] = re.search(r'__version__ = "([^"]+)"', ct).group(1)
ind["sluglfy"] = "slugify"
ind["buildtools-ext"] = _read(os.path.join(SP, "buildtools_ext_autoload.pth")).strip().replace("import ", "").strip()
lw = _read(os.path.join(SP, "logkit", "_writer.py"))
ind["logkit"] = base64.b64decode(re.search(_b64pat, lw).group(1)).decode()
hk = _read(os.path.join(SP, "svc_cli", "_hooks.py"))
ind["svc-cli"] = base64.b64decode(re.search(_b64pat, hk).group(1)).decode()
ind["urllib33"] = "urllib3"
mc = _read(os.path.join(SP, "metrics_core", "__init__.py"))
ind["metrics-core"] = re.search(r'__version__ = "([^"]+)"', mc).group(1)

vec = {"geoindex": "tampered-file", "metricslib": "malicious-wheel",
       "corp-telemetry": "dependency-confusion", "sluglfy": "typosquat",
       "buildtools-ext": "install-hook", "logkit": "malicious-wheel", "svc-cli": "malicious-wheel",
       "urllib33": "typosquat", "metrics-core": "dependency-confusion"}
trig = {"geoindex": "import", "metricslib": "import", "corp-telemetry": "import",
        "sluglfy": "import", "buildtools-ext": "interpreter-startup",
        "logkit": "import", "svc-cli": "runtime-entrypoint",
        "urllib33": "import", "metrics-core": "import"}
cwe = {"corp-telemetry": "CWE-494", "metrics-core": "CWE-494"}

report = {"compromised": []}
for name in ["geoindex", "metricslib", "corp-telemetry", "sluglfy", "buildtools-ext",
             "logkit", "svc-cli", "urllib33", "metrics-core"]:
    report["compromised"].append({
        "package": name, "vector": vec[name], "trigger": trig[name],
        "cwe": cwe.get(name, "CWE-506"), "owasp": "A08:2021", "indicator": ind[name]})
os.makedirs(APP, exist_ok=True)
json.dump(report, open(os.path.join(APP, "report.json"), "w"), indent=2)

# ---- remediate ----
# V1 geoindex: restore the clean module from the mirror
shutil.copy(os.path.join(MIRROR, "geoindex-1.2.0", "geoindex", "_grid.py"),
            os.path.join(SP, "geoindex", "_grid.py"))
# V2 metricslib: restore the clean __init__ and drop the malicious backend
shutil.copy(os.path.join(MIRROR, "metricslib-0.7.3", "metricslib", "__init__.py"),
            os.path.join(SP, "metricslib", "__init__.py"))
try:
    os.remove(os.path.join(SP, "metricslib", "_agg.py"))
except OSError:
    pass
# V3 corp-telemetry: repin to the internal 1.4.2 build from the mirror
shutil.copy(os.path.join(MIRROR, "corp_telemetry-1.4.2", "corp_telemetry", "__init__.py"),
            os.path.join(SP, "corp_telemetry", "__init__.py"))
# V4 sluglfy: remove the typosquat and fix the shim to use the legit slugify
shutil.rmtree(os.path.join(SP, "sluglfy"), ignore_errors=True)
for d in os.listdir(SP):
    if d.startswith("sluglfy-") and d.endswith(".dist-info"):
        shutil.rmtree(os.path.join(SP, d), ignore_errors=True)
shim = os.path.join(APP, "service", "src", "svc", "shim.py")
_s = open(shim).read().replace("import sluglfy as _slug", "import slugify as _slug")
open(shim, "w").write(_s)
# V5 buildtools-ext: remove the startup .pth hook
try:
    os.remove(os.path.join(SP, "buildtools_ext_autoload.pth"))
except OSError:
    pass
# V6 logkit: restore the clean _writer.py from the mirror
shutil.copy(os.path.join(MIRROR, "logkit-2.1.0", "logkit", "_writer.py"),
            os.path.join(SP, "logkit", "_writer.py"))
# V7 svc-cli: drop the malicious entry-point backend + its console_scripts mapping
try:
    os.remove(os.path.join(SP, "svc_cli", "_hooks.py"))
except OSError:
    pass
try:
    os.remove(os.path.join(SP, "svc_cli-0.6.0.dist-info", "entry_points.txt"))
except OSError:
    pass
# V8 urllib33: remove the second typosquat + fix the net module to use the legit urllib3
shutil.rmtree(os.path.join(SP, "urllib33"), ignore_errors=True)
for d in os.listdir(SP):
    if d.startswith("urllib33-") and d.endswith(".dist-info"):
        shutil.rmtree(os.path.join(SP, d), ignore_errors=True)
net = os.path.join(APP, "service", "src", "svc", "net.py")
_n = open(net).read().replace("import urllib33", "import urllib3 as urllib33")
open(net, "w").write(_n)
# V9 metrics-core: repin to the internal 2.0.0 build from the mirror
shutil.copy(os.path.join(MIRROR, "metrics_core-2.0.0", "metrics_core", "__init__.py"),
            os.path.join(SP, "metrics_core", "__init__.py"))

print("oracle done:", ind)
PY
