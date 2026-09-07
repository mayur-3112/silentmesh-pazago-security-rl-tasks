#!/usr/bin/env python3
"""Portable local runner for dep-confusion-hijack (no Docker). Builds env in a temp
dir, runs the oracle, grades with the same checks the container verifier uses.
Usage: python local_test.py         (oracle mode; expect full reward)
"""
import base64, zlib, os, hashlib, tempfile, subprocess, sys, json, re, shutil


def _w(p, t):
    with open(p, "w", newline="") as f:
        f.write(t)


def build(root):
    CACHE = os.path.join(root, "pip-cache"); MIRROR = os.path.join(root, "mirror")
    BUILD = os.path.join(root, "build"); SP = os.path.join(root, "sp")
    for d in (CACHE, MIRROR, BUILD, SP):
        os.makedirs(d, exist_ok=True)
    trusted = ('"""corp-auth-utils 2.9.0 (legit)."""\nimport hmac, hashlib\n'
               'def sign(secret, msg):\n    return hmac.new(secret, msg, hashlib.sha256).hexdigest()\n'
               '__version__ = "2.9.0"\n')
    twhl = os.path.join(CACHE, "corp_auth_utils-2.9.0-py3-none-any.whl"); _w(twhl, trusted)
    TSHA = hashlib.sha256(trusted.encode()).hexdigest()
    ind = 'host="auth-metrics-collector.net"; scheme="https"'
    blob = base64.b64encode(zlib.compress(ind.encode(), 9)).decode()
    mal = ('"""corp-auth-utils 2.9.9."""\nimport hmac, hashlib, base64 as _b, zlib as _z\n'
           '_M = "%s"\n'
           'def _bootstrap():\n    try:\n        exec(compile(_z.decompress(_b.b64decode(_M)), "<m>", "exec"), {})\n'
           '    except Exception:\n        pass\n'
           'def sign(secret, msg):\n    return hmac.new(secret, msg, hashlib.sha256).hexdigest()\n'
           '__version__ = "2.9.9"\n_bootstrap()\n') % blob
    mwhl = os.path.join(CACHE, "corp_auth_utils-2.9.9-py3-none-any.whl"); _w(mwhl, mal)
    _w(os.path.join(SP, "corp_auth_utils.py"), mal)     # active install = malicious
    _w(os.path.join(MIRROR, "index.json"),
       '{"corp-auth-utils": {"version": "2.9.0", "sha256": "%s"}}\n' % TSHA)
    _w(os.path.join(BUILD, "install.log"),
       "Found link corp-auth-utils 2.9.0 (from mirror.corp.internal)\n"
       "Found link corp-auth-utils 2.9.9 (from pypi.org)\n"
       "Using version 2.9.9\nSuccessfully installed corp-auth-utils-2.9.9\n")
    _w(os.path.join(BUILD, "requirements.lock"),
       "corp-auth-utils>=2.9.0\nrequests==2.31.0 --hash=sha256:deadbeef\n")
    return dict(root=root, SP=SP, CACHE=CACHE,
                LOCK=os.path.join(BUILD, "requirements.lock"),
                TWHL=twhl, MWHL=mwhl, REPORT=os.path.join(root, "report.json"),
                TSHA=TSHA)


def oracle(P):
    src = open(P["MWHL"]).read()
    host = re.search(r'host\s*=\s*"([^"]+)"',
                     zlib.decompress(base64.b64decode(
                         re.search(r'_M\s*=\s*"([^"]+)"', src).group(1))).decode()).group(1)
    sha = hashlib.sha256(open(P["TWHL"], "rb").read()).hexdigest()
    report = {"confused_package": "corp-auth-utils", "malicious_version": "2.9.9",
              "trusted_version": "2.9.0", "malicious_artifact": P["MWHL"],
              "missing_control": "hash-pinning", "indicator_host": host,
              "primary_cwe": "CWE-494", "owasp_a": "A08:2021"}
    json.dump(report, open(P["REPORT"], "w"), indent=2)
    out = ["corp-auth-utils==2.9.0 --hash=sha256:%s\n" % sha
           if l.lower().startswith("corp-auth-utils") else l for l in open(P["LOCK"])]
    _w(P["LOCK"], "".join(out))


def grade(P):
    res = []
    def chk(n, c): res.append((n, bool(c)))
    d = json.load(open(P["REPORT"]))
    g = lambda k: str(d.get(k, "")).strip()
    KEYS = {"confused_package","malicious_version","trusted_version","malicious_artifact",
            "missing_control","indicator_host","primary_cwe","owasp_a"}
    chk("R1 keys", set(d) == KEYS)
    chk("R2 package", g("confused_package").lower() == "corp-auth-utils")
    chk("R3 mal version", g("malicious_version") == "2.9.9")
    chk("R4 trusted version", g("trusted_version") == "2.9.0")
    chk("R5 artifact", os.path.normpath(g("malicious_artifact")) == os.path.normpath(P["MWHL"]))
    chk("R6 missing control", g("missing_control").lower() == "hash-pinning")
    chk("R7 indicator host", g("indicator_host").lower() == "auth-metrics-collector.net")
    chk("R8 cwe", g("primary_cwe").upper().replace(" ", "") == "CWE-494")
    chk("R9 owasp", g("owasp_a").upper().replace(" ", "") == "A08:2021")
    line = next((l for l in open(P["LOCK"]).read().splitlines()
                 if re.match(r"\s*corp-auth-utils", l, re.I)), "")
    m = re.search(r"sha256:([0-9a-fA-F]{64})", line)
    chk("R10 fix pins trusted+hash",
        bool(re.search(r"==\s*2\.9\.0", line)) and m and m.group(1).lower() == P["TSHA"])
    chk("R11 decoy untouched", "requests==2.31.0 --hash=sha256:deadbeef" in open(P["LOCK"]).read())
    o = subprocess.run([sys.executable, "-c",
                        "import corp_auth_utils;print(corp_auth_utils.sign(b'k', b'm'))"],
                       env=dict(os.environ, PYTHONPATH=P["SP"]), capture_output=True, text=True)
    chk("R12 import preserved", o.returncode == 0 and len(o.stdout.strip()) == 64)
    passed = sum(1 for _, ok in res if ok)
    for n, ok in res:
        print(("  PASS " if ok else "  FAIL ") + n)
    print("\nREWARD = %d/%d = %.3f" % (passed, len(res), passed / len(res)))
    return passed / len(res)


if __name__ == "__main__":
    root = tempfile.mkdtemp(prefix="dch_")
    P = build(root)
    print("Environment built at: " + root)
    oracle(P)
    grade(P)
    print("(temp env left at %s)" % root)
