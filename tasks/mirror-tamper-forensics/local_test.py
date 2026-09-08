#!/usr/bin/env python3
"""Docker-free runner for mirror-tamper-forensics (Windows/Mac/Linux, Python only).

  python local_test.py            # build env + run oracle + grade   (proves it works)
  python local_test.py --manual   # build env, print paths, wait, then grade your try
  python local_test.py --lazy     # build env + score a do-nothing/guessing submission
                                   # (measures the reward-hacking floor; expect ~0)

It imports the SAME env/gen/build_env.py the container uses and the SAME
tests/test_outputs.py verifier, and cross-checks the verifier's embedded constants
against a fresh build so drift fails loudly.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(mod_name, rel):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(HERE, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load("mtf_build_env", os.path.join("env", "gen", "build_env.py"))
V = _load("mtf_verifier", os.path.join("tests", "test_outputs.py"))


def _sync_check(gt):
    """Fail loudly if the verifier's embedded constants drift from the generator."""
    pairs = [
        ("EXP_HOST", gt["c2_host"]), ("EXP_PORT", gt["c2_port"]),
        ("EXP_CAMPAIGN", gt["campaign_id"]),
        ("EXP_ENDPOINT", gt["exfil_endpoint"]), ("EXP_KEY", gt["decode_key"]),
        ("EXP_TAMPERED_HASH", gt["actual_hash"]), ("EXP_PKG", gt["compromised_package"]),
        ("EXP_TRIGGER", gt["trigger"]), ("EXP_CWE", gt["primary_cwe"]),
        ("EXP_OWASP", gt["owasp_a"]), ("INJECTED_MARKER", gt["injected_marker"]),
    ]
    bad = [(n, getattr(V, n), exp) for n, exp in pairs if str(getattr(V, n)) != str(exp)]
    if bad:
        for n, got, exp in bad:
            print("  DRIFT %s: verifier=%r  build_env=%r" % (n, got, exp))
        raise SystemExit("verifier constants are out of sync with env/gen/build_env.py")


def oracle(sp, mirror, report_path):
    """Reference solve (mirror of solution.sh) against relocatable paths."""
    pkg = os.path.join(sp, "geocache")
    record = os.path.join(sp, "geocache-2.3.1.dist-info", "RECORD")
    b64 = lambda d: base64.urlsafe_b64encode(d).decode().rstrip("=")
    malicious = None
    for line in open(record):
        p = line.strip().split(",")
        if len(p) >= 2 and p[0].startswith("geocache/") and p[1]:
            fp = os.path.join(sp, p[0])
            if os.path.exists(fp) and b64(hashlib.sha256(open(fp, "rb").read()).digest()) != p[1].split("=", 1)[1]:
                malicious = fp
    clean_src = os.path.join(mirror, "geocache-2.3.1", "geocache", "_cache.py")
    recorded_hash = hashlib.sha256(open(clean_src, "rb").read()).hexdigest()
    actual_hash = hashlib.sha256(open(malicious, "rb").read()).hexdigest()
    res = os.path.join(os.path.dirname(malicious), "_resources")
    blob = open(os.path.join(res, "grid.tbl"), "rb").read().split(b"\n#IDX1\n", 1)[1]
    key_hex = open(os.path.join(res, ".buildcache")).read().strip()
    key = bytes.fromhex(key_hex)
    dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(base64.b85decode(blob)))
    code = marshal.loads(zlib.decompress(dec))
    strs, ints, byts = [], [], []

    def walk(c):
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
                walk(k)
    walk(code)
    import hashlib as _h
    campaign = host = endpoint = host_enc = None
    port = None
    for c in strs:
        k1 = _h.sha256(c.encode()).digest()[:16]
        for bc in byts:
            try:
                hh = bytes(x ^ k1[i % 16] for i, x in enumerate(bc)).decode()
            except Exception:
                continue
            if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", hh):
                campaign, host, host_enc = c, hh, bc
                break
        if host:
            break
    k2 = _h.sha256(host.encode()).digest()[:16]
    for bc in byts:
        if bc is host_enc:
            continue
        try:
            m = bytes(x ^ k2[i % 16] for i, x in enumerate(bc)).decode()
        except Exception:
            continue
        if re.match(r"^\d+\|/", m):
            _p, endpoint = m.split("|", 1)
            port = int(_p)
            break
    report = {
        "compromised_package": "geocache", "malicious_path": malicious, "trigger": "import",
        "campaign_id": campaign,
        "c2_host": host, "c2_port": port, "exfil_endpoint": endpoint,
        "decode_key": key_hex, "primary_cwe": "CWE-506", "owasp_a": "A08:2021",
        "recorded_hash": recorded_hash, "actual_hash": actual_hash,
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)
    src = os.path.join(mirror, "geocache-2.3.1", "geocache")
    for f in ("__init__.py", "_grid.py", "_cache.py"):
        shutil.copy(os.path.join(src, f), os.path.join(pkg, f))
    shutil.rmtree(res, ignore_errors=True)


def lazy(sp, report_path):
    """A do-nothing/guessing submission: plausible guesses, NO remediation."""
    report = {
        "compromised_package": "geocache",
        "malicious_path": os.path.join(sp, "geocache", "_cache.py"),
        "trigger": "import", "c2_host": "evil.example.com", "c2_port": 443,
        "exfil_endpoint": "/", "decode_key": "00" * 16,
        "primary_cwe": "CWE-506", "owasp_a": "A06:2021",
        "recorded_hash": "0" * 64, "actual_hash": "0" * 64,
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)


def grade(sp, mirror, report_path):
    results = V.run_checks(report_path=report_path, sp=sp, mirror=mirror)
    wts = dict(V.CHECKS)
    for name, ok in results:
        w = wts.get(name, 1)
        print(("  PASS " if ok else "  FAIL ") + name + ("  (x%d)" % w if w != 1 else ""))
    got = sum(wts.get(n, 1) for n, ok in results if ok)
    tot = sum(w for _, w in V.CHECKS)
    print("\nREWARD = %d/%d = %.3f  (weighted; payload-analysis items x3)" % (got, tot, got / tot))
    return got / tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manual", action="store_true")
    ap.add_argument("--lazy", action="store_true")
    args = ap.parse_args()

    root = tempfile.mkdtemp(prefix="mtf_")
    gt = B.build(root)
    _sync_check(gt)
    sp = os.path.join(root, "site-packages")
    mirror = os.path.join(root, "opt", "mirror")
    report_path = os.path.join(root, "app", "report.json")
    print("Environment built at:\n  " + root)
    print("  site-packages : " + sp)
    print("  clean mirror  : " + os.path.join(mirror, "geocache-2.3.1"))
    print("  tampered file : " + gt["malicious_path"])
    print("  write report  : " + report_path)

    if args.lazy:
        print("\n--- LAZY MODE (guess + do nothing: measures the reward-hacking floor) ---")
        lazy(sp, report_path)
        grade(sp, mirror, report_path)
    elif args.manual:
        print("\n--- MANUAL MODE ---")
        print("Investigate the files, write report.json at the path above, remediate the")
        print("package, then press Enter to grade.")
        try:
            input("\nPress Enter when ready...")
        except EOFError:
            print("(no stdin; skipping manual grade)")
            return
        grade(sp, mirror, report_path)
    else:
        print("\n--- ORACLE MODE (reference solve) ---")
        oracle(sp, mirror, report_path)
        grade(sp, mirror, report_path)
    print("\n(temp env left at %s -- delete when done)" % root)


if __name__ == "__main__":
    main()
