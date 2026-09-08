#!/usr/bin/env python3
"""Docker-free runner for dependency-confusion-pin (Windows/Mac/Linux, Python only).

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
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(mod_name, rel):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(HERE, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load("dcp_build_env", os.path.join("env", "gen", "build_env.py"))
V = _load("dcp_verifier", os.path.join("tests", "test_outputs.py"))


def _sync_check(gt):
    """Fail loudly if the verifier's embedded constants drift from the generator."""
    pairs = [
        ("EXP_HOST", gt["indicator_host"]), ("EXP_PORT", gt["indicator_port"]),
        ("EXP_PKG", gt["confused_package"]), ("EXP_MAL_VER", gt["malicious_version"]),
        ("EXP_TRUST_VER", gt["trusted_version"]), ("EXP_CONTROL", gt["missing_control"]),
        ("EXP_CWE", gt["primary_cwe"]), ("EXP_OWASP", gt["owasp_a"]),
        ("INJECTED_MARKER", gt["injected_marker"]),
        ("MAL_WHEEL", gt["malicious_wheel_name"]),
        ("TRUST_WHEEL", gt["trusted_wheel_name"]),
        ("LOCK_BASELINE", gt["lock_baseline"]),
    ]
    bad = [(n, getattr(V, n), exp) for n, exp in pairs if str(getattr(V, n)) != str(exp)]
    if bad:
        for n, got, exp in bad:
            print("  DRIFT %s: verifier=%r  build_env=%r" % (n, got, exp))
        raise SystemExit("verifier constants are out of sync with env/gen/build_env.py")


def oracle(sp, cache, mirror, build_dir, report_path):
    """Reference solve (mirror of solution.sh) against relocatable paths."""
    pkg = os.path.join(sp, "corp_auth_utils")
    index = json.load(open(os.path.join(mirror, "index.json")))
    entry = index["packages"]["corp-auth-utils"]
    trusted_version = entry["trusted_version"]
    trust_wheel = os.path.join(cache, entry["wheel"])
    cand = sorted(f for f in os.listdir(cache)
                  if f.startswith("corp_auth_utils-") and f.endswith(".whl"))
    mal_name = next(f for f in cand if entry["wheel"] not in f)
    mal_wheel = os.path.join(cache, mal_name)
    malicious_version = mal_name.split("-")[1]

    trusted_sha = hashlib.sha256(open(trust_wheel, "rb").read()).hexdigest()

    res = os.path.join(pkg, "_resources")
    blob = open(os.path.join(res, "vendor.dat"), "rb").read().split(b"\n#VBC1\n", 1)[1]
    key = bytes.fromhex(open(os.path.join(res, "cachekey.bin")).read().strip())
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
    # host is XOR-encrypted; the runtime decrypt key is read from an env var (unset in the
    # sandbox). The real key combines the trusted build's signing-module hash (recompute it
    # from the clean _signing.py inside the trusted wheel) with the outer stage-2 decode key.
    _sig = None
    with zipfile.ZipFile(trust_wheel) as _zf:
        for _n in _zf.namelist():
            if _n.endswith("_signing.py"):
                _sig = _zf.read(_n)
    build_sig = hashlib.sha256((hashlib.sha256(_sig).hexdigest() + key.hex()).encode()).hexdigest()
    key16 = bytes.fromhex(build_sig)[:16]
    host = None
    for bc in byts:
        try:
            cand = bytes(x ^ key16[i % 16] for i, x in enumerate(bc)).decode()
        except Exception:
            continue
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", cand):
            host = cand
    report = {
        "confused_package": "corp-auth-utils",
        "malicious_version": malicious_version,
        "trusted_version": trusted_version,
        "malicious_artifact": mal_wheel,
        "trusted_artifact": trust_wheel,
        "trusted_sha256": trusted_sha,
        "missing_control": "hash-pinning",
        "indicator_host": host,
        "indicator_port": next(i for i in ints if 1024 < i < 65536),
        "primary_cwe": "CWE-494",
        "owasp_a": "A08:2021",
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)

    lock = os.path.join(build_dir, "requirements.lock")
    out = []
    for line in open(lock).read().splitlines():
        if line.startswith("corp-auth-utils=="):
            out.append("corp-auth-utils==%s --hash=sha256:%s" % (trusted_version, trusted_sha))
        else:
            out.append(line)
    with open(lock, "w", newline="") as f:
        f.write("\n".join(out) + "\n")

    shutil.rmtree(pkg, ignore_errors=True)
    with zipfile.ZipFile(trust_wheel) as zf:
        for name in zf.namelist():
            if name.startswith("corp_auth_utils/") and not name.endswith("/"):
                dst = os.path.join(sp, name)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as f:
                    f.write(zf.read(name))


def lazy(sp, cache, report_path):
    """A do-nothing/guessing submission: plausible guesses, NO earned work, NO fix."""
    report = {
        "confused_package": "corp-auth-utils",
        "malicious_version": "2.9.9",
        "trusted_version": "2.9.0",
        "malicious_artifact": os.path.join(cache, "corp_auth_utils-2.9.9-py3-none-any.whl"),
        "trusted_artifact": os.path.join(cache, "corp_auth_utils-2.9.0-py3-none-any.whl"),
        "trusted_sha256": "0" * 64,
        "missing_control": "hash-pinning",
        "indicator_host": "evil.example.com",
        "indicator_port": 443,
        "primary_cwe": "CWE-494",
        "owasp_a": "A08:2021",
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)


def grade(sp, cache, build_dir, report_path):
    results = V.run_checks(report_path=report_path, sp=sp, cache=cache, build_dir=build_dir)
    wts = dict(V.CHECKS)
    for name, ok in results:
        w = wts.get(name, 1)
        print(("  PASS " if ok else "  FAIL ") + name + ("  (x%d)" % w if w != 1 else ""))
    got = sum(wts.get(n, 1) for n, ok in results if ok)
    tot = sum(w for _, w in V.CHECKS)
    print("\nREWARD = %d/%d = %.3f  (weighted; payload-analysis items x5)" % (got, tot, got / tot))
    return got / tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manual", action="store_true")
    ap.add_argument("--lazy", action="store_true")
    args = ap.parse_args()

    root = tempfile.mkdtemp(prefix="dcp_")
    gt = B.build(root)
    _sync_check(gt)
    sp = os.path.join(root, "site-packages")
    cache = os.path.join(root, "opt", "pip-cache")
    mirror = os.path.join(root, "opt", "mirror")
    build_dir = os.path.join(root, "app", "build")
    report_path = os.path.join(root, "app", "report.json")
    print("Environment built at:\n  " + root)
    print("  site-packages : " + sp)
    print("  pip cache     : " + cache)
    print("  mirror index  : " + os.path.join(mirror, "index.json"))
    print("  lock file     : " + os.path.join(build_dir, "requirements.lock"))
    print("  write report  : " + report_path)

    if args.lazy:
        print("\n--- LAZY MODE (guess + do nothing: measures the reward-hacking floor) ---")
        lazy(sp, cache, report_path)
        grade(sp, cache, build_dir, report_path)
    elif args.manual:
        print("\n--- MANUAL MODE ---")
        print("Investigate the files, write report.json at the path above, remediate the")
        print("lock and the installed package, then press Enter to grade.")
        try:
            input("\nPress Enter when ready...")
        except EOFError:
            print("(no stdin; skipping manual grade)")
            return
        grade(sp, cache, build_dir, report_path)
    else:
        print("\n--- ORACLE MODE (reference solve) ---")
        oracle(sp, cache, mirror, build_dir, report_path)
        grade(sp, cache, build_dir, report_path)
    print("\n(temp env left at %s -- delete when done)" % root)


if __name__ == "__main__":
    main()
