#!/usr/bin/env python3
"""Docker-free runner for install-hook-exfil (Windows/Mac/Linux, Python only).

  python local_test.py            # build env + run oracle + grade   (proves it works)
  python local_test.py --manual   # build env, print paths, wait, then grade your try
  python local_test.py --lazy     # build env + score a do-nothing/guessing submission
                                   # (measures the reward-hacking floor; expect a low fraction)

It imports the SAME env/gen/build_env.py the container uses and the SAME
tests/test_outputs.py verifier, and cross-checks the verifier's embedded constants
against a fresh build so drift fails loudly.
"""
import argparse
import base64
import glob
import hashlib
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
    import importlib.util
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(HERE, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load("ihe_build_env", os.path.join("env", "gen", "build_env.py"))
V = _load("ihe_verifier", os.path.join("tests", "test_outputs.py"))


def _sync_check(gt):
    """Fail loudly if the verifier's embedded constants drift from the generator."""
    pairs = [
        ("EXP_HOST", gt["c2_host"]), ("EXP_PORT", gt["c2_port"]),
        ("EXP_ENDPOINT", gt["exfil_endpoint"]), ("EXP_KEY", gt["decode_key"]),
        ("EXP_PKG", gt["compromised_package"]), ("EXP_TRIGGER", gt["trigger"]),
        ("EXP_CWE", gt["primary_cwe"]), ("EXP_OWASP", gt["owasp_a"]),
        ("INJECTED_MARKER", gt["injected_marker"]),
        ("EXP_PTH_NAME", os.path.basename(gt["pth_file"])),
    ]
    bad = [(n, getattr(V, n), exp) for n, exp in pairs if str(getattr(V, n)) != str(exp)]
    # loader rel path is stored as a tuple in the verifier
    loader_rel = os.sep.join(V.EXP_LOADER_REL)
    if not gt["loader_module"].endswith(loader_rel):
        bad.append(("EXP_LOADER_REL", V.EXP_LOADER_REL, gt["loader_module"]))
    if bad:
        for n, got, exp in bad:
            print("  DRIFT %s: verifier=%r  build_env=%r" % (n, got, exp))
        raise SystemExit("verifier constants are out of sync with env/gen/build_env.py")


def _localise(sp):
    """Return (pth_file, loader_module): the injected .pth and the module it imports
    (a file absent from its distribution's RECORD manifest)."""
    def record_files(top):
        for d in glob.glob(os.path.join(sp, top + "-*.dist-info")):
            rec = os.path.join(d, "RECORD")
            if os.path.exists(rec):
                return {ln.strip().split(",")[0] for ln in open(rec) if ln.strip().split(",")[0]}
        return None
    pth_file = loader_module = None
    for pth in sorted(glob.glob(os.path.join(sp, "*.pth"))):
        for line in open(pth, errors="replace"):
            s = line.strip()
            if s.startswith(("import ", "import\t")) and "." in s:
                mod = s.split(None, 1)[1].strip().split()[0]
                rel = mod.replace(".", "/") + ".py"
                fp = os.path.join(sp, rel)
                listed = record_files(mod.split(".")[0])
                if os.path.exists(fp) and listed is not None and rel not in listed:
                    pth_file, loader_module = pth, fp
    return pth_file, loader_module


def oracle(sp, report_path):
    """Reference solve (mirror of solution.sh) against relocatable paths."""
    pth_file, loader_module = _localise(sp)
    res = os.path.join(os.path.dirname(loader_module), "_resources")
    blob = open(os.path.join(res, "table.bin"), "rb").read().split(b"\n#SEG2\n", 1)[1]
    key_hex = open(os.path.join(res, ".keycache")).read().strip()
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
    # host is XOR-encrypted; the runtime decrypt key is read from an env var (unset in the
    # sandbox). The real key is the build signature: sha256 of the clean metricslib/_stats.py.
    key16 = bytes.fromhex(hashlib.sha256(
        open(os.path.join(sp, "metricslib", "_stats.py"), "rb").read()).hexdigest())[:16]
    host = None
    for bc in byts:
        try:
            cand = bytes(x ^ key16[i % 16] for i, x in enumerate(bc)).decode()
        except Exception:
            continue
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", cand):
            host = cand
    report = {
        "compromised_package": os.path.basename(os.path.dirname(loader_module)),
        "pth_file": pth_file, "loader_module": loader_module,
        "trigger": "interpreter-startup",
        "c2_host": host,
        "c2_port": next(i for i in ints if 1024 < i < 65536),
        "exfil_endpoint": next(s for s in strs if s.startswith("/")),
        "decode_key": key_hex, "primary_cwe": "CWE-506", "owasp_a": "A06:2021",
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)
    os.remove(pth_file)
    os.remove(loader_module)
    shutil.rmtree(res, ignore_errors=True)


def lazy(sp, report_path):
    """A do-nothing/guessing submission: plausible guesses from a directory listing,
    NO decode and NO remediation. Names the obvious .pth but guesses the loader and
    every decoded indicator; performs no fix."""
    report = {
        "compromised_package": "metricslib",
        "pth_file": os.path.join(sp, "metricslib-autoload.pth"),
        "loader_module": os.path.join(sp, "metricslib", "__init__.py"),  # wrong guess
        "trigger": "interpreter-startup",
        "c2_host": "evil.example.com", "c2_port": 443,
        "exfil_endpoint": "/", "decode_key": "00" * 16,
        "primary_cwe": "CWE-506", "owasp_a": "A06:2021",
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    json.dump(report, open(report_path, "w"), indent=2)


def grade(sp, report_path):
    results = V.run_checks(report_path=report_path, sp=sp)
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

    root = tempfile.mkdtemp(prefix="ihe_")
    gt = B.build(root)
    _sync_check(gt)
    sp = os.path.join(root, "site-packages")
    report_path = os.path.join(root, "app", "report.json")
    print("Environment built at:\n  " + root)
    print("  site-packages : " + sp)
    print("  malicious .pth: " + gt["pth_file"])
    print("  loader module : " + gt["loader_module"])
    print("  write report  : " + report_path)

    if args.lazy:
        print("\n--- LAZY MODE (guess + do nothing: measures the reward-hacking floor) ---")
        lazy(sp, report_path)
        grade(sp, report_path)
    elif args.manual:
        print("\n--- MANUAL MODE ---")
        print("Investigate the files, write report.json at the path above, remediate the")
        print("package, then press Enter to grade.")
        try:
            input("\nPress Enter when ready...")
        except EOFError:
            print("(no stdin; skipping manual grade)")
            return
        grade(sp, report_path)
    else:
        print("\n--- ORACLE MODE (reference solve) ---")
        oracle(sp, report_path)
        grade(sp, report_path)
    print("\n(temp env left at %s -- delete when done)" % root)


if __name__ == "__main__":
    main()
