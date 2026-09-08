#!/usr/bin/env python3
"""Docker-free runner for supply-chain-audit (Python only, any OS).

  python local_test.py            # build env + run oracle + grade   (proves it solves -> 1.0)
  python local_test.py --lazy     # do-nothing submission            (reward-hacking floor -> 0)
  python local_test.py --flagall  # flag EVERY package incl. benign  (no-precision ceiling)
  python local_test.py --manual   # build env, print paths, wait, grade your own attempt

Imports the SAME env/gen/build_env.py the container uses and the SAME tests/test_outputs.py
verifier, and cross-checks the verifier's embedded ground truth against a fresh build so any
drift fails loudly.
"""
import argparse
import base64
import importlib.util
import json
import os
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(mod, rel):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(HERE, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


B = _load("sca_build_env", os.path.join("env", "gen", "build_env.py"))
V = _load("sca_verifier", os.path.join("tests", "test_outputs.py"))


def _sync_check(gt):
    """Fail loudly if the verifier's ground truth drifts from the generator."""
    bad = []
    if set(V.TRUE_COMPROMISED) != set(gt["compromised"]):
        bad.append(("compromised set", set(V.TRUE_COMPROMISED), set(gt["compromised"])))
    if set(V.RED_HERRINGS) != set(gt["red_herrings"]):
        bad.append(("red herrings", set(V.RED_HERRINGS), set(gt["red_herrings"])))
    for name, meta in gt["compromised"].items():
        vm = V.TRUE_COMPROMISED[name]
        for k in ("vector", "trigger", "cwe", "owasp", "indicator"):
            if str(vm[k]) != str(meta[k]):
                bad.append(("%s.%s" % (name, k), vm[k], meta[k]))
    if V.GEOINDEX_MARKER != gt["geoindex_marker"]:
        bad.append(("geoindex_marker", V.GEOINDEX_MARKER, gt["geoindex_marker"]))
    if bad:
        for n, a, b in bad:
            print("  DRIFT %s: verifier=%r build_env=%r" % (n, a, b))
        raise SystemExit("verifier ground truth out of sync with env/gen/build_env.py")


def _recover_indicators(sp):
    """Reference recovery of the encoded indicators straight from disk (proves solvability)."""
    import re
    b64pat = r"b64decode\(\s*['\"]([^'\"]+)['\"]"
    ind = {}
    # geoindex: base64 host
    txt = open(os.path.join(sp, "geoindex", "_grid.py")).read()
    ind["geoindex"] = base64.b64decode(re.search(b64pat, txt).group(1)).decode()
    # metricslib: XOR host = bytes.fromhex(_H) ^ key _K
    agg = open(os.path.join(sp, "metricslib", "_agg.py")).read()
    h = re.search(r'_H = bytes\.fromhex\((.+?)\)', agg).group(1).strip().strip("'\"")
    k = re.search(r"_K = (.+?)\.encode", agg).group(1).strip().strip("'\"")
    hb = bytes.fromhex(h); kb = k.encode()
    ind["metricslib"] = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(hb)).decode()
    # corp-telemetry: the installed (malicious) version
    ct = open(os.path.join(sp, "corp_telemetry", "__init__.py")).read()
    ind["corp-telemetry"] = re.search(r'__version__ = "([^"]+)"', ct).group(1)
    # sluglfy: impersonated legit dependency present in the tree (levenshtein-1)
    ind["sluglfy"] = "slugify"
    # buildtools-ext: the module the .pth executes at startup
    pth = open(os.path.join(sp, "buildtools_ext_autoload.pth")).read().strip()
    ind["buildtools-ext"] = pth.replace("import ", "").strip()
    # logkit: base64 host inside the grep-resistant _writer.py beacon
    lw = open(os.path.join(sp, "logkit", "_writer.py")).read()
    ind["logkit"] = base64.b64decode(re.search(b64pat, lw).group(1)).decode()
    # svc-cli: base64 host inside the entry-point backend _hooks.py
    hk = open(os.path.join(sp, "svc_cli", "_hooks.py")).read()
    ind["svc-cli"] = base64.b64decode(re.search(b64pat, hk).group(1)).decode()
    # urllib33: impersonated legit dependency (urllib3 is present in the tree)
    ind["urllib33"] = "urllib3"
    # metrics-core: the installed (malicious) version
    mc = open(os.path.join(sp, "metrics_core", "__init__.py")).read()
    ind["metrics-core"] = re.search(r'__version__ = "([^"]+)"', mc).group(1)
    return ind


def oracle(root):
    sp = os.path.join(root, "site-packages")
    mirror = os.path.join(root, "opt", "mirror")
    app = os.path.join(root, "app")
    ind = _recover_indicators(sp)

    vec = {"geoindex": "tampered-file", "metricslib": "malicious-wheel",
           "corp-telemetry": "dependency-confusion", "sluglfy": "typosquat",
           "buildtools-ext": "install-hook", "logkit": "malicious-wheel",
           "svc-cli": "malicious-wheel", "urllib33": "typosquat",
           "metrics-core": "dependency-confusion"}
    trig = {"geoindex": "import", "metricslib": "import", "corp-telemetry": "import",
            "sluglfy": "import", "buildtools-ext": "interpreter-startup",
            "logkit": "import", "svc-cli": "runtime-entrypoint",
            "urllib33": "import", "metrics-core": "import"}
    cwe = {"corp-telemetry": "CWE-494", "metrics-core": "CWE-494"}
    report = {"compromised": []}
    for name in V.TRUE_COMPROMISED:
        report["compromised"].append({
            "package": name, "vector": vec[name], "trigger": trig[name],
            "cwe": cwe.get(name, "CWE-506"), "owasp": "A08:2021", "indicator": ind[name],
        })
    _write_report(os.path.join(app, "report.json"), report)

    # --- remediate ---
    # V1 geoindex: restore clean _grid.py from mirror
    shutil.copy(os.path.join(mirror, "geoindex-1.2.0", "geoindex", "_grid.py"),
                os.path.join(sp, "geoindex", "_grid.py"))
    # V2 metricslib: restore clean __init__ from mirror, drop the malicious backend
    shutil.copy(os.path.join(mirror, "metricslib-0.7.3", "metricslib", "__init__.py"),
                os.path.join(sp, "metricslib", "__init__.py"))
    _rm(os.path.join(sp, "metricslib", "_agg.py"))
    # V3 corp-telemetry: repin to the internal 1.4.2 build from the mirror
    shutil.copy(os.path.join(mirror, "corp_telemetry-1.4.2", "corp_telemetry", "__init__.py"),
                os.path.join(sp, "corp_telemetry", "__init__.py"))
    # V4 sluglfy: remove the typosquat and fix the shim to use the legit slugify
    _rmtree(os.path.join(sp, "sluglfy"))
    for d in os.listdir(sp):
        if d.startswith("sluglfy-") and d.endswith(".dist-info"):
            _rmtree(os.path.join(sp, d))
    shim = os.path.join(app, "service", "src", "svc", "shim.py")
    s = open(shim).read().replace("import sluglfy as _slug", "import slugify as _slug")
    open(shim, "w").write(s)
    # V5 buildtools-ext: remove the startup .pth hook
    _rm(os.path.join(sp, "buildtools_ext_autoload.pth"))
    # V6 logkit: restore the clean _writer.py from the mirror
    shutil.copy(os.path.join(mirror, "logkit-2.1.0", "logkit", "_writer.py"),
                os.path.join(sp, "logkit", "_writer.py"))
    # V7 svc-cli: drop the malicious entry-point backend
    _rm(os.path.join(sp, "svc_cli", "_hooks.py"))
    ep = os.path.join(sp, "svc_cli-0.6.0.dist-info", "entry_points.txt")
    if os.path.exists(ep):
        _rm(ep)
    # V8 urllib33: remove the typosquat and fix the net module to use the legit urllib3
    _rmtree(os.path.join(sp, "urllib33"))
    for d in os.listdir(sp):
        if d.startswith("urllib33-") and d.endswith(".dist-info"):
            _rmtree(os.path.join(sp, d))
    net = os.path.join(app, "service", "src", "svc", "net.py")
    s = open(net).read().replace("import urllib33", "import urllib3 as urllib33")
    open(net, "w").write(s)
    # V9 metrics-core: repin to the internal 2.0.0 build from the mirror
    shutil.copy(os.path.join(mirror, "metrics_core-2.0.0", "metrics_core", "__init__.py"),
                os.path.join(sp, "metrics_core", "__init__.py"))
    # red herrings: left untouched (benign)


def lazy(root):
    """Do nothing: empty report, no remediation."""
    _write_report(os.path.join(root, "app", "report.json"), {"compromised": []})


def flagall(root):
    """Flag EVERY package (incl. benign) with plausible-looking classification: no precision."""
    sp = os.path.join(root, "site-packages")
    names = sorted({d.split("-")[0].replace("_", "-") for d in os.listdir(sp) if d.endswith(".dist-info")})
    rep = {"compromised": [{"package": n, "vector": "tampered-file", "trigger": "import",
                            "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "unknown"} for n in names]}
    _write_report(os.path.join(root, "app", "report.json"), rep)


def _write_report(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(obj, open(path, "w"), indent=2)


def _rm(p):
    try:
        os.remove(p)
    except OSError:
        pass


def _rmtree(p):
    shutil.rmtree(p, ignore_errors=True)


def grade(root):
    sp = os.path.join(root, "site-packages")
    mirror = os.path.join(root, "opt", "mirror")
    report_path = os.path.join(root, "app", "report.json")
    results = V.run_checks(report_path=report_path, sp=sp, mirror=mirror)
    wts = dict(V.CHECKS)
    for name, ok in results:
        w = wts.get(name, 1)
        print(("  PASS " if ok else "  FAIL ") + name + ("  (x%d)" % w if w != 1 else ""))
    got = sum(wts.get(n, 1) for n, ok in results if ok)
    tot = sum(w for _, w in V.CHECKS)
    print("\nREWARD = %d/%d = %.3f" % (got, tot, got / tot))
    return got / tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lazy", action="store_true")
    ap.add_argument("--flagall", action="store_true")
    ap.add_argument("--manual", action="store_true")
    args = ap.parse_args()

    root = tempfile.mkdtemp(prefix="sca_")
    gt = B.build(root)
    _sync_check(gt)
    print("Environment built at:\n  " + root)
    print("  site-packages : " + os.path.join(root, "site-packages"))
    print("  mirror        : " + os.path.join(root, "opt", "mirror"))
    print("  service       : " + os.path.join(root, "app", "service"))
    print("  write report  : " + os.path.join(root, "app", "report.json"))

    if args.lazy:
        print("\n--- LAZY (do-nothing: reward-hacking floor) ---"); lazy(root); grade(root)
    elif args.flagall:
        print("\n--- FLAG-ALL (no precision) ---"); flagall(root); grade(root)
    elif args.manual:
        print("\n--- MANUAL: investigate, write report.json, remediate, then press Enter ---")
        try:
            input("\nPress Enter to grade...")
        except EOFError:
            print("(no stdin; skipping)"); return
        grade(root)
    else:
        print("\n--- ORACLE (reference solve) ---"); oracle(root); grade(root)
    print("\n(temp env left at %s -- delete when done)" % root)


if __name__ == "__main__":
    main()
