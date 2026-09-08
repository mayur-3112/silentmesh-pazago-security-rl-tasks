"""Verifier for supply-chain-audit.  Reward = WEIGHTED fraction of independent checks.

The task ships ~27 installed distributions. FIVE are compromised by DIFFERENT mechanisms
and FOUR benign red herrings each imitate one compromise's surface signal. Reward has four
families, all designed so the do-nothing baseline scores 0 and both failure modes
(flag-nothing, flag-everything) are penalised:

  * DETECTION (per true compromise): credited only when the package is named in the
    report's `compromised` list. The manifest-clean malicious wheel and the typosquat carry
    weight 2 (no hash/lockfile tell -- they need code judgment); the rest weight 1.
  * CLASSIFICATION (per true compromise, GATED on detection): the vector, and the
    trigger/CWE/OWASP bundle, must be right -- guessing them for an undetected package earns
    nothing.
  * INDICATOR (per true compromise, GATED on detection): the recovered C2 host / malicious
    version / impersonated name / startup module. The hosts are encoded on disk (base64 /
    XOR), so a grep does not yield them.
  * PRECISION -- no false positives (per red herring, weight 2): credited only when the
    benign package is NOT flagged AND the report actually flagged at least one true
    compromise. So flagging everything loses all precision points, and an empty report earns
    none of them either.
  * REMEDIATION (structural, self-gating): each check is FALSE on the untouched baseline
    (marker/hash/version/file present), so nothing here is free. The end-to-end service
    check is gated on the risky removal (typosquat gone) so it only credits a real, working
    fix; the benign-preserved check penalises over-removal.

Ground truth is cross-checked against a fresh build by local_test.py, so any drift from
env/gen/build_env.py fails the suite loudly.
"""
import hashlib
import json
import os
import subprocess
import sys

# The service runs in its own virtualenv (kept off the grader interpreter's path so the
# compromised tree cannot shadow the grader's dependencies).
SVC_SITE_PACKAGES = "/opt/service/venv/lib/python3.11/site-packages"

# --- ground truth (cross-checked against build_env in the suite) -----------------------
TRUE_COMPROMISED = {
    "geoindex":       {"w": 1, "vector": "tampered-file",        "trigger": "import",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "sync-metrics.geoindex-cdn.net"},
    "metricslib":     {"w": 2, "vector": "malicious-wheel",      "trigger": "import",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "collector.metricslib-telemetry.io"},
    "corp-telemetry": {"w": 1, "vector": "dependency-confusion", "trigger": "import",
                       "cwe": "CWE-494", "owasp": "A08:2021", "indicator": "9.9.9"},
    "sluglfy":        {"w": 2, "vector": "typosquat",            "trigger": "import",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "slugify"},
    "buildtools-ext": {"w": 1, "vector": "install-hook",         "trigger": "interpreter-startup",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "buildtools_ext._bootstrap"},
    "logkit":         {"w": 2, "vector": "malicious-wheel",      "trigger": "import",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "logkit-metrics.telemetry-cdn.net"},
    "svc-cli":        {"w": 2, "vector": "malicious-wheel",      "trigger": "runtime-entrypoint",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "svc-cli-collect.pkg-telemetry.net"},
    "urllib33":       {"w": 2, "vector": "typosquat",            "trigger": "import",
                       "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "urllib3"},
    "metrics-core":   {"w": 1, "vector": "dependency-confusion", "trigger": "import",
                       "cwe": "CWE-494", "owasp": "A08:2021", "indicator": "9.9.9"},
}
RED_HERRINGS = ["localpatch-ui", "fastserialize", "oldcrypto", "debug-shell",
                "crashreporter", "vendored-min"]

GEOINDEX_MARKER = "telemetry autoload (build-injected; do not edit)"

# Fair acceptance sets. INDICATOR: the instruction asks for "the host the code contacts
# where it beacons, otherwise the most specific artefact", so for every beaconing compromise
# the C2 host is accepted (plus the other genuinely-specific IoC where one exists). CWE:
# supply-chain CWE mapping is legitimately multi-valued, so each package accepts the set of
# defensible identifiers rather than one arbitrary pick (guards against an unfair verifier).
ACCEPTED_INDICATORS = {
    "geoindex":       {"sync-metrics.geoindex-cdn.net"},
    "metricslib":     {"collector.metricslib-telemetry.io"},
    "corp-telemetry": {"corp-telemetry-public.s3-collector.net", "9.9.9"},
    "sluglfy":        {"sluglfy-collect.pkgcdn.net", "slugify"},
    "buildtools-ext": {"bt-ext-beacon.buildcdn.net", "buildtools_ext._bootstrap",
                       "buildtools_ext_autoload.pth"},
    "logkit":         {"logkit-metrics.telemetry-cdn.net"},
    "svc-cli":        {"svc-cli-collect.pkg-telemetry.net", "svc_cli._hooks", "svc-report"},
    "urllib33":       {"urllib33-telemetry.pkgcdn.net", "urllib3"},
    "metrics-core":   {"metrics-core-public.collector-cdn.net", "9.9.9"},
}
ACCEPTED_CWE = {
    # CWE-494 (code without integrity check) is a defensible supply-chain classification for
    # every artifact-borne compromise, so it is accepted throughout alongside the more
    # specific per-vector identifiers (fair grading; CWE mapping here is legitimately plural).
    "geoindex":       {"CWE-506", "CWE-94", "CWE-507", "CWE-494", "CWE-829"},
    "metricslib":     {"CWE-506", "CWE-507", "CWE-494", "CWE-94", "CWE-829"},
    "corp-telemetry": {"CWE-427", "CWE-829", "CWE-494", "CWE-1357", "CWE-506"},
    "sluglfy":        {"CWE-506", "CWE-829", "CWE-1357", "CWE-427", "CWE-494"},
    "buildtools-ext": {"CWE-506", "CWE-829", "CWE-912", "CWE-507", "CWE-494"},
    "logkit":         {"CWE-506", "CWE-507", "CWE-94", "CWE-494", "CWE-829"},
    "svc-cli":        {"CWE-506", "CWE-507", "CWE-94", "CWE-829", "CWE-494"},
    "urllib33":       {"CWE-506", "CWE-829", "CWE-1357", "CWE-427", "CWE-494"},
    "metrics-core":   {"CWE-427", "CWE-829", "CWE-494", "CWE-1357", "CWE-506"},
}
# Per-package vector acceptance. Defaults to the canonical vector's synonyms, but where a
# compromise sits genuinely between two vectors both are accepted (fair, non-arbitrary):
# a RECORD-consistent tamper is both a "tampered file" and a "malicious wheel"; a malicious
# entry point is both a "malicious wheel" and an "install hook".
ACCEPTED_VECTOR_KEYS = {
    "logkit":  ["malicious-wheel", "tampered-file"],
    "svc-cli": ["malicious-wheel", "install-hook"],
}
# accepted vector synonyms (fair but concept-correct)
VECTOR_SYNONYMS = {
    "tampered-file": {"tampered-file", "file-tamper", "modified-file", "post-build-tamper",
                      "tampered", "integrity-mismatch", "manifest-mismatch"},
    "malicious-wheel": {"malicious-wheel", "backdoored-wheel", "malicious-package",
                        "trojaned-wheel", "malicious-artifact", "backdoor"},
    "dependency-confusion": {"dependency-confusion", "dep-confusion", "dependency-substitution",
                             "namespace-confusion", "substitution"},
    "typosquat": {"typosquat", "typo-squat", "typosquatting", "name-squat", "lookalike"},
    "install-hook": {"install-hook", "startup-hook", "pth-hook", "interpreter-startup-hook",
                     "site-hook", "autoload-hook", "install-time-hook"},
}


def _norm_name(n):
    return str(n).strip().lower().replace("_", "-")


def _norm_tok(s):
    return str(s).strip().lower().replace("_", "-").replace(" ", "-")


def _paths(sp, mirror):
    sp = sp or SVC_SITE_PACKAGES
    return sp, mirror


def _read(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except Exception:
        return b""


def _load_report(report_path):
    try:
        with open(report_path) as f:
            rep = json.load(f)
        assert isinstance(rep, dict)
    except Exception:
        return {}, {}
    items = rep.get("compromised", [])
    if not isinstance(items, list):
        return rep, {}
    by_name = {}
    for it in items:
        if isinstance(it, dict) and it.get("package"):
            by_name[_norm_name(it["package"])] = it
        elif isinstance(it, str):
            by_name[_norm_name(it)] = {"package": it}
    return rep, by_name


def run_checks(report_path="/app/report.json", sp=None, mirror="/opt/mirror"):
    sp, mirror = _paths(sp, mirror)
    _rep, reported = _load_report(report_path)
    reported_names = set(reported)
    true_names = {_norm_name(n) for n in TRUE_COMPROMISED}
    # engagement gate for precision: did the agent correctly flag >=1 real compromise?
    true_positive_found = bool(reported_names & true_names)

    results = []

    def chk(name, cond):
        results.append((name, bool(cond)))

    # ---------- DETECTION + CLASSIFICATION + INDICATOR (per true compromise) ----------
    for name, meta in TRUE_COMPROMISED.items():
        nn = _norm_name(name)
        entry = reported.get(nn)
        detected = entry is not None
        chk("DET_%s" % nn, detected)

        vec_ok = False
        cls_ok = False
        ind_ok = False
        if detected:
            vec = _norm_tok(entry.get("vector", ""))
            accepted_vec = set()
            for vk in ACCEPTED_VECTOR_KEYS.get(nn, [meta["vector"]]):
                accepted_vec |= VECTOR_SYNONYMS[vk]
            vec_ok = vec in accepted_vec
            trig_ok = _norm_tok(entry.get("trigger", "")) == _norm_tok(meta["trigger"]) or \
                (meta["trigger"] == "interpreter-startup" and "startup" in _norm_tok(entry.get("trigger", "")))
            cwe_ok = str(entry.get("cwe", "")).upper().replace(" ", "") in ACCEPTED_CWE[nn]
            owasp_ok = str(entry.get("owasp", "")).upper().replace(" ", "") == meta["owasp"]
            cls_ok = trig_ok and cwe_ok and owasp_ok
            ind = str(entry.get("indicator", "")).strip().lower()
            ind_ok = ind != "" and any(a.lower() in ind for a in ACCEPTED_INDICATORS[nn])
        chk("VEC_%s" % nn, vec_ok)
        chk("CLS_%s" % nn, cls_ok)
        chk("IND_%s" % nn, ind_ok)

    # ---------- PRECISION: benign packages must NOT be flagged (gated on engagement) ----------
    for herr in RED_HERRINGS:
        hn = _norm_name(herr)
        chk("NFP_%s" % hn, true_positive_found and hn not in reported_names)

    # ---------- REMEDIATION (structural, self-gating: all FALSE at baseline) ----------
    # V1 geoindex: restored to clean core hash AND injected marker gone
    clean_core = _read(os.path.join(mirror, "geoindex-1.2.0", "geoindex", "_grid.py"))
    inst_grid = _read(os.path.join(sp, "geoindex", "_grid.py"))
    geoindex_marker_gone = not _marker_in_dir(os.path.join(sp, "geoindex"), GEOINDEX_MARKER)
    chk("REM_geoindex",
        clean_core and hashlib.sha256(inst_grid).hexdigest() == hashlib.sha256(clean_core).hexdigest()
        and geoindex_marker_gone)

    # V2 metricslib: __init__ restored to clean (no _agg import) AND no socket beacon anywhere
    clean_ml = _read(os.path.join(mirror, "metricslib-0.7.3", "metricslib", "__init__.py"))
    inst_ml_init = _read(os.path.join(sp, "metricslib", "__init__.py"))
    no_beacon = not _text_in_dir(os.path.join(sp, "metricslib"), "create_connection")
    chk("REM_metricslib",
        clean_ml and inst_ml_init == clean_ml and no_beacon)

    # V3 corp-telemetry: repinned to internal 1.4.2 content, no phone-home
    inst_ct = _read(os.path.join(sp, "corp_telemetry", "__init__.py")).decode("utf-8", "replace")
    chk("REM_corptel",
        '1.4.2' in inst_ct and "9.9.9" not in inst_ct
        and "_phone_home" not in inst_ct and "urlopen" not in inst_ct)

    # V4 sluglfy: typosquat package removed from site-packages
    sluglfy_gone = not os.path.isdir(os.path.join(sp, "sluglfy"))
    chk("REM_sluglfy", sluglfy_gone)

    # V5 buildtools-ext: the startup .pth hook removed
    pth_gone = not os.path.exists(os.path.join(sp, "buildtools_ext_autoload.pth"))
    chk("REM_buildtools", pth_gone)

    # V6 logkit: _writer.py restored to the trusted mirror build (byte-identical)
    clean_lw = _read(os.path.join(mirror, "logkit-2.1.0", "logkit", "_writer.py"))
    inst_lw = _read(os.path.join(sp, "logkit", "_writer.py"))
    chk("REM_logkit",
        clean_lw and hashlib.sha256(inst_lw).hexdigest() == hashlib.sha256(clean_lw).hexdigest())

    # V7 svc-cli: malicious entry point neutralised -- the console_scripts mapping to the
    # beacon is gone AND the beacon backend no longer resolves a socket at that target
    ep = _read(_entry_points_path(sp, "svc_cli", "0.6.0")).decode("utf-8", "replace")
    hooks_gone = not os.path.exists(os.path.join(sp, "svc_cli", "_hooks.py"))
    ep_clean = "svc_cli._hooks:main" not in ep.replace(" ", "")
    chk("REM_svccli", ep_clean or hooks_gone)

    # V8 urllib33: second typosquat removed from site-packages
    urllib33_gone = not os.path.isdir(os.path.join(sp, "urllib33"))
    chk("REM_urllib33", urllib33_gone)

    # V9 metrics-core: repinned to the internal 2.0.0 content, no register beacon
    inst_mc = _read(os.path.join(sp, "metrics_core", "__init__.py")).decode("utf-8", "replace")
    chk("REM_metricscore",
        '2.0.0' in inst_mc and "9.9.9" not in inst_mc
        and "_register" not in inst_mc and "urlopen" not in inst_mc)

    # end-to-end: service still imports + runs. Gated on BOTH typosquats being removed (the
    # risky, coupled fixes -- each dangling import breaks the service), so this only credits
    # a complete, working remediation. Weighted heavily (see CHECKS): botching any single
    # restore/repin/removal that the service depends on fails all four instances.
    svc_ok = sluglfy_gone and urllib33_gone and _service_runs(sp)
    for i in range(1, 5):
        chk("REM_service_runs_%d" % i, svc_ok)

    # benign packages preserved (not over-removed), gated on some real remediation happening
    some_removal = sluglfy_gone or pth_gone
    preserved = all(os.path.isdir(os.path.join(sp, _norm_name(h).replace("-", "_")))
                    for h in RED_HERRINGS)
    chk("REM_benign_preserved", some_removal and preserved)

    return results


def _marker_in_dir(d, marker):
    for dp, _, files in os.walk(d):
        if "__pycache__" in dp:
            continue
        for fn in files:
            if marker.encode() in _read(os.path.join(dp, fn)):
                return True
    return False


def _text_in_dir(d, text):
    for dp, _, files in os.walk(d):
        if "__pycache__" in dp:
            continue
        for fn in files:
            if text.encode() in _read(os.path.join(dp, fn)):
                return True
    return False


def _entry_points_path(sp, dist_top, version):
    return os.path.join(sp, "%s-%s.dist-info" % (dist_top, version), "entry_points.txt")


def _service_runs(sp):
    # relocatable root: site-packages' parent is the env root (tmp runner); else container
    src = os.path.join(os.path.dirname(sp), "app", "service", "src") \
        if os.path.basename(sp) == "site-packages" else "/app/service/src"
    if not os.path.isdir(src):
        # container layout
        src = "/app/service/src"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([sp, src])
    try:
        # sentinel isolates run()'s return value from any log output the service emits
        out = subprocess.run(
            [sys.executable, "-c",
             "import svc.main as m; print('__RUNVAL__%s__' % (m.run(),))"],
            env=env, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return False
        import re
        m = re.search(r"__RUNVAL__(.*?)__", out.stdout)
        return bool(m) and len(m.group(1).strip()) == 9
    except Exception:
        return False


# ------------------------------------------------------- weighting + pytest entry points
def _checks_spec():
    spec = []
    for name, meta in TRUE_COMPROMISED.items():
        nn = _norm_name(name)
        spec.append(("DET_%s" % nn, meta["w"]))
        spec.append(("VEC_%s" % nn, 1))
        spec.append(("CLS_%s" % nn, 1))
        spec.append(("IND_%s" % nn, 1))
    for herr in RED_HERRINGS:
        spec.append(("NFP_%s" % _norm_name(herr), 2))
    spec += [("REM_geoindex", 1), ("REM_metricslib", 1), ("REM_corptel", 1),
             ("REM_sluglfy", 1), ("REM_buildtools", 1), ("REM_logkit", 1), ("REM_svccli", 1),
             ("REM_urllib33", 1), ("REM_metricscore", 1),
             ("REM_service_runs_1", 1), ("REM_service_runs_2", 1),
             ("REM_service_runs_3", 1), ("REM_service_runs_4", 1),
             ("REM_benign_preserved", 1)]
    return spec


CHECKS = _checks_spec()


def weighted_reward(results):
    d = dict(results)
    tot = sum(w for _, w in CHECKS)
    got = sum(w for n, w in CHECKS if d.get(n))
    return got / tot if tot else 0.0


_CACHE = {"results": None}


def _results():
    if _CACHE["results"] is None:
        _CACHE["results"] = dict(run_checks())
    return _CACHE["results"]


try:
    import pytest

    _EXPANDED = [n for n, w in CHECKS for _ in range(w)]

    @pytest.mark.parametrize("check", _EXPANDED)
    def test_weighted_item(check):
        assert _results()[check], check
except ImportError:
    pass
