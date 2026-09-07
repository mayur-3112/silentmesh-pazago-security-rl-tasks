"""Benchmark agents. Each agent is a callable (task_mod, P) -> None.

- oracle:    calls the task's reference solution. Should score 1.0. Sanity check.
- empty:     writes {} as report, no remediation. Tests the exact-key gate.
- guess:     writes plausible-looking guesses for well-known enum fields (CWE / OWASP
             / trigger / scheme) and empties for the rest. Tests whether frontier
             heuristics ("guess the taxonomy") can score partial credit alone.
- pathonly:  writes a report with only paths correctly set (from task metadata) and
             everything else empty. Tests whether easy recon fields carry the score.

A real-model agent would live in bench/agents/model.py and would use an API-provided
LLM inside a tool-use loop; that plugs into the same harness once keys are available.
"""
import os, re, json


def _keys_of(task_id):
    """Parse the report keys straight out of task.yaml (no yaml dep)."""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                     "tasks", task_id, "task.yaml")
    txt = open(p, encoding="utf-8").read()
    keys = set()
    for l in txt.splitlines():
        m = re.match(r"\s{2,}([a-z][a-z0-9_]{2,})\s+-\s+\S", l)
        if m:
            keys.add(m.group(1))
    return keys


def _task_id_from_P(P):
    # P has fields like PKG/GRID/CACHE named by task. Cheapest reliable route:
    # infer via the temp dir prefix set by harness (bench_<agentname>_XXX) is not
    # enough; use the presence of characteristic keys.
    if "GRID" in P and "MIRROR_GRID" in P: return "nw-mirror-tamper-v2"
    if "LOADER" in P and "INIT" in P:      return "nw-mirror-tamper-v1"
    if "MWHL" in P and "TWHL" in P:        return "dep-confusion-hijack"
    if "PKL" in P and "CONFIG" in P:       return "pickle-policy-rce"
    return None


def _report_path(P):
    return P.get("REPORT") or os.path.join(P.get("root", "/tmp"), "report.json")


# ---- agents ----

def oracle(task_mod, P):
    task_mod.oracle(P)


def empty(task_mod, P):
    with open(_report_path(P), "w", newline="") as f:
        json.dump({}, f)


def guess(task_mod, P):
    """Guess common taxonomy values; leave the rest empty. Tests whether pure
    'guess the CWE/OWASP' scoring gets meaningful credit against real verifiers."""
    task_id = _task_id_from_P(P)
    keys = _keys_of(task_id) if task_id else set()
    guesses = {
        # taxonomy fields with a small enum
        "primary_cwe": "CWE-79",         # XSS — a popular wrong guess
        "owasp_a": "A03:2021",
        "trigger": "runtime",
        "exfil_scheme": "http",
        "missing_control": "version-pinning",
        # the "obviously wrong" defaults on other fields:
    }
    out = {k: guesses.get(k, "") for k in keys}
    with open(_report_path(P), "w", newline="") as f:
        json.dump(out, f)


def pathonly(task_mod, P):
    """Fill in only the fields recoverable by trivial file-recon (paths + package
    name), leave decode/classification/nonce empty. Tests whether shallow attempts
    can accumulate reward without doing the real work."""
    task_id = _task_id_from_P(P)
    keys = _keys_of(task_id) if task_id else set()
    fill = {}
    # path-like keys the recon-only attempt would fill
    if "malicious_path" in keys:      fill["malicious_path"] = P.get("GRID") or P.get("LOADER") or ""
    if "artifact_path" in keys:       fill["artifact_path"] = P.get("PKL") or ""
    if "malicious_artifact" in keys:  fill["malicious_artifact"] = P.get("MWHL") or ""
    if "compromised_package" in keys: fill["compromised_package"] = "geocache-lite"
    if "confused_package" in keys:    fill["confused_package"] = "corp-auth-utils"
    if "vulnerable_call" in keys:     fill["vulnerable_call"] = "pickle.load"
    out = {k: fill.get(k, "") for k in keys}
    with open(_report_path(P), "w", newline="") as f:
        json.dump(out, f)


ALL = {"oracle": oracle, "empty": empty, "guess": guess, "pathonly": pathonly}
