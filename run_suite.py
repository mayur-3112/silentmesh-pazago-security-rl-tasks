#!/usr/bin/env python3
"""SilentMesh task suite — one command validates every task in tasks/.

For each task it runs:
  DYNAMIC  build env + oracle solve + grade  -> must reach reward 1.000
  STATIC   spec-compliance checks on the delivered files:
     - instruction: <=1500 words, no markdown headings, no steering phrases,
       no relative paths, has at least one absolute path
     - required files present (task.yaml, Dockerfile, tests/, solution.sh, run-tests.sh)
     - Dockerfile pins the base image and deletes the env generator
     - report-key parity: the keys named in task.yaml appear in the verifier

Exit code 0 iff every task passes every check. Needs only Python (no Docker).
Run:  python run_suite.py
"""
import os, re, sys, subprocess, glob

ROOT = os.path.dirname(os.path.abspath(__file__))
TASKS = sorted(d for d in glob.glob(os.path.join(ROOT, "tasks", "*")) if os.path.isdir(d))
STEER = ["step by step", "you are an expert", "please think", "as an expert"]
REQUIRED = ["task.yaml", "Dockerfile", "docker-compose.yaml", "solution.sh",
            "run-tests.sh", os.path.join("tests", "test_outputs.py"),
            os.path.join("env", "gen", "build_env.py")]


def read(p):
    return open(p, encoding="utf-8").read()


def instruction_of(task):
    # extract the standard `instruction: |` block from task.yaml without a yaml dep
    txt = read(os.path.join(task, "task.yaml"))
    m = re.search(r"^instruction:\s*\|\s*\n(.*?)(?:^\w[\w-]*:|\Z)", txt, re.S | re.M)
    if not m:
        return ""
    lines = m.group(1).splitlines()
    indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    base = min(indents) if indents else 0
    return "\n".join(l[base:] if l.strip() else "" for l in lines)


def report_keys_from_instruction(instr):
    # keys are the lower_snake tokens introduced as "  name  - description"
    keys = set()
    for l in instr.splitlines():
        m = re.match(r"\s{2,}([a-z][a-z0-9_]{2,})\s+-\s+\S", l)
        if m:
            keys.add(m.group(1))
    return keys


def static_checks(task):
    out = []
    def chk(n, c): out.append((n, bool(c)))
    files_ok = all(os.path.exists(os.path.join(task, f)) for f in REQUIRED)
    chk("required files present", files_ok)
    instr = instruction_of(task)
    wc = len(instr.split())
    chk("instruction <=1500 words (%d)" % wc, wc <= 1500 and wc > 0)
    chk("no markdown headings", not re.search(r"^\s*#{1,6}\s", instr, re.M))
    chk("no steering phrases", not any(s in instr.lower() for s in STEER))
    chk("no relative paths", not re.findall(r"(?<!\w)\.\.?/[\w./-]+", instr))
    chk("uses an absolute path", bool(re.search(r"(?<!\w)/[\w./-]+", instr)))
    if files_ok:
        dockp = read(os.path.join(task, "Dockerfile"))
        chk("Dockerfile pins base image", bool(re.search(r"FROM\s+\S+:\S+", dockp)))
        chk("Dockerfile deletes generator", "rm -f /tmp/build_env.py" in dockp)
        verifier = read(os.path.join(task, "tests", "test_outputs.py"))
        keys = report_keys_from_instruction(instr)
        missing = [k for k in keys if k not in verifier]
        chk("report keys covered by verifier (%d keys)" % len(keys), not missing)

    # Schema requirements from the requirements-PDF compliance audit (Phase 1):
    # every task must declare its CWE/OWASP classification, and the public
    # dossier must not carry solution-specific values (those belong only in
    # internal/ANSWER_KEY.md, never shipped to an agent or grader).
    manifest = read(os.path.join(task, "task.yaml"))
    chk("primary_cwe present in task.yaml",
        bool(re.search(r"^primary_cwe:\s*CWE-\d+\s*$", manifest, re.M)))
    chk("owasp_a present in task.yaml",
        bool(re.search(r"^owasp_a:\s*A\d\d:20\d\d\s*$", manifest, re.M)))
    chk("internal/ answer-key directory exists",
        os.path.isdir(os.path.join(task, "internal")))
    doc_path = os.path.join(task, "DOCUMENTATION.md")
    if os.path.exists(doc_path):
        doc = read(doc_path)
        SECRET_MARKERS = ("decode_key=", "c2_host=", "trusted_sha256=",
                           "recorded_hash=", "Ground truth (graders only")
        leaked = [m for m in SECRET_MARKERS if m in doc]
        chk("DOCUMENTATION.md carries no plaintext answer-key values",
            not leaked)
    return out


def dynamic_check(task):
    lt = os.path.join(task, "local_test.py")
    if not os.path.exists(lt):
        return None, "no local_test.py"
    r = subprocess.run([sys.executable, lt], capture_output=True, text=True)
    m = re.search(r"REWARD = \d+/\d+ = ([0-9.]+)", r.stdout)
    if not m:
        return False, (r.stdout + r.stderr)[-400:]
    return abs(float(m.group(1)) - 1.0) < 1e-9, "reward=%s" % m.group(1)


def main():
    print("=" * 62)
    print("SilentMesh task suite —", len(TASKS), "tasks")
    print("=" * 62)
    all_ok = True
    for task in TASKS:
        name = os.path.basename(task)
        print("\n### %s" % name)
        stat = static_checks(task)
        for n, ok in stat:
            print(("  [static]  PASS " if ok else "  [static]  FAIL ") + n)
            all_ok &= ok
        dok, info = dynamic_check(task)
        if dok is None:
            print("  [dynamic] SKIP  " + info)
        else:
            print(("  [dynamic] PASS  " if dok else "  [dynamic] FAIL  ") + info)
            all_ok &= dok
    print("\n" + "=" * 62)
    print("SUITE RESULT:", "ALL PASS ✓" if all_ok else "FAILURES ✗")
    print("=" * 62)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
