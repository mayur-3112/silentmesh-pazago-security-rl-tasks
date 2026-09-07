"""Capability-ladder verifier for pickle-policy-rce (CWE-502 / OWASP A08).

Reward = fraction of ladder rungs passed (0..1) -> partial credit, non-zero variance.

Deterministic oracle: the per-build C2 host and nonce are recovered here by the same
static decode the solver must perform (no answer file on disk). Because they are
randomized every build, a memorized/hardcoded report fails R_host / R_nonce.

Anti-reward-hacking:
  * env is offline; the payload cannot beacon, so the indicator is reachable only by
    static decode of the pickle bytes (never executed).
  * R_no_exec: after remediation, loading the policy must run no payload.
  * R_functionality: the loader must still return the correct effective policy.
"""
import json, os, re, sys, base64, zlib, subprocess, importlib

APP = "/app"
REPORT = os.path.join(APP, "report.json")
PKL = os.path.join(APP, "service", "cache", "policy.pkl")
SAFE = "/opt/mirror/policy.json"
SVC_SRC = os.path.join(APP, "service", "src")

EXPECTED_POLICY = json.load(open(SAFE))


def _decode_indicator():
    raw = open(PKL, "rb").read().decode("latin-1")
    key = bytes.fromhex(re.search(r'_K\s*=\s*bytes\.fromhex\("([0-9a-f]+)"\)', raw).group(1))
    d = re.search(r'_D\s*=\s*"([A-Za-z0-9+/=]+)"', raw).group(1)
    src = (lambda raw,key: zlib.decompress(bytes([raw[i] ^ key[i%len(key)] for i in range(len(raw))])).decode())(base64.b64decode(d), key)
    return (re.search(r'host="([^"]+)"', src).group(1),
            re.search(r'nonce="([^"]+)"', src).group(1))


HOST, NONCE = _decode_indicator()
KEYS = {"vulnerable_call", "artifact_path", "trigger", "c2_host", "exfil_scheme",
        "indicator_nonce", "primary_cwe", "owasp_a"}


def _r():
    with open(REPORT) as f:
        return json.load(f)


def _g(k):
    return str(_r().get(k, "")).strip()


def test_l0_keys():
    assert set(_r()) == KEYS


def test_l1_vulnerable_call():
    assert _g("vulnerable_call").replace(" ", "").lower() == "pickle.load"


def test_l2_artifact_path():
    assert os.path.normpath(_g("artifact_path")) == os.path.normpath(PKL)


def test_l3_trigger():
    assert _g("trigger").lower() == "deserialization"


def test_l4_cwe():
    assert _g("primary_cwe").upper().replace(" ", "") == "CWE-502"


def test_l5_owasp():
    assert _g("owasp_a").upper().replace(" ", "") == "A08:2021"


def test_l6_scheme():
    assert _g("exfil_scheme").lower() == "https"


def test_l7_c2_host_decoded():            # challenge-response (randomized)
    assert _g("c2_host").lower() == HOST.lower()


def test_l8_nonce_decoded():              # challenge-response (randomized)
    assert _g("indicator_nonce").lower() == NONCE.lower()


def test_l9_no_exec_on_load():
    probe = ("import socket\nh={'n':0}\n"
             "def t(*a,**k):\n h['n']+=1; raise OSError('blocked')\n"
             "socket.create_connection=t\n"
             "import sys; sys.path.insert(0, r'%s')\n"
             "from svc.config import get\nget()\n"
             "open('/tmp/hit','w').write(str(h['n']))\n" % SVC_SRC)
    subprocess.run([sys.executable, "-c", probe], check=True)
    assert open("/tmp/hit").read().strip() == "0", "payload still executes on policy load"


def test_l10_functionality_preserved():
    code = ("import sys; sys.path.insert(0, r'%s')\n"
            "from svc.config import get\nimport json; print(json.dumps(get()))\n" % SVC_SRC)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip()) == EXPECTED_POLICY, "loader no longer returns the correct policy"
