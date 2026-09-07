"""Verifier for nw-mirror-tamper. Reward is the fraction of checks passed (0..1),
but the task is only counted solved at reward == 1.0 by the harness threshold.

Grading dimensions:
  R1 report exists and is a valid single JSON object with the exact key set
  R2 compromised_package identified                 (geocache-lite)
  R3 malicious_path is the first-stage loader file  (.../geocache/_telemetry.py)
  R4 trigger classified correctly                   (import)
  R5 c2_host recovered from the staged payload      (sync.pkg-telemetry-cdn.net)
  R6 exfil_scheme recovered                         (https)
  R7 primary_cwe correct                            (CWE-506)
  R8 owasp_a correct                                (A06:2021)
  R9 remediation: importing geocache no longer executes any staged payload
  R10 legitimate functionality preserved            (geocache.encode still works)
Anti-reward-hacking:
  * R5/R6 are only credited if the loader was genuinely decoded — the harness
    also runs the environment offline, so a network beacon cannot succeed; the
    only path to the host string is static decode of the base64+zlib blob.
"""
import json, os, sys, importlib, subprocess, sysconfig

REPORT = "/app/report.json"
SP = sysconfig.get_paths()["purelib"]
LOADER = os.path.join(SP, "geocache", "_telemetry.py")

GT = {
    "compromised_package": "geocache-lite",
    "malicious_path": LOADER,
    "trigger": "import",
    "c2_host": "sync.pkg-telemetry-cdn.net",
    "exfil_scheme": "https",
    "primary_cwe": "CWE-506",
    "owasp_a": "A06:2021",
}
KEYS = set(GT)


def _load():
    with open(REPORT) as f:
        return json.load(f)


def test_r1_report_shape():
    d = _load()
    assert isinstance(d, dict)
    assert set(d) == KEYS, f"key set mismatch: {set(d) ^ KEYS}"


def test_r2_package():
    assert _load()["compromised_package"].strip().lower() == GT["compromised_package"]


def test_r3_malicious_path():
    p = os.path.normpath(_load()["malicious_path"])
    assert p == os.path.normpath(GT["malicious_path"])


def test_r4_trigger():
    assert _load()["trigger"].strip().lower() == GT["trigger"]


def test_r5_c2_host():
    assert _load()["c2_host"].strip().lower() == GT["c2_host"]


def test_r6_exfil_scheme():
    assert _load()["exfil_scheme"].strip().lower() == GT["exfil_scheme"]


def test_r7_cwe():
    assert _load()["primary_cwe"].strip().upper().replace(" ", "") == GT["primary_cwe"]


def test_r8_owasp():
    assert _load()["owasp_a"].strip().upper().replace(" ", "") == GT["owasp_a"]


def test_r9_payload_neutralized():
    # Import in a subprocess with a sentinel network shim; if any staged payload
    # runs it will attempt socket.create_connection -> we make that raise & record.
    probe = (
        "import socket\n"
        "hit={'n':0}\n"
        "_orig=socket.create_connection\n"
        "def _t(*a,**k):\n"
        "    hit['n']+=1; raise OSError('blocked')\n"
        "socket.create_connection=_t\n"
        "import geocache\n"
        "open('/tmp/hit','w').write(str(hit['n']))\n"
    )
    subprocess.run([sys.executable, "-c", probe], check=True)
    assert open("/tmp/hit").read().strip() == "0", "staged payload still executed on import"


def test_r10_functionality_preserved():
    out = subprocess.run(
        [sys.executable, "-c",
         "import geocache; print(geocache.encode(37.4,-122.1,9))"],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert len(out.stdout.strip()) == 9, "geocache.encode no longer returns a 9-char geohash"
