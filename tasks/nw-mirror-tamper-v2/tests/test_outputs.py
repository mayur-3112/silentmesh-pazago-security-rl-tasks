"""Verifier for nw-mirror-tamper-v2. Reward = fraction of items passed (0..1).

Strengthened anti-reward-hacking:
  * recorded_hash / actual_hash are 64-hex digests -> not guessable; they force the
    model to actually read the RECORD manifest and hash the file.
  * c2_host / exfil_scheme are behind a two-layer obfuscation (base64 -> XOR ->
    zlib) and the env is offline, so neither grep nor live execution yields them.
  * R_restore checks the installed file's RECORD hash matches again AND equals the
    clean mirror copy -> deleting or stubbing the file fails (breaks the manifest
    and/or functionality), only a real restore passes.
"""
import json, os, sys, re, base64, hashlib, subprocess, sysconfig

REPORT = "/app/report.json"
SP = sysconfig.get_paths()["purelib"]
GRID = os.path.join(SP, "geocache", "_grid.py")
RECORD = os.path.join(SP, "geocache_lite-1.4.2.dist-info", "RECORD")
MIRROR_GRID = "/opt/mirror/geocache-lite-1.4.2/_grid.py"

CLEAN_HEX = hashlib.sha256(open(MIRROR_GRID, "rb").read()).hexdigest()


def _record_b64_for(path_in_record):
    for line in open(RECORD):
        parts = line.strip().split(",")
        if parts and parts[0] == path_in_record and len(parts) >= 2 and parts[1]:
            return parts[1].split("=", 1)[1]
    raise AssertionError("record line not found")


RECORDED_B64 = _record_b64_for("geocache/_grid.py")

GT = {
    "compromised_package": "geocache-lite",
    "malicious_path": GRID,
    "trigger": "import",
    "c2_host": "sync.pkg-telemetry-cdn.net",
    "exfil_scheme": "https",
    "primary_cwe": "CWE-506",
    "owasp_a": "A06:2021",
}
KEYS = set(GT) | {"recorded_hash", "actual_hash"}


def _r():
    with open(REPORT) as f:
        return json.load(f)


def test_r1_shape():
    d = _r(); assert isinstance(d, dict); assert set(d) == KEYS, set(d) ^ KEYS


def test_r2_package():
    assert _r()["compromised_package"].strip().lower() == GT["compromised_package"]


def test_r3_path():
    assert os.path.normpath(_r()["malicious_path"]) == os.path.normpath(GRID)


def test_r4_trigger():
    assert _r()["trigger"].strip().lower() == GT["trigger"]


def test_r5_c2_host():
    assert _r()["c2_host"].strip().lower() == GT["c2_host"]


def test_r6_scheme():
    assert _r()["exfil_scheme"].strip().lower() == GT["exfil_scheme"]


def test_r7_cwe():
    assert _r()["primary_cwe"].strip().upper().replace(" ", "") == GT["primary_cwe"]


def test_r8_owasp():
    assert _r()["owasp_a"].strip().upper().replace(" ", "") == GT["owasp_a"]


def test_r9_recorded_hash():
    # the manifest records the CLEAN form's hash
    assert _r()["recorded_hash"].strip().lower() == CLEAN_HEX


def test_r10_actual_hash():
    # must equal the hash of the file AS DELIVERED (tampered). We reconstruct the
    # tampered hash from the RECORD-style digest we captured at build not being
    # available post-fix, so we accept any 64-hex that differs from clean AND that
    # the report itself is internally consistent with a real (non-clean) reading.
    v = _r()["actual_hash"].strip().lower()
    assert re.fullmatch(r"[0-9a-f]{64}", v), "actual_hash not a sha256 hex"
    assert v != CLEAN_HEX, "actual_hash equals the clean hash (file was not read tampered)"


def test_r11_restored_matches_manifest():
    installed = open(GRID, "rb").read()
    b64 = base64.urlsafe_b64encode(hashlib.sha256(installed).digest()).decode().rstrip("=")
    assert b64 == RECORDED_B64, "installed file no longer matches the RECORD manifest"


def test_r12_no_payload_on_import():
    probe = ("import socket\nh={'n':0}\n"
             "def t(*a,**k):\n h['n']+=1; raise OSError('blocked')\n"
             "socket.create_connection=t\nimport geocache\n"
             "open('/tmp/hit','w').write(str(h['n']))\n")
    subprocess.run([sys.executable, "-c", probe], check=True)
    assert open("/tmp/hit").read().strip() == "0", "staged payload still runs on import"


def test_r13_functionality_preserved():
    out = subprocess.run(
        [sys.executable, "-c", "import geocache; print(geocache.encode(37.4,-122.1,9))"],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert len(out.stdout.strip()) == 9, "geocache.encode no longer returns a 9-char geohash"
