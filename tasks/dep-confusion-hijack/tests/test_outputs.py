"""Verifier for dep-confusion-hijack. Reward = fraction of items passed (0..1).

Anti-reward-hacking design:
  * malicious_version (2.9.9) is greppable, so it earns little on its own; the real
    credit is R_fix: the corrected lockfile must re-resolve to the TRUSTED build and
    carry the sha256 the mirror actually publishes (recomputed here — a guessed hash
    fails).
  * indicator_host is only recoverable by statically decoding the base64+zlib blob;
    the env is offline so a live beacon cannot leak it.
  * R_import: corp_auth_utils must still import (no rm-the-package shortcut).
"""
import json, os, sys, re, hashlib, subprocess, sysconfig

REPORT = "/app/report.json"
LOCK = "/app/build/requirements.lock"
CACHE = "/opt/pip-cache"
MIRROR_INDEX = "/opt/mirror/index.json"

TRUSTED_WHL = os.path.join(CACHE, "corp_auth_utils-2.9.0-py3-none-any.whl")
MAL_WHL = os.path.join(CACHE, "corp_auth_utils-2.9.9-py3-none-any.whl")
TRUSTED_SHA = hashlib.sha256(open(TRUSTED_WHL, "rb").read()).hexdigest()

GT = {
    "confused_package": "corp-auth-utils",
    "malicious_version": "2.9.9",
    "trusted_version": "2.9.0",
    "malicious_artifact": MAL_WHL,
    "missing_control": "hash-pinning",
    "indicator_host": "auth-metrics-collector.net",
    "primary_cwe": "CWE-494",
    "owasp_a": "A08:2021",
}
KEYS = set(GT)


def _r():
    with open(REPORT) as f:
        return json.load(f)


def test_r1_shape():
    d = _r(); assert isinstance(d, dict); assert set(d) == KEYS


def test_r2_package():
    assert _r()["confused_package"].strip().lower() == GT["confused_package"]


def test_r3_malicious_version():
    assert _r()["malicious_version"].strip() == GT["malicious_version"]


def test_r4_trusted_version():
    assert _r()["trusted_version"].strip() == GT["trusted_version"]


def test_r5_artifact():
    assert os.path.normpath(_r()["malicious_artifact"]) == os.path.normpath(MAL_WHL)


def test_r6_missing_control():
    assert _r()["missing_control"].strip().lower() == GT["missing_control"]


def test_r7_indicator_host():
    assert _r()["indicator_host"].strip().lower() == GT["indicator_host"]


def test_r8_cwe():
    assert _r()["primary_cwe"].strip().upper().replace(" ", "") == GT["primary_cwe"]


def test_r9_owasp():
    assert _r()["owasp_a"].strip().upper().replace(" ", "") == GT["owasp_a"]


def test_r10_fix_reresolves_to_trusted():
    """The corrected lock must pin ==2.9.0 AND carry the mirror's real sha256."""
    txt = open(LOCK).read()
    line = next((l for l in txt.splitlines()
                 if re.match(r"\s*corp-auth-utils", l, re.I)), "")
    assert re.search(r"==\s*2\.9\.0(\b|$|\s|--)", line), f"not pinned to 2.9.0: {line!r}"
    m = re.search(r"sha256:([0-9a-fA-F]{64})", line)
    assert m, "no sha256 hash pin present"
    assert m.group(1).lower() == TRUSTED_SHA, "hash does not match the trusted artifact"


def test_r11_decoy_untouched():
    txt = open(LOCK).read()
    assert "requests==2.31.0 --hash=sha256:deadbeef" in txt, "unrelated entry altered"


def test_r12_import_preserved():
    out = subprocess.run(
        [sys.executable, "-c", "import corp_auth_utils; print(corp_auth_utils.sign(b'k', b'm'))"],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert len(out.stdout.strip()) == 64, "sign() no longer returns a sha256 hex digest"
