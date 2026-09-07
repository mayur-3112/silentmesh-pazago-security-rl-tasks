#!/usr/bin/env python3
"""Deterministically construct a dependency-confusion incident environment.

Mechanism: the build resolved `corp-auth-utils` to a PUBLIC index artifact
version 2.9.9 (attacker) instead of the INTERNAL mirror's 2.9.0 (trusted),
because the lockfile pinned no hash. The installed 2.9.9 carries a staged,
offline-recoverable indicator. The fix is to pin ==2.9.0 with the trusted
sha256 so re-resolution can never pick the public artifact again.

Ground truth (graders only):
  confused_package   = corp-auth-utils
  malicious_version  = 2.9.9
  trusted_version    = 2.9.0
  malicious_artifact = /opt/pip-cache/corp_auth_utils-2.9.9-py3-none-any.whl
  missing_control    = hash-pinning
  indicator_host     = auth-metrics-collector.net
  primary_cwe        = CWE-494
  owasp_a            = A08:2021
"""
import base64, zlib, os, hashlib, textwrap, sysconfig

CACHE = "/opt/pip-cache"
MIRROR = "/opt/mirror"
BUILD = "/app/build"
SP = sysconfig.get_paths()["purelib"]
for d in (CACHE, MIRROR, BUILD):
    os.makedirs(d, exist_ok=True)

# ---- the legitimate 2.9.0 artifact (trusted, internal mirror) ----
trusted_src = textwrap.dedent('''
    """corp-auth-utils 2.9.0 (internal, legitimate)."""
    import hmac, hashlib
    def sign(secret: bytes, msg: bytes) -> str:
        return hmac.new(secret, msg, hashlib.sha256).hexdigest()
    __version__ = "2.9.0"
''').encode()
trusted_whl = os.path.join(CACHE, "corp_auth_utils-2.9.0-py3-none-any.whl")
open(trusted_whl, "wb").write(trusted_src)          # stand-in "wheel" = its payload bytes
TRUSTED_SHA = hashlib.sha256(trusted_src).hexdigest()

# ---- the malicious 2.9.9 artifact (public index, attacker) ----
indicator = 'host="auth-metrics-collector.net"; scheme="https"; path="/collect"'
blob = base64.b64encode(zlib.compress(indicator.encode(), 9)).decode()
malicious_src = textwrap.dedent(f'''
    """corp-auth-utils 2.9.9."""
    import hmac, hashlib, base64 as _b, zlib as _z
    _M = "{blob}"
    def _bootstrap():
        try:
            exec(compile(_z.decompress(_b.b64decode(_M)), "<m>", "exec"), {{}})
        except Exception:
            pass
    def sign(secret: bytes, msg: bytes) -> str:
        return hmac.new(secret, msg, hashlib.sha256).hexdigest()
    __version__ = "2.9.9"
    _bootstrap()
''').encode()
malicious_whl = os.path.join(CACHE, "corp_auth_utils-2.9.9-py3-none-any.whl")
open(malicious_whl, "wb").write(malicious_src)

# ---- the ACTIVE install is the malicious 2.9.9 (what got resolved) ----
open(os.path.join(SP, "corp_auth_utils.py"), "wb").write(malicious_src)
di = os.path.join(SP, "corp_auth_utils-2.9.9.dist-info")
os.makedirs(di, exist_ok=True)
open(os.path.join(di, "METADATA"), "w").write(
    "Metadata-Version: 2.1\nName: corp-auth-utils\nVersion: 2.9.9\n")

# ---- internal mirror index: publishes the TRUSTED version + its sha256 ----
open(os.path.join(MIRROR, "index.json"), "w").write(
    '{"corp-auth-utils": {"version": "2.9.0", "sha256": "%s", '
    '"source": "internal-mirror"}}\n' % TRUSTED_SHA)

# ---- the pip resolution log: shows 2.9.9 chosen from the PUBLIC index ----
open(os.path.join(BUILD, "install.log"), "w").write(textwrap.dedent(f'''
    Looking in indexes: https://pypi.org/simple, https://mirror.corp.internal/simple
    Collecting corp-auth-utils
      Found link corp-auth-utils 2.9.0 (from mirror.corp.internal)
      Found link corp-auth-utils 2.9.9 (from pypi.org)
      Using version 2.9.9 (newest of: 2.9.0, 2.9.9)
    Downloading corp_auth_utils-2.9.9-py3-none-any.whl
    Installing collected packages: corp-auth-utils
    Successfully installed corp-auth-utils-2.9.9
'''))

# ---- the lockfile: NO hash pin (the missing control) ----
open(os.path.join(BUILD, "requirements.lock"), "w").write(
    "# resolved build lock\ncorp-auth-utils>=2.9.0\n")

# ---- decoy: an unrelated pinned dep, correct, to punish shallow edits ----
open(os.path.join(BUILD, "requirements.lock"), "a").write(
    "requests==2.31.0 --hash=sha256:deadbeef\n")

print("built. trusted sha256:", TRUSTED_SHA)
