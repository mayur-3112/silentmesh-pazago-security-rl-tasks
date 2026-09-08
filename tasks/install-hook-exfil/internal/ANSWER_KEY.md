# Answer key — install-hook-exfil

**INTERNAL ONLY. Never include this file in any agent-facing, public, or
grader-shared deliverable.** It exists so a human QA reviewer or the verifier's
own `_sync_check` can confirm ground truth without re-deriving it, and to
satisfy the answer-dependency audit item by making the boundary explicit and
enforceable (see `../DOCUMENTATION.md` for everything that IS safe to publish).

compromised_package=metricslib · pth_file=<site-packages>/metricslib-autoload.pth
loader_module=<site-packages>/metricslib/_autoload.py · trigger=interpreter-startup
c2_host=sync.metrics-collector-cdn.net · c2_port=9443 · exfil_endpoint=/ingest/v1
decode_key=a3f10c5e7b9284d16f0e3a5c9d7182b4
primary_cwe=CWE-506 · owasp_a=A06:2021
fix=remove metricslib-autoload.pth, remove metricslib/_autoload.py, and remove
metricslib/_resources; the legitimate metricslib/{__init__,_stats}.py stay and still
match the dist-info RECORD.
