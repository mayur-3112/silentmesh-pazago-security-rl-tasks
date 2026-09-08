# Answer key — mirror-tamper-forensics

**INTERNAL ONLY. Never include this file in any agent-facing, public, or
grader-shared deliverable.** It exists so a human QA reviewer or the verifier's
own `_sync_check` can confirm ground truth without re-deriving it, and to
satisfy the answer-dependency audit item by making the boundary explicit and
enforceable (see `../DOCUMENTATION.md` for everything that IS safe to publish).

compromised_package=geocache · malicious_path=<site-packages>/geocache/_cache.py
trigger=import · c2_host=telemetry.pkg-sync-cdn.net · c2_port=8443 · exfil_endpoint=/v2/collect
decode_key=9f1c33a75be24d0186ca4471e2d5b8f0
primary_cwe=CWE-506 · owasp_a=A08:2021
recorded_hash=sha256(clean _cache.py) · actual_hash=sha256(tampered _cache.py)
fix=restore geocache/{__init__,_grid,_cache}.py from /opt/mirror/geocache-2.3.1 and remove geocache/_resources

## Fixed weakness (was: ceiling bug, resolved)
The C2 host's XOR-obfuscation key is meant to come from an env var
(`GC_BUILD_SIG`) deliberately unset in the sandbox. A prior build derived that
key as `sha256(recorded_hash)` alone — since `recorded_hash` is already
published in the dist-info RECORD (which the agent reads anyway), 5/5 blind
Opus 5 rollouts found this independently, collapsing D2/D4 variance. Fixed:
the key is now `sha256(recorded_hash + outer_stage2_key)`, where the outer
key (`.buildcache`) is only obtainable after solving the four-stage
base85/XOR/zlib/marshal obfuscation — a genuine second, non-free ingredient.
`env/gen/build_env.py`, `solution.sh`, and `local_test.py` all updated to
match; oracle still scores 1.000, floor unchanged at 0.111.
