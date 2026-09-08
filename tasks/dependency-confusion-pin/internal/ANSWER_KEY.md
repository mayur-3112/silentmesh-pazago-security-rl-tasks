# Answer key — dependency-confusion-pin

**INTERNAL ONLY. Never include this file in any agent-facing, public, or
grader-shared deliverable.** It exists so a human QA reviewer or the verifier's
own `_sync_check` can confirm ground truth without re-deriving it, and to
satisfy the answer-dependency audit item by making the boundary explicit and
enforceable (see `../DOCUMENTATION.md` for everything that IS safe to publish).

confused_package=corp-auth-utils · malicious_version=2.9.9 · trusted_version=2.9.0
malicious_artifact=/opt/pip-cache/corp_auth_utils-2.9.9-py3-none-any.whl
trusted_artifact=/opt/pip-cache/corp_auth_utils-2.9.0-py3-none-any.whl
trusted_sha256=sha256(trusted wheel file) — RECOMPUTED by the verifier, published nowhere
missing_control=hash-pinning · indicator_host=collector.authlib-cdn.net · indicator_port=8444
(exfil endpoint /ingest/v1, not graded) · decode key 4d3a9fc1e07b625d8a14f39c2be5710d (in
corp_auth_utils/_resources/cachekey.bin) · primary_cwe=CWE-494 · owasp_a=A08:2021
fix=(a) requirements.lock corp-auth-utils line -> `==2.9.0 --hash=sha256:<recomputed>`,
every other line byte-identical; (b) byte-restore corp_auth_utils from the trusted wheel
(rm the package dir incl. _resources, extract the 2.9.0 wheel) so import fires no socket
audit event and the marker is absent; (c) sign() still returns a 64-char hex.
