# Answer key — supply-chain-audit

**INTERNAL ONLY. Never mount or copy this directory into an agent episode.**

The authoritative machine-readable ground truth is generated deterministically by
`env/gen/build_env.py` and enforced by `tests/test_outputs.py`. The task contains nine
compromised distributions spanning tampered-file, malicious-wheel,
dependency-confusion, typosquat, and install-hook vectors, plus six benign red
herrings. The primary category mapping is CWE-506 / OWASP A08:2021; individual
findings use the verifier's mechanism-specific accepted CWE sets.

The reference remediation and report construction are implemented in `solution.sh`.
This file documents the answer-key boundary without duplicating indicator values in
public `DOCUMENTATION.md`.
