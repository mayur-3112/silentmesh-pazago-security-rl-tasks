# nw-mirror-tamper — SilentMesh sample task for Pazago QC

Category: **Security / Cyber exploits — supply-chain attack + CWE/OWASP mapping.**
A Terminal-Bench-style, long-horizon agentic task: analyze a post-build-tampered
Python dependency, statically de-obfuscate its staged payload in an air-gapped
environment, classify the weakness (CWE-506 / OWASP A06:2021), file a precise
machine-checked report, and remediate without breaking function.

## Layout
- `task.yaml` — task + outcome-only instruction (252 words, spec-compliant)
- `Dockerfile` — pinned base + pinned apt tooling; builds the tampered env
- `env/gen/build_env.py` — deterministic env generator (removed from final image)
- `tests/test_outputs.py` — verifier, 10 partial-credit items, anti-reward-hack probe
- `run-tests.sh` — grader entrypoint (pytest)
- `solution.sh` — oracle solution (graders only; proves solvability, feeds SOTA variance)
- `DOCUMENTATION.md` — curation history, rollout/difficulty plan, failure-mode & QA

## Build & grade (Docker)
    docker build -t nw-mirror-tamper .
    docker run --network=none -d --name t nw-mirror-tamper sleep infinity
    # agent works inside container, writes /app/report.json, then:
    docker exec t bash /app/solution.sh      # oracle only — skip for a real rollout
    docker cp tests t:/app/tests && docker cp run-tests.sh t:/app/
    docker exec --network=none t bash /app/run-tests.sh

## Status
Env build, tamper-on-import, static-decode oracle, offline anti-hack probe, and
remediation+functionality checks all verified end-to-end locally. Rollout mean-reward
numbers (D1–D4) are to be produced on the official harness — see DOCUMENTATION.md.
