# SilentMesh — Security RL Task Environments

CWE/OWASP-mapped, long-horizon reinforcement-learning environments for training a
security model, built to the Terminal-Bench 4 / "Long-horizon tasks" procurement
spec. Category: **Security — Cyber exploits (supply-chain attacks)**.

We build the **environment and the reward function** (the gym and the referee); the
rollout/scoring against Hy4-Preview and SOTA models runs on the lab's harness.

## What's here

| Path | What it is |
|---|---|
| `requirement-brief.html` | Plain-language brief of the client requirement (open in a browser) |
| `study/` | Foundation study guide + method walkthroughs (start at `study/README.md`) |
| `tasks/nw-mirror-tamper-v2/` | **Flagship sample** — post-build tamper, CWE-506 / OWASP A06, frontier-hardened |
| `tasks/dep-confusion-hijack/` | Dependency confusion, CWE-494 / OWASP A08 |
| `tasks/nw-mirror-tamper-v1/` | The un-hardened first draft (kept to show the v1→v2 strengthening) |

## Each task follows the same contract
- `task.yaml` — the instruction (outcome-only, ≤1500 words, absolute paths, no steering)
- `Dockerfile` — pinned base + pinned tooling; builds the environment
- `env/gen/build_env.py` — deterministic environment generator (deleted from the final image)
- `tests/test_outputs.py` — the verifier / reward function (partial credit, anti-reward-hacking)
- `solution.sh` — reference oracle (graders only; proves solvability)
- `run-tests.sh` — grader entrypoint
- `DOCUMENTATION.md` — curation history, difficulty/rollout plan, failure-mode analysis, QA

## Testing
See `HOW-TO-TEST.md`. Quickest path (no Docker needed):

```bash
python tasks/nw-mirror-tamper-v2/local_test.py
```

Expected: `REWARD = 13/13 = 1.000` (oracle solves it; verifier agrees).

## Status
All tasks verified end-to-end locally (environment builds, oracle solves, verifier
agrees, anti-cheat checks hold). Real mean-reward difficulty numbers (D1–D4) are
produced on the official rollout harness — not fabricated here.
