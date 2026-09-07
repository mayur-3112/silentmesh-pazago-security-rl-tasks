# SilentMesh — Security RL Task Environments

[![task-suite](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml/badge.svg)](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml)

Long-horizon, CWE/OWASP-mapped reinforcement-learning environments for training a
security model, authored to the Terminal-Bench 4 procurement specification.
**Category: Security — Cyber exploits (supply-chain attacks).**

We deliver the **environment and the reward function** (the gym and the referee).
Difficulty scoring against Hy4-Preview and SOTA models runs on the customer's rollout
harness; this repository ships everything required to run it.

## Repository layout

```
.
├── dataset.yaml            # dataset manifest: tasks, grading gates, harness map
├── run_suite.py            # validates every task (static compliance + oracle solve)
├── Makefile                # make suite | test | build | verify
├── tasks/
│   └── <task-id>/
│       ├── task.yaml           # instruction + metadata (standard schema)
│       ├── Dockerfile          # pinned, reproducible environment
│       ├── docker-compose.yaml # standard run definition
│       ├── env/gen/build_env.py# deterministic environment generator
│       ├── tests/test_outputs.py# verifier / reward function
│       ├── solution.sh         # reference oracle (graders only)
│       ├── run-tests.sh        # grader entrypoint
│       ├── local_test.py       # Docker-free local runner
│       └── DOCUMENTATION.md     # curation history, difficulty & failure-mode analysis
├── CONTRIBUTING.md         # task-authoring standard (enforced by run_suite.py)
├── CODEOWNERS · LICENSE
└── .github/workflows/ci.yml# runs the suite on every push
```

## Tasks

Three distinct trigger surfaces across CWE-mapped classes:

| ID | Difficulty | CWE | OWASP | Trigger | Attack mechanism |
|---|---|---|---|---|---|
| `nw-mirror-tamper-v2` | hard | CWE-506 | A06:2021 | import | Post-build tamper, integrity-manifest detection (flagship) |
| `pickle-policy-rce` | hard | CWE-502 | A08:2021 | deserialization | Unsafe deserialization RCE, capability-ladder + randomized challenge-response |
| `dep-confusion-hijack` | hard | CWE-494 | A08:2021 | resolve | Dependency confusion, hash-pin remediation |
| `nw-mirror-tamper-v1` | medium | CWE-506 | A06:2021 | import | Post-build tamper (baseline; shows the v1→v2 hardening) |

Design follows the ExploitBench pattern: **capability-ladder rewards** (graded rungs,
partial credit) and a **deterministic oracle with per-build randomized
challenge-response** so answers cannot be memorized or hardcoded (see
`pickle-policy-rce`).

### Authoring new gyms
`templates/task-template/` + `tools/new_task.py` scaffold a spec-compliant skeleton;
`run_suite.py` is the gate every new task must pass before commit (see `CONTRIBUTING.md`).

```bash
python tools/new_task.py <task-id> "Title"
```

## Quick start

```bash
pip install -r requirements-dev.txt
make suite          # expected last line: SUITE RESULT: ALL PASS
```

Single task, no Docker: `make test T=nw-mirror-tamper-v2`
In the real container: `make verify T=nw-mirror-tamper-v2` (requires Docker).
Full testing guide: `HOW-TO-TEST.md`.

## Acceptance model (`dataset.yaml`)
Graded on **mean reward**, four conjunctive gates: D1 Hy4-Preview (think) ≥8 rollouts
mean ≤ 0.4 · D2 SOTA ≥5 rollouts mean ≤ 0.6 · D3 mean(Hy) < mean(SOTA) · D4 SOTA
variance ≠ 0. Real rollout figures are produced on the official harness.

## Status
All tasks pass the suite (static compliance + oracle solve) locally and in CI. The
in-container Docker build and the live mean-reward rollouts are the two steps that run
on the customer's infrastructure.
