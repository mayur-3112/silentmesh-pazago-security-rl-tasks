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

| ID | Difficulty | CWE | OWASP | Attack mechanism |
|---|---|---|---|---|
| `mirror-tamper-forensics` | hard | CWE-506 | A08:2021 | Post-build tamper; multi-stage non-inline obfuscation; RECORD/SBOM integrity forensics; restore |
| `dependency-confusion-pin` | hard | CWE-494 | A08:2021 | Resolution-time substitution; recompute-the-trusted-hash; lockfile re-pin + reinstall |
| `install-hook-exfil` | hard | CWE-506 | A06:2021 | Malicious `.pth` startup hook; static payload decode; hook removal verified at interpreter startup |

Every task's reward is the fraction of independent verifier items passed. The reward is
**earned-dominant and un-gameable**: C2 indicators live only inside a multi-stage
obfuscated payload (nothing greppable), guessable/classification fields are credited only
after localization, and remediation is checked behaviourally (exact restore, injected-marker
absence, and an un-clobberable `sys.addaudithook` probe). Measured reward-hacking floor per
task (`python local_test.py --lazy`): **0.00–0.19**; the reference oracle scores **1.000**.

## Quick start

```bash
pip install -r requirements-dev.txt
make suite          # expected last line: SUITE RESULT: ALL PASS
```

Single task, no Docker: `make test T=mirror-tamper-forensics`
In the real container: `make verify T=mirror-tamper-forensics` (requires Docker).
Full testing guide: `HOW-TO-TEST.md`.

## Acceptance model (`dataset.yaml`)
Graded on **mean reward**, four conjunctive gates: D1 Hy4-Preview (think) ≥8 rollouts
mean ≤ 0.4 · D2 SOTA ≥5 rollouts mean ≤ 0.6 · D3 mean(Hy) < mean(SOTA) · D4 SOTA
variance ≠ 0. Real rollout figures are produced on the official harness. The full
vendor-side compilation (category / difficulty / turn-count distribution, rollout
results, failure-mode and provenance pointers, QA re-inspection status) is in
`DELIVERY.md`.

## Status
All three tasks pass the suite (static compliance + oracle solve) locally and in CI; the
real pinned-container Docker path (`make verify`) — oracle + fractional verifier — passes
locally for every task; and each task also grades **1.000** under the Harbor harness
(`harbor run -a oracle`, `terminal-bench-3` reference). The measured reward-hacking floor
is 0.00–0.19 per task. The live mean-reward rollouts (D1–D4) are the one step that runs on
the customer's official harness.
