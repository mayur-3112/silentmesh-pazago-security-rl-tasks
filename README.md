# SilentMesh — Security RL Environments

[![task-suite](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml/badge.svg)](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml)

**Interactive multi-host cyber gyms for training a security model on
supply-chain compromise scenarios.** Each task is a stateful environment the
agent operates in via discrete actions, with partial observability and
outcome-based rewards — not a filesystem puzzle with a JSON report.

## Current focus: one vertical, done properly
This repository has been reorganised around a single scenario family — **CI/CD
supply-chain compromise** — with the flagship task
[`ci-supply-chain-compromise`](tasks/ci-supply-chain-compromise) built on a new
interactive-environment core (`env/core.py`). The plan is to prove the
architecture on one family, then fan out to ten families × ten variants for the
100-task set.

The previous puzzle-style tasks (post-build tamper, dependency-confusion
lockfile, pickle deserialization) are archived under [`legacy/`](legacy) and
should not be used as benchmark deliverables — QC review scored them 46–53/100
because they were static forensic puzzles with encoding tricks rather than true
long-horizon cyber environments. See `legacy/README.md` for why they were
retired and what changed in the new architecture.

## The new architecture (`env/`)
```
env/core.py                     # Environment / Action / Observation / Outcome
tasks/<task-id>/
    scenario.py                 # multi-host state + action handlers + outcomes
    oracle.py                   # reference correct action sequence
    adversarial.py              # cheat agents for reward-shape validation
    local_test.py               # portable runner (no Docker)
    task.yaml                   # instruction + metadata (standard schema)
    DOCUMENTATION.md            # dossier: scenario, reward, topology, limits
```

## Reward semantics
Reward is derived from **security outcomes achieved in the environment**, not
from field-parity in a JSON report:
- positive outcomes for identification, containment, credential hygiene,
  dependency remediation, clean rebuild, verified redeploy, production
  preservation;
- **negative outcomes** (penalties) for destructive actions, deploying
  unverified artefacts, and using leaked credentials without rotation.
- summed and clipped to `[0, 1]`.

The reward shape is validated by adversarial agents that walk plausible-but-bad
strategies; see each task's `adversarial.py` and `DOCUMENTATION.md §5`.

## Quick start
```bash
pip install -r requirements-dev.txt
make suite              # expected last line: SUITE RESULT: ALL PASS
```
Single task, no Docker:
```bash
python tasks/ci-supply-chain-compromise/local_test.py
```
Adversarial reward-shape check:
```bash
python tasks/ci-supply-chain-compromise/adversarial.py
```

## Task inventory
| Task                          | Kind             | Family                         | Status  |
|-------------------------------|------------------|--------------------------------|---------|
| `ci-supply-chain-compromise`  | interactive env  | supply-chain compromise (CI/CD)| Active  |
| `legacy/nw-mirror-tamper-v2`  | puzzle           | post-build tamper              | Retired |
| `legacy/dep-confusion-hijack` | puzzle           | dependency confusion (static)  | Retired |
| `legacy/pickle-policy-rce`    | puzzle           | unsafe deserialization         | Retired |

## Roadmap for the ten-variant family
Same topology; different attack paths / initial footholds / defensive controls:
1. Dependency confusion (current)
2. Compromised CI runner
3. Malicious build action
4. Artifact substitution after signing
5. Poisoned base image
6. Leaked deploy token used by attacker
7. Transitive dependency compromise
8. Registry proxy poisoning
9. Signed but revoked artifact accepted by policy
10. Multi-stage intrusion (registry + build + deploy)
