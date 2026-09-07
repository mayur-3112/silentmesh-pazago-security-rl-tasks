# SilentMesh — Security RL Environment (Sample)

[![task-suite](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml/badge.svg)](https://github.com/mayur-3112/silentmesh-pazago-security-rl-tasks/actions/workflows/ci.yml)

One interactive multi-host cyber gym, submitted as the sample task for QC.
The agent operates in a stateful environment via discrete actions with partial
observability; reward is derived from security outcomes achieved, not from
matching fields in a report.

## The task
[`tasks/ci-supply-chain-compromise`](tasks/ci-supply-chain-compromise) — a
CI/CD dependency-confusion compromise. Six hosts (dev-laptop, ci-runner,
pkg-registry, artifact-store, staging, prod); the agent must identify, contain,
rotate, remediate, rebuild, verify, and redeploy — without damaging production.

See that task's `DOCUMENTATION.md` for the full dossier: scenario, topology,
reward table, adversarial validation, container delivery, and known limitations.

## Why this replaced the earlier submission
An initial batch of three puzzle-style tasks (static forensic inspection + a
JSON report) was reviewed and scored 46–53/100 — rejected. The critique was
correct: those were long filesystem puzzles with encoding tricks, not stateful
RL environments. They're archived under [`legacy/`](legacy) with the review
findings; `env/core.py` and this task are the response.

## Quick start
```bash
pip install -r requirements-dev.txt
make suite                                          # SUITE RESULT: ALL PASS
python tasks/ci-supply-chain-compromise/local_test.py   # oracle: score 1.000
python tasks/ci-supply-chain-compromise/adversarial.py  # reward-shape check
```
Docker (the agent's real interface):
```bash
docker build -f tasks/ci-supply-chain-compromise/Dockerfile -t ci-scc .
docker run --network=none -it ci-scc
# inside: gym
```

## Layout
```
env/core.py                                    # Environment / Action / Observation / Outcome
tasks/ci-supply-chain-compromise/
    scenario.py        # multi-host state + action handlers + outcomes
    oracle.py           # reference correct action sequence (score 1.000)
    adversarial.py      # cheat agents for reward-shape validation
    gym.py               # shell-facing agent interface (the Docker entrypoint)
    local_test.py        # portable runner, no Docker
    Dockerfile · docker-compose.yaml · run-tests.sh
    task.yaml · DOCUMENTATION.md · AGENT.md
legacy/                # retired puzzle-style tasks; see legacy/README.md
```
