# Contributing — task authoring standard

Every task in `tasks/` MUST satisfy the checks in `run_suite.py` before it is
committed. Run `make suite` locally; CI runs it on every push.

## Required files per task
`task.yaml` · `Dockerfile` · `docker-compose.yaml` · `env/gen/build_env.py` ·
`tests/test_outputs.py` · `solution.sh` · `run-tests.sh` · `local_test.py` ·
`DOCUMENTATION.md`

## Instruction rules (task.yaml `instruction:`)
- Outcome-only: state WHAT to produce, never HOW to solve it.
- <= 1500 words (`content.split()`); no markdown headings; no steering phrases
  ("think step by step", "you are an expert"); absolute paths only.

## Verifier rules (tests/test_outputs.py)
- Reward = fraction of independent checks (partial credit -> non-zero variance).
- Answers must not be recoverable by grep or by live execution; block the
  "report without remediation" and "delete instead of fix" shortcuts.
- Every field named in the instruction must be graded (report-key parity).

## Difficulty target (graded on mean reward by the harness, not here)
D1 Hy4-Preview think >=8 rollouts mean <= 0.4 · D2 SOTA >=5 rollouts mean <= 0.6 ·
D3 mean(Hy) < mean(SOTA) · D4 SOTA variance != 0. Turn-count: Hy>80 or Opus5-xhigh>60.

## Provenance
`DOCUMENTATION.md` must carry curation history (v1->final), difficulty/rollout plan,
failure-mode analysis, and QA notes.
