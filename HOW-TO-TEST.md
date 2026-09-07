# How to test

Four levels, easiest first. Levels 1–2 need only Python; 3 needs Docker; 4 needs the
lab's model harness.

## 0. Whole-repo test suite (recommended first check)
```bash
python run_suite.py
```
Validates **every** task at once: builds each env, runs its oracle to full reward,
and statically checks spec compliance (instruction word count, no headings/steering,
absolute paths, Dockerfile pinning, report-key parity). Expected last line:
`SUITE RESULT: ALL PASS`. This also runs automatically in CI on every push
(`.github/workflows/ci.yml`).

## 1. Logic test — no Docker (Windows/Mac/Linux, just Python)
```bash
python tasks/nw-mirror-tamper-v2/local_test.py
```
Builds the environment in a temp folder, runs the reference solution, and grades it
with the same 13 checks the container verifier uses. Expected:
`REWARD = 13/13 = 1.000`. This proves the task is solvable and the verifier is correct.

## 2. Solve it yourself (best way to learn the task)
```bash
python tasks/nw-mirror-tamper-v2/local_test.py --manual
```
It builds the env, prints the file paths, and waits. Investigate the files, write your
`report.json`, restore the tampered file, press Enter — it scores your attempt.

## 3. Real container test — Docker
Needs Docker Desktop. From inside a task folder (e.g. `tasks/nw-mirror-tamper-v2`):
```bash
docker build -t nwmt-v2 .
docker run --network=none -dit --name nwmt nwmt-v2
docker exec nwmt bash /app/solution.sh
docker cp tests nwmt:/app/tests && docker cp run-tests.sh nwmt:/app/
docker exec --network=none nwmt bash /app/run-tests.sh
```
Runs the oracle then the verifier inside the real pinned container; all tests pass.
Cleanup: `docker rm -f nwmt`.

## 4. Difficulty rollout — lab harness (Pazago side)
Skip `solution.sh`; instead let a model (Hy4-Preview think mode via Claude Code, or
Opus 5 / GPT via its native harness) attempt the task ≥8 / ≥5 times and record the
mean reward. This is the D1–D4 acceptance measurement; it needs model access we don't
hold locally.

## What each level proves
| Level | Proves | Needs |
|---|---|---|
| 1 `local_test.py` | task solvable + verifier correct | Python |
| 2 `--manual` | you understand the task | Python |
| 3 Docker | works in the real pinned container | Docker |
| 4 rollouts | hits the ≤0.4 / ≤0.6 difficulty gate | model harness |
