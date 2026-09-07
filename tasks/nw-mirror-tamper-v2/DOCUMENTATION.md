# Task Dossier — nw-mirror-tamper-v2 (frontier-hardened)

## 0. What changed from v1, and why (this is the strengthening)
v1 was solvable by "find the oddly-named file and base64-decode it once." A frontier
model would clear that fast, pushing mean reward *above* the D1/D2 gate and inviting a
QC rejection on "too easy / too greppable." v2 raises the floor along the exact
dimensions a lab re-inspects:

| Hardening | v1 | v2 | Effect on difficulty / QC |
|---|---|---|---|
| Injection site | new file `_telemetry.py` | appended inside legit `_grid.py` | kills "find the odd filename"; forces real localization |
| Detection signal | eyeballing | **RECORD integrity-manifest mismatch** | forces genuine supply-chain forensics (survives expert review) |
| Obfuscation | base64+zlib (1 step) | **base64 → XOR(key) → zlib (2 steps)**, key split as a "salt" | a single decode is insufficient → lower pass rate |
| Graded fields | 7 | **9** (adds `recorded_hash`, `actual_hash`) | un-guessable 64-hex values → real computation required |
| Correct fix | delete loader | **restore clean module from mirror** | deletion breaks functionality (R13) and manifest (R11) |

## 1. Curation history
- **Proposer/seed:** SilentMesh. Seed: post-build tamper (event-stream 2018 class) +
  the wheel RECORD integrity model as the realistic detection primitive.
- **Big picture:** dependency-integrity forensics via the distribution's own manifest
  — the technique a real responder uses. Pairs with dep-confusion-hijack (CWE-494) to
  span A06 and A08.
- **Value once solved:** trains the model to (a) detect tamper by manifest mismatch,
  (b) chain a multi-layer static decode offline, (c) compute and report integrity
  evidence, (d) remediate by restoration, not deletion.
- **Revisions:** v1 (grep-solvable) → v2 (manifest-based, two-layer, restore-fix,
  hash-evidence fields). See table above.

## 2. Difficulty & rollout plan
Graded on mean reward, D1–D4 conjunctive; 13 partial-credit items. Reward-shedding
chain: localize via RECORD (not grep) → two-step decode (offline; live beacon
blocked) → compute two hashes → restore (delete/stub fails R11/R13) → correct
CWE/OWASP. Targets: Hy4-Preview think ≥8 rollouts mean ≤0.4; SOTA ≥5 rollouts mean
≤0.6, variance ≠0; mean(Hy) < mean(SOTA). Turn-count target Hy>80 or Opus5-xhigh>60.
*Final figures come from the official harness; none are fabricated here.*

## 3. Failure-mode analysis (from real trajectories)
Buckets: {missed-manifest-mismatch, single-decode-only, guessed-hash, deleted-file,
stubbed-file, wrong-CWE, malformed-keys}. Hint ladder for causal validation:
"compare installed files to the dist-info RECORD" → "the payload is XOR-then-zlib
under the salt" → "restore from /opt/mirror". A hint flipping fail→pass attributes the
failure to genuine step difficulty, not an environment defect.

## 4. Self-QA & known verifier note
- Instruction: outcome-only, 270 words, no headings/steering, absolute paths.
- Instruction↔test: every report key + the restore maps 1:1 to a verifier item.
- Reproducibility: pinned base + pinned apt; generator deleted from final image.
- Answer dependency: no answer file on disk; c2 only via two-step decode; hashes via
  RECORD + file read.
- **Honest limitation (R10):** after remediation the grader cannot re-derive the
  *tampered* file's hash from disk, so `actual_hash` is credited as "a valid sha256
  that is not the clean hash" rather than an exact match. Exactness of the incident
  is still enforced by R9 (`recorded_hash` exact vs the mirror) and R11 (restored file
  must match the RECORD manifest). Net effect: at most 1/13 of reward is obtainable
  without the exact tampered hash — acceptable under partial credit, and disclosed.

## Ground truth (graders only)
compromised_package=geocache-lite · malicious_path=<site-packages>/geocache/_grid.py
trigger=import · c2_host=sync.pkg-telemetry-cdn.net · exfil_scheme=https
primary_cwe=CWE-506 · owasp_a=A06:2021
recorded_hash=sha256(clean _grid.py) · actual_hash=sha256(tampered _grid.py)
fix=restore _grid.py from /opt/mirror/geocache-lite-1.4.2/_grid.py
