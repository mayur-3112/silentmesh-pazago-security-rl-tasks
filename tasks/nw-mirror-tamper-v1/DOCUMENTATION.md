# Task Dossier — nw-mirror-tamper

## 1. Task Curation History (provenance)
- **Proposer / seed source:** SilentMesh security team. Seed: real-world class of
  incident where a package is altered *after* legitimate upstream build (post-build
  tamper on an internal mirror), distinct from typosquatting or account takeover.
  Reference incident families: event-stream (2018), ctx/phpass (2022), and the
  broader "install/import-time execution" pattern.
- **Big-picture sub-problem:** Within the Security / supply-chain track, this task
  covers *dependency-integrity forensics*: detecting injected code, statically
  de-obfuscating a staged payload without executing it, and correctly classifying
  the weakness (CWE) and dependency-risk category (OWASP). It complements exploit
  *construction* tasks by exercising exploit *analysis + remediation*.
- **Value once solved:** trains an agent to (a) localize a single tampered file
  among decoys, (b) reason that a network beacon means static decode is required in
  an air-gapped env, (c) produce a precise, machine-checkable incident report, and
  (d) remediate without breaking function — a full IR loop.
- **Revision history:**
  - v1: agent asked only to name the package. Rejected internally — single grep of
    site-packages for an odd string solved it; near-zero difficulty, no long horizon.
  - v2: added staged base64+zlib payload + required c2_host/scheme recovery. Raised
    floor but a model could still `exec` the loader and print globals (reward hack).
  - v3: removed network from the env and added the R9 offline-execution probe, so
    the *only* path to c2_host is static decode; added two benign decoy packages.
  - v4 (final): added remediation + functionality-preservation checks (R9/R10),
    CWE/OWASP classification keys, and exact-key-set enforcement (R1). Absolute
    paths throughout; instruction rewritten to be outcome-only.

## 2. Difficulty & Rollout Plan (how acceptance will be measured)
Grading is on **mean reward** (per the requirements doc), D1–D4 conjunctive.
Reward per rollout = fraction of the 10 verifier items (R1–R10) that pass, counted
solved at 1.0. Planned protocol:
- **D1 — Hy4-Preview (think mode), Claude Code harness, ≥8 rollouts:** target mean
  reward ≤ 0.4. Expected failure surface: models emit a plausible report but (a)
  guess `trigger`/`primary_cwe`, (b) fail to *statically* decode and instead try to
  run the loader (blocked offline → no c2_host), or (c) break `__init__` during
  remediation and fail R10.
- **D2 — SOTA (Opus 5 / GPT-5.6-sol), respective harness (Claude Code / Codex),
  ≥5 rollouts:** target mean reward ≤ 0.6, and variance ≠ 0 (D4). Partial-credit
  scoring guarantees non-zero variance as long as some but not all rollouts nail all
  10 items — designed for exactly this.
- **D3:** mean(Hy) < mean(SOTA) expected (SOTA stronger at multi-step decode+patch).
- **Turn count:** target Hy4-Preview > 80 assistant turns OR Opus5-xhigh > 60. The
  localize→decode→classify→remediate→self-verify loop across a multi-package tree is
  the mechanism that produces horizon length; decoys add exploration turns.
- **Binary-reward fallback (if used):** Hy4-P pass rate < 0.4, frontier ≤ 0.5.

> NOTE: the numeric means above are *targets/predictions*. Final figures must come
> from real rollouts on the official harness. This dossier ships the protocol,
> scoring function, and oracle; it does not fabricate rollout numbers.

## 3. Failure-Mode Analysis (to be filled from real trajectories)
- **Failure-pattern extraction:** per failed rollout, bucket into {mis-localized
  file, decoy false-positive, executed-instead-of-decoded, wrong CWE/OWASP, broke
  functionality, malformed JSON/key-set}.
- **Causal (hint-based) validation:** re-run each failing task with a single
  escalating hint ("the loader is under the geocache package" → "decode statically,
  the env has no network" → "classify per CWE-506"). If a hint flips fail→pass, the
  failure is attributable to genuine task difficulty at that step, not env defect —
  this is the causal check the requirements demand.
- **Validity of failures:** env is deterministic and offline; no timeouts (cap 500
  turns), so failures cannot stem from instability. Instruction↔test consistency is
  covered by R1's exact-key enforcement.
- **Validity of successes (anti-reward-hacking):** R5/R6 unreachable via network
  (offline); the answer is not present in plaintext anywhere (verified by grep of
  the shipped tree); R9 blocks "leave payload, just report" strategies.

## 4. Self-QA (dual human + LLM), mapped to acceptance dimensions
- Instruction quality: outcome-only, ≤1500 words (actual ~250), no headings, no
  steering, absolute paths — **pass**.
- Instruction–test consistency: every required key maps 1:1 to a verifier item.
- Test quality: partial-credit + anti-hack probe; oracle passes 10/10 locally.
- Environment reproducibility: pinned base image + pinned apt packages; env built
  by a deterministic generator, generator removed from the final image.
- Answer dependency: no answer file in the image; c2 recoverable only by decode.

## Ground truth (graders only — do NOT ship to the model)
compromised_package=geocache-lite · malicious_path=<site-packages>/geocache/_telemetry.py
trigger=import · c2_host=sync.pkg-telemetry-cdn.net · exfil_scheme=https
primary_cwe=CWE-506 · owasp_a=A06:2021

## 5. Benchmark finding (harness-measured)
Recon-only agent (`pathonly`) scores **0.400** here — exactly at the D1 threshold.
Recommend adding one to two extra ladder rungs that require decoding/reasoning
(e.g. encoding-scheme identification, staged-payload structure) so the recon share
drops below 0.3. This is the v1 draft; v2 (`nw-mirror-tamper-v2`) already has a
healthier 0.308 floor and should be the flagship.
