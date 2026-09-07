# Delivery & Acceptance Dossier — SilentMesh security RL tasks

This document is the vendor-side compilation the procurement brief requires: it
aggregates **category, difficulty, turn-count, and rollout distribution** across the
suite, the **measured anti-reward-hacking evidence**, and pointers to the per-task
**failure-mode analysis** and **provenance** dossiers. It is the single entry point a
grader reads before re-inspection.

Scope: the **Security — Cyber exploits (supply-chain attacks)** category, mapped to
CWE / OWASP. This repository ships the **environment and the reward function** for each
task; the live mean-reward rollouts run on the customer's official harness.

> **On numbers:** per the brief, rollout means / pass-rates are produced on the official
> harness and are **not fabricated here**. Cells marked _pending (official harness)_ are
> filled after the D1–D4 measurement runs. Everything else is a fact about the shipped
> artifacts, reproducible with the commands in `HOW-TO-TEST.md`.

---

## 1. Task inventory & category distribution

| ID | Difficulty | Primary CWE | OWASP 2021 | Attack mechanism | Items |
|---|---|---|---|---|---|
| `mirror-tamper-forensics` | hard | CWE-506 | A08:2021 | Post-build tamper hidden in a legit module; multi-stage **non-inline** obfuscation (loader + key + resource blob + marshalled payload); RECORD/SBOM integrity forensics; restore remediation | 16 |
| `dependency-confusion-pin` | hard | CWE-494 | A08:2021 | Resolution-time substitution from a non-mirror index; trusted hash **must be recomputed** (published nowhere); lockfile re-pin + reinstall of the trusted build | 14 |
| `install-hook-exfil` | hard | CWE-506 | A06:2021 | Malicious `.pth` file executed at **interpreter startup**; multi-stage static payload decode; hook removal verified by a fresh-interpreter audit probe | 16 |

**Category:** 3/3 Security / supply-chain, CWE- and OWASP-mapped, spanning CWE-494 + CWE-506
and A06 + A08 across three **distinct** mechanics (module tamper / resolution-time
substitution / startup-hook). **Difficulty distribution:** hard × 3.

---

## 2. Difficulty, reward design & measured anti-reward-hacking evidence

Difficulty is judged on **mean reward** (D1–D4 conjunctive). Reward = **weighted fraction
of independent verifier items** (partial credit → non-zero variance, D4): payload-analysis /
un-guessable items carry weight 3–5, routine incident-response items weight 1. The reward
is **earned-dominant and un-gameable** by construction:

- **No free points** — guessable/small-set fields (package, trigger, CWE, OWASP, version,
  control) are credited **only** after localization (and, for weakness classification,
  the decoded indicator) is already correct.
- **Un-guessable, non-greppable, detonation-proof core** — C2 host/port/endpoint live only
  inside a marshalled code object behind a four-stage decode (base85 → XOR(key) → zlib →
  marshal) split across files; the host is additionally XOR-encrypted under a key the payload reads at runtime from an
  **environment variable unset in the sandbox** (environmental keying), so a naive "import
  and capture the socket call" detonation decrypts to garbage and recovers nothing — the host must be reconstructed by real
  static reverse engineering. Exact SHA-256 digests are matched exactly (never a wildcard).
- **Weighted so mechanical IR is the minority** — an agent that localizes, hashes, restores
  and classifies but does **no payload analysis** caps at **0.333**, under the D1 (Hy ≤ 0.4)
  gate; only genuine reverse engineering reaches 1.0.
- **Do-nothing = 0** — every remediation item is false on the untouched baseline.
- **Structural, loophole-proof remediation** — exact restore/content match + injected-marker
  absence + injected artifacts physically gone (not merely de-listed from the agent-editable
  manifest). Delete / stub / manifest-edit / socket-clobber all fail.

**Measured reward profile** (reproducible; `local_test.py` and `--lazy`):

| ID | do-nothing / guess | competent IR, **no payload analysis** | naive detonation | oracle |
|---|---|---|---|---|
| `mirror-tamper-forensics` | 0.11 | **0.333** | 0.333 | 1.000 |
| `dependency-confusion-pin` | 0.00 | **0.333** | 0.333 | 1.000 |
| `install-hook-exfil` | 0.11 | **0.333** | 0.333 | 1.000 |

So an agent that does everything except the genuine payload reverse engineering caps at
0.333; dynamic detonation is defeated by environmental keying (measured: 0 real-host captures); and reward
rises only with real RE. Each task was **adversarially audited** (an independent multi-agent
pass that reproduced the floors and hunted reward-hacks: guessable fields, do-nothing credit,
single-decode/grep shortcuts, symptom-suppression, wildcard hashes, dynamic detonation,
manifest-edit, answer-leaks); every confirmed hole was closed and re-verified.

> **Rollout caveat (stated plainly):** these floors are *structural* evidence, measured
> locally. Whether a frontier model's **actual mean reward** lands under the aggressive
> D1 (≤0.4) / D2 (≤0.6) gates depends on how reliably it completes the reverse engineering
> — a model-behaviour question only the official Hy4/SOTA rollouts (§5) can settle.

**Acceptance gates.** D1 Hy4-Preview (**think mode**), ≥8 rollouts, mean ≤ 0.4 · D2 SOTA
(**Opus 5 / GPT-5.6-sol or newer**), ≥5 rollouts, mean ≤ 0.6 · D3 mean(Hy) < mean(SOTA) ·
D4 reward_variance(SOTA) ≠ 0. Security-category target: frontier pass@5 < 0.4, Hy pass@8 < 0.5.
**Solvability** is demonstrated by the reference oracle (full reward locally, in Docker, and
under Harbor).

---

## 3. Harness map (model-specialized — not mixed)

| Model family | Harness |
|---|---|
| Claude-family | Claude Code |
| GPT-family | Codex |
| Hy4-Preview (think mode) | Claude Code |

Source of truth: `dataset.yaml` → `harness_map`. Verified runnable under **Harbor 0.20**
(`terminal-bench-3` reference): each task grades **1.000** with `harbor run -a oracle`.

---

## 4. Turn-count distribution & timeout policy

Turn count = number of `role=assistant` messages. Bar: Hy4-Preview (think) turns **> 80**
(TB4 ≈ 100) **or** Opus5-xhigh turns **> 60** (TB4 ≈ 75). Each task's horizon is driven by
a broad forensic loop over a multi-package tree with decoys, manifests, and an
SBOM/lockfile, plus a multi-stage decode and a behaviourally-verified remediation.

**Timeout policy:** the acceptance harness should run with **no wall-clock timeout** and a
**500-turn cap** (Hy4-Preview API calls can be slow); the per-task `max_agent_timeout_sec`
is the Terminal-Bench schema fallback, not a substitute for the cap. Measured turn-count
distributions are filled from the official harness (pending).

---

## 5. Rollout results (pending official harness)

| ID | Hy mean (≥8) | SOTA mean (≥5) | mean(Hy)<mean(SOTA) | SOTA var≠0 | Hy pass@8 | Frontier pass@5 |
|---|---|---|---|---|---|---|
| `mirror-tamper-forensics` | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
| `dependency-confusion-pin` | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
| `install-hook-exfil` | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

Acceptance uses the mean-reward gates (§2); pass@k are reference figures.

---

## 6. Failure-mode analysis & 7. Provenance

Each task's `DOCUMENTATION.md` carries: failure-pattern extraction (bucketed classes),
causal validation via an escalating hint ladder (a hint that flips fail→pass attributes the
failure to genuine step difficulty, not an environment defect), validity of failed
trajectories (deterministic offline env, no instability), validity of successful
trajectories (the measured anti-reward-hacking evidence above), and full curation history
(proposer + seed, sub-problem/big-picture, value/role, every revision → final).

- `tasks/mirror-tamper-forensics/DOCUMENTATION.md`
- `tasks/dependency-confusion-pin/DOCUMENTATION.md`
- `tasks/install-hook-exfil/DOCUMENTATION.md`

---

## 8. QA & acceptance

QA is a **dual human + LLM** mechanism; the official Terminal-Bench standard
(`harbor-framework/terminal-bench-3`) is the reference. The suite is validated at four
levels (`HOW-TO-TEST.md`): whole-repo static + oracle (`run_suite.py`, also in CI), a
no-Docker logic test **plus a `--lazy` reward-hacking-floor measurement**, the real
pinned-container Docker verify, and the official-harness rollouts. Each task was also put
through an independent adversarial reward-hack audit.

Internal re-inspection dimensions and current status:

| Dimension | Status |
|---|---|
| Instruction quality | Pass — outcome-only, ≤ 1500 words (346/406/382), no headings, no steering, absolute paths; graded values (trigger, CWE, OWASP, control) are not stated in the instruction. |
| Instruction–test consistency | Pass — every report key + each remediation clause maps 1:1 to a verifier item; oracle reaches full reward in the container and under Harbor. |
| Test quality | Pass — fractional partial-credit reward; earned work dominates; guessing / do-nothing / symptom-suppression / grep / wildcard / manifest-edit reward-hacks provably blocked and, where measurable, measured. |
| Environment reproducibility | Pass — pinned base + apt + pytest; one deterministic generator (the same one `local_test.py` imports), COPYed then removed from the final image; no answer written to disk. |
| Answer dependency | Pass — C2 indicators and tampered-file digests are greppable nowhere on the agent filesystem; verifier constants are cross-checked against a fresh build so they cannot drift. |
