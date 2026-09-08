# Task Dossier — install-hook-exfil

## 1. Curation history (provenance)
- **Proposer / seed source:** SilentMesh security team. Seed: the real-world class of
  supply-chain attack that achieves persistence by dropping a `.pth` file into
  `site-packages`. Because CPython's `site` module executes any `.pth` line that begins
  with `import ` at every interpreter startup (a documented, load-bearing behaviour used
  by setuptools' `distutils-precedence.pth`, `__editable__` shims, and namespace-package
  bootstraps), a single injected line runs attacker code before any user code — a
  distinct mechanic from in-module tamper. Reference families: startup/site-init
  execution abuse and the broader install/import-time execution pattern, combined with
  the wheel RECORD integrity manifest and a CycloneDX SBOM as the detection primitives a
  responder actually uses.
- **Big-picture sub-problem:** within the Security / supply-chain track this covers
  *startup-hook forensics*: localizing an injected `.pth` and the loader it runs among
  benign `.pth` decoys via manifest/inventory evidence (not string search), statically
  reversing a multi-stage obfuscated payload without executing it in an air-gapped
  environment, reporting machine-checkable incident evidence, and remediating by removing
  the whole injected mechanism without breaking functionality. It pairs with
  `mirror-tamper-forensics` (CWE-506 / import-time, post-build file tamper, A08) and
  `dependency-confusion-pin` (CWE-494 / resolution-time) to span A06/A08 across three
  distinct attack mechanics; this task is the **startup-hook / A06** member.
- **Value once solved:** trains an agent to (a) reason that a `.pth` import line is a
  startup execution primitive and localize the malicious one among benign `.pth` files,
  (b) trace it to a loader module that is absent from the dist-info RECORD, (c) reason
  that the env-keyed payload cannot be recovered by naive detonation and must be statically
  reverse engineered, (d) reverse a four-stage transform (base85 → XOR(key) → zlib →
  marshal) split across bundled resources, read indicators out of a marshalled code
  object, and reverse the XOR host mask, and (e) remediate by removing the `.pth`,
  the loader, and the payload resources so the package again matches its manifest — a
  full incident-response loop.
- **Revision history:**
  - v1 (retired lineage): named the injected `.pth` only and put an inline base64
    one-liner in it; a single `cat *.pth` solved it and the decode was inline. Rejected
    internally as too easy / greppable.
  - v2 (retired lineage): moved the loader into the package but kept a single-stage
    decode, a wildcard-ish behavioural check, and a guessable-field floor ~0.5. Failed
    an internal difficulty grade.
  - **final (this task):** the `.pth` only does `import metricslib._autoload`; the decode
    routine lives in the loader module and reads a **blob resource** and a **separate key
    resource**; the payload is a **marshalled code object** behind four transforms; the
    graded indicators (host/port/endpoint) exist in plaintext nowhere on disk; every
    guessable/classification field is credited **only** when the earned localisation
    (and, for CWE/OWASP, the decoded host) is already correct. A later hardening pass added
    **environmental keying** — the host XOR-encrypted with a decrypt key the payload reads
    at runtime from an env var unset in the sandbox — to the recovered code object (so a
    fresh interpreter runs no beacon and a naive detonation decrypts to garbage),
    replaced the behavioural `sys.addaudithook` startup probes with **structural**
    remediation checks (`.pth` neutralised, loader module gone, `_resources` gone,
    marker-absent, manifest-clean, functionality gated on removal), and moved to a
    **weighted, analysis-heavy reward** so a no-payload-analysis agent caps at 0.333.
    Benign `.pth` decoys, decoy packages, an SBOM, and a RECORD manifest widen the
    forensic search (longer horizon).

## 2. Difficulty & rollout plan (graded on mean reward, D1–D4 conjunctive)
Reward = **weighted** fraction of independent checks: the six payload-analysis /
un-guessable items (c2_host, c2_port, exfil_endpoint, decode_key, and the host-gated
CWE/OWASP) carry weight 3; the nine routine incident-response items (localise the `.pth`
and its loader, package, trigger, and five structural remediation checks) carry weight 1 —
27 weighted units in all. Recovering the C2 host is genuine reverse engineering: the
host is XOR-encrypted and the payload reads its decrypt key at runtime from an env var
unset in the sandbox (so a fresh interpreter / naive detonation decrypts to garbage and
contacts no real host), so it must be reconstructed by static decode + recomputing the
build-signature key and decrypting, not read as a constant or sniffed from a live call.

**Measured reward profile** (reproducible; `--lazy` for the floor):
- do-nothing / blind guess → **~0.11**
- competent incident response **without any payload analysis** (localise the `.pth`/loader
  via RECORD, classify package/trigger, and fully remove the `.pth`/loader/`_resources`) →
  **0.333**
- naive dynamic detonation (fresh interpreter startup driving site `.pth` processing under
  a socket audit hook) → **0.333** (environmental keying defeats it — decrypts to garbage; 0 socket events, no real host recovered)
- full static reverse engineering + remediation → **1.000** (reference oracle)

So an agent that does everything except the genuine payload reverse engineering caps at
**0.333 — under the D1 (Hy ≤ 0.4) gate** — and only real RE reaches full reward. This is
the intended difficulty profile (partial credit → non-zero SOTA variance, D4).

**Targets (measured on the official harness, not fabricated here):** Hy4-Preview
(think mode, Claude Code) ≥8 rollouts mean ≤ 0.4; SOTA (Opus 5 / GPT-5.6-sol or newer)
≥5 rollouts mean ≤ 0.6, variance ≠ 0; mean(Hy) < mean(SOTA); frontier pass@5 < 0.4,
Hy pass@8 < 0.5. **Turn-count target** Hy > 80 OR Opus5-xhigh > 60: driven by the
enumerate-`.pth` → distinguish-benign-from-malicious → cross-check-RECORD → trace-loader →
locate-resources → four-stage-decode → inspect-marshalled-consts → remove-`.pth`+loader+
resources → re-verify-startup loop across a multi-package tree with decoys and an SBOM.

## 3. Failure-mode analysis
- **Failure-pattern extraction (buckets):** {mis-localized `.pth` (picked a benign one),
  loader-not-found, single-layer-decode-only, executed-instead-of-decoded,
  guessed-host/key, wrong-trigger (import vs interpreter-startup), wrong-CWE/OWASP,
  symptom-suppression fake-fix (neuter but leave `.pth`), deleted-package,
  left-dormant-loader/resources}.
- **Causal (hint-based) validation:** escalating hint ladder — "list the `.pth` files in
  site-packages and see which import line runs a module that its distribution's RECORD
  does not list" → "the loader reads a blob and a key from `_resources`; the transform is
  base85→XOR→zlib→marshal to a code object" → "delete the `.pth`, the loader module, and
  the `_resources` directory." A hint that flips fail→pass attributes the failure to
  genuine step difficulty, not an environment defect.
- **Validity of failed trajectories:** the environment is deterministic and fully offline
  (`network_mode: none`); no wall-clock timeout risk (500-turn cap), so failures cannot
  stem from instability; instruction↔test consistency is enforced (every report key maps
  1:1 to a graded item).
- **Validity of successful trajectories (anti-reward-hacking):** host/port/endpoint are
  recoverable only by statically decoding the four-stage payload and reversing the XOR host
  assembly — plaintext nowhere on disk (verified by grep), and the environmental keying
  means a naive "launch a fresh interpreter and capture the socket call" detonation records
  nothing (measured: 0 audit events even with site `.pth` processing driven under a socket
  audit hook). Localisation is earned (benign import-line and path-only `.pth` decoys, plus
  the RECORD manifest, are required to disambiguate); identification/classification is gated
  on localisation and the decoded host. Remediation is checked **structurally** (no
  behavioural beacon probe — the env-keyed payload does not beacon at baseline (its runtime
  decrypt key is unset), so a socket probe would pass on the untouched environment and silently break do-nothing=0): delete/
  stub/manifest-edit fake-fixes that leave any injected artifact on disk fail `R11`
  (`.pth` still imports the loader), `R12` (loader module still present), `R13` (manifest
  dirty or `_resources` still present) or `R14` (marker still present), and `R16`
  (functionality) is gated on the injected artifacts actually being gone. A do-nothing
  submission scores 0 on all five remediation items. Floors above are *measured*, not
  asserted.

## 4. Self-QA (dual human + LLM), mapped to acceptance dimensions
- **Instruction quality:** outcome-only, ~360 words, no markdown headings, no steering,
  absolute paths only; the `trigger` and CWE/OWASP values are not stated (must be
  determined), and the remediation is described as an end-state, not a procedure — **pass**.
- **Instruction–test consistency:** all 10 report keys + the remediation end-state map
  1:1 to the 15 verifier items (10 report + 5 structural remediation; weighted, with the
  payload-analysis items ×3).
- **Test quality:** partial-credit **weighted** fractional reward (payload-analysis items
  ×3); earned reverse engineering dominates; four classes of reward-hack (guess,
  do-nothing, symptom-suppression, naive detonation) provably blocked and measured.
- **Environment reproducibility:** pinned base (`python:3.11.9-slim-bookworm`) + pinned
  apt + pinned pytest; a single deterministic generator (`env/gen/build_env.py`), the
  same one `local_test.py` imports, is COPYed then removed from the final image; no answer
  is written to disk.
- **Answer dependency:** verified — the C2 host/port/endpoint are greppable nowhere on the
  agent filesystem; only the XOR key sits in its resource file (an intended forensic
  artifact). Constants embedded in the verifier are cross-checked against a fresh build by
  `local_test.py` (`_sync_check`), so they cannot drift.

## Ground truth
Moved to `internal/ANSWER_KEY.md` — graders/QA only, never included in any agent-facing or public deliverable. This file (`DOCUMENTATION.md`) is the public-facing dossier and contains no solution-specific values.


## Docker validation
Verified in the real pinned container (not just the Python simulation):
`docker build` → `solution.sh` (oracle) → `run-tests.sh` (verifier) → **REWARD = 1.000**.
