# Task Dossier — dependency-confusion-pin

## 1. Curation history (provenance)
- **Proposer / seed source:** SilentMesh security team. Seed: dependency confusion /
  resolution-time substitution (Alex Birsan's 2021 research and the internal-package
  hijacks that followed), combined with the realistic detection primitives a responder
  actually uses — a resolver log, an internal-mirror index, a pinned lockfile, and two
  cached wheels whose integrity must be recomputed rather than trusted.
- **Seed determinism:** `env/gen/build_env.py` is a single deterministic generator
  (fixed zip timestamps, sorted wheel entries, fixed XOR key); the container Dockerfile
  runs it with system paths and `local_test.py` imports the same module with a tmp
  root, so the container and the offline runner cannot drift.
- **Big-picture sub-problem:** within the Security / supply-chain track this covers
  *resolution-time* compromise and the *integrity-control gap* (a version-only pin with
  no hash) that enables it. It pairs with `mirror-tamper-forensics` (CWE-506 / post-build
  tamper, A06) to span A06/A08 and two distinct attack mechanics, and hardens the
  earlier `dep-confusion-hijack` lineage (which used a single-stage inline blob, a
  mirror-published hash, and no behavioural remediation check).
- **Value once solved:** trains an agent to (a) reason from resolver evidence + a
  mirror index to a substitution conclusion and identify the two cached artifacts among
  decoys, (b) RECOMPUTE a trusted-build integrity hash that is published nowhere, (c)
  reason that an offline environment forces a *static* decode and reverse a four-stage
  transform (base85 → XOR(key) → zlib → marshal) split across two resource files to
  read indicators out of a marshalled code object, (d) produce machine-checkable
  incident evidence, and (e) remediate by re-pinning the lock to the trusted build with
  its recomputed hash *and* byte-restoring the installed package so import runs no
  injected code — a full detection→classification→fix loop verified by re-resolution
  and by behaviour, not by assertion.
- **Revision history:**
  - v1/v2 lineage (`dep-confusion-hijack`): named the bad version (greppable) and later
    an inline single-step base64+zlib blob; the trusted hash was published by the mirror
    (copyable), remediation was only a lock edit + an importability check, and there was
    a guessable-field floor. Retained as a separate, easier task.
  - **final (this task):** the decode routine is no longer inline in a single blob — a
    loader orchestrates a read of a resource blob and a separate key file and reverses
    four transforms into a **marshalled code object**; the C2 host inside it is
    **XOR-encrypted** and the beacon reads its decrypt key at runtime from an environment
    variable (`$CORP_BUILD_SIG`) that is **unset in the sandbox** (environmental keying),
    so a plain import — or a naive "detonate and capture the socket call" attempt with the
    env generically neutralised — cannot derive the key, decrypts to garbage, and opens no
    socket to the real host; the graded indicators (host/port) exist in plaintext nowhere
    on disk (host greppable nowhere, recoverable only by static decode + recomputing the
    build-signature key and decrypting, not by detonation); the trusted
    integrity hash is **published nowhere** and must be recomputed; every
    guessable/classification field is credited **only** after the earned work (both
    artifact paths are credited only once the trusted hash is recomputed; CWE/OWASP only
    once the host is decoded); and remediation is verified **structurally** by exact lock
    re-pin + full byte-restore (installed bytes == trusted wheel contents) +
    marker-absence — no behavioural socket probe, because the guarded payload does not
    beacon at baseline, so a probe would pass on the untouched install and break
    do-nothing=0. The reward is **weighted**: the payload-analysis items (host, port,
    and the CWE/OWASP that gate on the host) carry weight 5, routine IR items weight 1,
    so a competent responder who skips the payload analysis caps at 0.333. Decoy wheels
    and a mirror index widen the forensic search (longer horizon).

## 2. Difficulty & rollout plan (graded on mean reward, D1–D4 conjunctive)
Reward = **weighted** fraction of the 14 independent verifier items (payload-analysis
items ×5, routine items ×1; total weight **30**, expanded into 30 pytest instances so
`pytest passed/total` == the weighted reward under any harness). The reward mass is
**earned**: the two artifact identifications are gated on the recomputed trusted hash;
the trusted hash is an un-guessable, non-published recompute; host+port come only from
the full four-stage decode + host-XOR reversal; the four identification/classification
fields are credited only after that earned work; and the three remediation items are
each FALSE on the untouched baseline and loophole-gated. Nothing a blind guesser can
fill scores, and the weighting means genuine reverse engineering — not routine IR — is
what carries the reward past 0.333.

**Measured reward-hacking floor** (via `python local_test.py`, reproducible):
- do-nothing / blind guess with correct-looking paths + package + versions + control +
  CWE/OWASP but no recompute, no decode, no fix → **0.000** (artifacts gate on the
  recompute; classification gates on the decode; remediation is untouched)
- competent IR, NO payload analysis (recompute hash + identify artifacts + versions +
  package + control + full structural remediation, but host/port left unknown) →
  **0.333** (10/30) — the four weight-5 payload-analysis items are unreachable without
  the static decode, so routine IR alone cannot clear the difficulty gate
- full static analysis (recompute + four-stage decode + XOR reversal + identification +
  classification), no remediation → **0.900** (27/30)
- symptom-suppression fake fix (delete the marker string / suppress the symptom, no
  byte-restore) → remediation items earn **0** (installed bytes ≠ trusted wheel), so it
  cannot exceed the 0.900 no-fix ceiling and, without the decode, stays at 0.333
- delete-the-package or leave the rogue `_resources` behind → remediation items earn
  **0** (content mismatch)
- naive dynamic detonation (import / fresh interpreter under `sys.addaudithook`) →
  records **0** socket events (runtime decrypt key absent, host decrypts to garbage)
- reference oracle → **1.000**

So a guessing or symptom-suppressing agent cannot clear the D1/D2 mean-reward gates;
the reward only rises with genuine multi-step work (partial credit → non-zero SOTA
variance, D4).

**Targets (measured on the official harness, not fabricated here):** Hy4-Preview (think
mode, Claude Code) ≥8 rollouts mean ≤ 0.4; SOTA (Opus 5 / GPT-5.x-sol or newer) ≥5
rollouts mean ≤ 0.6, variance ≠ 0; mean(Hy) < mean(SOTA); frontier pass@5 < 0.4, Hy
pass@8 < 0.5. **Turn-count target** Hy > 80 OR Opus5-xhigh > 60: driven by the
survey-cache-and-index → distinguish-the-two-wheels → recompute-hash → locate-resources
→ four-stage-decode → inspect-marshalled-consts → classify → re-pin-lock → byte-restore
→ re-verify loop across a multi-wheel cache with decoys and a mirror index.

## 3. Failure-mode analysis
- **Failure-pattern extraction (buckets):** {mis-identified artifact / which-is-trusted,
  decoy-wheel false-positive, guessed-hash, single-layer-decode-only,
  executed-instead-of-decoded, wrong-CWE (506 vs 494), decoy-lockline-edited,
  symptom-suppression fake-fix, deleted-package, left-rogue-resources, malformed
  key-set}.
- **Causal (hint-based) validation:** escalating hint ladder — "compare the resolver log
  and the mirror index; the installed version is the one from the public index" → "the
  trusted hash is not published; hash the trusted wheel yourself" → "the loader reads a
  blob and a key from `_resources`; the transform is base85→XOR→zlib→marshal" →
  "byte-restore the package from the trusted wheel and re-pin the lock with the
  recomputed hash." A hint that flips fail→pass attributes the failure to genuine step
  difficulty, not an environment defect.
- **Validity of failed trajectories:** the environment is deterministic and fully
  offline (`network_mode: none`); the report-key set maps 1:1 to graded items; there is
  no wall-clock instability (generous cap). Failures reflect step difficulty.
- **Validity of successful trajectories (anti-reward-hacking):** host/port are
  recoverable **only** by the full static decode plus reversing the host XOR — the
  host is XOR-encrypted under a key read at runtime from an unset env var, so both
  grep and naive dynamic detonation (import / fresh interpreter under an audit hook)
  surface **nothing** (verified: 0 socket events, host greppable nowhere); the trusted
  hash is a recompute (published nowhere, not greppable); the two artifact paths are
  credited only once that recompute is correct, so a blind which-is-which guess earns
  nothing; CWE/OWASP are credited only once the host is decoded; delete/stub/
  symptom-suppression fake-fixes fail the remediation **structurally** because the
  installed package must **byte-match** the trusted build's contents AND the marker must
  be absent (no behavioural socket probe — the guarded payload does not beacon at
  baseline, so a probe would pass on the untouched install and break do-nothing=0);
  functionality is credited only alongside a real restore; a do-nothing submission
  scores 0 on all three remediation items. The reward is weighted (payload-analysis
  items ×5) so a competent responder who skips the reverse engineering caps at 0.333.
  Floors above are *measured*, not asserted.

## 4. Self-QA (dual human + LLM), mapped to acceptance dimensions
- **Instruction quality:** outcome-only, 406 words, no markdown headings, no steering,
  absolute paths only; the CWE, OWASP category, and correct control value are NOT
  stated (the `missing_control` enum is presented as a three-way multiple choice the
  agent must resolve), and remediation is described as an end-state, not a procedure —
  **pass**.
- **Instruction–test consistency:** all 11 report keys + the three remediation clauses
  map 1:1 to the 14 verifier items (weighted into 30 pytest instances).
- **Test quality:** partial-credit weighted fractional reward (analysis items ×5);
  earned work dominates; guessing, symptom-suppression, dynamic-detonation, and
  do-nothing reward-hacks are provably blocked and *measured*.
- **Environment reproducibility:** pinned base (`python:3.11.9-slim-bookworm`) + pinned
  apt (file/xxd/ripgrep) + pinned pytest==8.2.0; a single deterministic generator
  (`env/gen/build_env.py`), the same one `local_test.py` imports, is COPYed then removed
  from the final image; no answer is written to disk.
- **Answer dependency:** verified — the C2 host/port and the trusted-wheel sha256 are
  greppable nowhere on the agent filesystem; only the XOR key sits in its resource file
  (an intended forensic artifact, insufficient alone). Constants embedded in the
  verifier are cross-checked against a fresh build by `local_test.py` (`_sync_check`),
  so they cannot drift.

## Ground truth (graders only — do NOT ship to the model)
confused_package=corp-auth-utils · malicious_version=2.9.9 · trusted_version=2.9.0
malicious_artifact=/opt/pip-cache/corp_auth_utils-2.9.9-py3-none-any.whl
trusted_artifact=/opt/pip-cache/corp_auth_utils-2.9.0-py3-none-any.whl
trusted_sha256=sha256(trusted wheel file) — RECOMPUTED by the verifier, published nowhere
missing_control=hash-pinning · indicator_host=collector.authlib-cdn.net · indicator_port=8444
(exfil endpoint /ingest/v1, not graded) · decode key 4d3a9fc1e07b625d8a14f39c2be5710d (in
corp_auth_utils/_resources/cachekey.bin) · primary_cwe=CWE-494 · owasp_a=A08:2021
fix=(a) requirements.lock corp-auth-utils line -> `==2.9.0 --hash=sha256:<recomputed>`,
every other line byte-identical; (b) byte-restore corp_auth_utils from the trusted wheel
(rm the package dir incl. _resources, extract the 2.9.0 wheel) so import fires no socket
audit event and the marker is absent; (c) sign() still returns a 64-char hex.
