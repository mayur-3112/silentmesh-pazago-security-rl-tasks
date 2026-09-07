# legacy/ — archived puzzle-style tasks

These three tasks are **retired**. They are kept for history and to document
the architectural pivot; they should not be used as benchmark deliverables.

## Why they were retired
An external QC review scored these tasks at 46–53/100 and rejected all three.
The critique — accurate in every point — was:

1. **They are puzzles, not RL environments.** The agent inspects files, decodes
   payloads, writes a JSON report, edits a file, exits. There is no state, no
   action space, no transitions, no partial observability.
2. **Encoding difficulty is not cyber difficulty.** base64 + XOR + zlib
   obfuscation is steganography, not security reasoning. A frontier model that
   knows Python solves it; the added rungs are just annoyance.
3. **The verifiers have real design weaknesses.** `nw-mirror-tamper-v2`'s
   `actual_hash` field was accepting any 64-hex ≠ clean (documented, but
   unfixed); `dep-confusion-hijack`'s "re-resolves" check is string-matching a
   lockfile, not actually re-resolving; `missing_control` combined three
   controls into one ambiguous answer.
4. **Not actually long-horizon.** 13 verifier rungs ≠ 13 decisions. Each task
   is solvable in a handful of shell commands.

## What the new architecture does differently
The active work under [`../tasks/ci-supply-chain-compromise`](../tasks/ci-supply-chain-compromise)
uses [`../env/core.py`](../env/core.py), an interactive multi-host environment
with:

- A discrete action space (`ssh`, `read_log`, `rotate_credential`,
  `pin_dependency`, `rebuild_artifact`, `verify_artifact`, `deploy_artifact`,
  `shutdown_service`, …).
- **Partial observability**: the agent starts on `dev-laptop` and discovers
  `pkg-registry`, `deploy-token`, `build-token` only by reading the CI log.
- **Outcome-based reward**: containment, rotation, remediation, rebuild,
  verification, safe redeploy, production preservation. Not JSON field parity.
- **Penalties** for destructive shortcuts (breaking prod, deploying unverified
  artefacts, using a leaked credential post-alert without rotating).
- **Adversarial reward-shape validation** via cheat agents in `adversarial.py`
  (sledgehammer scores 0.20, skipped-rotation 0.45 — genuinely below the
  security-competent threshold).

Legacy tasks remain runnable (`python tasks/<name>/local_test.py`) for
comparison, but are not shipped as deliverables and are not counted by
`run_suite.py`.
