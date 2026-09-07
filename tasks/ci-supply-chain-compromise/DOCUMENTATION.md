# ci-supply-chain-compromise — task dossier

## 1. What this task is (and why it's not a puzzle)
An **interactive multi-host cyber environment** modelling a supply-chain
compromise via CI/CD. Not a filesystem-inspection puzzle with a JSON output:
the agent runs discrete actions in a stateful world; observations are partial;
transitions have consequences; reward is derived from *security outcomes*, not
from field-parity in a report.

## 2. Scenario
- Internal package `corp-auth-utils` (trusted 2.9.0 on the internal mirror) was
  shadowed by an attacker-published 2.9.9 on public PyPI (Alex Birsan class).
- The CI resolver, without version pin or hash pin, picked 2.9.9 (highest).
- The built artifact `art-2026090614:22` shipped with a backdoor and was
  deployed to staging.
- SOC alerted on the outbound beacon. Production still runs the previous clean
  artifact — do not break it.

## 3. Topology
```
dev-laptop        (agent starts here; has SOC alert + creds file)
   │
   ├─ ssh(ops-token)      ─► ci-runner       (build logs, requirements.lock)
   ├─ ssh(deploy-token*)  ─► staging         (compromised)
   ├─ ssh(deploy-token*)  ─► prod            (clean; destroy = penalty)
   ├─ http               ─► pkg-registry     (versions + source + sha256)
   └─ http(build-token*)  ─► artifact-store  (artifacts + provenance)

*deploy-token and build-token are only DISCOVERED via the CI build log —
 partial observability. build-token is LEAKED (in the CI log itself) and
 attracts a penalty if used after the SOC alert without rotating first.
```

## 4. Reward (outcome-based, sums into [0, 1])

Positive outcomes:
| key                              | value | condition                                                |
|----------------------------------|------:|----------------------------------------------------------|
| identified_compromised_package   | +0.10 | read the CI build log, saw the 2.9.9 resolution          |
| identified_attack_path           | +0.10 | traced alert → staging → ci → registry                   |
| contained_pipeline               | +0.15 | disabled CI before rebuild                               |
| rotated_leaked_credential        | +0.15 | rotated build-token                                      |
| pinned_trusted_dependency        | +0.15 | pinned corp-auth-utils to 2.9.0 with the trusted hash    |
| rebuilt_clean_artifact           | +0.10 | rebuild produced a signature-valid artifact              |
| verified_new_artifact            | +0.05 | explicitly verified before deploying                     |
| redeployed_staging_clean         | +0.10 | staging now runs a trusted artifact                      |
| preserved_production             | +0.10 | prod was reachable and not damaged (evaluated at end)    |

Penalties:
| key                                          | value | condition                                     |
|----------------------------------------------|------:|-----------------------------------------------|
| PENALTY_deployed_unverified                  | -0.15 | deployed an artifact without verifying it     |
| PENALTY_used_leaked_build_token_after_alert  | -0.10 | used leaked build-token pre-rotation          |
| PENALTY_rebuild_before_rotation              | -0.10 | rebuilt while leaked build-token was active   |

## 5. Reward-shape validation (adversarial agents, `adversarial.py`)
| Agent                  | Score | What it did                                                     |
|------------------------|------:|-----------------------------------------------------------------|
| oracle                 | 1.000 | Full correct response, no penalties                             |
| sledgehammer           | 0.200 | Shutdown prod, no remediation                                   |
| skipped_rotation       | 0.450 | Fixed the deps but never rotated leaked token; two penalties    |

The reward is genuinely non-trivial: even a broadly competent response that
skips one security-process step (rotation) sits below D2=0.6.

## 6. Difficulty framing
- **Real long horizon**: solving needs ~14 dependent actions across ≥3 hosts.
  Each action is a decision, not a report field.
- **Real partial observability**: `pkg-registry`, `deploy-token`, `build-token`
  are only discovered by reading CI logs. `prod` is only reachable via CMDB
  reference in the SOC alert.
- **Multiple valid solutions**: pinning + hash, index restriction, or removing
  public registry all satisfy `pinned_trusted_dependency`; the reward function
  scores the outcome, not one specific recipe.
- **Extensible to family**: the same topology admits ≥10 variants (attacker on
  registry, malicious runner, artifact substitution post-signing, transitive
  compromise, secret in Dockerfile, etc.) — the plan is 10 scenarios × 10
  variants = the 100-task set, one family at a time.

## 7. Known limitations (honest)
- The environment is a simulated topology in memory, not a Dockerised cluster.
  A follow-up scales this to real containers per host with real ssh/http.
- The pkg-registry hash strings are placeholder tokens (`TRUSTED_HASH`,
  `EVIL_HASH`) rather than real sha256s; the reward checks equality of these
  tokens. Follow-up: generate real content hashes per build.
- Only one attack path is currently modelled. The 10-variant plan (family
  fan-out) is the next milestone.
