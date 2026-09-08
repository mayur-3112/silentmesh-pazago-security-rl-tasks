# supply-chain-audit — task documentation

## Scenario

A Python service (`/app/service`) runs in its own virtualenv at
`/opt/service/venv/lib/python3.11/site-packages`, which holds ~55 installed
distributions. The environment has been compromised through its software supply chain.
The agent is an incident responder who must (1) triage the whole installed tree, (2) file
a precise findings report identifying every genuinely compromised distribution — and
nothing else — and (3) remediate the environment so it is clean and the service still
imports and runs. No network access; every reported value is recoverable from disk.

This is a long-horizon, industrial-grade triage task, not a puzzle: the difficulty comes
from breadth (many packages), from several *different* compromise mechanisms that no
single check catches, from benign look-alikes that punish sloppy precision, and from an
exacting, coupled remediation that must keep the service working.

## The nine compromises (five distinct mechanisms)

| Package | Vector | How it is found | Trigger |
|---|---|---|---|
| `geoindex` | tampered-file | dist-info RECORD hash mismatch (post-build tamper) | import |
| `metricslib` | malicious-wheel | RECORD is self-consistent → must read the code (import-time exec-decode beacon) | import |
| `logkit` | malicious-wheel | RECORD self-consistent → only a **byte-diff against the mirror** reveals it; beacon is grep-resistant (`"so"+"cket"`, `getattr`) | import |
| `corp-telemetry` | dependency-confusion | installed 9.9.9 from the **public** index vs lockfile-pinned internal 1.4.2 | import |
| `metrics-core` | dependency-confusion | installed 9.9.9 from public vs lockfile-pinned internal 2.0.0 | import |
| `sluglfy` | typosquat | Levenshtein-1 of the legit `slugify`; not in the lockfile; imported by a service shim | import |
| `urllib33` | typosquat | Levenshtein-1 of the legit `urllib3`; not in the lockfile; imported by the service net module | import |
| `svc-cli` | malicious-wheel / install-hook | malicious `console_scripts` **entry point** in dist-info | runtime-entrypoint |
| `buildtools-ext` | install-hook | a `.pth` file that executes at interpreter startup | interpreter-startup |

The C2 hosts are encoded on disk (base64 / XOR), so `grep` does not surface them; they are
recovered by reading and decoding the malicious code. Ground truth is never written to the
agent-visible filesystem.

## The six benign red herrings (precision traps)

Each imitates a real vector's surface signal, so heuristics produce false positives:

- `localpatch-ui` — RECORD **mismatch** (like a tamper) but a documented, approved local hotfix (`/app/service/PATCHES.md`).
- `fastserialize` — `base64`+`marshal`+`exec` (like a malicious loader) but a documented plugin loader that only compiles local, first-party codecs.
- `oldcrypto` — an outdated version with a **CVE** noted in the SBOM: a vulnerability, *not* a supply-chain compromise (a different finding class).
- `debug-shell` — opens a socket, but **loopback-only** and off unless `DEBUG_SHELL_ENABLE=1`; documented.
- `crashreporter` — socket code, but connects only to `127.0.0.1`; no external egress.
- `vendored-min` — a `base64`+`exec` blob (packed-malware surface) that decodes to plainly benign vendored code.

## Reward model — binary, with a self-gating fractional verifier underneath

The verifier (`tests/test_outputs.py`) scores four families of independent checks
(weighted, expanded into pytest instances so pass-fraction == weighted reward):

- **Detection** — one per true compromise; the hard-to-spot ones (mirror-diff wheel,
  typosquats) carry weight 2.
- **Classification & indicator** — vector / trigger / CWE / OWASP / recovered indicator,
  each **gated on detection** (guessing an undetected package earns nothing). CWE and the
  indicator are graded against **defensible acceptance sets** (e.g. the beacon host is
  accepted as the indicator per the instruction; CWE-494/506/427/829/… are all accepted
  where defensible) so the reward is never an arbitrary single-answer trap.
- **Precision (no false positives)** — one per red herring, weight 2, **gated on the report
  actually flagging ≥1 real compromise**. Flagging everything loses all precision points;
  an empty report earns none of them.
- **Remediation** — structural and **self-gating** (every check is false on the untouched
  baseline). The service-integration check is **weighted 4×** and gated on the risky,
  coupled fixes (both typosquats removed *and* their dependent imports fixed), so it only
  credits a complete, working remediation and a botched cleanup fails all four instances.

The **emitted reward is binary**: `1.0` iff every item passes (a complete, correct
triage + remediation), else `0.0` (`run-tests.sh`). This is the PDF's binary-acceptance
route (security category: frontier pass@5 < 0.4). The fractional pass-fraction is still
logged for failure-mode analysis.

Measured reward profile (oracle / floors): do-nothing **0.00**, flag-everything **0.343**,
oracle **1.00**.

## Anti-reward-hacking

- No free points: classification/indicator credited only when the package is detected;
  precision credited only when the report is non-trivial.
- Do-nothing = 0: every remediation check is false at baseline (marker/hash/version/file/
  entry-point present), so partial or absent work earns no remediation credit.
- Not greppable: C2 hosts are encoded (base64/XOR, plus `getattr`/string-split), and ground
  truth is never on disk.
- Loophole-proof remediation: exact restore-to-mirror-hash / repin-to-trusted-content /
  physical removal, plus an end-to-end service run that a de-listing or a stub cannot fake.

## Solvability & rollout evidence (real models)

- **Oracle** (`solution.sh` / `local_test.py`): full solve → **1.000** (verified in Docker,
  offline, and via the local runner).
- **SOTA (Opus 5), 5 blind rollouts** in separate path-isolated episode roots, graded externally:
  full-solve rate **1/5 = 20%** (target for the security category: frontier pass@5 < 0.4 →
  **met**); per-rollout fractional rewards `[1.00, 0.87, 0.99, 0.91, 0.90]`, variance
  `0.0027` (**vendor pilot D4: ≠ 0; official D4 remains pending**). The failures are genuine — Opus-5 reliably finds all nine
  compromises and avoids all six red herrings, but slips on the *exacting coupled
  remediation* (removing a typosquat while keeping its dependent import working; fully
  cleaning the entry point), which is where the difficulty lives.

### Honest caveat — turn count

The PDF's turn-count target is > 60 assistant messages for Opus5-xhigh (TB4 ≈ 75). On our
measurement harness (`claude -p --model claude-opus-5`, a directed incident-responder
brief), Opus 5 completed the task in **~26 assistant turns** despite the 55-package tree —
it batches dozens of parallel tool calls per turn (≈1M cache-read + ≈30k output tokens per
rollout across ~26 turns), so the turn count reflects the model's tool-batching efficiency
rather than the task's size, and does not rise with breadth. Our figure is best read as a
**lower bound** from a directed harness; the org's Opus5-xhigh measurement on the
Terminal-Bench harness (less directed, TB4 averaging ~75 turns) is the number of record.
If it falls short there, the intended next step is to restructure the remediation into an
explicit run → observe → fix → re-run loop (a non-batchable serial dependency), which is
the reliable way to drive assistant-turn count up.

## Verification

```
python tasks/supply-chain-audit/local_test.py            # oracle  -> REWARD 67/67 = 1.000
python tasks/supply-chain-audit/local_test.py --lazy     # do-nothing -> 0.000
python tasks/supply-chain-audit/local_test.py --flagall  # flag-everything -> 0.343

# Docker (offline, gold standard):
docker build -t sca tasks/supply-chain-audit
cid=$(docker run -d --network=none sca sleep infinity)
docker cp tasks/supply-chain-audit/solution.sh  $cid:/app/solution.sh
docker cp tasks/supply-chain-audit/tests         $cid:/app/tests
docker cp tasks/supply-chain-audit/run-tests.sh  $cid:/app/run-tests.sh
docker exec $cid bash /app/solution.sh
docker exec $cid bash /app/run-tests.sh          # REWARD = 1.0
```

`local_test.py` cross-checks the verifier's embedded ground truth against a fresh build, so
any drift between `env/gen/build_env.py` and `tests/test_outputs.py` fails loudly.
