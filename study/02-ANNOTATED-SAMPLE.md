# Annotated walkthrough — `nw-mirror-tamper` (task #1), decision by decision
*Open each referenced file beside this. Every choice below is a rule you can reuse.
The task files themselves are kept clean/spec-compliant — the teaching lives here.*

---

## `task.yaml` — the instruction (the reward's contract)

**Why outcome-only.** The instruction says *what to produce* (a report with 7 named
keys + remediation) and never *how* (never "decode the base64"). The spec forbids
revealing solution steps — and for RL it matters more: if we tell the model the
method, we are training it to follow instructions, not to *do security reasoning*.

**Why the exact 7 keys.** Each key is a column the verifier grades. Naming them
precisely is what makes instruction↔test *consistent* (an acceptance dimension). A
vague ask ("investigate and report") would make the reward unscorable.

**Why "no outbound network access" is stated.** It is a fair-play signal to the
model AND the mechanism that forces static analysis. It converts "run it and watch
the traffic" (a shortcut) into "decode the payload" (the real skill).

**Rules embedded here you must reuse:** absolute paths only (`/app/report.json`),
≤1500 words (this is 252), no `## headings`, no "you are an expert / think step by
step." All checked mechanically — never by taste.

---

## `env/gen/build_env.py` — the environment (why it is realistic AND hard)

**The package genuinely works** (`_grid.py` is a real geohash encoder). A toy stub
would read as "demo," which the spec bans. Realism = the package does something a
real service would import.

**Two-stage payload, not one.** `_telemetry.py` holds `base64(zlib(second_stage))`.
Stage 1 (loader) is visible; stage 2 (the beacon with the C2 host) is *encoded*.
Why two stages: it mirrors real malware, and it means the C2 host — a graded answer
— exists nowhere in plaintext. The model must actually decode. **This single choice
is what makes the answer un-greppable.**

**Trigger = import, wired in `__init__.py`.** `_t._load()` fires on `import geocache`.
This makes `trigger` a real forensic question (import vs install vs runtime), not a
freebie — the model has to trace *when* the code runs.

**Decoy packages (`geo-metrics`, `routecalc`).** Benign, but they each `import
base64` so a naive "grep for base64" flags them too. Decoys convert a 1-step lookup
into a multi-step *localize-the-right-one* problem → horizon length + lower pass rate.

**`dist-info` with `Name: geocache-lite`.** Forces the model to resolve *import name*
(`geocache`) → *distribution name* (`geocache-lite`). A small realistic gap that trips
shallow answers.

**Generator is deleted in the Dockerfile after it runs** — so the ground truth is
never shipped inside the image. (Answer-dependency is an acceptance dimension.)

---

## `tests/test_outputs.py` — the verifier (the actual product)

Reward = fraction of 10 checks. Read each as a defense against a specific cheat:

- **R1 exact key set** → blocks "report extra/renamed keys and hope." Enforces the
  contract.
- **R2–R4, R7, R8** → the classification answers (package, path, trigger, CWE, OWASP).
  Individually greppable-ish → so they are worth *partial* credit only. Partial credit
  is deliberate: it produces the non-zero **variance** D4 demands and a smooth signal.
- **R5/R6 (c2_host, scheme)** → only obtainable by decode. The offline env means a
  live beacon can't leak them. This is the anti-hack core.
- **R9 offline-execution probe** → re-imports with `socket.create_connection` shimmed
  to *count* calls; asserts the count is 0. Translation: "prove you actually removed
  the payload, not just wrote a nice report." Blocks report-without-remediation.
- **R10 functionality preserved** → `geocache.encode` must still return a 9-char
  geohash. Blocks the "delete the whole package" non-solution.

**The lesson:** every graded field must be either (a) impossible to obtain without the
real skill, or (b) cheap enough that partial credit is fine. Never let a *single grep*
score the whole task.

---

## `solution.sh` — the oracle (why we ship it to graders, not the model)

It proves the task is *solvable* (a hard requirement — an unsolvable task with all-zero
SOTA is auto-rejected) and it is what the lab runs to measure SOTA variance. It statically
decodes, writes the report, neutralizes the loader, and strips the `__init__` call —
the minimal correct fix. If the oracle can't score 10/10, the task is broken. Ours does.

---

## `Dockerfile` — reproducibility (an acceptance dimension)

Pinned base image *and* pinned apt packages (`file=1:5.44-3`, …). The spec requires
pinned dependency versions for a reproducible environment. Unpinned = "works on my
machine" = rejected.

---

## How to read difficulty from this design (tie back to D1–D4)
- Low mean reward comes from the *chain*: localize (decoys) → decode (no plaintext) →
  classify (real CWE) → remediate (R9) → not break it (R10). Each dependent step sheds
  reward.
- Non-zero variance comes from *partial credit*: some rollouts nail 7/10, some 10/10.
- Turn count comes from exploration across the multi-package tree + verify-your-own-fix.

**If you can explain this whole file back to Nikhil unprompted, you have proven the
security-building half of the JV.**
