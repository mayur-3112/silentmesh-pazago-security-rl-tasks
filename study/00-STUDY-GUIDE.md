# SilentMesh × Pazago — Foundation Study Guide
*The only things you need to master for this JV. Everything is tied to the sample
task we built (`nw-mirror-tamper`) so nothing here is abstract.*

The deal in one sentence: **we build CWE/CVE-mapped RL training environments for the
security vertical; the reward function is the product, not the puzzle.**

---

## PART 1 — What we are actually selling (read this first)

We are building **gyms, not athletes.**
- A **task** = an environment a model is dropped into.
- The **verifier** (`test.sh`) = the **reward function**.
- The model attempts the task many times (**rollouts**), gets a score each time,
  and — over hundreds of these — *learns the security vertical*.
- **The model never sees the verifier.** It learns by trial-and-reward. If it could
  see the reward function, it would cheat, and the task becomes worthless.

Our AI being weak is irrelevant: we don't train anything. Our job is to make sure
each environment is **correct, solvable, hard, and un-cheatable.** That is a
*security + verifier-design* skill, not an AI-horsepower skill.

---

## PART 2 — Security taxonomies (your working vocabulary)

You must be able to name these cold for any exploit.

| Layer | What it is | Example | Role in our work |
|---|---|---|---|
| **CWE** | *Class of weakness* | CWE-506 Embedded Malicious Code | What we map each task to |
| **CVE** | *One real named incident* | the event-stream 2018 compromise | Seed source for realism |
| **OWASP Top 10 (2021)** | *Risk category* | A06 Vulnerable & Outdated Components | Coverage / risk labeling |

**CWE cheat-sheet — supply-chain relevant (memorize the top block):**
- CWE-506 — Embedded Malicious Code *(our sample: injected loader)*
- CWE-494 — Download of Code Without Integrity Check *(dependency confusion)*
- CWE-829 — Inclusion of Functionality from Untrusted Control Sphere
- CWE-427 — Uncontrolled Search Path Element *(dependency-resolution hijack)*
- CWE-1357 — Reliance on Insufficiently Trustworthy Component
- CWE-78 — OS Command Injection *(malicious install / postinstall hooks)*
- CWE-502 — Deserialization of Untrusted Data

**OWASP 2021 quick map:** A01 Broken Access Control · A02 Cryptographic Failures ·
A03 Injection · A04 Insecure Design · A05 Security Misconfiguration ·
**A06 Vulnerable & Outdated Components (our home turf)** · A07 Auth Failures ·
**A08 Software & Data Integrity Failures (supply-chain! CI/CD, deserialization)** ·
A09 Logging Failures · A10 SSRF.

> For this contract, most tasks live in **A06** and **A08**, mapped to the CWE block
> above. That pairing *is* your coverage plan for 100 tasks.

---

## PART 3 — Supply-chain exploit classes (your task pipeline)

Each class is a reusable environment template. Build one, vary it, repeat.

1. **Post-build tamper** — package altered after legit build. *(sample — CWE-506)*
2. **Dependency confusion** — internal package name resolves to a public malicious one. *(CWE-494)*
3. **Typosquatting** — `reqeusts` vs `requests`.
4. **Malicious install hook** — evil `setup.py` / postinstall runs at install. *(CWE-78)*
5. **Poisoned CI/CD step** — compromised build action injects at pipeline time. *(A08)*
6. **Lockfile / hash bypass** — integrity check skipped or forged. *(CWE-494 / CWE-353)*
7. **Compromised transitive dep** — the bad package is three levels down.

For each you decide: *what is tampered · how it is hidden · what the agent must
recover · how the verifier proves the real skill without being game-able.*

---

## PART 4 — Verifier design (your highest-value skill)

A task is only as good as its reward function. Rules we followed and must always follow:

1. **Answer not in plaintext.** In our sample the C2 host is `base64(zlib(...))` —
   the only way to get it is to actually decode. No grep shortcut.
2. **Block execution shortcuts.** The env is offline + a probe checks that importing
   the package runs *no* payload — so "just run it and read the output" fails.
3. **Partial credit.** Reward = fraction of checks passed → gives non-zero *variance*
   (a hard spec requirement, D4) and a smooth training signal.
4. **Functionality preserved.** Remediation must not just delete everything — the
   package must still work. Stops the lazy "rm -rf" solution.
5. **Exact output contract.** Enforce the precise key set of the report → guarantees
   instruction↔test consistency.

> Reward hacking = the model gets full score without doing the real task. A frontier
> lab rejects any task a model can hack, because it teaches the model to cheat.
> **Preventing this is the single most valuable thing we do.**

---

## PART 5 — Rough AI/ML/RL literacy (enough to speak; friend goes deeper)

Six concepts. Learn these and you can hold any technical conversation in this deal.

1. **RL loop:** agent → acts in environment → gets reward → updates policy → repeat.
2. **RLVR (RL with Verifiable Rewards):** reward comes from a *checkable test*, not a
   human rating. **This is exactly what we build.** (Read one primer on RLVR — it is
   the entire thesis of this contract.)
3. **Rollout / trajectory:** one full attempt (the assistant turns). "≥8 rollouts"
   = run the task 8 times.
4. **Metrics:**
   - *mean reward* — average score over rollouts → **the acceptance gate** (≤0.4 Hy, ≤0.6 SOTA).
   - *pass@k* — probability of solving within k tries (reference figure only).
   - *variance* — spread of scores; must be ≠ 0 (D4) or the task can't teach.
5. **Agent harness:** the scaffold that lets a model drive a terminal — Claude Code
   (Claude / Hy4), Codex (GPT). **Never mix them** (spec rule) — different models need
   their native harness for a fair difficulty read.
6. **Why hard + un-cheatable = good training data:** a model only *learns* from
   problems (a) at the edge of its ability and (b) it cannot shortcut. That is *why*
   the spec demands both low mean reward AND anti-reward-hacking.

---

## PART 6 — How difficulty is graded (the acceptance gate, precisely)

Graded on **mean reward**, four conditions, ALL must hold (conjunctive):
- **D1** Hy4-Preview (think mode), ≥8 rollouts, mean reward ≤ 0.4
- **D2** SOTA (Opus 5 / GPT-5.6-sol), ≥5 rollouts, mean reward ≤ 0.6
- **D3** mean(Hy) < mean(SOTA)
- **D4** SOTA variance ≠ 0  (all-zero SOTA = auto-reject unless proven solvable)

Plus a **turn-count** gate (either): Hy4-P > 80 turns OR Opus5-xhigh > 60 turns.
Binary-reward fallback: Hy pass < 0.4, frontier ≤ 0.5.

*We author to hit these; the official harness produces the final numbers.*

---

## PART 7 — Your 2-week ramp

- **Days 1–3:** read 5–10 real tasks in `harbor-framework/terminal-bench-3`. Note
  their instruction length, structure, verifier style. That is the bar.
- **Days 3–5:** memorize the CWE block (Part 2) + OWASP A06/A08. Map every exploit
  class in Part 3 to a CWE yourself.
- **Days 4–7 (with friend):** read one RLVR primer together. He owns "how training
  consumes this"; you own "does my environment give a clean signal."
- **Ongoing:** for every task we build, *you* write the CWE/OWASP mapping and the
  one-paragraph "why this can't be reward-hacked." That paragraph is your proof of worth.

## Proof-of-worth checklist (when you can do all 5, your half is real)
- [ ] Name the CWE + OWASP category for any exploit on sight
- [ ] Explain why our sample's verifier cannot be gamed (3 reasons)
- [ ] Describe the RL loop and what mean-reward / variance mean
- [ ] Design a new exploit-class environment on paper
- [ ] State the D1–D4 gate from memory
