# Building Task #2 live — dependency confusion (CWE-494 / OWASP A08)
*Read this next to the files in `dep-confusion-hijack/`. This is the method, shown.*

## Step 0 — Why THIS exploit (coverage thinking)
Task #1 was **post-build tamper** — the attacker edits a package that is already
installed. Task #2 must exercise a *different mechanism* or we have not proven the
method generalizes. **Dependency confusion** is a resolution-time attack: a build
pulls an *internal* package name, but a higher-version package of the same name
exists on a public index, so the resolver grabs the attacker's public one. Nothing
was "edited" — the wrong thing was *selected*. Different root cause → different CWE
(494, download of code without integrity check) → different OWASP (A08, integrity
failure). This is how you plan 100 tasks: one per mechanism, each a distinct CWE.

## Step 1 — Design the scenario before writing code
Decisions, in order:
- **What is the artifact the agent inspects?** A `pip` install log + a lockfile +
  two candidate distributions cached on disk (the internal one and the public one).
- **Where is the "hard" part?** The agent must reason from *evidence of resolution*
  (the log shows version 2.9.9 was chosen over the internal 2.9.0) to conclude
  confusion happened — not just find a bad string. Then confirm the chosen artifact
  is hostile by decoding its payload.
- **What makes it long-horizon?** localize the suspicious resolution → compare the
  two candidates → decode the payload → identify integrity gap (no hash pin) →
  classify → produce the fix (pin + hash). Multiple dependent steps.
- **What is the un-hackable output?** A report naming the confused package, the
  malicious version, the integrity control that was missing, the exfil indicator
  recovered by decode, CWE, OWASP — plus a corrected requirements pin the verifier
  actually re-resolves.

## Step 2 — Ground truth (graders only)
    confused_package   = corp-auth-utils
    malicious_version  = 2.9.9            (public, attacker)
    trusted_version    = 2.9.0            (internal, legitimate)
    malicious_artifact = <cache>/corp_auth_utils-2.9.9-.../evil marker
    missing_control    = hash-pinning     (no --require-hashes / no hash in lock)
    indicator_host     = auth-metrics-collector.net
    primary_cwe        = CWE-494
    owasp_a            = A08:2021
    fix                = pin corp-auth-utils==2.9.0 with the trusted sha256 in the lock

## Step 3 — Anti-reward-hacking, applied to THIS task
- The malicious version string could be grepped — so the *credit* is not for naming
  2.9.9, it is for the corrected lockfile **re-resolving to 2.9.0 with a matching
  hash** (verifier recomputes the sha256; a guessed hash fails).
- `indicator_host` is base64+zlib inside the public artifact → decode-only, same as
  task #1. No network in the env.
- The fix must keep the package importable (functionality preserved) → cannot just
  delete it.
- Exact report key set enforced.

## Step 4 — Why difficulty should land in-band
- A model can *guess* CWE-494/A08 sometimes → partial credit → non-zero variance (D4).
- The chain (evidence-of-confusion → decode → correct hash-pinned fix that actually
  re-resolves) is where mean reward drops: guessing the hash fails, deleting the pkg
  fails R-func, reading the payload live fails (offline). That is the ≤0.4 pressure.

## Your exercise (do this before reading the code)
On paper, answer:
1. Which CWE and OWASP category, and why not CWE-506?
2. Name two ways a model might reward-hack this, and how you would block each.
3. What single check makes "guess the answer" fail here?

*(Answers are Step 2 + Step 3. Grade yourself.)*
