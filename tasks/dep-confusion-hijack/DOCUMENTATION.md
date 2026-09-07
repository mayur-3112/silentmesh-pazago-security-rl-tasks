# Task Dossier — dep-confusion-hijack

## 1. Curation history
- **Proposer/seed:** SilentMesh. Seed class: dependency confusion (Alex Birsan's 2021
  research; the class behind numerous real internal-package hijacks).
- **Sub-problem / big picture:** covers *resolution-time* supply-chain compromise and
  the *integrity-control gap* (missing hash pin) that enables it — complementary to
  task #1's *post-build tamper*. Together they span CWE-506 (A06) and CWE-494 (A08).
- **Value once solved:** trains the model to reason from *resolver evidence* to a
  substitution conclusion, decode a payload offline, and produce a fix that is
  verified by *re-resolution* (pin + real hash), not by assertion.
- **Revisions:** v1 asked only "name the bad version" — greppable, trivial. v2 added
  payload decode. v3 (final) made the graded remediation a lockfile that must
  re-resolve to the trusted build with the *mirror-published sha256* (recomputed by
  the verifier), plus a decoy pinned line that must stay untouched.

## 2. Difficulty & rollout plan
Graded on mean reward (D1–D4 conjunctive), 12 partial-credit items. Expected failure
surface driving mean reward down: guessing the sha256 (fails R10), deleting the pkg
(fails R12), classifying as CWE-506 instead of 494, trying a live beacon (offline).
Targets: Hy4-Preview think ≥8 rollouts mean ≤0.4; SOTA ≥5 rollouts mean ≤0.6, var ≠0;
mean(Hy) < mean(SOTA). Turn-count target Hy>80 or Opus5-xhigh>60 via the
evidence→decode→hash-fix→self-verify chain. *Final numbers from the official harness.*

## 3. Failure-mode analysis (from real trajectories)
Buckets: {wrong-CWE, guessed-hash, deleted-package, decoy-line-edited, malformed-keys,
executed-instead-of-decoded}. Hint ladder for causal validation: "compare the two
cached artifacts" → "the fix is a hash pin the mirror publishes" → "classify as
CWE-494." A hint flipping fail→pass attributes the failure to genuine step difficulty.

## 4. Self-QA
Instruction outcome-only, 288 words, no headings/steering, absolute paths. Every
report key + the fix maps 1:1 to a verifier item. Pinned Dockerfile. No answer file in
image (generator deleted). Oracle passes all items locally.

## Ground truth (graders only)
confused_package=corp-auth-utils · malicious_version=2.9.9 · trusted_version=2.9.0
malicious_artifact=/opt/pip-cache/corp_auth_utils-2.9.9-py3-none-any.whl
missing_control=hash-pinning · indicator_host=auth-metrics-collector.net
primary_cwe=CWE-494 · owasp_a=A08:2021 · fix=pin ==2.9.0 with mirror sha256
