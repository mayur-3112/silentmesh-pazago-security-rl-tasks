# `supply-chain-audit` rollout evidence

This directory contains the observable action transcripts and grading record for
five blind Claude Opus 5 episodes. It directly supports the vendor-side pilot
reported in `DELIVERY.md`; it is not a substitute for the customer's official
HY-4/Terminal-Bench measurement.

## Results

The shipped verifier emits a **binary reward**: 1 only when all 67 expanded checks
pass. The fractional score below is retained as diagnostic evidence.

| Episode | Diagnostic score | Binary reward | Assistant turns | Wall clock |
|---|---:|---:|---:|---:|
| r0 | 1.000 | 1 | 26 | 451.031 s |
| r1 | 0.866 | 0 | 27 | 380.065 s |
| r2 | 0.985 | 0 | 23 | 472.210 s |
| r3 | 0.910 | 0 | 28 | 514.318 s |
| r4 | 0.896 | 0 | 28 | 391.412 s |

Binary full-solve rate is **1/5 = 0.20**. Diagnostic mean is 0.931 and
population variance is 0.0027. The measured 23–28 turns do **not** satisfy the
PDF's >60-turn Opus target; that remains an official-harness item.

`summary.json` is the machine-readable record. `episode-rN.jsonl` contains the
ordered prompt, assistant-visible text, tool calls, and tool results. Private
reasoning blocks, billing fields, host metadata, and unrelated Claude Code
attachments were intentionally omitted. `$EPISODE_ROOT` replaces the original
machine-specific scratch path; no action path was otherwise changed.

## Isolation and limitations

Each rollout received a freshly generated episode root and used that root as its
working directory. Only the generated incident environment and adapted task brief
were placed there. The task generator, verifier, `solution.sh`, documentation,
other rollout roots, and answer key were not copied into the episode root. The
prompt explicitly restricted investigation to that root. Grading happened only
after the agent exited, from outside the episode.

This was **logical/path isolation, not a hard OS filesystem sandbox**. Claude Code
was launched on the host with `--dangerously-skip-permissions`; therefore the
process technically had the host user's filesystem and network access. The
transcripts provide the audit trail showing the actions taken, but this pilot must
not be represented as proof of strict sandbox enforcement. A solve counts as
official only after rerunning in the customer's restricted Harbor/Terminal-Bench
harness (restricted mounts, non-root user, and the task container's offline
network policy).

The audit trail also records the concrete boundary exceptions: r3 queried the host
Python executable path and created/used a helper at `/tmp/mkrecord.py`. No episode
read the repository's generator, verifier, documentation, `solution.sh`, another
episode, or an answer key. These exceptions are why the pilot is supporting model-
behavior evidence rather than an official sandboxed score.

## Invocation and grading

Episodes used Claude Code subscription authentication, model
`claude-opus-5`, a 60-turn cap, and one process per episode:

```text
claude -p "$(cat EPISODE_BRIEF)" --model claude-opus-5 \
  --dangerously-skip-permissions --max-turns 60 --output-format json
```

The external grader imported the shipped
`tasks/supply-chain-audit/tests/test_outputs.py`, ran `run_checks()` against each
post-episode root, and calculated its diagnostic weighted fraction. Binary reward
was 1 only where every expanded check passed.

## Artifact finality

These episodes exercised the final 55-distribution environment, 67-check verifier,
and binary reward logic introduced by commit `1ad9249`. Commit `f5ff156` only added
`jobs/` to `.gitignore`; it did not change task environment or reward behavior.
No environment or reward changes are included with this evidence package. The
task is frozen for customer reruns at the evidence commit and later documentation-
only descendants unless explicitly announced.

## Oracle evidence

`oracle.log` records a fresh local build and reference solve of the same 55-
distribution/67-check task. It reaches 67/67 and demonstrates deterministic
solvability. The repository's Docker/Harbor oracle remains the stronger execution-
isolation check; reproduce it using `HOW-TO-TEST.md`.
