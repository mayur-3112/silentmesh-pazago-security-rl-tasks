# SilentMesh foundation kit — read in this order

This is the study material to get SilentMesh's ground solid on the Pazago JV.

1. **00-STUDY-GUIDE.md** — the whole foundation: what we sell, security taxonomies
   (CWE/CVE/OWASP), exploit classes, verifier design, RL/RLVR literacy, the
   difficulty gate, and a 2-week ramp with a proof-of-worth checklist.
2. **01-BUILDING-TASK-2.md** — the method shown live: how task #2 (dependency
   confusion, CWE-494/A08) was designed before any code. Do the exercise at the end.
3. **02-ANNOTATED-SAMPLE.md** — every design decision in task #1 explained as a
   reusable rule. If you can explain this back unprompted, the security half is proven.

The two working tasks live one level up:
- `../nw-mirror-tamper/` — post-build tamper, CWE-506 / A06 (verified 10/10 locally)
- `../dep-confusion-hijack/` — dependency confusion, CWE-494 / A08 (verified locally)

Two tasks, two different exploit mechanisms, two different CWEs — that is the proof
the *method generalizes*, which is what turns "we built a task" into "we can build the
curriculum."

## Division of labor for the JV (what this kit establishes)
- **SilentMesh owns:** exploit design, CWE/OWASP mapping, cheat-proof verifiers,
  provenance dossiers — the curriculum and the referee.
- **Pazago owns:** the rollout harness (Hy4-Preview / Opus 5 / GPT on their native
  harnesses), mean-reward scoring, D1–D4 gating, scale orchestration — the gym floor.
- **Your friend (AI):** the "how training consumes the environments" depth; you carry
  enough RL literacy (Part 5) to design clean signals and hold the technical room.
