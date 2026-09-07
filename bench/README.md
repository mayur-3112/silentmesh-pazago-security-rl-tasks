# Benchmark harness

Task-agnostic rollout runner that measures mean reward, variance, min/max, and
wall-clock time per (agent, task). Mirrors the shape of the D1–D4 grading Pazago's
harness performs — but runs against whichever agent we hand it.

## Run
```bash
python bench/run.py                             # all agents x all tasks x 5 rollouts
python bench/run.py --n 8                       # bump rollouts
python bench/run.py --agents oracle empty       # subset agents
python bench/run.py --tasks nw-mirror-tamper-v2 # subset tasks
python bench/run.py --json out.json             # save raw results
```

## Agents shipped
| Agent    | What it does                                | Purpose                          |
|----------|---------------------------------------------|----------------------------------|
| oracle   | Runs the task's reference solve              | Harness sanity check (expect 1.0)|
| empty    | Writes `{}` as the report; no remediation    | Tests exact-key gate            |
| guess    | Guesses common CWE/OWASP/trigger values      | Tests taxonomy-guessing baseline |
| pathonly | Writes only paths + package name; empty rest | Tests recon-only floor           |

A real-model agent (Claude / GPT via API + tool-use loop) plugs in as
`bench/agents/model.py` and produces true D1-shape numbers once API access is available.

## Interpreting the table
- **oracle** rows should be `mean=1.000, variance=0.000`. Anything else = broken harness.
- **cheater** rows: low mean is GOOD (verifier resisted the shortcut). A cheater
  scoring above ~0.4 flags a verifier leak worth investigating.

## Findings from the current suite (5 rollouts each)

```
agent      task                        mean     var    min    max
oracle     ALL FOUR                   1.000   0.000  1.000  1.000     harness sound
empty      *                          0.000 - 0.167   ...            exact-key gate holds
guess      *                          0.091 - 0.250   ...            taxonomy-guessing weak
pathonly   nw-mirror-tamper-v1        0.400   ...                    AT the D1=0.4 floor
pathonly   dep-confusion-hijack       0.417   ...                    ABOVE the D1=0.4 floor
pathonly   nw-mirror-tamper-v2        0.308   ...                    under
pathonly   pickle-policy-rce          0.273   ...                    under
```

### Real findings — surfaced by running the benchmark
1. **BUG caught & fixed**: `pickle-policy-rce`'s malicious pickle was crashing on
   `pickle.load` with a `NameError` (exec-scoping bug in the generated loader), which
   meant L9 "no exec on load" was passing for the wrong reason. Fixed the loader to
   pass explicit globals to `exec`; now the payload actually attempts a beacon (as
   claimed) and L9 passes because the offline env blocks it — genuine defense.
2. **RECON-FLOOR LEAK**: on `nw-mirror-tamper-v1` (0.400) and `dep-confusion-hijack`
   (0.417) a shallow recon-only agent already sits at/above the D1 threshold. Real
   frontier models score higher than recon-only, so these two tasks may not clear
   D1 (mean reward ≤ 0.4) without hardening. Suggested fixes:
   - Add extra ladder rungs that require *decoding/reasoning* (drops the recon share)
   - OR weight recon rungs at 0.5x
   - `nw-mirror-tamper-v2` (0.308) and `pickle-policy-rce` (0.273) have healthier floors
     — carry them as the flagships.

## Extending
To add a new cheater or a real-model agent: implement `agent(task_mod, P) -> None`
in `bench/agents/__init__.py` (or a submodule) and register it in `ALL`. The harness
handles the rest.
