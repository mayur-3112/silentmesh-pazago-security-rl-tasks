#!/usr/bin/env python3
"""SilentMesh benchmark runner.

Runs one or more agents against one or more tasks, N rollouts each, and prints a
mean-reward + variance table. This is the same measurement shape as Pazago's D1-D4
grading, just against whichever agent we hand it.

Usage:
    python bench/run.py                    # all agents x all tasks x 5 rollouts
    python bench/run.py --n 8              # bump rollouts
    python bench/run.py --agents oracle empty guess
    python bench/run.py --tasks nw-mirror-tamper-v2 pickle-policy-rce
    python bench/run.py --json out.json    # also save raw results

Interpretation:
    - oracle rows show whether the harness itself is sound (expect mean = 1.000).
    - non-oracle rows are ADVERSARIAL agents; a low mean is GOOD -- it means the
      verifier resists that shortcut. If a cheater gets > ~0.4 the verifier has a
      leak worth investigating.
"""
import argparse, os, sys, json, glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import rollout_series
from agents import ALL


def all_tasks():
    root = os.path.dirname(HERE)
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(root, "tasks", "*"))
                  if os.path.exists(os.path.join(p, "local_test.py")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5, help="rollouts per (agent, task)")
    ap.add_argument("--agents", nargs="+", default=list(ALL), choices=list(ALL))
    ap.add_argument("--tasks", nargs="+", default=None)
    ap.add_argument("--json", default=None, help="write raw results to this path")
    args = ap.parse_args()

    tasks = args.tasks or all_tasks()
    print(f"benchmark: {len(args.agents)} agents x {len(tasks)} tasks x {args.n} rollouts")
    print("=" * 78)
    header = f"{'agent':<10} {'task':<24} {'mean':>7} {'var':>7} {'min':>6} {'max':>6} {'sec/rollout':>11}"
    print(header); print("-" * len(header))
    all_results = []
    for agent_name in args.agents:
        agent = ALL[agent_name]
        for task in tasks:
            r = rollout_series(task, agent, n=args.n)
            all_results.append(r)
            print(f"{r['agent']:<10} {r['task']:<24} "
                  f"{r['mean']:>7.3f} {r['variance']:>7.3f} "
                  f"{r['min']:>6.3f} {r['max']:>6.3f} {r['mean_seconds']:>11.3f}")
        if agent_name != args.agents[-1]:
            print("-" * len(header))
    print("=" * 78)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"wrote raw results to {args.json}")


if __name__ == "__main__":
    main()
