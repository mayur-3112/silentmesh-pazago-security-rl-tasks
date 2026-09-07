#!/usr/bin/env python3
"""Benchmark harness for ci-supply-chain-compromise.

Runs multiple agent strategies against the environment, records per-rollout
scores, and checks against the procurement difficulty gates (D1-D4).

Usage:
  python benchmark.py                    # run all built-in agents
  python benchmark.py --agent oracle     # run only the oracle
"""
import sys, os, json, statistics, argparse
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from scenario import Env
from oracle import run as oracle_run
from adversarial import sledgehammer, skipped_rotation


# --- Agent strategies (simulate model-level competence tiers) ---------------

def agent_oracle(env):
    """Reference oracle — perfect play, score=1.0."""
    return oracle_run(env)

def agent_sledgehammer(env):
    """Panic agent — destructive, low score."""
    return sledgehammer(env)

def agent_skipped_rotation(env):
    """Partial agent — skips credential rotation."""
    return skipped_rotation(env)

def agent_greedy_no_verify(env):
    """Gets most things right but skips verification and hits the token penalty."""
    env.reset()
    env.step({"op": "read_file", "args": {"path": "/var/soc/alert-2026-09-07.log"}})
    env.step({"op": "read_file", "args": {"path": "/home/responder/.creds"}})
    env.step({"op": "ssh", "args": {"host": "ci-runner", "credential": "ops-token"}})
    env.step({"op": "read_log", "args": {"service": "ci"}})
    env.step({"op": "inspect_artifact", "args": {"artifact_id": "art-2026090614:22"}})
    env.step({"op": "disable_pipeline", "args": {}})
    env.step({"op": "rotate_credential", "args": {"name": "build-token"}})
    env.step({"op": "query_package", "args": {"name": "corp-auth-utils"}})
    env.step({"op": "pin_dependency", "args": {
        "package": "corp-auth-utils", "version": "2.9.0", "sha256": "TRUSTED_HASH"}})
    env.step({"op": "enable_pipeline", "args": {}})
    _, _, _, info = env.step({"op": "rebuild_artifact", "args": {}})
    new_id = info.get("new_artifact_id", "art-0018-clean")
    # skip verify_artifact
    env.step({"op": "deploy_artifact", "args": {"artifact_id": new_id, "target": "staging"}})
    env.step({"op": "done", "args": {}})
    return env.summary()

def agent_near_perfect(env):
    """Like oracle but inspects the bad artifact before rotating (penalty)."""
    env.reset()
    env.step({"op": "read_file", "args": {"path": "/var/soc/alert-2026-09-07.log"}})
    env.step({"op": "read_file", "args": {"path": "/home/responder/.creds"}})
    env.step({"op": "ssh", "args": {"host": "ci-runner", "credential": "ops-token"}})
    env.step({"op": "read_log", "args": {"service": "ci"}})
    env.step({"op": "query_package", "args": {"name": "corp-auth-utils"}})
    env.step({"op": "inspect_artifact", "args": {"artifact_id": "art-2026090614:22"}})
    env.step({"op": "disable_pipeline", "args": {}})
    env.step({"op": "rotate_credential", "args": {"name": "build-token"}})
    env.step({"op": "pin_dependency", "args": {
        "package": "corp-auth-utils", "version": "2.9.0", "sha256": "TRUSTED_HASH"}})
    env.step({"op": "enable_pipeline", "args": {}})
    _, _, _, info = env.step({"op": "rebuild_artifact", "args": {}})
    new_id = info.get("new_artifact_id", "art-0018-clean")
    env.step({"op": "verify_artifact", "args": {"artifact_id": new_id}})
    env.step({"op": "deploy_artifact", "args": {"artifact_id": new_id, "target": "staging"}})
    env.step({"op": "done", "args": {}})
    return env.summary()


AGENTS = {
    "oracle":            agent_oracle,
    "near_perfect":      agent_near_perfect,
    "greedy_no_verify":  agent_greedy_no_verify,
    "skipped_rotation":  agent_skipped_rotation,
    "sledgehammer":      agent_sledgehammer,
}


def run_rollouts(agent_name, n=5):
    fn = AGENTS[agent_name]
    results = []
    for i in range(n):
        env = Env()
        summary = fn(env)
        results.append({
            "rollout": i + 1,
            "score": summary["score"],
            "steps": summary["steps"],
            "achieved": summary["achieved"],
            "missed": summary["missed"],
            "penalties": summary["penalties"],
        })
    return results


def check_difficulty_gates(sota_results, hy_results=None):
    """Check D1-D4 from the procurement requirements."""
    gates = {}
    sota_scores = [r["score"] for r in sota_results]
    sota_mean = statistics.mean(sota_scores)
    sota_var = statistics.variance(sota_scores) if len(sota_scores) > 1 else 0.0

    gates["D2_sota_mean_le_0.6"] = {
        "pass": sota_mean <= 0.6,
        "value": sota_mean,
        "n": len(sota_scores),
        "threshold": 0.6,
    }
    gates["D4_sota_variance_ne_0"] = {
        "pass": sota_var > 0,
        "value": sota_var,
    }
    if hy_results:
        hy_scores = [r["score"] for r in hy_results]
        hy_mean = statistics.mean(hy_scores)
        gates["D1_hy_mean_le_0.4"] = {
            "pass": hy_mean <= 0.4,
            "value": hy_mean,
            "n": len(hy_scores),
            "threshold": 0.4,
        }
        gates["D3_hy_lt_sota"] = {
            "pass": hy_mean < sota_mean,
            "hy_mean": hy_mean,
            "sota_mean": sota_mean,
        }
    return gates


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agent", choices=list(AGENTS), default=None)
    p.add_argument("-n", type=int, default=5, help="rollouts per agent")
    args = p.parse_args()

    agents_to_run = [args.agent] if args.agent else list(AGENTS)
    all_results = {}

    for name in agents_to_run:
        print(f"\n{'='*50}")
        print(f"Agent: {name}  ({args.n} rollouts)")
        print(f"{'='*50}")
        results = run_rollouts(name, args.n)
        all_results[name] = results
        scores = [r["score"] for r in results]
        for r in results:
            pens = [a for a in r["achieved"] if a.startswith("PENALTY")]
            pen_str = f"  penalties={pens}" if pens else ""
            print(f"  rollout {r['rollout']}: score={r['score']:.3f}  steps={r['steps']}{pen_str}")
        print(f"  mean={statistics.mean(scores):.3f}  "
              f"var={statistics.variance(scores) if len(scores)>1 else 0:.4f}  "
              f"min={min(scores):.3f}  max={max(scores):.3f}")

    # Difficulty gate check (using oracle as SOTA proxy, sledgehammer as Hy proxy)
    if "oracle" in all_results:
        print(f"\n{'='*50}")
        print("Difficulty Gate Check (D1-D4)")
        print(f"{'='*50}")
        sota = all_results.get("oracle", [])
        hy = all_results.get("sledgehammer", [])
        gates = check_difficulty_gates(sota, hy if hy else None)
        for k, v in gates.items():
            status = "PASS" if v["pass"] else "FAIL"
            print(f"  {k}: {status}  {v}")

    # Write results
    out = {
        "timestamp": datetime.now().isoformat(),
        "task": "ci-supply-chain-compromise",
        "results": all_results,
    }
    outpath = os.path.join(HERE, "benchmark_results.json")
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written to {outpath}")


if __name__ == "__main__":
    main()
