#!/usr/bin/env python3
"""Portable runner for ci-supply-chain-compromise. Instantiates the interactive
environment, runs the reference oracle, and prints the reward + achievement
breakdown. No Docker required.

Usage: python local_test.py
Expected: score = 1.000 with all objectives achieved, zero penalties.
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from scenario import Env
from oracle import run


def main():
    env = Env()
    summary = run(env)
    print("=" * 62)
    print(f"episode ended at step {summary['steps']}, score = {summary['score']:.3f}")
    print("-" * 62)
    print("achieved objectives:")
    for a in summary["achieved"]:
        marker = "!" if a.startswith("PENALTY") else "+"
        val = next(o.value for o in env.outcomes if o.key == a)
        print(f"  [{marker}] {a:<45} {val:+.2f}")
    if summary["missed"]:
        print("\nmissed objectives:")
        for m in summary["missed"]:
            print(f"  [ ] {m}")
    print("=" * 62)
    # for the harness / suite compatibility
    print(f"REWARD = {summary['score']:.3f}")
    return summary["score"]


if __name__ == "__main__":
    main()
