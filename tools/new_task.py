#!/usr/bin/env python3
"""Scaffold a new task (cyber gym) from templates/task-template.

Usage:
    python tools/new_task.py <task-id> ["Task Title"]

Creates tasks/<task-id>/ with the standard skeleton, substitutes __TASK_ID__, and
prints the next steps. The new task will FAIL run_suite.py until you fill in the
generator, verifier, and oracle — that is intentional (the suite is the gate).
"""
import os, sys, shutil, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "templates", "task-template")


def main():
    if len(sys.argv) < 2 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,40}", sys.argv[1]):
        print("usage: python tools/new_task.py <task-id: lowercase-kebab> [\"Title\"]")
        sys.exit(2)
    task_id = sys.argv[1]
    title = sys.argv[2] if len(sys.argv) > 2 else task_id
    dest = os.path.join(ROOT, "tasks", task_id)
    if os.path.exists(dest):
        print("error: tasks/%s already exists" % task_id)
        sys.exit(1)
    shutil.copytree(TEMPLATE, dest)
    # substitute placeholders that are safe to auto-fill
    doc = os.path.join(dest, "DOCUMENTATION.md")
    with open(doc, encoding="utf-8") as f:
        s = f.read()
    with open(doc, "w", encoding="utf-8", newline="") as f:
        f.write(s.replace("__TASK_ID__", "%s (%s)" % (task_id, title)))
    print("created tasks/%s\n" % task_id)
    print("next steps:")
    print("  1. env/gen/build_env.py  - construct the compromised environment")
    print("  2. task.yaml             - write the outcome-only instruction + keys")
    print("  3. tests/test_outputs.py - capability-ladder verifier (partial credit)")
    print("  4. solution.sh           - reference oracle (must score full reward)")
    print("  5. add a local_test.py   - portable runner (copy one from a sibling task)")
    print("  6. DOCUMENTATION.md      - curation history, difficulty, failure modes")
    print("\nthen:  python run_suite.py   (must reach ALL PASS before committing)")


if __name__ == "__main__":
    main()
