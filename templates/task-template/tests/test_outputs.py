"""Capability-ladder verifier. Reward = fraction of rungs passed (partial credit).
Rules: answers not greppable / not reachable by execution (offline); block
report-without-remediation and delete-instead-of-fix; enforce exact key set.
Prefer a randomized challenge-response re-derived here (deterministic oracle).
"""
import json, os
REPORT = "/app/report.json"
KEYS = {"__field_a__", "__field_b__", "primary_cwe", "owasp_a"}
def _r():
    with open(REPORT) as f: return json.load(f)
def test_l0_keys():
    assert set(_r()) == KEYS
# TODO: one test_l<N>_* per ladder rung; last rungs verify remediation + functionality.
