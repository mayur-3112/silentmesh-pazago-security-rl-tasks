"""SilentMesh interactive cyber-gym framework.

This is the RL-environment abstraction that replaces the previous puzzle-style
tasks. A gym here is a stateful multi-host world the agent operates in via
discrete actions; the reward is derived from *security outcomes* achieved, not
from matching fields in a JSON report.

See env/core.py for the abstract interface; tasks/<name>/scenario.py for a
concrete scenario. See legacy/ for the previous puzzle-style tasks (kept for
history and framework demonstration; do NOT use them as the benchmark).
"""
from .core import Environment, Action, Observation, Outcome
