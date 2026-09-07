"""Interactive cyber-gym core.

An Environment is a stateful world with:
  - hosts, services, credentials, files, logs, artifacts (state)
  - a partial-observability filter (what the agent sees now)
  - discrete parameterized actions the agent can take
  - transitions that mutate state (some silently reveal info; some fail)
  - a set of graded outcomes (positive rewards) and penalties (negative)

An episode is: reset() -> obs; then step(action) -> (obs, reward_delta, done, info)
until the agent calls action {"op":"done"} or step_limit is hit.

Reward semantics (outcome-based, not field-parity based):
  - Each Outcome has a value in (-1, 1]. Positive = objective achieved.
    Negative = penalty for a bad action (destructive, ignored SOC signal, etc.)
  - The total reward is sum of achieved outcomes, clipped to [0, 1].
  - An outcome fires at most once per episode.
  - reward_delta at each step is the change since the previous step.

This lets pass@k, mean-reward, and variance be measured meaningfully across
independent rollouts by any agent (oracle, adversarial, real LLM).
"""
from dataclasses import dataclass, field
from typing import Any, Callable


Action = dict          # {"op": str, "args": dict}
Observation = dict     # arbitrary agent-visible snapshot


@dataclass
class Outcome:
    """One graded outcome. `check(env)` returns True when achieved."""
    key: str
    value: float                     # positive for objectives, negative for penalties
    description: str
    check: Callable[["Environment"], bool]
    terminal_only: bool = False  # only evaluate when episode ends (for "preserved_X" style outcomes)
    achieved: bool = False
    achieved_at_step: int | None = None


class Environment:
    """Abstract multi-host stateful environment. Subclass and override:
       - reset_state()   -> initialise self.state
       - observation()   -> compute the agent-visible view
       - handle(action)  -> mutate state + return info dict; may raise ActionError
       - outcomes        -> list[Outcome] (declared once, evaluated after every step)
    """
    step_limit: int = 200

    def __init__(self):
        self.state: dict = {}
        self.outcomes: list[Outcome] = []
        self.step_count: int = 0
        self.done: bool = False
        self._last_score: float = 0.0

    # ---- lifecycle ----
    def reset(self) -> Observation:
        self.state = {}
        self.outcomes = self._declare_outcomes()
        self.step_count = 0
        self.done = False
        self._last_score = 0.0
        self.reset_state()
        return self.observation()

    def step(self, action: Action) -> tuple[Observation, float, bool, dict]:
        if self.done:
            return self.observation(), 0.0, True, {"error": "episode already ended"}
        self.step_count += 1
        info: dict = {"action": action}
        try:
            result = self.handle(action)
            if isinstance(result, dict):
                info.update(result)
        except ActionError as e:
            info["error"] = str(e)
        if action.get("op") == "done" or self.step_count >= self.step_limit:
            self.done = True
        self._evaluate_outcomes()
        score = self.current_score()
        reward_delta = score - self._last_score
        self._last_score = score
        return self.observation(), reward_delta, self.done, info

    # ---- to override ----
    def reset_state(self) -> None:  # populate self.state
        raise NotImplementedError

    def observation(self) -> Observation:
        raise NotImplementedError

    def handle(self, action: Action) -> dict | None:
        raise NotImplementedError

    def _declare_outcomes(self) -> list[Outcome]:
        raise NotImplementedError

    # ---- utility ----
    def _evaluate_outcomes(self):
        for oc in self.outcomes:
            if oc.terminal_only and not self.done:
                continue
            if not oc.achieved and oc.check(self):
                oc.achieved = True
                oc.achieved_at_step = self.step_count

    def current_score(self) -> float:
        raw = sum(oc.value for oc in self.outcomes if oc.achieved)
        return max(0.0, min(1.0, raw))

    def achievements(self) -> dict[str, float]:
        return {oc.key: oc.value for oc in self.outcomes if oc.achieved}

    def summary(self) -> dict:
        return {
            "score": self.current_score(),
            "steps": self.step_count,
            "achieved": [oc.key for oc in self.outcomes if oc.achieved],
            "missed":   [oc.key for oc in self.outcomes if not oc.achieved and oc.value > 0],
            "penalties":[oc.key for oc in self.outcomes if oc.achieved and oc.value < 0],
        }


class ActionError(Exception):
    """Raised inside handle(action) when the action is invalid, unauthorised, or
    otherwise not executable in the current state. Info is surfaced to the agent
    as info['error'] — it does NOT end the episode, it's just a normal failure
    response the agent has to reason about."""
