#!/usr/bin/env python3
"""Shell-facing agent interface for ci-supply-chain-compromise.

The agent runs this from a shell inside the task container. It presents a
line-oriented text protocol:

    action  <op> [--k v [--k v ...]]
    obs                                  # print current observation
    score                                # print current score + achieved outcomes
    help                                 # list available actions
    quit                                 # end episode (equivalent to `action done`)

Each `action` line is parsed into {"op": <op>, "args": {k: v, ...}} and passed
to env.step(). The resulting observation, reward_delta, and info dict are
printed as pretty JSON on stdout. The episode ends when the agent runs `quit`,
issues `action done`, or the step limit is reached.

State is written to /app/state.json every step so a separate grader can
observe outcome & achievement state without opening a Python REPL.
"""
from __future__ import annotations
import json, os, sys, shlex, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from scenario import Env

STATE_FILE = os.environ.get("GYM_STATE_FILE", "/app/state.json")


def _emit_state(env):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(env.summary(), f, indent=2)
    except OSError:
        pass


def _parse_kv(tokens):
    """Turn --k v --k v tokens into a dict. Values are strings unless integer."""
    args = {}
    it = iter(tokens)
    for tok in it:
        if not tok.startswith("--"):
            raise ValueError(f"expected --key, got: {tok!r}")
        key = tok[2:]
        try:
            val = next(it)
        except StopIteration:
            raise ValueError(f"missing value for --{key}")
        # try int, else string
        try:
            val = int(val)
        except ValueError:
            pass
        args[key] = val
    return args


HELP = textwrap.dedent("""\
    Available actions:
      action list_hosts
      action read_file --path <absolute-path>
      action list_dir  --path <absolute-path>
      action read_log  --service <ci|soc|service>
      action ssh --host <host> --credential <name>
      action http_get --url <host>/<resource> [--credential <name>]
      action query_package --name <pkg>
      action inspect_artifact --artifact_id <id> [--credential <name>]
      action rotate_credential --name <credential>
      action disable_pipeline [--pipeline_id <id>]
      action enable_pipeline  [--pipeline_id <id>]
      action pin_dependency --package <name> --version <v> --sha256 <hash>
      action rebuild_artifact [--pipeline_id <id>]
      action verify_artifact --artifact_id <id>
      action deploy_artifact --artifact_id <id> --target <staging|prod>
      action shutdown_service --host <host>
      action done
    Meta commands:
      obs           print the current observation
      score         print current score + achievements
      help          this text
      quit          end the episode
    """)


def _print_result(kind, payload):
    print(json.dumps({"kind": kind, **payload}, indent=2, default=str))


def main():
    env = Env()
    obs = env.reset()
    _emit_state(env)
    _print_result("reset", {"observation": obs})
    for raw in sys.stdin:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            _print_result("error", {"error": f"parse: {e}"})
            continue
        head = tokens[0]
        rest = tokens[1:]
        if head == "help":
            print(HELP); continue
        if head == "obs":
            _print_result("observation", {"observation": env.observation(),
                                          "score": env.current_score()})
            continue
        if head == "score":
            _print_result("score", {"score": env.current_score(),
                                    "achieved": list(env.achievements().keys()),
                                    "steps": env.step_count})
            continue
        if head in ("quit", "exit"):
            env.step({"op": "done"})
            _emit_state(env)
            _print_result("end", {"summary": env.summary()})
            break
        if head == "action":
            if not rest:
                _print_result("error", {"error": "action requires an op"})
                continue
            op = rest[0]
            try:
                args = _parse_kv(rest[1:])
            except ValueError as e:
                _print_result("error", {"error": f"args: {e}"})
                continue
            obs, r, done, info = env.step({"op": op, "args": args})
            _emit_state(env)
            _print_result("step", {"observation": obs, "reward_delta": r,
                                   "done": done, "info": info})
            if done:
                _print_result("end", {"summary": env.summary()}); break
            continue
        _print_result("error", {"error": f"unknown command: {head}"})
    else:
        # stdin closed without quit -- end the episode cleanly
        if not env.done:
            env.step({"op": "done"})
            _emit_state(env)
            _print_result("end", {"summary": env.summary()})


if __name__ == "__main__":
    main()
