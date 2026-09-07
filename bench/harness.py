"""Task-agnostic rollout harness.

Loads a task's local_test module, runs N rollouts of a chosen agent against it,
and aggregates the mean reward, variance, and per-rollout scores. This is the same
shape as the D1-D4 grading Pazago's harness performs, run against whichever agent
we hand it.
"""
import importlib.util, os, sys, tempfile, shutil, statistics, time, traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_task(task_id):
    path = os.path.join(ROOT, "tasks", task_id, "local_test.py")
    if not os.path.exists(path):
        raise SystemExit(f"no local_test.py for task '{task_id}'")
    spec = importlib.util.spec_from_file_location(f"task_{task_id}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def one_rollout(task_mod, agent):
    """Build env -> run agent -> grade. Returns (reward, elapsed_seconds)."""
    root = tempfile.mkdtemp(prefix=f"bench_{agent.__name__}_")
    t0 = time.time()
    try:
        P = task_mod.build(root)
        try:
            agent(task_mod, P)
        except Exception:
            pass  # agent errors are graded as low reward, not fatal
        reward = _grade_capturing(task_mod, P)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return reward, time.time() - t0


def _grade_capturing(task_mod, P):
    """Call task_mod.grade(P) while capturing stdout so per-rollout logs stay quiet."""
    import io
    buf, saved = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        r = task_mod.grade(P)
    except Exception:
        return 0.0
    finally:
        sys.stdout = saved
    return float(r) if r is not None else 0.0


def rollout_series(task_id, agent, n=8):
    task_mod = load_task(task_id)
    rewards, times = [], []
    for i in range(n):
        r, t = one_rollout(task_mod, agent)
        rewards.append(r); times.append(t)
    return {
        "task": task_id, "agent": agent.__name__, "n": n,
        "rewards": rewards, "mean": statistics.mean(rewards),
        "variance": statistics.pvariance(rewards) if len(rewards) > 1 else 0.0,
        "min": min(rewards), "max": max(rewards),
        "mean_seconds": statistics.mean(times),
    }
