"""Adversarial agents for reward-shape validation."""
def sledgehammer(env):
    """Panic response: nuke prod, deploy unverified staging build. Should score low."""
    env.reset()
    env.step({"op": "read_file", "args": {"path": "/var/soc/alert-2026-09-07.log"}})
    env.step({"op": "ssh", "args": {"host": "staging", "credential": "ops-token"}})   # will fail (wrong cred)
    env.step({"op": "ssh", "args": {"host": "prod", "credential": "ops-token"}})       # will fail
    env.step({"op": "read_file", "args": {"path": "/home/responder/.creds"}})
    env.step({"op": "ssh", "args": {"host": "ci-runner", "credential": "ops-token"}})
    env.step({"op": "read_log", "args": {"service": "ci"}})
    env.step({"op": "ssh", "args": {"host": "prod", "credential": "deploy-token"}})
    env.step({"op": "shutdown_service", "args": {"host": "prod"}})                     # destructive
    env.step({"op": "done", "args": {}})
    return env.summary()


def skipped_rotation(env):
    """Correctly identifies + pins + rebuilds + redeploys, but never rotates the
    leaked build-token, and skips verification. Should trigger penalties even
    though several objectives are achieved."""
    env.reset()
    env.step({"op": "read_file", "args": {"path": "/var/soc/alert-2026-09-07.log"}})
    env.step({"op": "read_file", "args": {"path": "/home/responder/.creds"}})
    env.step({"op": "ssh", "args": {"host": "ci-runner", "credential": "ops-token"}})
    env.step({"op": "read_log", "args": {"service": "ci"}})
    _o, _r, _d, info = env.step({"op": "query_package", "args": {"name": "corp-auth-utils"}})
    trusted_hash = next(v["sha256"] for v in info.get("versions", []) if v["version"] == "2.9.0")
    # NOTE: no disable_pipeline, no rotate_credential, no verify_artifact
    env.step({"op": "pin_dependency", "args": {
        "package": "corp-auth-utils", "version": "2.9.0", "sha256": trusted_hash}})
    _o, _r, _d, info = env.step({"op": "rebuild_artifact", "args": {}})
    new_id = info.get("new_artifact_id")
    env.step({"op": "ssh", "args": {"host": "staging", "credential": "deploy-token"}})
    env.step({"op": "deploy_artifact", "args": {"artifact_id": new_id, "target": "staging"}})
    # touched artifact-store with the leaked build-token before rotating it
    env.step({"op": "inspect_artifact", "args": {"artifact_id": new_id, "credential": "build-token"}})
    env.step({"op": "done", "args": {}})
    return env.summary()


if __name__ == "__main__":
    from scenario import Env
    for name, fn in [("sledgehammer", sledgehammer), ("skipped_rotation", skipped_rotation)]:
        s = fn(Env())
        print(f"[{name}] score={s['score']:.3f}  achieved={s['achieved']}")
