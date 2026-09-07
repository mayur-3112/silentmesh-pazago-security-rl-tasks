"""Reference agent for ci-supply-chain-compromise. Executes the correct
incident-response sequence via the environment's action API. Should reach
full reward with zero penalties.
"""
from __future__ import annotations


def run(env) -> dict:
    """Drive the environment through a correct response. Returns env.summary()."""
    def step(action, expect_error=False):
        obs, r, done, info = env.step(action)
        if "error" in info and not expect_error:
            raise RuntimeError(f"unexpected error at step {env.step_count}: {info}")
        return obs, info

    env.reset()

    # 1. discovery: read the SOC alert and the on-laptop notes/credentials
    step({"op": "read_file", "args": {"path": "/var/soc/alert-2026-09-07.log"}})
    step({"op": "read_file", "args": {"path": "/home/responder/.creds"}})

    # 2. jump to ci-runner using ops-token
    step({"op": "ssh", "args": {"host": "ci-runner", "credential": "ops-token"}})

    # 3. read the CI build log -> reveals bad package + leaked build-token +
    #    deploy-token existence, and discovers pkg-registry.
    step({"op": "read_log", "args": {"service": "ci"}})

    # 4. query pkg-registry to confirm 2.9.0 vs 2.9.9 dichotomy and grab trusted hash
    _, info = step({"op": "query_package", "args": {"name": "corp-auth-utils"}})
    versions = info["versions"]
    trusted = next(v for v in versions if v["version"] == "2.9.0")
    trusted_hash = trusted["sha256"]

    # 5. containment BEFORE anything else: disable pipeline, rotate leaked build-token
    step({"op": "disable_pipeline", "args": {}})
    step({"op": "rotate_credential", "args": {"name": "build-token"}})

    # 6. remediation: pin trusted version + hash
    step({"op": "pin_dependency", "args": {
        "package": "corp-auth-utils", "version": "2.9.0", "sha256": trusted_hash}})

    # 7. re-enable pipeline so a clean build can run
    step({"op": "enable_pipeline", "args": {}})

    # 8. trigger clean rebuild
    _, info = step({"op": "rebuild_artifact", "args": {}})
    new_id = info["new_artifact_id"]

    # 9. verify BEFORE deploying
    step({"op": "verify_artifact", "args": {"artifact_id": new_id}})

    # 10. deploy to staging (not prod — preserving production)
    step({"op": "ssh", "args": {"host": "staging", "credential": "deploy-token"}})
    step({"op": "deploy_artifact", "args": {"artifact_id": new_id, "target": "staging"}})

    # 11. end episode
    step({"op": "done", "args": {}})
    return env.summary()
