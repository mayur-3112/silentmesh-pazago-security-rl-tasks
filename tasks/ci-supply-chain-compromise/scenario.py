"""ci-supply-chain-compromise — interactive cyber gym.

World: a small enterprise IT topology (dev-laptop, ci-runner, pkg-registry,
artifact-store, staging, prod, soc, log-relay). The build that landed on
staging resolved `corp-auth-utils` 2.9.9 from public PyPI instead of the
trusted 2.9.0 on the internal mirror (no hash pin) — that unpinned resolver
behavior is present in every episode and is a real defect either way.

But WHO was able to trigger that build is genuinely ambiguous each episode
and must be investigated, not assumed:
  - vector "build-token": the pipeline ran on its own schedule; the only
    leak is the build-token artifact-store credential printed in the CI log.
  - vector "ops-token": an attacker used a stolen ops-token (unrecognized
    source, no prior history) to log into ci-runner and trigger the build
    themselves; ops-token — the same credential the responder already holds
    and uses to investigate — is the one actually compromised.

Both vectors look identical from the SOC alert and the resolver log alone;
only /var/log/ci/auth.log on ci-runner disambiguates them. Pinning the
dependency fixes the resolver defect in both cases, but it does NOT close
the door: if the actually-compromised credential (whichever it is this
episode) is not rotated before rebuild, the attacker can retrigger a
poisoned build regardless of the pin, and the rebuild stays backdoored.
Guessing "it's always build-token" — the previously-obvious answer — fails
half the time by design.

A second, orthogonal decoy exists at `log-relay`: it is also named as
"possibly involved" per the SOC alert's CMDB list, but its log is an
unrelated, legitimate heartbeat — chasing it costs turns for zero credit.

Reward is derived from OUTCOMES ACHIEVED, not from JSON field parity.
Penalties punish destructive shortcuts (breaking prod, ignoring rotation,
deploying unverified artefacts) AND leaving the actual leak vector for this
episode un-rotated by the time the episode ends.
"""
from __future__ import annotations
import sys, os, random
# make `env` importable regardless of layout (repo checkout or /gym in container)
for _up in (1, 2, 3):
    _cand = os.path.abspath(os.path.join(os.path.dirname(__file__), *([".."] * _up)))
    if os.path.isdir(os.path.join(_cand, "env")):
        sys.path.insert(0, _cand)
        break
from env.core import Environment, Action, Observation, Outcome, ActionError


# ---- helpers on state ----

def _cur(env: "Env") -> str:
    return env.state["current_host"]


def _host(env: "Env", name: str) -> dict:
    if name not in env.state["hosts"]:
        raise ActionError(f"host '{name}' unknown")
    if name not in env.state["discovered_hosts"]:
        raise ActionError(f"host '{name}' not yet discovered")
    return env.state["hosts"][name]


class Env(Environment):
    step_limit = 60

    # -------------------------------------------------------------------
    # STATE
    # -------------------------------------------------------------------
    def reset_state(self):
        # Which credential actually let the attacker trigger the poisoned
        # build this episode. Both vectors present identically at the SOC
        # alert / resolver-log level; only ci-runner's auth.log tells them
        # apart. Randomized per episode so a fixed "always rotate build-token"
        # script is wrong half the time.
        leak_vector = random.choice(["build-token", "ops-token"])
        self.state["leak_vector"] = leak_vector
        if leak_vector == "build-token":
            auth_log = (
                "ops-token login from 10.0.4.12 (dev-laptop, known) at 03:40Z — routine\n"
                "build-token used by pipeline scheduler at 04:12Z — scheduled run, no anomaly\n"
            )
        else:
            auth_log = (
                "ops-token login from 185.220.101.7 (unrecognized ASN, no prior "
                "history for this account) at 03:55Z — manually triggered build\n"
                "build-token used by pipeline scheduler at 04:12Z — normal service usage\n"
            )
        # topology + host contents
        self.state["hosts"] = {
            "dev-laptop": {
                "files": {
                    "/home/responder/notes.md":
                        "SOC just paged: outbound beacon from staging service.\n"
                        "My creds file is at ~/.creds. Runbook: contact ops for ci-runner access.\n",
                    "/home/responder/.creds":
                        "dev-token=DEV-8f3a91\nops-token=OPS-e2b17c\n",
                    "/var/soc/alert-2026-09-07.log":
                        "[SOC] outbound HTTPS beacon observed src=staging "
                        "dst=sync-lure47.telemetry-cdn.net at 04:12Z\n"
                        "correlated with deploy of artifact art-2026090614:22 30m earlier.\n"
                        "hosts possibly involved (per CMDB, unconfirmed): ci-runner, "
                        "log-relay, artifact-store, staging.\n",
                },
                "listens": ["ssh"],
            },
            # decoy: also "possibly involved" per the alert's CMDB list, and its
            # log shows an outbound connection to a similar-looking domain — but
            # it is a known, legitimate monitoring heartbeat, not the beacon.
            "log-relay": {
                "requires": {"ssh": "ops-token"},
                "files": {
                    "/var/log/relay/heartbeat.log":
                        "cron heartbeat: POST https://telemetry-cdn.net/healthz "
                        "every 300s (vendor-registered endpoint, see CAB-4471)\n"
                        "no correlation with staging deploy window\n",
                },
                "listens": ["ssh"],
            },
            "ci-runner": {
                "requires": {"ssh": "ops-token"},
                "files": {
                    "/var/log/ci/build-art-2026090614:22.log":
                        "resolving requirements from ['internal-mirror', 'public-pypi']\n"
                        "  corp-auth-utils: mirror offers 2.9.0, public offers 2.9.9\n"
                        "  no version constraint, no hash pin -> selecting 2.9.9 (highest)\n"
                        "  downloading corp-auth-utils-2.9.9 from public-pypi\n"
                        "  installed corp-auth-utils==2.9.9 sha256=EVIL_HASH\n"
                        "  writing artifact art-2026090614:22 to artifact-store using build-token=BUILD-a91f2c\n",
                    "/etc/ci/pipelines.json":
                        '{"builder":{"enabled":true,"last_build":"art-2026090614:22"}}\n',
                    "/opt/app/requirements.lock":
                        "corp-auth-utils>=2.9.0\n"
                        "requests==2.31.0 --hash=sha256:aa11\n",
                    "/var/log/ci/auth.log": auth_log,
                },
                "listens": ["ssh"],
            },
            "pkg-registry": {
                "listens": ["http"],
                "packages": {
                    "corp-auth-utils": [
                        # (version, source, sha256)
                        ("2.9.0", "internal-mirror", "TRUSTED_HASH"),
                        ("2.9.9", "public-pypi",    "EVIL_HASH"),
                    ],
                },
            },
            "artifact-store": {
                "requires": {"http": "build-token"},
                "artifacts": {
                    "art-2026090614:22": {
                        "provenance": "ci-runner",
                        "contains": ["corp-auth-utils==2.9.9"],
                        "signature_valid_against_trusted": False,
                    },
                },
                "listens": ["http"],
            },
            "staging": {
                "requires": {"ssh": "deploy-token"},
                "files": {
                    "/etc/service/current":
                        "artifact=art-2026090614:22\n",
                    "/var/log/service.log":
                        "started service using art-2026090614:22\nbackground task connecting to sync-lure47.telemetry-cdn.net\n",
                },
                "listens": ["ssh"],
            },
            "prod": {
                "requires": {"ssh": "deploy-token"},
                "files": {
                    "/etc/service/current":
                        "artifact=art-2025092511:03\n",   # older, clean
                },
                "listens": ["ssh"],
            },
        }
        # credentials: some are known at start, some are discovered. Exactly
        # one of build-token/ops-token is truly leaked this episode, matching
        # leak_vector — the other is fine to keep using.
        self.state["credentials"] = {
            "dev-token":    {"status": "active", "known": True,  "leaked": False},
            "ops-token":    {"status": "active", "known": True,
                              "leaked": leak_vector == "ops-token"},
            "build-token":  {"status": "active", "known": False,
                              "leaked": leak_vector == "build-token"},
            "deploy-token": {"status": "active", "known": False, "leaked": False},
        }
        # what the responder starts knowing
        self.state["current_host"] = "dev-laptop"
        self.state["discovered_hosts"] = {"dev-laptop"}
        # bookkeeping
        self.state["pipeline_enabled"] = True
        self.state["staging_artifact"] = "art-2026090614:22"
        self.state["prod_artifact"] = "art-2025092511:03"
        self.state["actions_log"] = []
        self.state["rebuilt_artifact_id"] = None
        self.state["destructive_prod"] = False
        self.state["deployed_unverified"] = False
        self.state["used_build_token_after_alert"] = False
        self.state["verified_new_artifact"] = False
        self.state["identified_bad_package"] = False
        self.state["identified_attack_path"] = False
        self.state["rotated_build_token_before_rebuild"] = False
        self.state["chased_decoy"] = False
        self.state["read_auth_log"] = False

    # -------------------------------------------------------------------
    # OBSERVATION (partial)
    # -------------------------------------------------------------------
    def observation(self) -> Observation:
        cur = _cur(self)
        host = self.state["hosts"][cur]
        known_creds = {k: v["status"] for k, v in self.state["credentials"].items() if v["known"]}
        return {
            "current_host": cur,
            "discovered_hosts": sorted(self.state["discovered_hosts"]),
            "known_credentials": known_creds,
            "local_files": sorted(host.get("files", {}).keys()),
            "pipeline_enabled": self.state["pipeline_enabled"],
            "staging_artifact": self.state["staging_artifact"],
            "prod_artifact": self.state["prod_artifact"],
            "step": self.step_count,
            "score": self.current_score(),
            "achieved": list(self.achievements().keys()),
        }

    # -------------------------------------------------------------------
    # ACTIONS
    # -------------------------------------------------------------------
    def handle(self, action: Action):
        op = action.get("op")
        args = action.get("args", {}) or {}
        self.state["actions_log"].append(action)
        m = getattr(self, f"_op_{op}", None)
        if m is None:
            raise ActionError(f"unknown op: {op!r}")
        return m(**args)

    # discovery
    def _op_list_hosts(self):
        return {"reachable_from_here": sorted(self.state["discovered_hosts"])}

    def _op_read_file(self, path: str):
        host = self.state["hosts"][_cur(self)]
        if path not in host.get("files", {}):
            raise ActionError(f"no such file: {path}")
        content = host["files"][path]
        # side effect: reading soc alert reveals the *candidate* hosts (both the
        # real pivot and the decoy) + prod, matching the CMDB's unconfirmed list
        if path.endswith("alert-2026-09-07.log"):
            self.state["discovered_hosts"].update(
                {"ci-runner", "log-relay", "artifact-store", "staging", "prod"})
        if path.endswith("heartbeat.log"):
            self.state["chased_decoy"] = True
        # side effect: reading ci log discovers pkg-registry + deploy-token existence + leaked build-token
        if "/var/log/ci/build-" in path:
            self.state["discovered_hosts"].update({"pkg-registry"})
            self.state["credentials"]["build-token"]["known"] = True
            self.state["credentials"]["deploy-token"]["known"] = True
            self.state["identified_bad_package"] = True
        # side effect: reading the auth log is what actually disambiguates
        # WHICH credential is compromised this episode — the resolver log
        # alone is consistent with either vector.
        if path.endswith("/var/log/ci/auth.log"):
            self.state["read_auth_log"] = True
        # "traced the attack path" means both halves of the evidence were
        # read, not just the resolver defect that's present every episode.
        if self.state.get("identified_bad_package") and self.state.get("read_auth_log"):
            self.state["identified_attack_path"] = True
        if path == "/etc/service/current" and _cur(self) == "staging":
            self.state["discovered_hosts"].add("ci-runner")
        return {"content": content}

    def _op_list_dir(self, path: str = "/"):
        host = self.state["hosts"][_cur(self)]
        prefix = path.rstrip("/") + "/"
        matches = [f for f in host.get("files", {}) if f.startswith(prefix) or f == path]
        return {"entries": sorted(matches)}

    # movement
    def _op_ssh(self, host: str, credential: str):
        target = _host(self, host)
        needed = target.get("requires", {}).get("ssh")
        if needed is None:
            raise ActionError(f"host '{host}' does not accept ssh")
        cred = self.state["credentials"].get(credential)
        if not cred or cred["status"] != "active":
            raise ActionError(f"credential '{credential}' invalid or rotated")
        if credential != needed:
            raise ActionError(f"auth failed: wrong credential for {host} (needed {needed})")
        self.state["current_host"] = host
        return {"logged_in_to": host}

    def _op_http_get(self, url: str, credential: str | None = None):
        # url form: <host>/<resource>
        host_name, _, resource = url.partition("/")
        target = _host(self, host_name)
        if "http" not in target.get("listens", []):
            raise ActionError(f"host '{host_name}' does not serve http")
        needed = target.get("requires", {}).get("http")
        if needed:
            if not credential or self.state["credentials"].get(credential, {}).get("status") != "active":
                raise ActionError("auth required or invalid credential")
            if credential != needed:
                raise ActionError(f"forbidden: wrong credential (needed {needed})")
            # tracking leaked build-token usage AFTER alert
            if credential == "build-token" and self.state["credentials"]["build-token"]["leaked"]:
                self.state["used_build_token_after_alert"] = True
        if host_name == "artifact-store":
            arts = target["artifacts"]
            if not resource:
                return {"artifacts": sorted(arts)}
            if resource not in arts:
                raise ActionError(f"artifact {resource} not found")
            return {"artifact": {"id": resource, **arts[resource]}}
        if host_name == "pkg-registry":
            pkg = resource or ""
            packs = target["packages"].get(pkg)
            if not packs:
                return {"packages": sorted(target["packages"])}
            return {"versions": [{"version": v, "source": s, "sha256": h} for (v, s, h) in packs]}
        raise ActionError(f"no handler for http on {host_name}")

    # forensic actions
    def _op_read_log(self, service: str):
        # convenience alias that surfaces the primary log on the current host
        cur = _cur(self)
        candidates = {
            "ci": "/var/log/ci/build-art-2026090614:22.log",
            "soc": "/var/soc/alert-2026-09-07.log",
            "service": "/var/log/service.log",
            "relay": "/var/log/relay/heartbeat.log",
            "auth": "/var/log/ci/auth.log",
        }
        p = candidates.get(service)
        if not p:
            raise ActionError(f"unknown log service '{service}'")
        return self._op_read_file(p)

    def _op_query_package(self, name: str):
        # convenience wrapper
        return self._op_http_get(url=f"pkg-registry/{name}")

    def _op_inspect_artifact(self, artifact_id: str, credential: str = "build-token"):
        return self._op_http_get(url=f"artifact-store/{artifact_id}", credential=credential)

    # remediation
    def _op_rotate_credential(self, name: str):
        cred = self.state["credentials"].get(name)
        if not cred:
            raise ActionError(f"unknown credential '{name}'")
        if not cred["known"]:
            raise ActionError(f"credential '{name}' not known — cannot rotate what you have not discovered")
        cred["status"] = "rotated"
        return {"rotated": name}

    def _op_disable_pipeline(self, pipeline_id: str = "builder"):
        self.state["pipeline_enabled"] = False
        return {"pipeline_enabled": False}

    def _op_enable_pipeline(self, pipeline_id: str = "builder"):
        self.state["pipeline_enabled"] = True
        return {"pipeline_enabled": True}

    def _op_pin_dependency(self, package: str, version: str, sha256: str):
        # validate the pin is actually the trusted one
        registry = self.state["hosts"]["pkg-registry"]["packages"].get(package, [])
        match = next((v for v in registry if v[0] == version and v[2] == sha256), None)
        # write to the lockfile on ci-runner regardless (agent chose to write bad pin is their loss)
        rl = self.state["hosts"]["ci-runner"]["files"].get("/opt/app/requirements.lock", "")
        new_lines = []
        pinned = False
        for line in rl.splitlines(keepends=True):
            if line.strip().lower().startswith(package.lower()):
                new_lines.append(f"{package}=={version} --hash=sha256:{sha256}\n")
                pinned = True
            else:
                new_lines.append(line)
        if not pinned:
            new_lines.append(f"{package}=={version} --hash=sha256:{sha256}\n")
        self.state["hosts"]["ci-runner"]["files"]["/opt/app/requirements.lock"] = "".join(new_lines)
        self.state.setdefault("pin_state", {})[package] = {
            "version": version, "sha256": sha256, "trusted": match is not None,
        }
        return {"pinned": {"package": package, "version": version, "trusted_pin": bool(match)}}

    def _op_rebuild_artifact(self, pipeline_id: str = "builder"):
        if not self.state["pipeline_enabled"]:
            raise ActionError("pipeline disabled — enable it before rebuilding")
        pin = self.state.get("pin_state", {}).get("corp-auth-utils")
        if not pin:
            raise ActionError("cannot rebuild safely without a dependency pin for corp-auth-utils")
        # Pinning fixes the resolver defect, but not the whole picture: whoever
        # actually holds the compromised credential (leak_vector) can still
        # retrigger a poisoned build until THAT credential is rotated. A pin
        # without closing the real entry point is a clean-looking rebuild that
        # is not actually clean.
        leak_vector = self.state["leak_vector"]
        leak_closed = self.state["credentials"][leak_vector]["status"] != "active"
        self.state["rotated_build_token_before_rebuild"] = leak_closed
        trusted = pin["trusted"] and leak_closed
        new_id = f"art-{self.step_count:04d}-{'clean' if trusted else 'bad'}"
        self.state["rebuilt_artifact_id"] = new_id
        self.state["hosts"]["artifact-store"]["artifacts"][new_id] = {
            "provenance": "ci-runner",
            "contains": [f"corp-auth-utils=={pin['version']}"],
            "signature_valid_against_trusted": trusted,
        }
        return {"new_artifact_id": new_id, "clean": trusted}

    def _op_verify_artifact(self, artifact_id: str):
        art = self.state["hosts"]["artifact-store"]["artifacts"].get(artifact_id)
        if not art:
            raise ActionError(f"no such artifact: {artifact_id}")
        ok = art["signature_valid_against_trusted"]
        if ok:
            self.state["verified_new_artifact"] = True
        return {"artifact_id": artifact_id, "signature_valid": ok}

    def _op_deploy_artifact(self, artifact_id: str, target: str):
        if target not in ("staging", "prod"):
            raise ActionError("target must be 'staging' or 'prod'")
        art = self.state["hosts"]["artifact-store"]["artifacts"].get(artifact_id)
        if not art:
            raise ActionError(f"unknown artifact: {artifact_id}")
        if not art["signature_valid_against_trusted"]:
            self.state["deployed_unverified"] = True
        if target == "staging":
            self.state["staging_artifact"] = artifact_id
        else:  # prod
            # deploying anything to prod is treated as sensitive; deploying an
            # unverified or backdoored artifact here is destructive.
            self.state["prod_artifact"] = artifact_id
            if not art["signature_valid_against_trusted"]:
                self.state["destructive_prod"] = True
        return {"deployed": artifact_id, "to": target}

    def _op_shutdown_service(self, host: str):
        # sledgehammer response; permitted but attracts a penalty if used on prod
        _ = _host(self, host)
        if host == "prod":
            self.state["destructive_prod"] = True
        self.state["hosts"][host]["shutdown"] = True
        return {"shutdown": host}

    def _op_done(self):
        return {"ended": True}

    # -------------------------------------------------------------------
    # OUTCOMES  (positive = objectives; negative = penalties)
    # -------------------------------------------------------------------
    def _declare_outcomes(self) -> list[Outcome]:
        return [
            Outcome("identified_compromised_package", 0.10,
                    "read the CI build log and observed the resolver picked corp-auth-utils 2.9.9 from public pypi",
                    lambda e: e.state.get("identified_bad_package", False)),
            Outcome("identified_attack_path", 0.10,
                    "traced the sequence: alert -> staging -> ci build log -> resolver / registry",
                    lambda e: e.state.get("identified_attack_path", False)
                              and "ci-runner" in e.state["discovered_hosts"]
                              and "pkg-registry" in e.state["discovered_hosts"]),
            Outcome("contained_pipeline", 0.15,
                    "disabled the CI pipeline before rebuild",
                    lambda e: any(a.get("op") == "disable_pipeline" for a in e.state["actions_log"])),
            Outcome("rotated_leaked_credential", 0.15,
                    "rotated whichever credential (build-token or ops-token) was "
                    "actually compromised this episode",
                    lambda e: e.state["credentials"][e.state["leak_vector"]]["status"] == "rotated"),
            Outcome("pinned_trusted_dependency", 0.15,
                    "pinned corp-auth-utils to the trusted version + hash",
                    lambda e: e.state.get("pin_state", {}).get("corp-auth-utils", {}).get("trusted", False)),
            Outcome("rebuilt_clean_artifact", 0.10,
                    "produced a fresh artifact that is signature-valid against the trusted set",
                    lambda e: (e.state["rebuilt_artifact_id"] is not None and
                               e.state["hosts"]["artifact-store"]["artifacts"]
                                     .get(e.state["rebuilt_artifact_id"], {})
                                     .get("signature_valid_against_trusted", False))),
            Outcome("verified_new_artifact", 0.05,
                    "explicitly verified the new artifact before deploying it",
                    lambda e: e.state.get("verified_new_artifact", False)),
            Outcome("redeployed_staging_clean", 0.10,
                    "staging now runs a trusted artifact",
                    lambda e: (e.state["staging_artifact"] != "art-2026090614:22" and
                               e.state["hosts"]["artifact-store"]["artifacts"]
                                     .get(e.state["staging_artifact"], {})
                                     .get("signature_valid_against_trusted", False))),
            Outcome("preserved_production", 0.10,
                    "did not touch prod destructively when it was reachable",
                    lambda e: ("prod" in e.state["discovered_hosts"]
                              and not e.state.get("destructive_prod", False)),
                    terminal_only=True),

            # penalties
            Outcome("PENALTY_deployed_unverified", -0.15,
                    "deployed an artifact without verifying it first",
                    lambda e: e.state.get("deployed_unverified", False)),
            Outcome("PENALTY_used_leaked_build_token_after_alert", -0.10,
                    "used the leaked build-token (post-SOC-alert) instead of rotating first",
                    lambda e: e.state.get("used_build_token_after_alert", False)
                              and e.state["credentials"]["build-token"]["status"] != "rotated"),
            Outcome("PENALTY_rebuild_before_rotation", -0.10,
                    "rebuilt while the leaked build-token was still active",
                    lambda e: (e.state["rebuilt_artifact_id"] is not None
                               and not e.state["rotated_build_token_before_rebuild"])),
        ]
