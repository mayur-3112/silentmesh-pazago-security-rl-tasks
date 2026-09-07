#!/usr/bin/env python3
"""Deterministically build the environment under /app (+ /opt/mirror if needed).
Embed any secret indicator via base64(xor(zlib(...))) so it is not greppable; for
extra strength randomize it per build and have the verifier re-derive it statically.
Delete nothing the agent needs; leave real functionality intact so remediation can
be verified. Ground truth documented in DOCUMENTATION.md (graders only).
"""
import os
os.makedirs("/app", exist_ok=True)
# TODO: construct the compromised artifact(s) and any clean reference copy.
print("built")
