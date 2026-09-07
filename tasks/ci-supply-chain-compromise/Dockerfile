# Pinned base for reproducibility
FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/gym \
    GYM_STATE_FILE=/app/state.json \
    DEBIAN_FRONTEND=noninteractive

# Realistic shell tooling the agent may reasonably reach for
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash-completion=1:2.11-6 \
        coreutils=9.1-1 \
        less=590-2.1~deb12u2 \
        procps=2:4.0.2-3 \
        jq=1.6-2.1 \
        openssh-client=1:9.2p1-2+deb12u3 \
    && rm -rf /var/lib/apt/lists/*

# Task materials
WORKDIR /gym
COPY env/ /gym/env/
COPY tasks/ci-supply-chain-compromise/scenario.py \
     tasks/ci-supply-chain-compromise/oracle.py \
     tasks/ci-supply-chain-compromise/adversarial.py \
     tasks/ci-supply-chain-compromise/gym.py \
     /gym/

# Agent shell working directory + README
RUN mkdir -p /app && chmod +x /gym/gym.py \
    && ln -sf /gym/gym.py /usr/local/bin/gym
COPY tasks/ci-supply-chain-compromise/AGENT.md /app/README.md

WORKDIR /app
CMD ["/bin/bash"]
