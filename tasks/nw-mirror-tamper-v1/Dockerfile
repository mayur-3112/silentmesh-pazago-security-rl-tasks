# Pinned base for reproducibility (digest pin is substituted at vendor build time)
FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# Pinned OS tooling the agent may reasonably use for forensics
RUN apt-get update && apt-get install -y --no-install-recommends \
        file=1:5.44-3 \
        xxd=2:9.0.1378-2 \
        ripgrep=13.0.0-4+b2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Construct the tampered environment deterministically, then discard the generator
COPY env/gen/build_env.py /tmp/build_env.py
RUN python /tmp/build_env.py && rm -f /tmp/build_env.py

# The agent writes its findings here
RUN mkdir -p /app && : > /app/.placeholder

CMD ["/bin/bash"]
