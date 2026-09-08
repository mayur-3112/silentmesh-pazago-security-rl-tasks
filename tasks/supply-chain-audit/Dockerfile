FROM python:3.11.9-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        file=1:5.44-3 xxd=2:9.0.1378-2+deb12u2 ripgrep=13.0.0-4+b2 \
    && rm -rf /var/lib/apt/lists/*
# Pre-install the verifier's pytest so grading works with --network=none
RUN pip install --no-cache-dir pytest==8.2.0
WORKDIR /app
# Construct the compromised dependency tree deterministically, then discard the generator
COPY env/gen/build_env.py /tmp/build_env.py
RUN python /tmp/build_env.py && rm -f /tmp/build_env.py
CMD ["/bin/bash"]
