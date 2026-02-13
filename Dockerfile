# ────────────────────────────────────────────────────────────────
# Neutron-Wipe — Dockerfile
# Optimized container for secure file sanitization
# ────────────────────────────────────────────────────────────────
FROM python:3.9-slim AS base

LABEL maintainer="Neutron Security Team"
LABEL description="Neutron-Wipe — DoD 5220.22-M Secure File Sanitization"
LABEL version="1.0.0"

# Security: non-root user
RUN groupadd --gid 1000 neutron \
    && useradd --uid 1000 --gid neutron --shell /bin/bash --create-home neutron

WORKDIR /app

# Install dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application
COPY wiper.py main.py ./

# Workspace for files to sanitize
RUN mkdir -p /data && chown neutron:neutron /data

USER neutron

ENTRYPOINT ["python", "/app/main.py"]
CMD ["--help"]
