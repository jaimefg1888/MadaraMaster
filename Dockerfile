# ────────────────────────────────────────────────────────────────
# MadaraMaster — Dockerfile
# Optimized container for secure file sanitization
# ────────────────────────────────────────────────────────────────
FROM python:3.9-slim AS base

LABEL maintainer="MadaraMaster Team"
LABEL description="MadaraMaster — DoD 5220.22-M Secure File Sanitization"
LABEL version="2.1.0"

# Security: non-root user
RUN groupadd --gid 1000 madara \
    && useradd --uid 1000 --gid madara --shell /bin/bash --create-home madara

WORKDIR /app

# Install dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application
COPY wiper.py madara.py ./

# Workspace for files to sanitize
RUN mkdir -p /data && chown madara:madara /data

USER madara

ENTRYPOINT ["python", "/app/madara.py"]
CMD ["--help"]
