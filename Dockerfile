FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AEGIS_DB_PATH=/data/aegis.db \
    AEGIS_LOG_DIR=/var/log/aegis \
    AEGIS_RUNBOOK_DIR=/app/runbooks

WORKDIR /app
COPY pyproject.toml .
COPY aegis ./aegis
COPY runbooks ./runbooks

# Runtime dependencies only (no dev extras). The service runs as an unprivileged user
# that owns just the two writable locations: the database and the log directory.
RUN pip install . \
    && rm -rf build ./*.egg-info \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin aegis \
    && mkdir -p /data /var/log/aegis \
    && chown aegis:aegis /data /var/log/aegis

USER aegis
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, httpx; httpx.get('http://127.0.0.1:%s/healthz' % os.getenv('PORT', '8000')).raise_for_status()"]

CMD ["python", "-m", "aegis.control_main"]
