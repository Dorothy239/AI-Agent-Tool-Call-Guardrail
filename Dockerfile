# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install .

# The default policy is baked in read-only. Mount your own over this path to change it.
COPY policy.yaml /etc/guardrail/policy.yaml

# Run as an unprivileged user; only the log directory is writable.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin guardrail \
    && mkdir -p /var/log/guardrail \
    && chown guardrail:guardrail /var/log/guardrail \
    && chmod 0444 /etc/guardrail/policy.yaml

ENV GUARDRAIL_POLICY_PATH=/etc/guardrail/policy.yaml \
    GUARDRAIL_AUDIT_LOG=/var/log/guardrail/audit.jsonl
# GUARDRAIL_API_KEY is deliberately NOT set here: the service refuses to start without it.

USER guardrail
VOLUME ["/var/log/guardrail"]
EXPOSE 8000

# /healthz returns 503 when the policy failed to load, which marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

CMD ["uvicorn", "guardrail.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
