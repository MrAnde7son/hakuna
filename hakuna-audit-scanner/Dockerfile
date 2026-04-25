FROM python:3.11-slim

LABEL org.opencontainers.image.title="Hakuna Audit Scanner"
LABEL org.opencontainers.image.description="Credentialed protocol-audit ReAct agent (SSH/WMI/LDAP/SMB/SNMP) — open-source extraction of Hakuna's audit pipeline."

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scanner/ /app/scanner/
COPY templates/ /app/templates/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TEMPLATES_DIR=/app/templates

EXPOSE 8001

# Default entrypoint runs the API. Celery worker is started via
# docker-compose with `celery -A scanner.audit.celery_app worker`.
CMD ["uvicorn", "scanner.audit.api:app", "--host", "0.0.0.0", "--port", "8001"]
