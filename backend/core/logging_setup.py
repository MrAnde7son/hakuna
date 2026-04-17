"""Structured JSON logging for Cloud Logging / Sentry ingestion.

Called once at process start from app.py. Respects LOG_LEVEL and falls back
to the unstructured human formatter when LOG_FORMAT=text (useful in dev).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

# Fields we consider sensitive and redact from any log record's extra dict.
# Keeping this conservative — scrubs by key name, so payloads with these keys
# in JSON dicts logged as extras will be sanitised before shipping.
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "cookie", "set-cookie", "jwt", "access_token",
    "refresh_token", "client_secret", "stripe_secret_key",
    "integration_secret_key", "jwt_secret",
}

# Standard LogRecord attributes we skip when copying "extras".
_STD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}


def _redact(value):
    """Recursively redact sensitive keys from dicts/lists embedded in extras."""
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """One JSON object per line — Cloud Logging parses this natively."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Cloud Run / GCP expects `severity` for log routing.
        payload["severity"] = record.levelname

        # Pull through any extra=... fields but drop sensitive ones.
        for key, value in record.__dict__.items():
            if key in _STD_ATTRS or key.startswith("_"):
                continue
            if key.lower() in _SENSITIVE_KEYS:
                payload[key] = "[REDACTED]"
            else:
                try:
                    json.dumps(value)
                    payload[key] = _redact(value)
                except (TypeError, ValueError):
                    payload[key] = repr(value)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Install the JSON handler as the root logger's only handler.

    LOG_FORMAT=text keeps the default human formatter — useful for local dev.
    LOG_LEVEL defaults to INFO.
    """
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("LOG_FORMAT", "json").lower()

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s - %(message)s"
        ))
    root.addHandler(handler)

    # Quiet some chatty libraries — they re-emit per-request noise.
    for noisy in ("uvicorn.access", "sqlalchemy.engine.Engine"):
        logging.getLogger(noisy).setLevel(
            os.environ.get(f"LOG_LEVEL_{noisy.upper().replace('.', '_')}", "WARNING")
        )
