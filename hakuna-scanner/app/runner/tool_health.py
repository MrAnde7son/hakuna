"""Worker startup health check for external tool dependencies.

Pipeline A depends on a stack of binaries from ProjectDiscovery + nmap +
puredns/massdns. The previous failure mode was that any one of these going
missing produced silent degradation: discovery would skip the affected
stage, scans would fail with empty error fields, and nobody noticed for
weeks.

This module runs at celery worker boot via the ``worker_ready`` signal,
checks every required tool with ``shutil.which``, and:

  * logs a warning per missing tool with the exact name of the broken stage
  * captures a Sentry event (if SENTRY_DSN is configured) with the full list

Workers do **not** refuse to boot when tools are missing — degraded
operation is better than no operation. The point is making the failure
visible.

Add a tool to the matrix when you add a new runner. Keep the list in sync
with the runners in ``app/runner/tools.py``.
"""

import logging
import os
import shutil
from dataclasses import dataclass

from celery.signals import worker_ready

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    binary: str
    stage: str            # which Pipeline A stage breaks if missing
    required: bool        # if False, degradation is acceptable (e.g. screenshots)


# Keep ordered roughly by pipeline stage so the warning log reads top-to-bottom.
REQUIRED_TOOLS: tuple[ToolSpec, ...] = (
    # Discovery
    ToolSpec("subfinder",  "discovery.subfinder",     required=True),
    ToolSpec("puredns",    "discovery.bruteforce",    required=True),
    ToolSpec("massdns",    "discovery.bruteforce",    required=True),
    ToolSpec("asnmap",     "discovery.asnmap",        required=False),
    ToolSpec("uncover",    "discovery.uncover",       required=False),
    ToolSpec("dnsx",       "discovery.dnsx",          required=True),
    ToolSpec("naabu",      "discovery.naabu",         required=True),
    # Enrichment
    ToolSpec("tlsx",       "enrichment.tlsx",         required=True),
    ToolSpec("httpx",      "enrichment.httpx",        required=True),
    ToolSpec("cdncheck",   "enrichment.cdncheck",     required=False),
    ToolSpec("katana",     "enrichment.katana",       required=False),
    ToolSpec("kr",         "enrichment.kiterunner",   required=False),
    ToolSpec("nmap",       "enrichment.nmap",         required=True),
)

# Wordlists / data files that puredns + Pipeline A need at runtime. These were
# the cause of half a day of debugging when /app/wordlists/ got shadowed by a
# bind mount — adding them here so the next breakage is loud.
REQUIRED_FILES: tuple[tuple[str, str], ...] = (
    ("/opt/hakuna/wordlists/subdomains.txt", "discovery.bruteforce wordlist"),
    ("/opt/hakuna/wordlists/resolvers.txt",  "discovery.bruteforce resolvers"),
)

# Optional data files — logged as a warning when missing, not treated as a
# required failure. Pair with the matching ToolSpec(required=False).
OPTIONAL_FILES: tuple[tuple[str, str], ...] = (
    ("/opt/hakuna/wordlists/kiterunner-routes.kite", "enrichment.kiterunner wordlist"),
)


def check_tools() -> tuple[list[str], list[str]]:
    """Return ``(missing_required, missing_optional)`` lists of human-readable strings."""
    missing_required: list[str] = []
    missing_optional: list[str] = []

    for tool in REQUIRED_TOOLS:
        if shutil.which(tool.binary) is None:
            label = f"{tool.binary} (stage: {tool.stage})"
            (missing_required if tool.required else missing_optional).append(label)

    for path, label in REQUIRED_FILES:
        if not os.path.isfile(path):
            missing_required.append(f"{path} ({label})")

    for path, label in OPTIONAL_FILES:
        if not os.path.isfile(path):
            missing_optional.append(f"{path} ({label})")

    return missing_required, missing_optional


def _capture_sentry(missing_required: list[str], missing_optional: list[str]) -> None:
    """Best-effort Sentry capture. Silently no-ops if sentry-sdk isn't installed."""
    try:
        import sentry_sdk  # type: ignore
    except ImportError:
        return
    if not os.environ.get("SENTRY_DSN"):
        return
    sentry_sdk.capture_message(
        f"Worker boot: {len(missing_required)} required tool(s) missing",
        level="error" if missing_required else "warning",
        extras={
            "missing_required": missing_required,
            "missing_optional": missing_optional,
        },
    )


@worker_ready.connect
def _on_worker_ready(sender=None, **_kwargs) -> None:
    missing_required, missing_optional = check_tools()

    if not missing_required and not missing_optional:
        logger.info("Tool health check: all %d Pipeline A tools present", len(REQUIRED_TOOLS))
        return

    if missing_required:
        logger.error(
            "Tool health check: %d REQUIRED tool(s) MISSING — Pipeline A is degraded. "
            "Missing: %s",
            len(missing_required), ", ".join(missing_required),
        )
    if missing_optional:
        logger.warning(
            "Tool health check: %d optional tool(s) missing: %s",
            len(missing_optional), ", ".join(missing_optional),
        )

    _capture_sentry(missing_required, missing_optional)
