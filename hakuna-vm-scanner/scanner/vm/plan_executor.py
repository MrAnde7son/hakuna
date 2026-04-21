"""Build Nuclei commands from a precomputed adaptive scan plan.

The plan is produced by backend services/scan_planner.compute_and_persist_scan_plan
and shipped to the worker via the Celery task arg. Each plan is a dict:

    {
        "asset_id": int,
        "asset_hostname": str,
        "risk_tier": "critical|high|medium|low",
        "actions": [
            {
                "tool": "nuclei|nmap|katana|testssl|nikto",
                "priority": int,
                "tags": [str, ...],
                "templates": [str, ...],
                "flags": dict,           # e.g. {"target_list": [...]} | {"profile": "graphql"}
                "timeout": int,
                "reasoning": str,
            },
            ...
        ],
        "skip_reason": str | None,
        "reasoning": str,
        ...
    }

This module owns the nuclei action subset of that plan. Other tools (nmap,
katana, testssl, nikto) are invoked elsewhere when their workers exist; for
now we silently skip non-nuclei actions and let the legacy router cover
template selection for them.

Backwards-compatible behavior:
  - When the plan is None or has no nuclei actions, callers must fall back
    to the legacy router (signaled by raising ScanPlanInvalidError).
  - When per-endpoint targeting is requested via flags.target_list, the
    target list is filtered to same-origin URLs (so credential headers
    aren't leaked to third-party CDN URLs that crawler enrichment may
    have surfaced) and capped at NUCLEI_MAX_TARGETS_PER_ASSET.
"""
from __future__ import annotations

import logging
import os
import tempfile
from urllib.parse import urlparse

from scanner.vm.config import (
    NUCLEI_BULK_CONCURRENCY,
    NUCLEI_CONCURRENCY,
    NUCLEI_EXCLUDE_TAGS,
    NUCLEI_MAX_TARGETS_PER_ASSET,
    NUCLEI_RETRIES,
)

logger = logging.getLogger(__name__)


class ScanPlanInvalidError(Exception):
    """Raised when a plan cannot be translated into a runnable Nuclei command.

    Caller (nuclei_worker) catches this and falls back to the legacy
    TemplateRouter — a malformed plan must never crash a scan.
    """


def extract_nuclei_actions(plan: dict) -> list[dict]:
    """Return the nuclei actions from a plan, sorted by priority ascending.

    Empty list when the plan has no nuclei action — the caller must then
    fall back to the legacy router or the plan would silently no-op.
    """
    actions = plan.get("actions") or []
    nuclei_actions = [a for a in actions if (a.get("tool") or "").lower() == "nuclei"]
    nuclei_actions.sort(key=lambda a: a.get("priority", 5))
    return nuclei_actions


def filter_same_origin_targets(target_list: list[str], host_target: str) -> list[str]:
    """Drop URLs whose hostname differs from the asset's hostname.

    Crawler-discovered endpoints frequently include third-party origins
    (CDNs, analytics, OAuth providers). Sending credentialed requests to
    those URLs is a credential-leak vector and noise in the scan.

    Comparison is hostname-only (case-insensitive); paths are preserved.
    Hostnames that fail to parse are dropped.
    """
    asset_host = _hostname(host_target)
    if not asset_host:
        # Nothing to compare against — return the list unchanged so that
        # plain hostname/IP targets (no http_url) still benefit from
        # per-endpoint targeting.
        return list(target_list)

    same_origin: list[str] = []
    for url in target_list:
        url_host = _hostname(url)
        if not url_host:
            continue
        if url_host == asset_host:
            same_origin.append(url)
    return same_origin


def _hostname(value: str) -> str:
    """Lowercased hostname from a URL or bare hostname/IP."""
    if not value:
        return ""
    try:
        if "://" in value:
            return (urlparse(value).hostname or "").lower()
        # Bare hostname or IP — strip port if present.
        return value.split(":", 1)[0].strip().lower()
    except Exception:
        return ""


def build_nuclei_commands_from_plan(
    plan: dict,
    target: str,
    nuclei_bin: str,
    cred_args: list[str],
    nuclei_timeout: int,
    rate_limit: int,
    target_list_dir: str | None = None,
) -> list[dict]:
    """Translate a plan into a list of nuclei commands.

    Returns a list of ``{"cmd": list[str], "tempfiles": list[str], "action": dict}``
    so the caller can run each command in sequence and clean up tmpfiles.
    Each plan action becomes (at most) one command; actions without enough
    information are skipped with a warning rather than failing the whole scan.

    Raises ScanPlanInvalidError when the plan has no usable nuclei action —
    that's the signal for the worker to fall back to the legacy router.
    """
    if plan is None:
        raise ScanPlanInvalidError("plan is None")

    if plan.get("skip_reason"):
        # Planner explicitly recommended skipping — represented as a no-op
        # command list. Worker should record skip_reason in result payload.
        return []

    nuclei_actions = extract_nuclei_actions(plan)
    if not nuclei_actions:
        raise ScanPlanInvalidError("plan has no nuclei actions")

    commands: list[dict] = []
    for action in nuclei_actions:
        try:
            built = _build_single_command(
                action=action,
                target=target,
                nuclei_bin=nuclei_bin,
                cred_args=cred_args,
                default_timeout=nuclei_timeout,
                rate_limit=rate_limit,
                target_list_dir=target_list_dir,
            )
        except ScanPlanInvalidError as e:
            # Per-action invalidity is non-fatal — log and continue. The
            # remaining actions still get to run.
            logger.warning("Skipping plan action %r: %s", action.get("reasoning", ""), e)
            continue
        if built:
            commands.append(built)

    if not commands:
        raise ScanPlanInvalidError("plan produced no runnable commands")

    return commands


def _build_single_command(
    action: dict,
    target: str,
    nuclei_bin: str,
    cred_args: list[str],
    default_timeout: int,
    rate_limit: int,
    target_list_dir: str | None,
) -> dict | None:
    """Compose one nuclei invocation from a single ScanAction dict."""
    flags = action.get("flags") or {}
    tags = list(action.get("tags") or [])
    templates = list(action.get("templates") or [])
    profile = (flags.get("profile") or "").lower()
    timeout = int(action.get("timeout") or default_timeout)

    cmd: list[str] = [nuclei_bin]
    tempfiles: list[str] = []

    # Per-endpoint targeting: write the (filtered, capped) URL list to a
    # tmpfile and use -list. Keep the file under target_list_dir so callers
    # can clean up an entire directory if they want; default to the OS tmp.
    target_list = flags.get("target_list") or []
    if target_list:
        if not isinstance(target_list, list):
            raise ScanPlanInvalidError("flags.target_list must be a list")
        same_origin = filter_same_origin_targets(target_list, target)
        if not same_origin:
            # All URLs were cross-origin — fall back to host targeting so
            # we still scan something meaningful for this asset.
            cmd.extend(["-target", target])
        else:
            capped = same_origin[:NUCLEI_MAX_TARGETS_PER_ASSET]
            tmp_path = _write_target_list(capped, target_list_dir)
            tempfiles.append(tmp_path)
            cmd.extend(["-list", tmp_path])
    else:
        cmd.extend(["-target", target])

    # GraphQL profile: ensure tags include 'graphql' and JSON content type.
    if profile == "graphql":
        if "graphql" not in tags:
            tags.append("graphql")
        # Cred args may already include Content-Type from auth headers;
        # adding another -H is harmless (Nuclei takes the last one).
        cmd.extend(["-H", "Content-Type: application/json"])

    if tags:
        cmd.extend(["-tags", ",".join(sorted(set(tags)))])

    for tpath in templates:
        cmd.extend(["-t", tpath])

    if not tags and not templates:
        # Nothing for nuclei to load. Per-endpoint scans are still valid
        # without explicit tags (Nuclei picks defaults for the URL), but
        # at minimum we should ask for the generic exposure suite to
        # avoid an empty run.
        cmd.extend(["-tags", "generic,exposure"])

    cmd.extend(cred_args)
    cmd.extend([
        "-jsonl",
        "-timeout", str(timeout),
        "-rate-limit", str(rate_limit),
        "-c", str(NUCLEI_CONCURRENCY),
        "-bc", str(NUCLEI_BULK_CONCURRENCY),
        "-retries", str(NUCLEI_RETRIES),
        "-no-color",
        "-stats",
    ])
    if NUCLEI_EXCLUDE_TAGS.strip():
        cmd.extend(["-etags", NUCLEI_EXCLUDE_TAGS])

    return {"cmd": cmd, "tempfiles": tempfiles, "action": action}


def _write_target_list(urls: list[str], target_list_dir: str | None) -> str:
    """Write URLs (one per line) to a tmpfile and return its path."""
    fd, path = tempfile.mkstemp(
        prefix="nuclei-targets-",
        suffix=".txt",
        dir=target_list_dir,
    )
    try:
        with os.fdopen(fd, "w") as f:
            for u in urls:
                f.write(u.strip() + "\n")
    except Exception:
        # Make a best-effort cleanup if we crashed mid-write.
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def cleanup_tempfiles(paths: list[str]) -> None:
    """Best-effort tmpfile cleanup — never raises."""
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass
