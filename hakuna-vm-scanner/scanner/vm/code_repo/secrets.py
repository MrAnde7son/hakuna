"""TruffleHog wrapper — runs on a locally-cloned repo.

TruffleHog's `filesystem` mode with `--json` emits one JSON object per line.
We care about:
  - DetectorName (what kind of secret)
  - Verified (true when TruffleHog's verifier successfully authenticated)
  - Raw / Redacted (Redacted is safe to log; Raw is the secret itself — never logged)
  - SourceMetadata.Data.Filesystem.file (where it was found)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time

logger = logging.getLogger(__name__)

TRUFFLEHOG_BIN = os.environ.get("TRUFFLEHOG_BIN", "trufflehog")
TRUFFLEHOG_TIMEOUT = int(os.environ.get("TRUFFLEHOG_TIMEOUT_SECONDS", "600"))
TRUFFLEHOG_ONLY_VERIFIED = os.environ.get("TRUFFLEHOG_ONLY_VERIFIED", "false").lower() == "true"


def _redact(raw: str) -> str:
    if not raw:
        return ""
    if len(raw) <= 6:
        return "***"
    return raw[:4] + "*" * min(len(raw) - 4, 12)


async def scan_directory(path: str) -> dict:
    """Run TruffleHog filesystem mode against `path` and normalize output."""
    if not shutil.which(TRUFFLEHOG_BIN):
        return {
            "available": False,
            "findings": [],
            "error": f"{TRUFFLEHOG_BIN} not in PATH",
        }

    cmd = [
        TRUFFLEHOG_BIN, "filesystem", path,
        "--json",
        "--no-update",
    ]
    if TRUFFLEHOG_ONLY_VERIFIED:
        cmd.append("--only-verified")

    start = time.monotonic()
    findings: list[dict] = []
    stderr_chunks: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            limit=1024 * 1024,
        )
    except FileNotFoundError:
        return {"available": False, "findings": [], "error": "trufflehog binary missing"}

    async def drain_stderr():
        assert proc.stderr is not None
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            stderr_chunks.append(line.decode("utf-8", errors="replace").strip())

    stderr_task = asyncio.create_task(drain_stderr())

    try:
        assert proc.stdout is not None
        while True:
            raw_line = await proc.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = entry.get("DetectorName") or "Unknown"
            verified = bool(entry.get("Verified"))
            raw = entry.get("Raw") or ""
            redacted = entry.get("Redacted") or _redact(raw)

            source_ref = ""
            meta = entry.get("SourceMetadata") or {}
            data = meta.get("Data") or {}
            fs = data.get("Filesystem") or {}
            if isinstance(fs, dict):
                source_ref = fs.get("file") or ""
            if source_ref and path:
                # Make the path relative to the clone root for readability.
                try:
                    source_ref = os.path.relpath(source_ref, path)
                except ValueError:
                    pass

            findings.append({
                "detector": detector,
                "verified": verified,
                "redacted": redacted,
                "source_ref": source_ref,
                "extra_data": entry.get("ExtraData") or {},
            })

        await asyncio.wait_for(proc.wait(), timeout=TRUFFLEHOG_TIMEOUT)
        await stderr_task
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "available": True,
            "findings": findings,
            "duration_seconds": time.monotonic() - start,
            "error": f"trufflehog timed out after {TRUFFLEHOG_TIMEOUT}s",
            "status": "timeout",
        }

    return {
        "available": True,
        "findings": findings,
        "duration_seconds": round(time.monotonic() - start, 2),
        "stderr_tail": "\n".join(stderr_chunks[-20:])[:2000],
        "exit_code": proc.returncode,
        "status": "complete",
    }
