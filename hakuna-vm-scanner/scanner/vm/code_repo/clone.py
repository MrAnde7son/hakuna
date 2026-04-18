"""Shallow-clone helper for repo scanning.

Uses `git clone --depth 1 --filter=blob:none` to minimize disk + bandwidth.
The full tree is present on disk (TruffleHog needs that), but the history
graph is truncated.

Cleanup is the caller's responsibility via the context manager.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import tempfile
from typing import AsyncIterator

logger = logging.getLogger(__name__)


class CloneError(Exception):
    pass


@contextlib.asynccontextmanager
async def shallow_clone(
    clone_url: str,
    *,
    branch: str | None = None,
    token: str | None = None,
    timeout_seconds: int = 180,
) -> AsyncIterator[str]:
    """Shallow-clone a repo into a tmpdir. Yields the path, then cleans up.

    Honors GITHUB_TOKEN (or caller-supplied token) for private repos via
    the credentials-in-URL form — which we never log.
    """
    tmpdir = tempfile.mkdtemp(prefix="hakuna_repo_")
    url = clone_url
    token = token or os.environ.get("GITHUB_TOKEN")
    if token and "github.com" in clone_url and "@" not in clone_url:
        # Inject token for HTTPS clone. We pass via URL so `git` doesn't prompt.
        url = clone_url.replace("https://", f"https://x-access-token:{token}@", 1)

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--filter=blob:none",
        "--no-tags",
        "--single-branch",
    ]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, tmpdir])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise CloneError(f"clone timed out after {timeout_seconds}s")

        if proc.returncode != 0:
            # Scrub the token out of any error output before surfacing it.
            err = stderr.decode("utf-8", errors="replace")
            if token:
                err = err.replace(token, "***")
            raise CloneError(f"git clone failed (exit {proc.returncode}): {err[:400]}")

        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
