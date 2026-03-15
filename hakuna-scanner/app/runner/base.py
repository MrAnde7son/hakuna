import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class RunResult:
    tool: str
    exit_code: int
    results: list[dict] = field(default_factory=list)
    stderr: str = ""
    duration_seconds: float = 0.0
    retries: int = 0


class BaseRunner:
    """Async subprocess wrapper for ProjectDiscovery tools.

    Features:
    - Streams stdout line-by-line, parses JSONL
    - Configurable timeout (default from SCAN_TIMEOUT_SECONDS)
    - Retries on non-zero exit (max 2, exponential backoff)
    - Captures stderr for error logging
    """

    tool_name: str = ""
    max_retries: int = 2
    timeout: int | None = None

    def build_command(self) -> list[str]:
        raise NotImplementedError

    def _get_timeout(self) -> int:
        return self.timeout or settings.scan_timeout_seconds

    async def run(self, org_id: str | None = None) -> RunResult:
        cmd = self.build_command()
        last_result = RunResult(tool=self.tool_name, exit_code=-1)

        for attempt in range(1 + self.max_retries):
            start = time.monotonic()
            try:
                result = await self._execute(cmd)
                result.retries = attempt
                result.duration_seconds = time.monotonic() - start

                logger.info(
                    "tool=%s org=%s exit=%d results=%d duration=%.1fs attempt=%d",
                    self.tool_name, org_id, result.exit_code,
                    len(result.results), result.duration_seconds, attempt + 1,
                )

                if result.exit_code == 0:
                    return result

                last_result = result
                if result.stderr:
                    logger.warning("tool=%s stderr: %s", self.tool_name, result.stderr[:500])

            except asyncio.TimeoutError:
                last_result = RunResult(
                    tool=self.tool_name, exit_code=-1,
                    stderr=f"Timeout after {self._get_timeout()}s",
                    duration_seconds=time.monotonic() - start, retries=attempt,
                )
                logger.error("tool=%s org=%s timed out after %ds", self.tool_name, org_id, self._get_timeout())

            if attempt < self.max_retries:
                wait = 2 ** (attempt + 1)
                logger.info("tool=%s retrying in %ds (attempt %d/%d)", self.tool_name, wait, attempt + 2, self.max_retries + 1)
                await asyncio.sleep(wait)

        return last_result

    async def _execute(self, cmd: list[str]) -> RunResult:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        results: list[dict] = []
        stderr_chunks: list[str] = []

        async def read_stdout():
            assert proc.stdout is not None
            async for line in proc.stdout:
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    results.append(json.loads(text))
                except json.JSONDecodeError:
                    logger.debug("tool=%s non-json line: %s", self.tool_name, text[:200])

        async def read_stderr():
            assert proc.stderr is not None
            async for line in proc.stderr:
                stderr_chunks.append(line.decode("utf-8", errors="replace").strip())

        try:
            await asyncio.wait_for(
                asyncio.gather(read_stdout(), read_stderr(), proc.wait()),
                timeout=self._get_timeout(),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        return RunResult(
            tool=self.tool_name,
            exit_code=proc.returncode or 0,
            results=results,
            stderr="\n".join(stderr_chunks),
        )
