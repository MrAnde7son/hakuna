import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger(__name__)


def batch_hosts(hosts: list, batch_size: int) -> list[list]:
    """Split a host list into batches of at most batch_size."""
    if batch_size <= 0 or len(hosts) <= batch_size:
        return [hosts] if hosts else []
    return [hosts[i:i + batch_size] for i in range(0, len(hosts), batch_size)]


async def run_batches_parallel(
    build_runner,
    batches: list,
    org_id: str | None,
    concurrency: int,
    stage_name: str = "",
) -> list:
    """Run a batch of runner invocations in parallel, bounded by concurrency.

    build_runner(batch) -> BaseRunner-like instance with an async .run() method.
    Returns a flat list of all result dicts from every batch (ignores failed batches).
    """
    if not batches:
        return []

    sem = asyncio.Semaphore(max(1, concurrency))
    total = len(batches)

    async def _run_one(idx: int, batch):
        async with sem:
            runner = build_runner(batch)
            result = await runner.run(org_id=org_id)
            logger.info(
                "stage=%s org=%s batch=%d/%d size=%d results=%d duration=%.1fs",
                stage_name, org_id, idx, total, len(batch),
                len(result.results), result.duration_seconds,
            )
            return result.results

    tasks = [_run_one(i + 1, b) for i, b in enumerate(batches)]
    results_per_batch = await asyncio.gather(*tasks, return_exceptions=True)

    flat: list = []
    for r in results_per_batch:
        if isinstance(r, Exception):
            logger.error("stage=%s org=%s batch failed: %s", stage_name, org_id, r)
            continue
        flat.extend(r)
    return flat


@dataclass
class RunResult:
    tool: str
    exit_code: int
    results: list[dict] = field(default_factory=list)
    stderr: str = ""
    duration_seconds: float = 0.0
    retries: int = 0


@dataclass
class BatchOutcome:
    """Per-batch outcome for callers that need to distinguish 'scanned with
    no results' from 'scan failed'. Yielded by run_batches_parallel_with_outcomes.
    """
    batch_input: list
    success: bool
    results: list[dict] = field(default_factory=list)
    error: str = ""


async def run_batches_parallel_with_outcomes(
    build_runner,
    batches: list,
    org_id: str | None,
    concurrency: int,
    stage_name: str = "",
) -> list[BatchOutcome]:
    """Like run_batches_parallel but preserves per-batch outcome.

    Returns one BatchOutcome per input batch. ``success=False`` when the
    runner raised, timed out, or exited non-zero. Use this when callers
    need to mark hosts in a failed batch differently from hosts that were
    scanned but produced no findings.
    """
    if not batches:
        return []

    sem = asyncio.Semaphore(max(1, concurrency))
    total = len(batches)

    async def _run_one(idx: int, batch) -> BatchOutcome:
        async with sem:
            try:
                runner = build_runner(batch)
                result = await runner.run(org_id=org_id)
            except Exception as e:
                logger.error("stage=%s org=%s batch=%d/%d crashed: %s",
                             stage_name, org_id, idx, total, e)
                return BatchOutcome(batch_input=batch, success=False, error=str(e))

            success = result.exit_code == 0
            logger.info(
                "stage=%s org=%s batch=%d/%d size=%d results=%d duration=%.1fs success=%s",
                stage_name, org_id, idx, total, len(batch),
                len(result.results), result.duration_seconds, success,
            )
            return BatchOutcome(
                batch_input=batch,
                success=success,
                results=result.results,
                error="" if success else (result.stderr[:500] or f"exit={result.exit_code}"),
            )

    tasks = [_run_one(i + 1, b) for i, b in enumerate(batches)]
    outcomes = await asyncio.gather(*tasks, return_exceptions=False)
    return list(outcomes)


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
    # If set (bytes), piped to subprocess stdin. Default behavior remains
    # DEVNULL so existing runners are unaffected.
    stdin_input: bytes | None = None

    def build_command(self) -> list[str]:
        raise NotImplementedError

    def _get_timeout(self) -> int:
        return self.timeout or settings.scan_timeout_seconds

    @staticmethod
    def timeout_for_host_count(host_count: int, per_host_seconds: float = 0.5) -> int:
        """Scale timeout based on host count. Returns at least the default."""
        base = settings.scan_timeout_seconds
        scaled = int(host_count * per_host_seconds)
        return max(base, scaled)

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
                break  # Don't retry on timeout — external tool is likely unreachable

            if attempt < self.max_retries:
                wait = 2 ** (attempt + 1)
                logger.info("tool=%s retrying in %ds (attempt %d/%d)", self.tool_name, wait, attempt + 2, self.max_retries + 1)
                await asyncio.sleep(wait)

        return last_result

    async def _execute(self, cmd: list[str]) -> RunResult:
        use_stdin = self.stdin_input is not None
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if use_stdin else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024,  # 1MB line buffer (httpx can emit long JSON lines)
        )

        results: list[dict] = []
        stderr_chunks: list[str] = []

        async def write_stdin():
            if not use_stdin or proc.stdin is None:
                return
            try:
                proc.stdin.write(self.stdin_input)  # type: ignore[arg-type]
                await proc.stdin.drain()
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

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
                asyncio.gather(write_stdin(), read_stdout(), read_stderr(), proc.wait()),
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
