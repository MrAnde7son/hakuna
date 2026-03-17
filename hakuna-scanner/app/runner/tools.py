import tempfile
import os

from app.config import settings
from app.runner.base import BaseRunner


class SubfinderRunner(BaseRunner):
    tool_name = "subfinder"

    def __init__(self, target_domain: str):
        self.target_domain = target_domain

    def build_command(self) -> list[str]:
        cmd = ["subfinder", "-d", self.target_domain, "-json", "-silent"]
        if settings.subfinder_sources and settings.subfinder_sources != "all":
            cmd.extend(["-sources", settings.subfinder_sources])
        return cmd


class DnsxRunner(BaseRunner):
    tool_name = "dnsx"

    def __init__(self, hosts: list[str]):
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="dnsx_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return ["dnsx", "-l", path, "-json", "-silent", "-a", "-cname", "-mx", "-txt"]

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)


class NaabuRunner(BaseRunner):
    tool_name = "naabu"

    def __init__(self, hosts: list[str], ports: str | None = None, timeout_seconds: int | None = None):
        self.hosts = hosts
        self.ports = ports
        self.custom_timeout = timeout_seconds
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="naabu_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        cmd = ["naabu", "-l", path, "-json", "-silent"]
        ports = self.ports or settings.naabu_ports
        cmd.extend(["-p", ports])
        if self.custom_timeout:
            cmd.extend(["--timeout", str(self.custom_timeout)])
        return cmd

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)


class HttpxRunner(BaseRunner):
    tool_name = "httpx"

    def __init__(self, hosts: list[str]):
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="httpx_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return [
            "httpx", "-l", path, "-json", "-silent",
            "-status-code", "-title", "-tech-detect",
            "-cdn", "-follow-redirects",
            "-content-length", "-web-server", "-method",
            "-location", "-ip",
        ]

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)


class TlsxRunner(BaseRunner):
    tool_name = "tlsx"

    def __init__(self, hosts: list[str]):
        """hosts can be hostname:port format to scan non-443 ports."""
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="tlsx_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return [
            "tlsx", "-l", path, "-json", "-silent",
            "-so", "-cipher", "-tls-version",
            "-san", "-expired",
        ]

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)


class CdncheckRunner(BaseRunner):
    tool_name = "cdncheck"

    def __init__(self, hosts: list[str]):
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="cdncheck_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return ["cdncheck", "-l", path, "-json", "-silent"]

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)


class AsnmapRunner(BaseRunner):
    tool_name = "asnmap"

    def __init__(self, org_name: str):
        self.org_name = org_name

    def build_command(self) -> list[str]:
        return ["asnmap", "-org", self.org_name, "-json", "-silent"]


class UncoverRunner(BaseRunner):
    tool_name = "uncover"

    def __init__(self, query: str):
        self.query = query

    def build_command(self) -> list[str]:
        cmd = ["uncover", "-q", self.query, "-json", "-silent"]
        engines = settings.uncover_sources
        if engines:
            cmd.extend(["-e", engines])
        return cmd


# --- New runners for Pipeline A extensions ---


class PurednsRunner(BaseRunner):
    """Run puredns bruteforce with native wildcard filtering."""
    tool_name = "puredns"
    timeout = 1200  # 20 min for brute force

    def __init__(self, domain: str, wordlist: str = "/app/wordlists/subdomains.txt"):
        self.domain = domain
        self.wordlist = wordlist
        self._tmpfile: str | None = None

    def build_command(self) -> list[str]:
        return [
            "puredns", "bruteforce", self.wordlist,
            "-d", self.domain, "--quiet",
        ]

    async def run(self, org_id: str | None = None):
        """puredns outputs plain hostnames, not JSON. Override to parse line-by-line."""
        from app.runner.base import RunResult
        import asyncio
        import time
        import logging

        logger = logging.getLogger(__name__)
        cmd = self.build_command()
        last_result = RunResult(tool=self.tool_name, exit_code=-1)

        for attempt in range(1 + self.max_retries):
            start = time.monotonic()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                results: list[dict] = []

                async def read_stdout():
                    assert proc.stdout is not None
                    async for line in proc.stdout:
                        text = line.decode("utf-8", errors="replace").strip()
                        if text:
                            results.append({"host": text})

                async def read_stderr():
                    pass  # puredns stderr is progress info

                await asyncio.wait_for(
                    asyncio.gather(read_stdout(), read_stderr(), proc.wait()),
                    timeout=self._get_timeout(),
                )

                result = RunResult(
                    tool=self.tool_name,
                    exit_code=proc.returncode or 0,
                    results=results,
                    duration_seconds=time.monotonic() - start,
                    retries=attempt,
                )

                logger.info(
                    "tool=%s org=%s exit=%d results=%d duration=%.1fs attempt=%d",
                    self.tool_name, org_id, result.exit_code,
                    len(result.results), result.duration_seconds, attempt + 1,
                )

                if result.exit_code == 0:
                    return result
                last_result = result

            except asyncio.TimeoutError:
                last_result = RunResult(
                    tool=self.tool_name, exit_code=-1,
                    stderr=f"Timeout after {self._get_timeout()}s",
                    duration_seconds=time.monotonic() - start, retries=attempt,
                )
                logger.error("tool=%s org=%s timed out", self.tool_name, org_id)

            if attempt < self.max_retries:
                wait = 2 ** (attempt + 1)
                await asyncio.sleep(wait)

        return last_result


class KatanaRunner(BaseRunner):
    """Run katana web crawler on HTTP/HTTPS targets."""
    tool_name = "katana"
    timeout = 300  # 5 min per batch

    def __init__(self, hosts: list[str]):
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="katana_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return [
            "katana", "-list", path, "-json", "-silent",
            "-depth", "2",
            "-js-crawl",
            "-headless=false",
            "-timeout", "10",
            "-rate-limit", "50",
        ]

    async def run(self, org_id: str | None = None):
        try:
            return await super().run(org_id)
        finally:
            if self._tmpfile and os.path.exists(self._tmpfile):
                os.unlink(self._tmpfile)
