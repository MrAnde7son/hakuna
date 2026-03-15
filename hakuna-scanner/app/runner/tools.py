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

    def __init__(self, hosts: list[str]):
        self.hosts = hosts
        self._tmpfile: str | None = None

    def _write_hosts(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="naabu_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.hosts))
        self._tmpfile = path
        return path

    def build_command(self) -> list[str]:
        path = self._write_hosts()
        return [
            "naabu", "-l", path, "-json", "-silent",
            "-p", settings.naabu_ports,
        ]

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
            "-san", "-cn", "-so", "-cipher", "-tls-version",
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
        return ["cdncheck", "-i", path, "-json", "-silent"]

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
