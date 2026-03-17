"""File Transport — local file, CSV, JSON, .nessus formats."""

import csv
import json
import io
import logging
from typing import AsyncIterator

from .base import BaseTransport, ConnectResult

logger = logging.getLogger(__name__)


class FileTransport(BaseTransport):

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Read a file and return sample records."""
        try:
            file_path = config.get("path")
            if not file_path:
                return ConnectResult(success=False, error="No file path provided")

            fmt = config.get("format", "auto")
            records = self._parse_file(file_path, fmt)

            return ConnectResult(
                success=True,
                sample_records=records[:10],
                raw_response={"total_records": len(records), "format": fmt},
            )
        except Exception as e:
            logger.exception("FileTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Yield all records from the file."""
        file_path = config.get("path")
        fmt = config.get("format", "auto")
        records = self._parse_file(file_path, fmt)
        for record in records:
            yield record

    def _parse_file(self, file_path: str, fmt: str) -> list:
        """Parse a file into a list of dicts."""
        if fmt == "auto":
            fmt = self._detect_format(file_path)

        with open(file_path, "rb") as f:
            content = f.read()

        if fmt == "nessus":
            return self._parse_nessus(content, file_path)
        elif fmt == "csv":
            return self._parse_csv(content)
        elif fmt == "json":
            return self._parse_json(content, None)
        elif fmt == "xml":
            # Generic XML — try nessus parser
            return self._parse_nessus(content, file_path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def _detect_format(self, file_path: str) -> str:
        path_lower = file_path.lower()
        if path_lower.endswith(".nessus"):
            return "nessus"
        if path_lower.endswith(".csv"):
            return "csv"
        if path_lower.endswith(".json"):
            return "json"
        if path_lower.endswith(".xml"):
            return "xml"
        return "json"  # default

    def _parse_nessus(self, content: bytes, filename: str) -> list:
        """Reuse existing .nessus XML parser and flatten findings into records."""
        from parsers.nessus_parser import NessusParser
        parser = NessusParser()
        result = parser.parse(content, filename)

        # Flatten findings with asset info for the field mapper
        records = []
        assets_by_ip = {}
        for asset in result.get("assets", []):
            assets_by_ip[asset.get("ip", "")] = asset

        for finding in result.get("findings", []):
            record = dict(finding)
            # Merge asset fields
            host_ip = finding.get("host_name") or finding.get("ip", "")
            asset = assets_by_ip.get(host_ip, {})
            record["ip"] = asset.get("ip", host_ip)
            record["hostname"] = asset.get("hostname", "")
            record["fqdn"] = asset.get("fqdn", "")
            record["os"] = asset.get("os", "")
            records.append(record)

        return records

    def _parse_csv(self, content: bytes) -> list:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)

    def _parse_json(self, content: bytes, records_path: str) -> list:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and records_path:
            from services.transports.api_transport import _resolve_dot_path
            records = _resolve_dot_path(data, records_path)
            return records if isinstance(records, list) else [data]
        return [data]
