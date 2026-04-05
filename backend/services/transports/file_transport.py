"""File Transport — parse any structured file: CSV, JSON, XML, YAML, .nessus, PDF, DOCX."""

import csv
import json
import io
import logging
from typing import AsyncIterator
from xml.etree import ElementTree

from sqlalchemy.orm import Session
from .base import BaseTransport, ConnectResult

logger = logging.getLogger(__name__)


class FileTransport(BaseTransport):

    def __init__(self, db: Session = None):
        self.db = db

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Read a file and return sample records."""
        try:
            file_path = config.get("path")
            if not file_path:
                return ConnectResult(success=False, error="No file path provided")

            fmt = config.get("format", "auto")
            records = self._parse_file(file_path, fmt)

            # For JSON objects (not arrays), return the whole thing as raw_response
            # so the records picker can let the user select which array to use
            raw = {"total_records": len(records), "format": fmt}
            if fmt in ("json", "auto") and len(records) == 1 and isinstance(records[0], dict):
                raw = records[0]  # return the root object for picker navigation
                records = records  # still return as sample

            return ConnectResult(
                success=True,
                sample_records=records[:10],
                raw_response=raw,
            )
        except Exception as e:
            logger.exception("FileTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Yield all records from the file."""
        file_path = config.get("path")
        fmt = config.get("format", "auto")
        records_path = config.get("records_path")
        records = self._parse_file(file_path, fmt, records_path)
        for record in records:
            yield record

    def _parse_file(self, file_path: str, fmt: str, records_path: str = None) -> list:
        """Parse a file into a list of dicts."""
        if fmt == "auto":
            fmt = self._detect_format(file_path)

        # PDF and DOCX need special handling (binary + LLM extraction)
        if fmt == "pdf":
            return self._parse_pentest_document(file_path, "pdf")
        elif fmt == "docx":
            return self._parse_pentest_document(file_path, "docx")

        with open(file_path, "rb") as f:
            content = f.read()

        if fmt == "nessus":
            return self._parse_nessus(content, file_path)
        elif fmt == "csv":
            return self._parse_csv(content)
        elif fmt == "json":
            return self._parse_json(content, records_path)
        elif fmt == "xml":
            return self._parse_xml(content)
        elif fmt in ("yaml", "yml"):
            return self._parse_yaml(content, records_path)
        else:
            # Try JSON, then CSV as fallback
            try:
                return self._parse_json(content, records_path)
            except Exception:
                try:
                    return self._parse_csv(content)
                except Exception:
                    raise ValueError(f"Could not parse file as any known format: {fmt}")

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
        if path_lower.endswith((".yaml", ".yml")):
            return "yaml"
        if path_lower.endswith(".pdf"):
            return "pdf"
        if path_lower.endswith(".docx"):
            return "docx"
        return "auto"

    def _parse_nessus(self, content: bytes, filename: str) -> list:
        """Reuse existing .nessus XML parser and flatten findings into records."""
        from parsers.nessus_parser import NessusParser
        parser = NessusParser()
        result = parser.parse(content, filename)

        records = []
        assets_by_ip = {}
        for asset in result.get("assets", []):
            assets_by_ip[asset.get("ip", "")] = asset

        for finding in result.get("findings", []):
            record = dict(finding)
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

    def _parse_json(self, content: bytes, records_path: str = None) -> list:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if records_path:
                from services.transports.api_transport import _resolve_dot_path
                records = _resolve_dot_path(data, records_path)
                return records if isinstance(records, list) else [data]
            return [data]
        return [{"value": data}]

    def _parse_xml(self, content: bytes) -> list:
        """Generic XML → list of dicts. Each child of root becomes a record."""
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")

        # Check if it's a .nessus file
        if "<NessusClientData" in text or "<NessusClientData_v2" in text:
            return self._parse_nessus(content, "upload.nessus")

        root = ElementTree.fromstring(text)
        records = []
        for child in root:
            record = self._xml_element_to_dict(child)
            records.append(record)
        return records if records else [self._xml_element_to_dict(root)]

    def _xml_element_to_dict(self, element) -> dict:
        """Recursively convert an XML element to a dict."""
        result = {}
        # Attributes
        for k, v in element.attrib.items():
            result[k] = v
        # Child elements
        for child in element:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag  # strip namespace
            child_data = self._xml_element_to_dict(child)
            if tag in result:
                # Multiple children with same tag → make array
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_data)
            else:
                result[tag] = child_data
        # Text content
        if element.text and element.text.strip():
            if result:
                result["_text"] = element.text.strip()
            else:
                return element.text.strip()
        return result

    def _parse_yaml(self, content: bytes, records_path: str = None) -> list:
        """Parse YAML file. Requires PyYAML."""
        try:
            import yaml
        except ImportError:
            raise ValueError("PyYAML is not installed. Install it with: pip install pyyaml")

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")

        data = yaml.safe_load(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if records_path:
                from services.transports.api_transport import _resolve_dot_path
                records = _resolve_dot_path(data, records_path)
                return records if isinstance(records, list) else [data]
            return [data]
        return [{"value": data}]

    # ─────────────────────────────────────────────────────────
    # PDF / DOCX — extract text, then use LLM to structure findings
    # ─────────────────────────────────────────────────────────

    def _extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file using pypdf."""
        try:
            from pypdf import PdfReader
        except ImportError:
            raise ValueError(
                "pypdf is not installed. Install it with: pip install pypdf"
            )

        reader = PdfReader(file_path)
        pages = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text)
        if not pages:
            raise ValueError("Could not extract any text from the PDF file")
        return "\n\n".join(pages)

    def _extract_text_from_docx(self, file_path: str) -> str:
        """Extract text from a DOCX file using python-docx."""
        try:
            from docx import Document
        except ImportError:
            raise ValueError(
                "python-docx is not installed. Install it with: pip install python-docx"
            )

        doc = Document(file_path)
        paragraphs = []
        for para in doc.paragraphs:
            if para.text.strip():
                paragraphs.append(para.text)

        # Also extract text from tables (pentest reports often use tables)
        for table in doc.tables:
            for row in table.rows:
                cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if cells:
                    paragraphs.append(" | ".join(cells))

        if not paragraphs:
            raise ValueError("Could not extract any text from the DOCX file")
        return "\n".join(paragraphs)

    def _parse_pentest_document(self, file_path: str, fmt: str) -> list:
        """Extract text from PDF/DOCX, then use LLM to extract structured findings."""
        from services.llm_extractor import extract_findings_with_llm

        # Step 1: Extract raw text
        if fmt == "pdf":
            text = self._extract_text_from_pdf(file_path)
        else:
            text = self._extract_text_from_docx(file_path)

        logger.info("Extracted %d chars from %s file for LLM parsing", len(text), fmt)

        if not self.db:
            raise ValueError(
                "No database session available — cannot resolve LLM provider. "
                "Ensure the transport is created with a db session."
            )

        # Step 2: Send to shared LLM extractor
        findings = extract_findings_with_llm(self.db, text, prompt_type="pentest")

        if not findings:
            raise ValueError("LLM could not extract any findings from the document")

        return findings
