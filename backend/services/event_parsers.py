"""Event format parsers for SIEM push ingestion.

Supported formats: json (generic), hec (Splunk HEC), cef (ArcSight CEF), leef (QRadar LEEF).
Each parser takes raw body data and returns a list of normalized event dicts
ready for SIEMEvent creation.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def parse_events(body: bytes | str, parser_type: str) -> list[dict]:
    """Parse raw event data using the specified parser type.

    Returns list of dicts with keys matching EventCreate fields.
    """
    parsers = {
        "json": parse_json,
        "hec": parse_hec,
        "cef": parse_cef,
        "leef": parse_leef,
    }
    parser = parsers.get(parser_type)
    if not parser:
        raise ValueError(f"Unknown parser type: {parser_type}")

    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")

    return parser(body)


# ── JSON parser ────────────────────────────────────────

def parse_json(body: str) -> list[dict]:
    """Parse generic JSON events. Accepts single object or array."""
    data = json.loads(body)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("JSON body must be an object or array")

    results = []
    for item in data:
        results.append(_normalize_json_event(item))
    return results


def _normalize_json_event(item: dict) -> dict:
    """Map common JSON field names to our schema."""
    return {
        "event_time": _parse_time(item.get("event_time") or item.get("timestamp") or item.get("@timestamp") or item.get("time")),
        "source_system": item.get("source_system") or item.get("source") or "unknown",
        "source_id": item.get("source_id") or item.get("id"),
        "event_type": item.get("event_type") or item.get("type") or "generic",
        "event_category": item.get("event_category") or item.get("category"),
        "severity": _normalize_severity(item.get("severity") or item.get("level") or "info"),
        "action": item.get("action"),
        "outcome": item.get("outcome") or item.get("result"),
        "user_name": item.get("user_name") or item.get("user") or item.get("username"),
        "source_ip": item.get("source_ip") or item.get("src_ip") or item.get("src"),
        "dest_ip": item.get("dest_ip") or item.get("dst_ip") or item.get("dst"),
        "host_name": item.get("host_name") or item.get("host") or item.get("hostname"),
        "message": item.get("message") or item.get("msg") or item.get("description"),
        "raw": item,
    }


# ── Splunk HEC parser ─────────────────────────────────

def parse_hec(body: str) -> list[dict]:
    """Parse Splunk HTTP Event Collector format.

    HEC can send multiple events separated by newlines (NDJSON),
    or a single JSON object with {"event": ...}.
    """
    results = []
    # Try NDJSON first (multiple events)
    lines = [line.strip() for line in body.strip().split("\n") if line.strip()]
    for line in lines:
        try:
            item = json.loads(line)
            results.append(_normalize_hec_event(item))
        except json.JSONDecodeError:
            logger.warning("Skipping invalid HEC line: %.100s", line)
    return results


def _normalize_hec_event(item: dict) -> dict:
    """Normalize a single HEC event."""
    event_data = item.get("event", item)
    if isinstance(event_data, str):
        event_data = {"message": event_data}

    # HEC uses epoch timestamps
    time_val = item.get("time")
    if time_val:
        try:
            event_time = datetime.utcfromtimestamp(float(time_val))
        except (ValueError, OSError):
            event_time = datetime.utcnow()
    else:
        event_time = datetime.utcnow()

    return {
        "event_time": event_time,
        "source_system": item.get("source") or item.get("sourcetype") or "hec",
        "source_id": item.get("source_id"),
        "event_type": item.get("sourcetype") or event_data.get("event_type") or "hec_event",
        "event_category": event_data.get("category"),
        "severity": _normalize_severity(event_data.get("severity") or "info"),
        "action": event_data.get("action"),
        "outcome": event_data.get("outcome"),
        "user_name": event_data.get("user"),
        "source_ip": event_data.get("src_ip") or event_data.get("src"),
        "dest_ip": event_data.get("dest_ip") or event_data.get("dest"),
        "host_name": item.get("host") or event_data.get("host"),
        "message": event_data.get("message") or event_data.get("_raw") or (event_data if isinstance(event_data, str) else json.dumps(event_data)),
        "raw": item,
    }


# ── CEF parser ─────────────────────────────────────────

# CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
_CEF_HEADER_RE = re.compile(
    r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)


def parse_cef(body: str) -> list[dict]:
    """Parse ArcSight Common Event Format."""
    results = []
    for line in body.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        parsed = _parse_cef_line(line)
        if parsed:
            results.append(parsed)
    return results


def _parse_cef_line(line: str) -> Optional[dict]:
    match = _CEF_HEADER_RE.match(line)
    if not match:
        logger.warning("Invalid CEF line: %.100s", line)
        return None

    version, vendor, product, dev_version, sig_id, name, severity, extension = match.groups()

    # Parse extension key=value pairs
    ext = _parse_cef_extension(extension)

    return {
        "event_time": _parse_time(ext.get("rt") or ext.get("end") or ext.get("start")),
        "source_system": f"{vendor}_{product}".lower().replace(" ", "_"),
        "source_id": sig_id,
        "event_type": ext.get("cat") or name,
        "event_category": ext.get("cat"),
        "severity": _normalize_cef_severity(severity),
        "action": ext.get("act"),
        "outcome": ext.get("outcome"),
        "user_name": ext.get("suser") or ext.get("duser"),
        "source_ip": ext.get("src"),
        "dest_ip": ext.get("dst"),
        "host_name": ext.get("shost") or ext.get("dhost"),
        "message": name,
        "raw": {"cef_header": {"vendor": vendor, "product": product, "version": dev_version,
                                "signature_id": sig_id, "name": name, "severity": severity},
                "extension": ext},
    }


def _parse_cef_extension(ext_str: str) -> dict:
    """Parse CEF extension key=value pairs."""
    result = {}
    # CEF extension is space-separated key=value; values can contain spaces
    parts = re.findall(r"(\w+)=((?:[^ =]| (?!\w+=))*)", ext_str)
    for key, value in parts:
        result[key] = value.strip()
    return result


def _normalize_cef_severity(sev: str) -> str:
    """Map CEF severity (0-10 or string) to our severity levels."""
    try:
        num = int(sev)
        if num <= 3:
            return "low"
        elif num <= 6:
            return "medium"
        elif num <= 8:
            return "high"
        else:
            return "critical"
    except ValueError:
        return _normalize_severity(sev)


# ── LEEF parser ────────────────────────────────────────

# LEEF format: LEEF:Version|Vendor|Product|Version|EventID|delimiter?|Extension
_LEEF_HEADER_RE = re.compile(
    r"^LEEF:([12]\.\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)


def parse_leef(body: str) -> list[dict]:
    """Parse IBM QRadar Log Event Extended Format."""
    results = []
    for line in body.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        parsed = _parse_leef_line(line)
        if parsed:
            results.append(parsed)
    return results


def _parse_leef_line(line: str) -> Optional[dict]:
    match = _LEEF_HEADER_RE.match(line)
    if not match:
        logger.warning("Invalid LEEF line: %.100s", line)
        return None

    version, vendor, product, dev_version, event_id, extension = match.groups()

    # LEEF 2.0 can specify a custom delimiter as first char of extension
    delimiter = "\t"
    if version.startswith("2"):
        if extension and len(extension) > 1:
            delimiter = extension[0]
            extension = extension[1:]

    ext = _parse_leef_extension(extension, delimiter)

    return {
        "event_time": _parse_time(ext.get("devTime") or ext.get("devTimeFormat")),
        "source_system": f"{vendor}_{product}".lower().replace(" ", "_"),
        "source_id": event_id,
        "event_type": ext.get("cat") or event_id,
        "event_category": ext.get("cat"),
        "severity": _normalize_severity(ext.get("sev") or "info"),
        "action": ext.get("action"),
        "outcome": ext.get("outcome"),
        "user_name": ext.get("usrName") or ext.get("srcUserName"),
        "source_ip": ext.get("src"),
        "dest_ip": ext.get("dst"),
        "host_name": ext.get("srcHostName") or ext.get("dstHostName"),
        "message": ext.get("msg") or event_id,
        "raw": {"leef_header": {"vendor": vendor, "product": product, "version": dev_version,
                                 "event_id": event_id}, "extension": ext},
    }


def _parse_leef_extension(ext_str: str, delimiter: str = "\t") -> dict:
    result = {}
    for pair in ext_str.split(delimiter):
        if "=" in pair:
            key, _, value = pair.partition("=")
            result[key.strip()] = value.strip()
    return result


# ── Shared helpers ─────────────────────────────────────

def _parse_time(val) -> datetime:
    """Best-effort timestamp parsing."""
    if val is None:
        return datetime.utcnow()
    if isinstance(val, datetime):
        return val
    if isinstance(val, (int, float)):
        try:
            return datetime.utcfromtimestamp(val)
        except (ValueError, OSError):
            return datetime.utcnow()
    if isinstance(val, str):
        # Try ISO format
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                     "%Y-%m-%d %H:%M:%S", "%b %d %Y %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
        # Try epoch
        try:
            return datetime.utcfromtimestamp(float(val))
        except (ValueError, OSError):
            pass
    return datetime.utcnow()


_SEVERITY_MAP = {
    "info": "info", "informational": "info", "0": "info",
    "low": "low", "1": "low", "minor": "low",
    "medium": "medium", "med": "medium", "2": "medium", "warning": "medium", "warn": "medium",
    "high": "high", "3": "high", "major": "high", "error": "high",
    "critical": "critical", "crit": "critical", "4": "critical", "fatal": "critical", "emergency": "critical",
}


def _normalize_severity(val: str) -> str:
    if not val:
        return "info"
    return _SEVERITY_MAP.get(val.lower().strip(), "info")
