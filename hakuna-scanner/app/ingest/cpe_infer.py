"""CPE inference — derive CPE 2.3 strings from httpx + tlsx fingerprints.

Why this exists
---------------
Pipeline B's Nuclei router (hakuna-vm-scanner/scanner/vm/router.py) selects
templates by CPE first. Without an inference layer, ``asset_ports.cpe_list``
is only populated by libnmap on the small subset of ports nmap can identify
— the rest of the web tier reaches the router with cpe_list = NULL and
falls through to the generic ``"generic,exposure"`` tag set.

This module bridges that gap. It takes the data already captured by httpx
and tlsx, runs a small hand-curated mapping table over it, and emits CPE
2.3 strings that match the routing_table.json `cpe_map` keys.

Routing only uses vendor:product (router.py:157), so version-accurate CPEs
are not required — emitting ``cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*`` is
fully sufficient to route templates. Versions are extracted opportunistically
when trivially available, for future CVE correlation.

Usage
-----
    from app.ingest.cpe_infer import infer_cpes
    cpes = infer_cpes(httpx_entry, tls_cert=tls_cert_for_host)

The function is pure: no I/O, no DB, no exceptions on empty input. The map
file is loaded once at module import.
"""

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

_MAP_PATH = os.path.join(os.path.dirname(__file__), "cpe_map.json")
_SERVER_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:[/ ]([0-9][0-9A-Za-z._\-]*))?")
_VERSION_SAFE_RE = re.compile(r"^[0-9][0-9A-Za-z._\-]*$")


def _load_map() -> dict:
    try:
        with open(_MAP_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("cpe_infer: failed to load %s: %s", _MAP_PATH, exc)
        return {"tech_to_cpe": {}, "server_header_to_cpe": [], "tls_subject_to_cpe": []}

    # Normalize: lowercase tech_to_cpe keys, lowercase substring matchers.
    tech = {k.lower(): v for k, v in (data.get("tech_to_cpe") or {}).items()}
    headers = [
        {**entry, "match": entry["match"].lower()}
        for entry in (data.get("server_header_to_cpe") or [])
        if "match" in entry
    ]
    subjects = [
        {**entry, "match": entry["match"].lower()}
        for entry in (data.get("tls_subject_to_cpe") or [])
        if "match" in entry
    ]
    return {
        "tech_to_cpe": tech,
        "server_header_to_cpe": headers,
        "tls_subject_to_cpe": subjects,
    }


_MAP = _load_map()


def _format_cpe(vendor: str, product: str, version: str = "*") -> str:
    """Build a CPE 2.3 application string. Versions are sanitized."""
    if version != "*" and not _VERSION_SAFE_RE.match(version):
        version = "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _emit(cpes: list[str], seen: set[str], vendor: str, product: str, version: str = "*") -> None:
    """Append a CPE if (vendor, product) not yet emitted. Dedup ignores version."""
    key = f"{vendor}:{product}"
    if key in seen:
        return
    seen.add(key)
    cpes.append(_format_cpe(vendor, product, version))


def _from_tech_tokens(tech: object, cpes: list[str], seen: set[str]) -> None:
    """httpx -tech-detect output. Tokens are typically just names ('Nginx'),
    occasionally name:version ('Nginx:1.18.0')."""
    if not tech:
        return
    if isinstance(tech, dict):
        tokens = list(tech.keys())
    elif isinstance(tech, list):
        tokens = [str(t) for t in tech]
    else:
        return

    table = _MAP["tech_to_cpe"]
    for tok in tokens:
        if not tok:
            continue
        name, _, version = tok.partition(":")
        hit = table.get(name.strip().lower())
        if hit:
            _emit(cpes, seen, hit["vendor"], hit["product"], version.strip() or "*")


def _from_server_header(server: str, cpes: list[str], seen: set[str]) -> None:
    """HTTP Server header. e.g. 'nginx/1.18.0 (Ubuntu)' or 'Microsoft-IIS/10.0'."""
    if not server:
        return
    server_lower = server.lower()
    m = _SERVER_RE.match(server)
    version = (m.group(2) or "*") if m else "*"

    for entry in _MAP["server_header_to_cpe"]:
        if entry["match"] in server_lower:
            _emit(cpes, seen, entry["vendor"], entry["product"], version)
            break  # first match wins — keep ordering meaningful


def _from_tls_subject(tls_cert: dict | None, cpes: list[str], seen: set[str]) -> None:
    """TLS cert subject CN. Most certs are hostname-issued, so this rarely fires.
    Only matches when the subject string contains a known appliance/product token."""
    if not tls_cert:
        return
    subject = tls_cert.get("subject") or tls_cert.get("subject_dn") or ""
    if not isinstance(subject, str) or not subject:
        return
    subject_lower = subject.lower()

    for entry in _MAP["tls_subject_to_cpe"]:
        if entry["match"] in subject_lower:
            _emit(cpes, seen, entry["vendor"], entry["product"])


def infer_cpes(httpx_entry: dict | None, tls_cert: dict | None = None) -> list[str]:
    """Derive CPE 2.3 strings from a httpx JSON entry and optional TLS cert.

    Parameters
    ----------
    httpx_entry
        A single line of httpx JSON output. May contain ``tech``, ``webserver``
        / ``web_server``, etc. Tolerates None and missing fields.
    tls_cert
        Optional dict with ``subject`` / ``issuer`` keys, as stored in
        ``asset_ports.tls_cert`` by tlsx ingest.

    Returns
    -------
    list[str]
        Ordered, deduped list of CPE 2.3 strings. Empty list when nothing
        matched. Never raises.
    """
    cpes: list[str] = []
    seen: set[str] = set()

    if not httpx_entry and not tls_cert:
        return cpes

    if httpx_entry:
        _from_tech_tokens(
            httpx_entry.get("tech") or httpx_entry.get("technologies"),
            cpes,
            seen,
        )
        _from_server_header(
            (httpx_entry.get("webserver") or httpx_entry.get("web_server") or "").strip(),
            cpes,
            seen,
        )

    _from_tls_subject(tls_cert, cpes, seen)

    return cpes


def reload_map() -> None:
    """Force-reload the map file from disk. For tests."""
    global _MAP
    _MAP = _load_map()
