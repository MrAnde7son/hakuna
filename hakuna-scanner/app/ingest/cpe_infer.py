"""CPE inference — derive CPE 2.3 strings from httpx + tlsx fingerprints.

Strategy
--------
The inference layer is open-ended: for every Server header token or httpx
``-tech-detect`` token it sees, it emits a CPE 2.3 string of the form
``cpe:2.3:a:{token}:{token}:{version}:*``, where ``{token}`` is the lowercased
identifier and ``{version}`` is extracted opportunistically.

A small alias table (``cpe_map.json``) handles the handful of cases where the
common-name token doesn't match the NVD canonical product — e.g. the Server
header ``Apache/2.4.49`` should become ``apache:http_server``, not
``apache:apache``. Anything not in the alias table is emitted as-is.

Filtering
---------
Not every detected technology is useful for CVE correlation. Tokens that
represent CDN/WAF services, HTTP policies, analytics embeds, or third-party
widgets are tracked as ``detected_technologies`` (for UI display) but excluded
from ``cpe_list`` (used for CVE matching and Nuclei routing).

Filtering happens at two levels:
  1. **Alias-level**: entries in ``cpe_map.json`` with ``"skip_cpe": true``
     are emitted only to ``detected_technologies``.
  2. **Open-ended path**: tokens not in the alias table that have no version
     (``*``) are treated as low-confidence and routed to
     ``detected_technologies`` only. Versioned tokens still get a CPE.

Why open-ended?
---------------
``services.cpe_matcher.match_cves_for_cpes`` feeds the product+version into
``services.downstream_impact._query_threat_intel_cves``, which queries
``ThreatCVE.affected_products`` via ``LIKE`` + a slug matcher. Vendor is
ignored. That means the inference layer only needs to get the *product name*
right — emitting a speculative CPE for an unknown product costs one empty
SQL lookup and nothing else, and covers the long tail of web servers (Yaws,
Caddy, LiteSpeed, Gunicorn, OpenResty, …) that a hand-curated allow-list
would miss.

Nuclei template routing (``hakuna-vm-scanner/scanner/vm/router.py``) reads
the same ``cpe_list`` but silently ignores vendor:product pairs it doesn't
know — so "extra" CPEs don't break routing, they just don't trigger any tag
expansion. That decouples CVE correlation (needs broad coverage) from
routing (needs a curated template set).
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import NamedTuple

logger = logging.getLogger(__name__)

_MAP_PATH = os.path.join(os.path.dirname(__file__), "cpe_map.json")
_JARM_DB_PATH = os.path.join(os.path.dirname(__file__), "jarm_hash_db.json")
# First token + optional version. Separator is "/" or " " so both
# "nginx/1.18.0" and "Yaws 2.0.6" parse.
_SERVER_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:[/ ]([0-9][0-9A-Za-z._\-]*))?")
_VERSION_SAFE_RE = re.compile(r"^[0-9][0-9A-Za-z._\-]*$")
# Strip characters outside the CPE-product-name safe set. Applied after
# lowercasing, so this also collapses whitespace and punctuation that crept
# into the token (e.g. trailing commas).
_TOKEN_SAFE_RE = re.compile(r"[^a-z0-9_.\-]")

# Tokens that are too generic to produce useful CVE correlation. These are
# typically deployment labels ("server", "unknown") rather than product
# names, and would produce noisy LIKE matches against every CVE description
# that happens to mention them. Keep this list short — Option 2 (NVD-derived
# product index) will do the real filtering.
_TOKEN_DENYLIST = frozenset({
    "server", "unknown", "none", "http", "https", "web", "httpd",
})


class CpeInferResult(NamedTuple):
    """Split inference output: CVE-matchable CPEs vs. all detected technologies.

    ``cpe_list`` contains only CPEs suitable for CVE correlation and Nuclei
    routing — real software with a version or a known-good alias.

    ``detected_technologies`` contains *everything* the inference layer saw,
    including CDNs, WAFs, analytics scripts, and versionless generic tokens.
    Use this for the asset's technology profile in the UI.
    """
    cpe_list: list[str]
    detected_technologies: list[str]


def _load_map() -> dict:
    try:
        with open(_MAP_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("cpe_infer: failed to load %s: %s", _MAP_PATH, exc)
        return {"token_aliases": {}, "tls_subject_aliases": []}

    return {
        "token_aliases": {
            k.lower(): v for k, v in (data.get("token_aliases") or {}).items()
            if not k.startswith("_")
        },
        "tls_subject_aliases": [
            {**entry, "match": entry["match"].lower()}
            for entry in (data.get("tls_subject_aliases") or [])
            if "match" in entry
        ],
    }


def _load_jarm_db() -> dict:
    try:
        with open(_JARM_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("cpe_infer: failed to load JARM DB %s: %s", _JARM_DB_PATH, exc)
        return {"full_hashes": {}, "prefix_hashes": {}}
    return {
        "full_hashes": data.get("full_hashes", {}),
        "prefix_hashes": data.get("prefix_hashes", {}),
    }


_MAP = _load_map()
_JARM_DB = _load_jarm_db()


def _sanitize_version(version: str) -> str:
    if not version:
        return "*"
    return version if _VERSION_SAFE_RE.match(version) else "*"


def _sanitize_token(token: str) -> str:
    """Normalize a token for use in a CPE segment: lowercase, drop unsafe chars."""
    return _TOKEN_SAFE_RE.sub("", token.strip().lower())


def _format_cpe(vendor: str, product: str, version: str = "*") -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _emit(
    cpes: list[str],
    seen: set[str],
    vendor: str,
    product: str,
    version: str = "*",
    *,
    techs: list[str] | None = None,
    tech_only: bool = False,
) -> None:
    """Append a CPE if (vendor, product) has not been emitted yet.

    Dedup ignores version — first-seen version wins for a given pair.

    If *tech_only* is True the CPE is added to *techs* (detected technologies)
    but **not** to *cpes* (CVE-matchable list). This is used for non-software
    detections like CDNs, WAFs, and analytics embeds that should appear in the
    asset's technology profile but not trigger CVE correlation.
    """
    if not vendor or not product:
        return
    key = f"{vendor}:{product}"
    if key in seen:
        return
    seen.add(key)
    cpe_str = _format_cpe(vendor, product, _sanitize_version(version))
    if tech_only:
        if techs is not None:
            techs.append(cpe_str)
    else:
        cpes.append(cpe_str)
        if techs is not None:
            techs.append(cpe_str)


def _resolve_token(
    token: str,
    version: str,
    cpes: list[str],
    seen: set[str],
    *,
    techs: list[str] | None = None,
) -> None:
    """Resolve one (token, version) pair into an emitted CPE.

    Precedence:
      1. Exact alias hit on the lowercased token (multi-word aliases allowed).
         If the alias has ``"skip_cpe": true``, emit to *techs* only.
      2. First-word alias hit, for unknown multi-word tokens.
      3. Open-ended emission with (vendor=product=sanitized_token).
         Versionless open-ended tokens go to *techs* only — they're too
         speculative for CVE matching (e.g. ``microsoft:microsoft:*``).

    Empty tokens and deny-listed tokens are dropped silently.
    """
    if not token:
        return
    key = token.strip().lower()
    if not key or key in _TOKEN_DENYLIST:
        return

    aliases = _MAP["token_aliases"]
    alias = aliases.get(key)
    if alias:
        _emit(
            cpes, seen, alias["vendor"], alias["product"], version,
            techs=techs, tech_only=bool(alias.get("skip_cpe")),
        )
        return

    # Fall back to the first whitespace-delimited word for unknown multi-word
    # tokens like "Foo Bar Server 1.2".
    first = key.split()[0] if " " in key else key
    if first != key:
        alias = aliases.get(first)
        if alias:
            _emit(
                cpes, seen, alias["vendor"], alias["product"], version,
                techs=techs, tech_only=bool(alias.get("skip_cpe")),
            )
            return

    if first in _TOKEN_DENYLIST:
        return
    safe = _sanitize_token(first)
    if not safe or safe in _TOKEN_DENYLIST:
        return

    # Open-ended path: no alias matched. Versionless tokens are too
    # speculative for CVE correlation (e.g. "microsoft:microsoft:*") —
    # route them to detected_technologies only.
    is_versionless = (version == "*" or not version)
    _emit(cpes, seen, safe, safe, version, techs=techs, tech_only=is_versionless)


def _from_tech_tokens(
    tech: object, cpes: list[str], seen: set[str], *, techs: list[str] | None = None,
) -> None:
    """httpx -tech-detect output. Tokens like 'Nginx' or 'Nginx:1.18.0',
    occasionally a dict {'Nginx': '1.18.0'}."""
    if not tech:
        return
    if isinstance(tech, dict):
        pairs = [(str(k), str(v) if v else "") for k, v in tech.items()]
    elif isinstance(tech, list):
        pairs = []
        for t in tech:
            tok = str(t)
            name, _, version = tok.partition(":")
            pairs.append((name, version))
    else:
        return

    for name, version in pairs:
        _resolve_token(name, version or "*", cpes, seen, techs=techs)


def _from_server_header(
    server: str, cpes: list[str], seen: set[str], *, techs: list[str] | None = None,
) -> None:
    """HTTP Server header, e.g. 'nginx/1.18.0 (Ubuntu)', 'Yaws 2.0.6'."""
    if not server:
        return
    m = _SERVER_RE.match(server)
    if not m:
        return
    token = m.group(1) or ""
    version = m.group(2) or "*"
    _resolve_token(token, version, cpes, seen, techs=techs)


def _from_tls_subject(
    tls_cert: dict | None, cpes: list[str], seen: set[str],
    *, techs: list[str] | None = None,
) -> None:
    """TLS cert subject CN. Most certs are hostname-issued so this rarely
    fires. Only matches when the subject contains a known appliance token."""
    if not tls_cert:
        return
    subject = tls_cert.get("subject") or tls_cert.get("subject_dn") or ""
    if not isinstance(subject, str) or not subject:
        return
    subject_lower = subject.lower()

    for entry in _MAP["tls_subject_aliases"]:
        if entry["match"] in subject_lower:
            _emit(cpes, seen, entry["vendor"], entry["product"], techs=techs)


def _from_jarm(
    jarm_hash: str | None, cpes: list[str], seen: set[str],
    *, techs: list[str] | None = None,
) -> list[str]:
    """Match a JARM TLS fingerprint against known server hashes.

    Returns a list of tags (e.g. ['c2']) if the JARM match has associated tags.
    JARM is especially valuable for detecting:
      - C2 frameworks (Cobalt Strike, Sliver, Metasploit) that have unique TLS stacks
      - Specific web servers and load balancers
      - Appliances behind generic reverse proxies
    """
    tags: list[str] = []
    if not jarm_hash or len(jarm_hash) < 10:
        return tags
    # Skip all-zero hashes (no TLS response).
    if jarm_hash.replace("0", "") == "":
        return tags

    full = _JARM_DB.get("full_hashes", {})
    match = full.get(jarm_hash)
    if match:
        if match.get("cpe_vendor") and match.get("cpe_product"):
            _emit(cpes, seen, match["cpe_vendor"], match["cpe_product"], techs=techs)
        tags.extend(match.get("tags", []))
        return tags

    # Fall back to prefix matching (first 20 chars).
    prefixes = _JARM_DB.get("prefix_hashes", {})
    for prefix, pmatch in prefixes.items():
        if jarm_hash.startswith(prefix):
            if pmatch.get("cpe_vendor") and pmatch.get("cpe_product"):
                _emit(cpes, seen, pmatch["cpe_vendor"], pmatch["cpe_product"], techs=techs)
            tags.extend(pmatch.get("tags", []))
            break

    return tags


def infer_cpes(
    httpx_entry: dict | None,
    tls_cert: dict | None = None,
    jarm_hash: str | None = None,
) -> CpeInferResult:
    """Derive CPE 2.3 strings from a httpx JSON entry and optional TLS cert.

    Returns a ``CpeInferResult`` with two lists:

    * ``cpe_list`` — CPEs suitable for CVE correlation and Nuclei routing.
      Excludes non-software detections (CDNs, WAFs, analytics) and
      versionless open-ended tokens.
    * ``detected_technologies`` — *all* detected technologies including
      non-software items. Use for the asset's tech profile in the UI.

    Never raises.
    """
    cpes: list[str] = []
    techs: list[str] = []
    seen: set[str] = set()

    if not httpx_entry and not tls_cert and not jarm_hash:
        return CpeInferResult(cpes, techs)

    if httpx_entry:
        _from_tech_tokens(
            httpx_entry.get("tech") or httpx_entry.get("technologies"),
            cpes,
            seen,
            techs=techs,
        )
        _from_server_header(
            (httpx_entry.get("webserver") or httpx_entry.get("web_server") or "").strip(),
            cpes,
            seen,
            techs=techs,
        )

    _from_tls_subject(tls_cert, cpes, seen, techs=techs)
    _from_jarm(jarm_hash, cpes, seen, techs=techs)

    return CpeInferResult(cpes, techs)


def filter_cpe_list(cpe_list: list[str]) -> CpeInferResult:
    """Retroactively filter an existing cpe_list into CVE-matchable vs. detected.

    Use this at read time to clean up stale data written before the filtering
    logic was deployed. Applies the same rules as ``infer_cpes``:
      - Aliases with ``skip_cpe: true`` → detected_technologies only
      - Versionless open-ended tokens (vendor == product, version == *) → detected only
      - Everything else → both lists
    """
    cpes: list[str] = []
    techs: list[str] = []

    aliases = _MAP["token_aliases"]
    # Build a reverse lookup: (vendor, product) → alias entry
    _skip_pairs: set[str] = set()
    for alias in aliases.values():
        if alias.get("skip_cpe"):
            _skip_pairs.add(f"{alias['vendor']}:{alias['product']}")

    for cpe_str in cpe_list:
        parts = cpe_str.split(":")
        if len(parts) < 6:
            continue
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        vp = f"{vendor}:{product}"

        if vp in _skip_pairs:
            techs.append(cpe_str)
        elif vendor == product and version == "*":
            # Versionless open-ended token — too speculative for CVE matching
            techs.append(cpe_str)
        else:
            cpes.append(cpe_str)
            techs.append(cpe_str)

    return CpeInferResult(cpes, techs)


def reload_map() -> None:
    """Force-reload the map file from disk. For tests."""
    global _MAP, _JARM_DB
    _MAP = _load_map()
    _JARM_DB = _load_jarm_db()
