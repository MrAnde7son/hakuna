"""Retire.js — match downloaded JS files against a known-vulnerable libs DB.

Three matchers run in priority order; first one that yields a version
wins:

  1. URI match     — /static/jquery-3.1.1.min.js → "jquery" 3.1.1
  2. Filename      — basename matched against the same regex set
  3. Filecontent   — version string in the file body (banner comments,
                     library copyright lines)

Each match is checked against the library's vulnerability ranges
(``below``: vulnerable when version < below). The hit carries the CVE
list and severity from the most-severe range that applies.

Why we ship our own seed DB rather than depending on retirejs/retire.js
upstream at runtime: the upstream JSON refreshes are periodic and the
schema is stable enough that vendoring a subset (jquery, lodash, angular,
moment, bootstrap — the biggest hit list in our scans) gives high signal
without a network dep at scan time. A separate cron job is expected to
refresh ``retirejs_db.json`` from upstream (left to PR 5).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache


logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(__file__), "retirejs_db.json")


@dataclass(frozen=True)
class RetireHit:
    """One vulnerable library detection."""
    library: str            # "jquery"
    version: str            # "1.7.2"
    severity: str           # "high" | "medium" | "low" | "info"
    cves: tuple[str, ...]   # ("CVE-2012-6708", ...)
    detection_method: str   # "uri" | "filename" | "filecontent"
    source_url: str
    info: tuple[str, ...]   # human-readable summaries from the DB
    file_sha256: str        # sha256 of the JS content this was found in

    def to_dict(self) -> dict:
        return {
            "library": self.library,
            "version": self.version,
            "severity": self.severity,
            "cves": list(self.cves),
            "detection_method": self.detection_method,
            "source_url": self.source_url,
            "info": list(self.info),
            "file_sha256": self.file_sha256,
        }


@lru_cache(maxsize=1)
def _load_db() -> dict:
    """Load and compile the retire.js seed DB once per process.

    Compiling the regexes here amortizes the cost across thousands of
    file scans during a large enrichment run.
    """
    with open(_DB_PATH) as f:
        raw = json.load(f)

    db: dict[str, dict] = {}
    for lib_name, lib_data in raw.items():
        if lib_name.startswith("_"):
            continue
        if not isinstance(lib_data, dict):
            continue
        extractors = lib_data.get("extractors") or {}
        compiled = {
            "uri": _compile_patterns(extractors.get("uri") or []),
            "filename": _compile_patterns(extractors.get("filename") or []),
            "filecontent": _compile_patterns(extractors.get("filecontent") or []),
        }
        db[lib_name] = {
            "extractors": compiled,
            "vulnerabilities": lib_data.get("vulnerabilities") or [],
        }
    return db


def _compile_patterns(patterns: list) -> list[re.Pattern]:
    out: list[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error as e:
            logger.warning("retirejs: bad regex %r: %s", p, e)
    return out


def reload_db() -> None:
    """Force re-load of the seed DB (used by tests after monkeypatching)."""
    _load_db.cache_clear()


def scan_js_file(
    js_url: str,
    js_content: str | None,
) -> list[RetireHit]:
    """Scan one JS file and return all matching vulnerable libraries.

    A single file can match multiple libraries (e.g. a vendor bundle that
    includes both jQuery and Lodash). Each library produces at most one
    hit per file — the most-severe vulnerability range that applies.

    ``js_content`` may be None if the caller only has the URL — filename
    + URI matchers still run; only filecontent is skipped.
    """
    db = _load_db()
    sha = hashlib.sha256((js_content or "").encode("utf-8", errors="replace")).hexdigest() if js_content else ""
    filename = os.path.basename(_url_path(js_url))

    hits: list[RetireHit] = []
    for lib_name, lib in db.items():
        version, method = _detect_version(lib["extractors"], js_url, filename, js_content)
        if not version:
            continue
        worst = _worst_applicable_vuln(lib["vulnerabilities"], version)
        if not worst:
            # Library matched but the detected version isn't in any
            # vulnerable range — not a finding.
            continue
        hits.append(RetireHit(
            library=lib_name,
            version=version,
            severity=worst["severity"],
            cves=tuple(worst.get("cves", [])),
            detection_method=method,
            source_url=js_url,
            info=tuple(worst.get("info", [])),
            file_sha256=sha,
        ))
    return hits


def _detect_version(
    extractors: dict[str, list[re.Pattern]],
    url: str,
    filename: str,
    content: str | None,
) -> tuple[str | None, str]:
    """Try URI → filename → filecontent. Return (version, method) or (None, '')."""
    for pat in extractors.get("uri", []):
        m = pat.search(url)
        if m and m.groupdict().get("version"):
            return m.group("version"), "uri"
    for pat in extractors.get("filename", []):
        m = pat.search(filename)
        if m and m.groupdict().get("version"):
            return m.group("version"), "filename"
    if content:
        # Filecontent regexes can be expensive on large bundles. Cap the
        # search window to the first 64KB — banner/version strings are
        # always near the top.
        head = content[:65536]
        for pat in extractors.get("filecontent", []):
            m = pat.search(head)
            if m and m.groupdict().get("version"):
                return m.group("version"), "filecontent"
    return None, ""


def _worst_applicable_vuln(vulns: list[dict], version: str) -> dict | None:
    """Return the highest-severity vuln entry that applies to ``version``.

    A vuln entry has ``below`` (and optionally ``atOrAbove``); we apply
    when version < below AND (no atOrAbove OR version >= atOrAbove).
    """
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    parsed = _parse_version(version)
    if parsed is None:
        return None

    candidates: list[tuple[int, dict, list[str]]] = []
    for v in vulns:
        below = v.get("below")
        at_or_above = v.get("atOrAbove")
        if not below:
            continue
        below_p = _parse_version(below)
        if below_p is None or parsed >= below_p:
            continue
        if at_or_above:
            aoa_p = _parse_version(at_or_above)
            if aoa_p is not None and parsed < aoa_p:
                continue
        sev = (v.get("severity") or "info").lower()
        cves = list((v.get("identifiers") or {}).get("CVE") or [])
        candidates.append((severity_rank.get(sev, 0), {
            "severity": sev,
            "cves": cves,
            "info": v.get("info") or [],
        }, cves))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _parse_version(v: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into a comparable tuple.

    Handles "3.1.1", "3.1.1-rc.2" (the suffix is dropped — close enough
    for vuln-range comparisons; pre-releases shouldn't be in production
    anyway).
    """
    if not v:
        return None
    base = re.split(r"[+_-]", v, 1)[0]
    parts = base.split(".")
    out: list[int] = []
    for p in parts:
        if not p.isdigit():
            return None
        out.append(int(p))
    if not out:
        return None
    return tuple(out)


def _url_path(url: str) -> str:
    """Best-effort path component for filename matching."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).path or url
    except Exception:
        return url
