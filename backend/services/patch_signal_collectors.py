"""
Patch reliability signal collectors.

Populates PatchReliabilitySignal from three source lanes:

1. MSRC supersedence chain — when a new KB supersedes an older one, the
   older KB gets a `supersedence` signal. Derived cheaply from the existing
   MSRCPatch.supercedence column (Microsoft's CVRF spec misspells it; we
   keep the column name in sync with the spec but use the correct spelling
   in our own signal types). No network fetches required.

2. MSRC known issues — re-fetches the recent Patch Tuesday CVRF documents
   and extracts Remediation entries of Type=7 ("Known Issue"), which is how
   Microsoft attaches BSOD / boot-loop / printer regressions to a specific KB.
   This is the highest-value signal lane and only needs to run monthly.

3. Ubuntu USN regression — Ubuntu re-releases a USN with a suffix bump
   (USN-6612-1 → USN-6612-2) when the original had an incomplete fix or
   introduced a regression. We detect these follow-ups by scanning the
   PatchAdvisory table and emit a `known_issue` signal against the base -1.

The collectors are idempotent: every signal has a stable fingerprint so
re-running them doesn't stack duplicates. Safe to run on a cron.

These run as background jobs — they can be slow (MSRC fetch in particular)
and should not block a request. The route layer wraps them in
BackgroundTasks.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from models.threat_intel_models import MSRCPatch, PatchAdvisory
from services import patch_reliability as reliability_svc

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 1. MSRC supersedence chain
# --------------------------------------------------------------------------- #
def collect_msrc_supercedence(db: Session) -> dict:
    """
    Walk MSRCPatch rows and emit a `supersedence` signal on every KB that
    has been superseded by a newer one.

    MSRC stores the superseded KB as a bare number (e.g. "5068403"), not
    with the "KB" prefix, so we normalize before writing the signal.

    This is a cheap, local-only pass — no HTTP. Meant to run on every patch
    catalog sync (or nightly).
    """
    added = 0
    skipped = 0

    rows = (
        db.query(MSRCPatch.kb_id, MSRCPatch.supercedence, MSRCPatch.product_name)
        .filter(MSRCPatch.supercedence.isnot(None))
        .filter(MSRCPatch.supercedence != "")
        .all()
    )

    for new_kb, superseded_raw, product_name in rows:
        if not superseded_raw or not new_kb:
            skipped += 1
            continue

        # The column stores a single number or a comma-separated list.
        for raw in re.split(r"[,\s]+", superseded_raw):
            raw = raw.strip()
            if not raw:
                continue
            old_kb = raw if raw.upper().startswith("KB") else f"KB{raw}"
            if old_kb == new_kb:
                continue  # defensive

            reliability_svc.record_signal(
                db,
                patch_source="msrc",
                patch_ref=old_kb,
                signal_source="msrc_supersedence",
                signal_type="supersedence",
                # Fingerprint collapses: same (old_kb, new_kb) pair is one signal
                # even if it's recorded against multiple products.
                fingerprint=f"superseded_by:{new_kb}",
                detail={
                    "superseded_by": new_kb,
                    "product_name": product_name,
                },
                rescore=False,
            )
            added += 1

    # Rescore the affected patches once at the end — one pass is much cheaper
    # than rescoring per-signal when we're ingesting hundreds of rows.
    db.commit()
    _rescore_touched(db, [("msrc", _kb_norm(old)) for _, old, _ in _iter_superseded(rows)])

    logger.info("collect_msrc_supercedence: %d signals recorded (%d skipped)", added, skipped)
    return {"signals_added": added, "skipped": skipped}


def _iter_superseded(rows):
    for new_kb, superseded_raw, product_name in rows:
        if not superseded_raw:
            continue
        for raw in re.split(r"[,\s]+", superseded_raw):
            raw = raw.strip()
            if raw:
                yield new_kb, raw, product_name


def _kb_norm(raw: str) -> str:
    return raw if raw.upper().startswith("KB") else f"KB{raw}"


# --------------------------------------------------------------------------- #
# 2. MSRC known issues (Type=7 Remediations in CVRF)
# --------------------------------------------------------------------------- #
# CVRF Remediation Type codes per the OASIS spec:
#   0 = Workaround
#   1 = Mitigation
#   2 = Vendor Fix   <-- we already read these in sync_msrc_patches_to_db
#   3 = None Available
#   4 = Will Not Fix
#   7 = Known Issue  <-- this is what we want
_REMEDIATION_KNOWN_ISSUE_TYPE = 7


def collect_msrc_known_issues(db: Session, months: int = 3) -> dict:
    """
    Re-fetch the last N MSRC Patch Tuesday documents and pull Type=7
    Known Issue remediations. Each Known Issue points at specific product IDs
    and describes an issue Microsoft has flagged on that patch.

    The parser is defensive: MSRC's schema occasionally deviates and we
    don't want a single malformed doc to break the whole collector.
    """
    # Imported lazily to avoid circular-import issues at module load time.
    # threat_intel_sync is a ~3000-line module that imports a lot.
    try:
        from threat_intel.threat_intel_sync import _fetch_msrc_document, _MSRC_UPDATES_URL, _get_ssl_context, _USER_AGENT
    except ImportError:
        logger.warning("collect_msrc_known_issues: threat_intel_sync helpers unavailable")
        return {"documents_processed": 0, "signals_added": 0}

    import json
    import urllib.request

    ctx = _get_ssl_context()
    req = urllib.request.Request(
        _MSRC_UPDATES_URL,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            index = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("collect_msrc_known_issues: failed to fetch update index: %s", exc)
        return {"documents_processed": 0, "signals_added": 0}

    docs = index.get("value", []) or []
    docs.sort(key=lambda d: d.get("InitialReleaseDate", ""), reverse=True)
    recent = docs[:months]

    added = 0
    processed = 0

    for doc_meta in recent:
        doc_id = doc_meta.get("ID", "")
        if not doc_id:
            continue
        cvrf = _fetch_msrc_document(doc_id)
        if not cvrf:
            continue
        processed += 1
        added += _parse_cvrf_known_issues(db, cvrf, doc_id)

    db.commit()
    logger.info(
        "collect_msrc_known_issues: %d signals from %d documents",
        added, processed,
    )
    return {"documents_processed": processed, "signals_added": added}


def _parse_cvrf_known_issues(db: Session, cvrf: dict, doc_id: str) -> int:
    """
    Walk a CVRF document and emit `known_issue` signals for every Remediation
    with Type=7. Separated from the HTTP layer so it's unit-testable with
    synthetic input.
    """
    added = 0
    vulns = cvrf.get("Vulnerability", [])
    if not isinstance(vulns, list):
        return 0

    for vuln in vulns:
        cve_id = vuln.get("CVE", "") or ""
        remediations = vuln.get("Remediations", []) or []

        for rem in remediations:
            if rem.get("Type") != _REMEDIATION_KNOWN_ISSUE_TYPE:
                continue

            description = (rem.get("Description") or {}).get("Value", "") or ""
            url = rem.get("URL", "") or ""
            kb_raw = description.strip()

            # Known-issue Remediations sometimes put the KB number in the
            # description (e.g. "KB5034441 - BSOD on unlock"), sometimes in
            # URL params, sometimes only in the ProductID. We have to infer.
            kb_id = _extract_kb_from_text(description) or _extract_kb_from_text(url)

            # If no explicit KB, attach the signal to every Type=2 fix KB in
            # the same vuln — they're the candidates this Known Issue applies to.
            # MSRC's Vendor Fix Description is usually a bare KB number like
            # "5034111" (no prefix) — match the normalization the existing
            # sync_msrc_patches_to_db uses.
            target_kbs: list[str] = []
            if kb_id:
                target_kbs = [kb_id]
            else:
                for other in remediations:
                    if other.get("Type") != 2:  # Type 2 = Vendor Fix
                        continue
                    fix_desc = (other.get("Description") or {}).get("Value", "") or ""
                    fix_desc = fix_desc.strip()
                    if not fix_desc:
                        continue
                    if fix_desc.isdigit():
                        target_kbs.append(f"KB{fix_desc}")
                    else:
                        extracted = _extract_kb_from_text(fix_desc)
                        if extracted:
                            target_kbs.append(extracted)

            if not target_kbs:
                continue

            # Fingerprint on (doc_id, vuln, description) so the same Known
            # Issue recorded across Patch Tuesday cycles dedupes.
            fingerprint = f"{doc_id}:{cve_id}:{hash(description)}"

            for target in set(target_kbs):
                reliability_svc.record_signal(
                    db,
                    patch_source="msrc",
                    patch_ref=target,
                    signal_source="msrc_known_issues",
                    signal_type="known_issue",
                    fingerprint=fingerprint,
                    detail={
                        "title": kb_raw[:200] or "Microsoft known issue",
                        "url": url or None,
                        "cve_id": cve_id,
                        "doc_id": doc_id,
                        "source": "MSRC Known Issues",
                    },
                    rescore=False,
                )
                added += 1

    return added


_KB_RE = re.compile(r"KB\s*(\d{5,7})", re.IGNORECASE)


def _extract_kb_from_text(text: str) -> Optional[str]:
    """Pull 'KB5034763' out of arbitrary text. Returns the normalized form."""
    if not text:
        return None
    m = _KB_RE.search(text)
    if not m:
        return None
    return f"KB{m.group(1)}"


# --------------------------------------------------------------------------- #
# 3. Ubuntu USN regression detection
# --------------------------------------------------------------------------- #
_USN_RE = re.compile(r"^USN-(\d+)-(\d+)$")

# Phrases in the follow-up advisory title/description that signal a true
# regression (as opposed to "we added kernel flavor X"). If any of these
# appear, we upgrade the signal from known_issue to regression.
_REGRESSION_KEYWORDS = (
    "regression",
    "re-released",
    "reverted",
    "reintroduced",
    "incomplete fix",
    "did not fully",
    "caused an issue",
    "broke",
)


def collect_ubuntu_usn_regressions(db: Session) -> dict:
    """
    Scan PatchAdvisory rows with source='ubuntu' and detect USN revision
    follow-ups (USN-NNNN-K where K >= 2). For each, emit a signal on the
    base USN-NNNN-1.

    Default signal type is `known_issue` (conservative — the follow-up might
    just add kernel flavors). Titles/descriptions matching regression
    keywords upgrade to `regression`.
    """
    added = 0

    # Group advisories by their base number, e.g. "USN-6612" -> [("USN-6612-1", row), ("USN-6612-2", row)]
    groups: dict[str, list[tuple[int, PatchAdvisory]]] = defaultdict(list)

    rows = (
        db.query(PatchAdvisory)
        .filter(PatchAdvisory.source == "ubuntu")
        .all()
    )

    for row in rows:
        m = _USN_RE.match((row.source_advisory_id or "").strip())
        if not m:
            continue
        base_num = m.group(1)
        revision = int(m.group(2))
        groups[f"USN-{base_num}"].append((revision, row))

    touched: set[tuple[str, str]] = set()
    for base_id, entries in groups.items():
        entries.sort(key=lambda e: e[0])
        if len(entries) < 2:
            continue  # no follow-ups
        # Follow-ups (revision >= 2) each emit a signal on the base -1.
        base_ref = f"{base_id}-1"
        for revision, row in entries:
            if revision < 2:
                continue

            title = (row.title or "").lower()
            description = (row.description or "").lower()
            haystack = f"{title} {description}"
            is_regression = any(kw in haystack for kw in _REGRESSION_KEYWORDS)

            signal_type = "regression" if is_regression else "known_issue"

            reliability_svc.record_signal(
                db,
                patch_source="ubuntu",
                patch_ref=base_ref,
                signal_source="usn_regression",
                signal_type=signal_type,
                fingerprint=f"followup:{row.source_advisory_id}",
                detail={
                    "title": row.title,
                    "url": row.advisory_url,
                    "follow_up_id": row.source_advisory_id,
                    "source": "Ubuntu USN revision",
                },
                rescore=False,
            )
            added += 1
            touched.add(("ubuntu", base_ref))

    db.commit()
    _rescore_touched(db, touched)
    logger.info("collect_ubuntu_usn_regressions: %d signals recorded", added)
    return {"signals_added": added}


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def collect_all(db: Session, *, msrc_months: int = 3, skip_network: bool = False) -> dict:
    """
    Run every collector in order. `skip_network` lets tests / local dev
    exercise just the DB-only collectors (supercedence, USN) without hitting
    microsoft.com.

    Returns a merged dict with per-collector stats.
    """
    results: dict = {}

    try:
        results["supercedence"] = collect_msrc_supercedence(db)
    except Exception as exc:
        logger.exception("collect_msrc_supercedence failed: %s", exc)
        results["supercedence"] = {"error": str(exc)}

    try:
        results["ubuntu_usn"] = collect_ubuntu_usn_regressions(db)
    except Exception as exc:
        logger.exception("collect_ubuntu_usn_regressions failed: %s", exc)
        results["ubuntu_usn"] = {"error": str(exc)}

    if not skip_network:
        try:
            results["msrc_known_issues"] = collect_msrc_known_issues(db, months=msrc_months)
        except Exception as exc:
            logger.exception("collect_msrc_known_issues failed: %s", exc)
            results["msrc_known_issues"] = {"error": str(exc)}

    # Final rescore pass applies decay + recomputes status for every touched row.
    reliability_svc.rescore_all(db)

    return results


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _rescore_touched(db: Session, pairs: Iterable[tuple[str, str]]) -> None:
    """Rescore a batch of (source, ref) pairs in one commit."""
    seen = set()
    for source, ref in pairs:
        key = (source.strip().lower(), ref.strip())
        if key in seen or not key[1]:
            continue
        seen.add(key)
        try:
            reliability_svc.score_patch(db, key[0], key[1], commit=False)
        except Exception as exc:
            logger.warning("rescore failed for %s/%s: %s", key[0], key[1], exc)
    db.commit()
