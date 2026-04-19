"""Schemathesis worker — property-based fuzzing for OpenAPI / GraphQL APIs.

Runs alongside nuclei_worker on the same ``vm_queue`` and emits the same
Celery result shape (``findings[]``) so ``services/post_ingest.finalize_scan``
ingests the results through the normal pipeline with no backend changes.

Why a separate worker: Nuclei's ``-dast`` engine fuzzes with a handful of
built-in strategies (SQLi/XSS/SSTI templates). Schemathesis is
property-based — it derives request examples from the OpenAPI/GraphQL
schema itself and checks the *responses* against the schema. That
catches a different class of bug:

  - server-side 5xx on valid-per-schema inputs (backend crash)
  - undocumented status codes (status_code_conformance)
  - response body violates the declared schema (response_schema_conformance)
  - content-type drift
  - negative-data (bad payload) returning 200 instead of 4xx

Handoff: we read ``asset_endpoints`` rows with ``source IN ('openapi',
'graphql')`` — populated by hakuna-scanner's openapi_discoverer /
graphql_introspector during Pipeline A discovery. One asset can have
rows from multiple spec_urls; we group by ``evidence->>'spec_url'`` and
fuzz each spec independently so a bad spec doesn't poison the others.

Credentials: the shape is identical to what nuclei_worker consumes
(ScanCredentials dict). form_login auth is resolved upstream in
``backend/services/vm_scanner._resolve_auth_profile``, which drives the
session broker and folds the resulting cookies/headers into
``credentials.headers`` — this worker treats every credential mode
uniformly as "a set of headers to send on every request".
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import uuid
from typing import Any

import asyncpg

from scanner.vm.celery_app import celery_app
from scanner.vm.config import DATABASE_URL, SCAN_TIMEOUT_SECONDS
from scanner.vm.db import _normalize_dsn

logger = logging.getLogger(__name__)


# Per-operation wall-clock budget. Schemathesis under Hypothesis can
# generate surprisingly many examples for complex schemas; this cap
# keeps one pathological operation from starving the rest of the spec.
OPERATION_TIMEOUT_SECONDS = int(__import__("os").environ.get("SCHEMATHESIS_OPERATION_TIMEOUT", "30"))

# Hypothesis example cap per operation. 25 is Schemathesis's own default
# — low enough to keep scans tractable, high enough to shake out the
# obvious response-schema / 5xx issues that make up the bulk of our
# true positives.
MAX_EXAMPLES_PER_OPERATION = int(__import__("os").environ.get("SCHEMATHESIS_MAX_EXAMPLES", "25"))

# Endpoints-per-spec cap — mirrors nuclei's NUCLEI_MAX_TARGETS_PER_ASSET
# rationale. A 2000-operation spec × 25 examples × 4 checks is hours of
# work; ranking is done upstream (discovery already ranks by auth_required
# and operation richness) so truncating here is safe.
MAX_OPERATIONS_PER_SPEC = int(__import__("os").environ.get("SCHEMATHESIS_MAX_OPERATIONS", "200"))


# Handoff: all endpoints with a parseable spec attached. Grouped at the
# Python layer by spec_url so we run schemathesis once per spec. Using
# DISTINCT on the spec URL-equivalents keeps the returned rowset small
# even for assets with thousands of discovered operations.
HANDOFF_QUERY = """
    SELECT
        ae.id,
        ae.asset_id,
        ae.url,
        ae.method,
        ae.path,
        ae.source,
        ae.auth_required,
        ae.content_type,
        ae.parameters,
        ae.evidence
    FROM asset_endpoints ae
    WHERE ae.asset_id = $1
      AND ae.source IN ('openapi', 'graphql')
    ORDER BY ae.auth_required DESC NULLS LAST, ae.discovered_at ASC
"""

ASSET_CONTEXT_QUERY = """
    SELECT a.id, a.org_id, a.hostname, a.ip, a.http_url
    FROM assets a
    WHERE a.id = $1
"""


# ── Credential → headers helper ──────────────────────────────────
# Intentionally narrower than nuclei_worker's version: the HTTP client
# Schemathesis uses (httpx / requests) takes a plain headers dict, not
# CLI -H flags, so we collapse all credential modes into a single dict.


def _credentials_to_headers(credentials: dict | None) -> dict[str, str]:
    """Flatten a ScanCredentials payload into an HTTP headers dict.

    Mirrors ``nuclei_worker._credentials_to_header_args`` but emits a
    plain dict — Schemathesis's ``Case.call()`` takes ``headers=`` kwarg.
    """
    headers: dict[str, str] = {}
    if not credentials:
        return headers

    ctype = (credentials.get("type") or "").lower()
    if ctype == "basic":
        user = credentials.get("username") or ""
        pw = credentials.get("password") or ""
        if user or pw:
            token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
    elif ctype == "bearer":
        token = credentials.get("token") or ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif ctype == "cookie":
        cookie = credentials.get("cookie") or credentials.get("token") or ""
        if cookie:
            headers["Cookie"] = cookie

    extra = credentials.get("headers") or {}
    if isinstance(extra, dict):
        for name, value in extra.items():
            if not name or value is None:
                continue
            headers[str(name)] = str(value)

    return headers


def _redacted_headers_for_log(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with every value masked.

    We don't maintain an allowlist of "safe" header names — any header
    could carry session state for a given target (Tenable uses X-Cookie,
    Okta uses x-okta-session, etc.). Redact unconditionally.
    """
    return {k: "***" for k in headers}


# ── Spec grouping ────────────────────────────────────────────────


def _group_endpoints_by_spec(rows: list[dict]) -> list[dict]:
    """Bucket endpoint rows by their source + spec_url (or graphql URL).

    Returns a list of ``{kind, spec_url|graphql_url, base_url, rows}``
    entries. GraphQL rows don't have a spec URL — the scan target IS the
    GraphQL endpoint URL — so we key them by ``url`` instead.
    """
    openapi: dict[str, list[dict]] = {}
    graphql: dict[str, list[dict]] = {}

    for row in rows:
        source = (row.get("source") or "").lower()
        evidence = _loads(row.get("evidence"))
        if source == "openapi":
            spec_url = (evidence or {}).get("spec_url") or ""
            if not spec_url:
                continue
            openapi.setdefault(spec_url, []).append(row)
        elif source == "graphql":
            gql_url = row.get("url") or ""
            if not gql_url:
                continue
            graphql.setdefault(gql_url, []).append(row)

    groups: list[dict] = []
    for spec_url, bucket in openapi.items():
        groups.append({
            "kind": "openapi",
            "spec_url": spec_url,
            "base_url": _derive_base_url(bucket),
            "rows": bucket,
        })
    for gql_url, bucket in graphql.items():
        groups.append({
            "kind": "graphql",
            "graphql_url": gql_url,
            "base_url": gql_url,
            "rows": bucket,
        })
    return groups


def _derive_base_url(rows: list[dict]) -> str:
    """Use the first row's URL to recover a base URL (scheme + host)."""
    from urllib.parse import urlsplit
    for row in rows:
        u = row.get("url") or ""
        if not u:
            continue
        parts = urlsplit(u)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return ""


def _loads(v: Any) -> Any:
    """asyncpg returns JSONB as either str or already-decoded dict."""
    if v is None or isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return None


# ── Finding emission ─────────────────────────────────────────────


_CHECK_TO_TEMPLATE_ID = {
    "status_code_conformance":    "schemathesis-status-code-conformance",
    "content_type_conformance":   "schemathesis-content-type-conformance",
    "response_schema_conformance": "schemathesis-response-schema-conformance",
    "response_headers_conformance": "schemathesis-response-headers-conformance",
    "negative_data_rejection":    "schemathesis-negative-data-rejection",
    "not_a_server_error":         "schemathesis-server-error",
    "ignored_auth":               "schemathesis-ignored-auth",
}

# Failures where the server exposed a concrete bug (crash / auth bypass /
# schema drift on inputs that are valid per the spec). These go in as
# high-confidence true positives and let the prioritizer rank them above
# Nuclei signature matches.
_TRUE_POSITIVE_CHECKS = {
    "not_a_server_error",
    "response_schema_conformance",
    "ignored_auth",
}

_CHECK_TO_SEVERITY = {
    "not_a_server_error":          "high",       # 5xx — backend bug
    "response_schema_conformance": "medium",     # schema drift / info disclosure surface
    "ignored_auth":                "high",       # auth bypass
    "status_code_conformance":     "low",        # mostly docs drift
    "content_type_conformance":    "low",
    "response_headers_conformance": "low",
    "negative_data_rejection":     "medium",     # accepting junk = input validation gap
}


def _check_to_finding(
    *,
    check_name: str,
    case: Any,
    response: Any,
    message: str,
    target: str,
    endpoint_row: dict,
) -> dict:
    """Normalize a Schemathesis check failure into the nuclei-compatible payload shape."""
    template_id = _CHECK_TO_TEMPLATE_ID.get(check_name, f"schemathesis-{check_name}")
    severity = _CHECK_TO_SEVERITY.get(check_name, "info")
    method = (getattr(case, "method", None) or endpoint_row.get("method") or "").upper()
    path = getattr(case, "path", None) or endpoint_row.get("path") or ""
    status_code = getattr(response, "status_code", None)

    matched_at = target
    try:
        matched_at = f"{method} {path}".strip() or target
    except Exception:
        pass

    curl_command = ""
    try:
        # Schemathesis 3.x: case.as_curl(); 4.x: case.as_curl_command()
        if hasattr(case, "as_curl_command"):
            curl_command = case.as_curl_command()
        elif hasattr(case, "as_curl"):
            curl_command = case.as_curl()
    except Exception:
        curl_command = ""

    finding = {
        "template_id": template_id,
        "severity": severity,
        "name": f"Schemathesis: {check_name.replace('_', ' ')}",
        "description": message or f"Schemathesis check {check_name} failed.",
        "matched_at": matched_at,
        "host": target,
        "port": "",
        "type": "api-fuzz",
        "tags": ["api-fuzz", "schemathesis", check_name],
        "reference": [],
        "classification": {},
        "curl_command": curl_command,
        "matcher_name": check_name,
        "extracted_results": _extracted_evidence(status_code, response, message),
    }

    verdict = "true_positive" if check_name in _TRUE_POSITIVE_CHECKS else "needs_review"
    # Pre-seed llm_validation so the prioritizer can reward
    # schema-confirmed bugs without waiting for the async validator to
    # re-check them. The backend's Finding.llm_validation JSON column
    # takes this through as-is when the ingest path passes it through
    # (see backend/services/vm_scanner._import_nuclei_job_findings).
    finding["llm_validation"] = {
        "verdict": verdict,
        "confidence": 0.9 if verdict == "true_positive" else 0.5,
        "reasoning": (
            f"Schemathesis property-based check {check_name} observed a "
            f"response inconsistent with the declared schema."
        ),
        "source": "schemathesis",
        "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return finding


def _extracted_evidence(status_code: int | None, response: Any, message: str) -> list[str]:
    """Minimal response evidence — status code + short body snippet.

    Kept deliberately tight to avoid leaking large payloads into plugin_output.
    """
    parts: list[str] = []
    if status_code is not None:
        parts.append(f"status_code={status_code}")
    try:
        body = getattr(response, "text", "") or ""
        if body:
            parts.append(f"body[:200]={body[:200]}")
    except Exception:
        pass
    if message:
        parts.append(message[:300])
    return parts


# ── Celery task ──────────────────────────────────────────────────


@celery_app.task(queue="vm_queue", bind=True, max_retries=2)
def run_schemathesis_scan(
    self,
    asset_id: str,
    credentials: dict | None = None,
) -> dict:
    """Fuzz OpenAPI / GraphQL endpoints for a single asset.

    Returns a result payload compatible with ``run_nuclei_scan`` — the
    backend's ``_import_nuclei_job_findings`` happily consumes it because
    the fields it relies on (asset_id, findings[], template_id, severity,
    matched_at, ...) are identical.
    """
    try:
        return _run_async(_run_schemathesis_scan_async(self, asset_id, credentials))
    except Exception as exc:
        logger.exception("run_schemathesis_scan failed for asset %s", asset_id)
        return {
            "asset_id": asset_id,
            "findings": [],
            "endpoints_scanned": 0,
            "specs_scanned": 0,
            "duration_seconds": 0,
            "status": "error",
            "error": str(exc),
            "scanner": "schemathesis",
        }


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _run_schemathesis_scan_async(
    task,
    asset_id: str,
    credentials: dict | None,
) -> dict:
    start = time.monotonic()
    dsn = _normalize_dsn(DATABASE_URL)
    conn = await asyncpg.connect(dsn)

    try:
        asset = await conn.fetchrow(ASSET_CONTEXT_QUERY, uuid.UUID(asset_id))
        if asset is None:
            return {
                "asset_id": asset_id,
                "findings": [],
                "endpoints_scanned": 0,
                "specs_scanned": 0,
                "duration_seconds": round(time.monotonic() - start, 2),
                "status": "skipped",
                "error": "Asset not found",
                "scanner": "schemathesis",
            }

        rows = await conn.fetch(HANDOFF_QUERY, uuid.UUID(asset_id))
        endpoint_rows = [dict(r) for r in rows]
    finally:
        await conn.close()

    if not endpoint_rows:
        return {
            "asset_id": asset_id,
            "org_id": str(asset["org_id"]) if asset["org_id"] is not None else None,
            "findings": [],
            "endpoints_scanned": 0,
            "specs_scanned": 0,
            "duration_seconds": round(time.monotonic() - start, 2),
            "status": "skipped",
            "error": "No openapi/graphql endpoints discovered for this asset",
            "scanner": "schemathesis",
        }

    target = _resolve_target(asset)
    headers = _credentials_to_headers(credentials)
    logger.info(
        "schemathesis start asset=%s target=%s endpoints=%d headers=%s",
        asset_id, target, len(endpoint_rows), list(_redacted_headers_for_log(headers)),
    )

    groups = _group_endpoints_by_spec(endpoint_rows)
    findings: list[dict] = []
    endpoints_scanned = 0
    specs_scanned = 0
    deadline = start + SCAN_TIMEOUT_SECONDS
    status = "complete"

    for group in groups:
        remaining = deadline - time.monotonic()
        if remaining <= 5:
            logger.warning("asset %s: per-asset budget exhausted before spec %s",
                           asset_id, group.get("spec_url") or group.get("graphql_url"))
            status = "partial"
            break

        try:
            group_findings, n_scanned = await _fuzz_group(
                group, target=target, headers=headers, deadline=deadline,
            )
        except _SchemathesisUnavailable as e:
            return {
                "asset_id": asset_id,
                "org_id": str(asset["org_id"]) if asset["org_id"] is not None else None,
                "findings": [],
                "endpoints_scanned": 0,
                "specs_scanned": 0,
                "duration_seconds": round(time.monotonic() - start, 2),
                "status": "error",
                "error": f"schemathesis not available: {e}",
                "scanner": "schemathesis",
            }
        except Exception as e:
            logger.exception("schemathesis spec group failed: %s", group.get("spec_url") or group.get("graphql_url"))
            # Don't let one bad spec abort the whole asset — record and continue.
            status = "partial"
            continue

        findings.extend(group_findings)
        endpoints_scanned += n_scanned
        specs_scanned += 1

    return {
        "asset_id": asset_id,
        "org_id": str(asset["org_id"]) if asset["org_id"] is not None else None,
        "target": target,
        "findings": findings,
        "endpoints_scanned": endpoints_scanned,
        "specs_scanned": specs_scanned,
        "duration_seconds": round(time.monotonic() - start, 2),
        "status": status,
        "scanner": "schemathesis",
    }


def _resolve_target(asset) -> str:
    """Same precedence as nuclei_worker — http_url > hostname > ip."""
    http_url = asset["http_url"] if "http_url" in asset.keys() else None
    if http_url:
        return http_url
    hostname = asset["hostname"] if "hostname" in asset.keys() else None
    if hostname:
        return hostname
    ip = asset["ip"] if "ip" in asset.keys() else None
    return str(ip) if ip else ""


# ── Schemathesis driver ──────────────────────────────────────────


class _SchemathesisUnavailable(ImportError):
    pass


async def _fuzz_group(
    group: dict,
    *,
    target: str,
    headers: dict[str, str],
    deadline: float,
) -> tuple[list[dict], int]:
    """Fuzz one spec group and return its findings + operation count.

    OpenAPI: load spec_url with Schemathesis, iterate operations, generate
    a Hypothesis example per check, call the target, record failures.

    GraphQL: scaffolded — Schemathesis supports GraphQL via
    ``schemathesis.graphql.from_url``; we route to a parallel driver but
    leave the actual loop to follow-up work since GraphQL fuzzing shapes
    differently (queries/mutations vs REST operations).
    """
    try:
        import schemathesis  # type: ignore
    except ImportError as e:
        raise _SchemathesisUnavailable(str(e))

    if group["kind"] == "openapi":
        return await _fuzz_openapi(
            schemathesis, spec_url=group["spec_url"], base_url=group["base_url"],
            rows=group["rows"], target=target, headers=headers, deadline=deadline,
        )
    if group["kind"] == "graphql":
        return await _fuzz_graphql(
            schemathesis, gql_url=group["graphql_url"],
            rows=group["rows"], target=target, headers=headers, deadline=deadline,
        )
    return [], 0


async def _fuzz_openapi(
    schemathesis,
    *,
    spec_url: str,
    base_url: str,
    rows: list[dict],
    target: str,
    headers: dict[str, str],
    deadline: float,
) -> tuple[list[dict], int]:
    """OpenAPI spec → Schemathesis operations → Hypothesis examples → findings."""
    # Schemathesis's `from_url` / `from_uri` is blocking I/O — hop to a
    # thread so we don't block the event loop while it downloads + parses
    # a multi-MB spec.
    schema = await asyncio.to_thread(_load_openapi_schema, schemathesis, spec_url, base_url, headers)

    # Index the discovery-layer rows by (method, path) so we can map
    # Schemathesis's operation objects back to the endpoint the planner
    # ranked (auth_required, parameters). We don't strictly need the
    # match to run the fuzz, but it lets finding payloads cite the
    # original endpoint row in future revisions.
    row_index: dict[tuple[str, str], dict] = {}
    for r in rows:
        key = ((r.get("method") or "GET").upper(), r.get("path") or "")
        row_index.setdefault(key, r)

    findings: list[dict] = []
    operations_run = 0
    operations = list(_iter_operations(schema))[:MAX_OPERATIONS_PER_SPEC]
    logger.info("schemathesis openapi spec=%s operations=%d", spec_url, len(operations))

    for operation in operations:
        if time.monotonic() >= deadline - 2:
            break

        method = getattr(operation, "method", "").upper()
        path = getattr(operation, "path", "")
        row = row_index.get((method, path), {"method": method, "path": path})

        try:
            op_findings = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_operation_examples, schemathesis, operation, headers, target, row,
                ),
                timeout=min(OPERATION_TIMEOUT_SECONDS, max(1, deadline - time.monotonic())),
            )
        except asyncio.TimeoutError:
            logger.warning("schemathesis: operation %s %s timed out after %ds",
                           method, path, OPERATION_TIMEOUT_SECONDS)
            continue
        except Exception:
            logger.exception("schemathesis: operation %s %s raised", method, path)
            continue

        findings.extend(op_findings)
        operations_run += 1

    return findings, operations_run


def _load_openapi_schema(schemathesis, spec_url: str, base_url: str, headers: dict[str, str]):
    """Cross-version wrapper for Schemathesis's schema loaders."""
    loader = None
    # Schemathesis 4.x: schemathesis.openapi.from_url
    if hasattr(schemathesis, "openapi") and hasattr(schemathesis.openapi, "from_url"):
        loader = schemathesis.openapi.from_url
    # Schemathesis 3.x: top-level from_uri
    elif hasattr(schemathesis, "from_uri"):
        loader = schemathesis.from_uri
    if loader is None:
        raise _SchemathesisUnavailable("no compatible Schemathesis loader found")
    return loader(spec_url, base_url=base_url or None, headers=headers or None)


def _iter_operations(schema):
    """Yield operations across Schemathesis major versions."""
    # 4.x: schema.operations()
    if hasattr(schema, "operations") and callable(getattr(schema, "operations", None)):
        try:
            return schema.operations()
        except TypeError:
            pass
    # 3.x: schema.get_all_operations() → iterable of Result(ok=operation)
    if hasattr(schema, "get_all_operations"):
        def _unwrap():
            for item in schema.get_all_operations():
                op = getattr(item, "ok", item)
                if op is not None:
                    yield op
        return _unwrap()
    # Fallback: treat schema itself as iterable of endpoints
    return iter(schema)


def _run_operation_examples(
    schemathesis,
    operation,
    headers: dict[str, str],
    target: str,
    row: dict,
) -> list[dict]:
    """Generate N Hypothesis examples per operation, call, and collect check failures.

    Intentionally hand-rolled (no pytest / no decorator magic) so the
    worker can run in a plain Celery thread with full control over
    timeouts, example counts, and error handling. Uses Schemathesis's
    public ``as_strategy`` / ``validate_response`` API which is stable
    across 3.x and 4.x.
    """
    from hypothesis import strategies as st  # noqa: F401 — imported for version check

    try:
        strategy = operation.as_strategy()
    except Exception as e:
        logger.debug("schemathesis: as_strategy failed for %s: %s", operation, e)
        return []

    findings: list[dict] = []

    # Enumerate checks in a version-agnostic way. `checks.ALL_CHECKS` is
    # 4.x; 3.x exposes the same set as top-level `schemathesis.checks`.
    check_fns = _resolve_checks(schemathesis)

    for _ in range(MAX_EXAMPLES_PER_OPERATION):
        try:
            # Hypothesis' @given provides the .example() helper on strategies.
            case = strategy.example()
        except Exception:
            break

        try:
            response = case.call(headers=headers or None, timeout=10)
        except Exception as e:
            logger.debug("schemathesis: call raised for %s: %s", operation, e)
            continue

        for check_name, check_fn in check_fns.items():
            try:
                check_fn(response, case)
            except AssertionError as exc:
                findings.append(_check_to_finding(
                    check_name=check_name,
                    case=case,
                    response=response,
                    message=str(exc),
                    target=target,
                    endpoint_row=row,
                ))
            except Exception:
                # A check's internal error is not a finding — swallow and
                # continue. Logged at debug to avoid noise on mismatched
                # Schemathesis versions.
                logger.debug("schemathesis: check %s errored", check_name, exc_info=True)

    return findings


def _resolve_checks(schemathesis) -> dict[str, Any]:
    """Return {check_name: callable} from whatever check module this Schemathesis exposes."""
    checks_mod = getattr(schemathesis, "checks", None)
    if checks_mod is None:
        return {}
    out: dict[str, Any] = {}
    for name in _CHECK_TO_TEMPLATE_ID.keys():
        fn = getattr(checks_mod, name, None)
        if callable(fn):
            out[name] = fn
    return out


async def _fuzz_graphql(
    schemathesis,
    *,
    gql_url: str,
    rows: list[dict],
    target: str,
    headers: dict[str, str],
    deadline: float,
) -> tuple[list[dict], int]:
    """GraphQL fuzzing — scaffolded; uses the same shape as OpenAPI.

    GraphQL has its own fuzzing pathologies (introspection-based query
    depth attacks, alias amplification, batched queries) that Nuclei's
    DAST doesn't cover and Schemathesis only partially addresses. For now
    we run Schemathesis's generic loader so 5xx / schema-conformance bugs
    on Query/Mutation fields are caught; dedicated GraphQL checks follow
    once the OpenAPI path is stable.
    """
    if not (hasattr(schemathesis, "graphql") and hasattr(schemathesis.graphql, "from_url")):
        logger.info("schemathesis: installed version lacks graphql.from_url — skipping GraphQL fuzz")
        return [], 0

    schema = await asyncio.to_thread(
        schemathesis.graphql.from_url, gql_url, headers=headers or None,
    )
    findings: list[dict] = []
    operations_run = 0
    operations = list(_iter_operations(schema))[:MAX_OPERATIONS_PER_SPEC]
    row_by_path = {r.get("path") or "": r for r in rows}

    for operation in operations:
        if time.monotonic() >= deadline - 2:
            break
        path = getattr(operation, "path", "") or getattr(operation, "verbose_name", "")
        row = row_by_path.get(path, {"method": "POST", "path": path})
        try:
            op_findings = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_operation_examples, schemathesis, operation, headers, target, row,
                ),
                timeout=OPERATION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            continue
        except Exception:
            logger.exception("schemathesis graphql: operation %s raised", path)
            continue
        findings.extend(op_findings)
        operations_run += 1

    return findings, operations_run
