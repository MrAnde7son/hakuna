"""Deep TLS audit: cipher enumeration, chain validation, OCSP, and CAA.

Sits alongside tlsx. Where tlsx records the *negotiated* cipher + version
from one handshake, this module enumerates what the server will *accept*
across every TLS version, validates the presented chain against a trust
store, checks OCSP, and cross-checks the issuer against DNS CAA records.

Split in two:

* ``grade()`` — pure function over already-parsed inputs (sslyze summary +
  CAA records). Unit-tested without network. Emits severity-tagged issues
  the backend turns into Findings.

* ``run_deep_audit()`` — thin orchestrator that calls sslyze + dnspython
  and feeds their output into ``grade()``. Best-effort: any sub-check that
  fails degrades to a "check_failed" issue rather than raising.

Output shape (stored on ``asset_ports.tls_deep_audit``):

    {
      "host": "example.com", "port": 443,
      "ciphers_accepted": {"TLSv1.2": [...], "TLSv1.3": [...]},
      "versions_accepted": ["TLSv1.2", "TLSv1.3"],
      "weak_ciphers_accepted": ["RC4-MD5", ...],
      "chain": {"trusted": bool, "errors": [...], "issuer_cn": "...", "issuer_org": "..."},
      "ocsp": {"status": "good"|"revoked"|"unknown"|"error", "detail": "..."},
      "caa": {"records": ["0 issue \"letsencrypt.org\""], "authorized": bool},
      "issues": [{"id": "...", "severity": int, "detail": "..."}],
    }
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# ── Weak-cipher classification ─────────────────────────────────────────────
#
# Mirrors the EASM-TLS-WEAK regex in backend/services/easm.py so a cipher
# flagged on the negotiated handshake would also be flagged here when offered.
# Match is case-insensitive on the IANA / OpenSSL cipher string.
_WEAK_CIPHER_RE = re.compile(r"RC4|3DES|DES[- _]|NULL|EXPORT|anon|MD5", re.IGNORECASE)
_DEPRECATED_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


# ── CAA authorization check ────────────────────────────────────────────────

_CAA_ISSUE_RE = re.compile(r'^\s*\d+\s+issue(?:wild)?\s+"([^"]+)"\s*;?', re.IGNORECASE)


_CAA_STOPWORDS = {
    "inc", "llc", "ltd", "limited", "authority", "authorities",
    "trust", "services", "service", "corporation", "corp",
    "gmbh", "sa", "ag", "co", "com", "org", "net",
    "group", "technologies", "technology", "the",
}


def _caa_allows_issuer(caa_records: list[str], issuer_org: str | None) -> bool | None:
    """Decide whether a CAA record set authorizes the cert's issuer.

    Returns True (authorized), False (records present but disallow issuer),
    or None (no CAA records — RFC 8659 says any CA may issue).

    Matching is fuzzy because CAA domains ("letsencrypt.org", "digicert.com")
    rarely match the cert Organization field verbatim ("Let's Encrypt",
    "DigiCert Inc"). Strategy: collapse both sides to an alphanumeric brand
    string with stopwords removed, then check substring in either direction
    with a minimum length threshold to kill false positives.
    """
    if not caa_records:
        return None
    if not issuer_org:
        # Records exist but we can't identify the cert issuer — fail closed,
        # surface as an issue for operator review.
        return False

    def _tokens(s: str) -> list[str]:
        return [
            t for t in re.split(r"[^a-z0-9]+", s.lower())
            if t and t not in _CAA_STOPWORDS
        ]

    issuer_tokens = _tokens(issuer_org)
    if not issuer_tokens:
        return False
    issuer_brand = "".join(issuer_tokens)

    for record in caa_records:
        match = _CAA_ISSUE_RE.match(record)
        if not match:
            continue
        allowed_domain = match.group(1).lower().strip()
        if not allowed_domain or allowed_domain == ";":
            # `0 issue ";"` explicitly denies all CAs — never a match.
            continue
        domain_brand = "".join(_tokens(allowed_domain))
        if len(issuer_brand) >= 4 and len(domain_brand) >= 4:
            if issuer_brand in domain_brand or domain_brand in issuer_brand:
                return True
        # Also try per-token match against the domain brand (handles
        # multi-word issuers where only one token appears in the domain,
        # e.g. "DigiCert Inc" ↔ "digicert.com").
        for tok in issuer_tokens:
            if len(tok) >= 4 and tok in domain_brand:
                return True

    return False


# ── Pure grader ────────────────────────────────────────────────────────────


def grade(
    *,
    host: str,
    port: int,
    ciphers_accepted: dict[str, list[str]],
    chain_trusted: bool | None,
    chain_errors: list[str] | None,
    ocsp_status: str | None,
    ocsp_detail: str | None,
    caa_records: list[str] | None,
    issuer_cn: str | None,
    issuer_org: str | None,
) -> dict:
    """Build the normalized ``tls_deep_audit`` dict from raw inputs.

    Callers supply the already-parsed sslyze summary and CAA records; this
    function does no I/O. Keeps grading deterministic and testable.
    """
    issues: list[dict] = []

    versions_accepted = [v for v, c in (ciphers_accepted or {}).items() if c]
    deprecated_accepted = [v for v in versions_accepted if v in _DEPRECATED_VERSIONS]
    weak_accepted: list[str] = []
    for version, cipher_list in (ciphers_accepted or {}).items():
        for cipher in cipher_list:
            if _WEAK_CIPHER_RE.search(cipher):
                weak_accepted.append(f"{version}: {cipher}")

    # Deprecated versions get Critical for SSLv2/SSLv3, High for TLS 1.0/1.1.
    for v in deprecated_accepted:
        if v in {"SSLv2", "SSLv3"}:
            issues.append({
                "id": "tls-broken-version-accepted",
                "severity": 4,
                "detail": f"Server accepts {v} — broken, must be disabled",
            })
        else:
            issues.append({
                "id": "tls-deprecated-version-accepted",
                "severity": 3,
                "detail": f"Server accepts {v} — deprecated by PCI-DSS and browsers",
            })

    if weak_accepted:
        issues.append({
            "id": "tls-weak-cipher-accepted",
            "severity": 3,
            "detail": "Server accepts weak cipher suites: " + ", ".join(sorted(set(weak_accepted))[:8]),
        })

    # Chain validation
    if chain_trusted is False:
        issues.append({
            "id": "cert-chain-untrusted",
            "severity": 3,
            "detail": "Presented chain did not validate to a trusted root: "
                      + "; ".join(chain_errors or ["unknown error"]),
        })

    # OCSP
    if ocsp_status == "revoked":
        issues.append({
            "id": "cert-revoked",
            "severity": 4,
            "detail": f"OCSP reports certificate as revoked: {ocsp_detail or 'no detail'}",
        })
    elif ocsp_status == "error":
        issues.append({
            "id": "cert-ocsp-check-failed",
            "severity": 1,
            "detail": f"OCSP lookup failed: {ocsp_detail or 'no detail'}",
        })
    # "good" and "unknown" are not graded as issues — "unknown" is common for
    # certs without OCSP URLs and isn't actionable on its own.

    # CAA
    caa_authorized = _caa_allows_issuer(caa_records or [], issuer_org)
    if caa_authorized is False:
        issues.append({
            "id": "cert-caa-mismatch",
            "severity": 2,
            "detail": (
                f"CAA records for {host} do not authorize the certificate's "
                f"issuer ({issuer_org or issuer_cn or 'unknown'}). "
                f"CAA: {'; '.join(caa_records or [])}"
            ),
        })

    return {
        "host": host,
        "port": port,
        "ciphers_accepted": ciphers_accepted or {},
        "versions_accepted": versions_accepted,
        "weak_ciphers_accepted": weak_accepted,
        "chain": {
            "trusted": chain_trusted,
            "errors": chain_errors or [],
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
        },
        "ocsp": {"status": ocsp_status, "detail": ocsp_detail},
        "caa": {"records": caa_records or [], "authorized": caa_authorized},
        "issues": issues,
    }


# ── sslyze + DNS orchestration ─────────────────────────────────────────────


_SSLYZE_CIPHER_COMMANDS = None  # lazy — sslyze is a heavyweight import


def _import_sslyze():
    """Defer the sslyze import until the stage actually runs.

    Keeps unit tests of ``grade()`` free of the sslyze dep, and keeps scanner
    startup fast on workers that don't run this stage.
    """
    global _SSLYZE_CIPHER_COMMANDS
    from sslyze import (
        Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand,
    )

    if _SSLYZE_CIPHER_COMMANDS is None:
        _SSLYZE_CIPHER_COMMANDS = {
            ScanCommand.SSL_2_0_CIPHER_SUITES: "SSLv2",
            ScanCommand.SSL_3_0_CIPHER_SUITES: "SSLv3",
            ScanCommand.TLS_1_0_CIPHER_SUITES: "TLSv1.0",
            ScanCommand.TLS_1_1_CIPHER_SUITES: "TLSv1.1",
            ScanCommand.TLS_1_2_CIPHER_SUITES: "TLSv1.2",
            ScanCommand.TLS_1_3_CIPHER_SUITES: "TLSv1.3",
        }

    return Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand


def _lookup_caa(hostname: str, timeout: float = 3.0) -> list[str]:
    """Return raw CAA records for ``hostname`` (walks up if leaf has none).

    Returns ``[]`` when no CAA records exist anywhere in the hierarchy —
    per RFC 8659 that means any CA may issue.
    """
    try:
        import dns.resolver
    except ImportError:
        logger.warning("dnspython not installed — skipping CAA lookup")
        return []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    current = hostname.rstrip(".")
    while "." in current:
        try:
            answers = resolver.resolve(current, "CAA")
            records = [r.to_text() for r in answers]
            if records:
                return records
        except Exception:
            pass
        # Walk up one label — CAA is inherited from the closest ancestor.
        current = current.split(".", 1)[1]
    return []


def _parse_sslyze_result(scan_result: Any) -> dict:
    """Translate one sslyze ServerScanResult into the kwargs grade() expects."""
    ciphers: dict[str, list[str]] = {}

    ssr = scan_result.scan_result
    if ssr is None:
        return {
            "ciphers_accepted": {},
            "chain_trusted": None, "chain_errors": ["sslyze returned no result"],
            "ocsp_status": "error", "ocsp_detail": "sslyze returned no result",
            "issuer_cn": None, "issuer_org": None,
        }

    Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand = _import_sslyze()

    for cmd, label in _SSLYZE_CIPHER_COMMANDS.items():
        attempt = ssr.__dict__.get(cmd.value) if hasattr(ssr, "__dict__") else None
        if attempt is None:
            attempt = getattr(ssr, cmd.value, None)
        if attempt is None or attempt.status != "COMPLETED" or attempt.result is None:
            continue
        accepted = [c.cipher_suite.name for c in (attempt.result.accepted_cipher_suites or [])]
        if accepted:
            ciphers[label] = accepted

    # Certificate info
    chain_trusted: bool | None = None
    chain_errors: list[str] = []
    ocsp_status: str | None = None
    ocsp_detail: str | None = None
    issuer_cn: str | None = None
    issuer_org: str | None = None

    certinfo = getattr(ssr, "certificate_info", None)
    if certinfo and getattr(certinfo, "result", None):
        deployments = certinfo.result.certificate_deployments or []
        if deployments:
            dep = deployments[0]

            validation_results = dep.path_validation_results or []
            trusted_count = sum(1 for r in validation_results if r.was_validation_successful)
            chain_trusted = trusted_count > 0 and trusted_count == len(validation_results)
            chain_errors = [
                f"{r.trust_store.name}: {r.openssl_error_string}"
                for r in validation_results
                if not r.was_validation_successful and r.openssl_error_string
            ]

            # Issuer fields from the leaf cert.
            leaf = dep.received_certificate_chain[0] if dep.received_certificate_chain else None
            if leaf is not None:
                try:
                    issuer = leaf.issuer
                    issuer_cn = next(
                        (a.value for a in issuer if a.oid.dotted_string == "2.5.4.3"),
                        None,
                    )
                    issuer_org = next(
                        (a.value for a in issuer if a.oid.dotted_string == "2.5.4.10"),
                        None,
                    )
                except Exception:
                    pass

            ocsp_response = getattr(dep, "ocsp_response", None)
            if ocsp_response is None:
                ocsp_status = "unknown"
                ocsp_detail = "No OCSP response stapled"
            else:
                status_attr = getattr(ocsp_response, "status", None) or getattr(ocsp_response, "response_status", None)
                status_str = str(status_attr).lower() if status_attr is not None else ""
                if "good" in status_str:
                    ocsp_status = "good"
                elif "revoked" in status_str:
                    ocsp_status = "revoked"
                    ocsp_detail = getattr(ocsp_response, "revocation_reason", None)
                else:
                    ocsp_status = "unknown"
                    ocsp_detail = status_str or "OCSP status not parseable"

    return {
        "ciphers_accepted": ciphers,
        "chain_trusted": chain_trusted,
        "chain_errors": chain_errors,
        "ocsp_status": ocsp_status,
        "ocsp_detail": ocsp_detail,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
    }


def audit_host(host: str, port: int = 443, caa_timeout: float = 3.0) -> dict:
    """Run the full deep audit against one (host, port) and return the graded result.

    This is a blocking network call — callers should batch with a thread pool
    bounded by settings.tls_deep_audit_concurrency.
    """
    Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand = _import_sslyze()

    commands = set(_SSLYZE_CIPHER_COMMANDS.keys()) | {ScanCommand.CERTIFICATE_INFO}

    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port),
        scan_commands=commands,
    )

    scanner = Scanner()
    scanner.queue_scans([request])

    scan_result = None
    for result in scanner.get_results():
        scan_result = result
        break

    if scan_result is None or scan_result.scan_status == "ERROR_NO_CONNECTIVITY":
        return grade(
            host=host, port=port,
            ciphers_accepted={},
            chain_trusted=None, chain_errors=["no connectivity"],
            ocsp_status="error", ocsp_detail="sslyze could not connect",
            caa_records=[], issuer_cn=None, issuer_org=None,
        )

    parsed = _parse_sslyze_result(scan_result)
    caa_records = _lookup_caa(host, timeout=caa_timeout)

    return grade(
        host=host, port=port,
        caa_records=caa_records,
        **parsed,
    )
