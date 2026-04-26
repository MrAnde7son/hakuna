"""Plugin metadata registry for EASM-emitted findings.

One source of truth for plugin_family, CWE IDs, OWASP Top 10 mappings, and
canonical references per EASM finding type. Refactored out of
services/easm.py:_generate_easm_findings so:

  - Compliance mappings can rely on stable plugin_family strings and
    populated cwe_ids without parsing free-form solution text.
  - Adding a new EASM finding type requires touching one table, not
    threading metadata through 600 lines of inline emission code.

Wildcard plugin IDs (e.g. EASM-PORT-443, EASM-TECH-NGINX, EASM-CVE-*)
share the same metadata regardless of the discriminator suffix; the
wildcard prefix is registered once.

Stub entries for EASM-SUBDOMAIN-TAKEOVER, EASM-EXPOSED-ADMIN-PANEL,
EASM-DIRECTORY-LISTING, and EASM-LEAKED-CREDENTIAL are present so
compliance rules referencing those CWEs validate at load time. The
scanner has to start emitting the corresponding signal before any
findings appear under those plugin_ids.
"""

from __future__ import annotations

from typing import Iterable, Optional, TypedDict


class EasmPluginMetadata(TypedDict, total=False):
    family: str                   # plugin_family written to Finding
    cwe_ids: list[str]            # canonical CWE list, e.g. ["CWE-79"]
    references: list[str]         # canonical reference URLs
    owasp_top10: list[str]        # e.g. ["A02:2021"]


# Exact-match plugin IDs.
_EXACT: dict[str, EasmPluginMetadata] = {
    "EASM-TLS-CERT": {
        "family": "EASM: TLS/SSL",
        "cwe_ids": ["CWE-295", "CWE-324"],
        "references": [
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://cwe.mitre.org/data/definitions/324.html",
        ],
        "owasp_top10": ["A02:2021"],
    },
    "EASM-TLS-WEAK": {
        "family": "EASM: TLS/SSL",
        "cwe_ids": ["CWE-326", "CWE-327"],
        "references": [
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
        ],
        "owasp_top10": ["A02:2021"],
    },
    "EASM-TLS-CIPHER-ACCEPTED": {
        "family": "EASM: TLS/SSL",
        "cwe_ids": ["CWE-327"],
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
        "owasp_top10": ["A02:2021"],
    },
    "EASM-CERT-CHAIN-UNTRUSTED": {
        "family": "EASM: TLS/SSL",
        "cwe_ids": ["CWE-295"],
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
        "owasp_top10": ["A02:2021"],
    },
    "EASM-CERT-OCSP": {
        "family": "EASM: TLS/SSL",
        "cwe_ids": ["CWE-299"],
        "references": ["https://cwe.mitre.org/data/definitions/299.html"],
        "owasp_top10": ["A02:2021"],
    },
    "EASM-CERT-CAA-MISMATCH": {
        "family": "EASM: DNS",
        "cwe_ids": ["CWE-345"],
        "references": [
            "https://cwe.mitre.org/data/definitions/345.html",
            "https://datatracker.ietf.org/doc/html/rfc8659",
        ],
    },
    "EASM-HTTP-HEADER-WEAK": {
        # CWE union is computed at emit time from the per-issue map below
        # because a single finding bundles multiple sub-issues with
        # different CWEs.
        "family": "EASM: HTTP",
        "cwe_ids": [],
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "EASM-COOKIE-WEAK": {
        "family": "EASM: HTTP",
        "cwe_ids": [],
        "references": ["https://owasp.org/www-community/HttpOnly"],
    },
    "EASM-HTTP-SERVICE": {
        "family": "EASM: Web Service",
        "cwe_ids": [],
        "references": [],
    },
    "EASM-DNS-RECORDS": {
        "family": "EASM: DNS",
        "cwe_ids": [],
        "references": [],
    },
    # ── Stubs for emissions pending in hakuna-scanner ────────────
    "EASM-SUBDOMAIN-TAKEOVER": {
        "family": "EASM: Takeover",
        "cwe_ids": ["CWE-1385"],
        "references": [
            "https://cwe.mitre.org/data/definitions/1385.html",
            "https://owasp.org/www-community/attacks/Subdomain_takeover",
        ],
        "owasp_top10": ["A05:2021"],
    },
    "EASM-EXPOSED-ADMIN-PANEL": {
        "family": "EASM: ExposedPanel",
        "cwe_ids": ["CWE-284"],
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "owasp_top10": ["A05:2021"],
    },
    "EASM-DIRECTORY-LISTING": {
        "family": "EASM: Exposure",
        "cwe_ids": ["CWE-548"],
        "references": ["https://cwe.mitre.org/data/definitions/548.html"],
        "owasp_top10": ["A05:2021"],
    },
    "EASM-LEAKED-CREDENTIAL": {
        "family": "EASM: LeakedCredential",
        "cwe_ids": ["CWE-798", "CWE-522"],
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        "owasp_top10": ["A07:2021"],
    },
}


# Prefix-match plugin IDs (everything after the prefix is a discriminator).
# Order does not matter — these are mutually exclusive prefixes.
_PREFIX: list[tuple[str, EasmPluginMetadata]] = [
    ("EASM-TECH-", {
        "family": "EASM: Web Technology",
        "cwe_ids": [],
        "references": [],
    }),
    ("EASM-PORT-", {
        "family": "EASM: Port Scan",
        "cwe_ids": [],
        "references": [],
    }),
    ("EASM-EXPOSED-DB-", {
        "family": "EASM: Exposed Service",
        "cwe_ids": ["CWE-284", "CWE-668"],
        "references": [
            "https://cwe.mitre.org/data/definitions/284.html",
            "https://cwe.mitre.org/data/definitions/668.html",
        ],
        "owasp_top10": ["A05:2021"],
    }),
    ("EASM-CDN-", {
        "family": "EASM: Infrastructure",
        "cwe_ids": [],
        "references": [],
    }),
    ("EASM-WAF-", {
        "family": "EASM: Infrastructure",
        "cwe_ids": [],
        "references": [],
    }),
    # CWE for CVE findings is backfilled by enrich_findings_from_threat_intel
    # (PR 0a) from ThreatCVE.cwe_ids; we leave the registry value empty so
    # the union doesn't double-count.
    ("EASM-CVE-", {
        "family": "EASM: CVE",
        "cwe_ids": [],
        "references": [],
    }),
]


# HTTP header / cookie audit sub-issue id → CWE list. Used by
# EASM-HTTP-HEADER-WEAK and EASM-COOKIE-WEAK to compute the CWE union for
# the bundled finding (one Finding row covers all matching sub-issues).
_SUBISSUE_CWE: dict[str, list[str]] = {
    # Headers
    "hsts-missing":                    ["CWE-319"],
    "hsts-weak":                       ["CWE-319"],
    "csp-missing":                     ["CWE-1021", "CWE-79"],
    "clickjacking-protection-missing": ["CWE-1021"],
    "content-type-sniffing":           ["CWE-436"],
    "referrer-policy-missing":         ["CWE-200"],
    "permissions-policy-missing":      ["CWE-693"],
    # Cookies
    "cookie-insecure":                 ["CWE-614"],
    "cookie-not-httponly":             ["CWE-1004"],
    "cookie-samesite-missing":         ["CWE-1275"],
    "cookie-samesite-none-insecure":   ["CWE-1275"],
}


def metadata_for(plugin_id: str) -> EasmPluginMetadata:
    """Return the metadata for an EASM plugin_id.

    Falls back to {family: "EASM: Other", cwe_ids: [], references: []} when
    the plugin_id is unknown — keeps the writer side well-defined while still
    surfacing unmapped types in logs.
    """
    if not plugin_id:
        return {"family": "EASM: Other", "cwe_ids": [], "references": []}
    if plugin_id in _EXACT:
        return _EXACT[plugin_id]
    for prefix, meta in _PREFIX:
        if plugin_id.startswith(prefix):
            return meta
    return {"family": "EASM: Other", "cwe_ids": [], "references": []}


def cwe_ids_for_subissues(subissue_ids: Iterable[str]) -> list[str]:
    """Return the deduped CWE list for a set of audit sub-issue ids."""
    seen: set[str] = set()
    union: list[str] = []
    for sid in subissue_ids:
        for cwe in _SUBISSUE_CWE.get(sid, []):
            if cwe not in seen:
                seen.add(cwe)
                union.append(cwe)
    return union


def references_dict(refs: Iterable[str]) -> dict:
    """Wrap reference URLs into the {urls: [...]} shape used on Finding.references."""
    urls = [r for r in refs if isinstance(r, str) and r.strip()]
    return {"urls": urls} if urls else {}


def seed_easm_context(
    *,
    is_kev: bool = False,
    exploit_available: bool = False,
) -> dict:
    """Derive ctx_* fields for an EASM finding.

    EASM is by construction internet-facing and unauthenticated; the only
    variable signal is exploitability, which we lift when the finding is
    KEV-listed or has a public exploit. Analysts can override via the
    standard user_edited_fields path on the upsert handler.
    """
    if is_kev or exploit_available:
        exploit_ctx: Optional[str] = "easily_exploitable"
    else:
        exploit_ctx = None
    return {
        "ctx_reachability": "internet_facing",
        "ctx_accessibility": "public",
        "ctx_exploitability": exploit_ctx,
    }
