"""
NLP Search Parser — converts natural language queries into structured filter params.
Rule-based with regex patterns covering the most common security search intents.
"""

import re
from typing import Any, List, Optional, Tuple

# ── Severity ──────────────────────────────────────────────────────────────────

SEVERITY_WORDS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "med": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}

# ── OS / Platform ──────────────────────────────────────────────────────────────

OS_PATTERNS = [
    (r"\bwindows\b", "Windows"),
    (r"\blinux\b", "Linux"),
    (r"\bubuntu\b", "Ubuntu"),
    (r"\bdebian\b", "Debian"),
    (r"\bcentos\b", "CentOS"),
    (r"\bred\s*hat\b|\brhel\b", "Red Hat"),
    (r"\bmacos?\b|\bosx\b", "macOS"),
    (r"\bsolaris\b", "Solaris"),
    (r"\baix\b", "AIX"),
    (r"\bfreebsd\b", "FreeBSD"),
    (r"\bcisco\b", "Cisco"),
]

# ── Environment ────────────────────────────────────────────────────────────────

ENV_PATTERNS = [
    (r"\bdmz\b", "dmz"),
    (r"\binternal\b", "internal"),
    (r"\bcloud\b", "cloud"),
    (r"\bexternal\b", "external"),
    (r"\bproduction\b|\bprod\b", "production"),
    (r"\bstaging\b|\bstage\b", "staging"),
    (r"\bdevelopment\b|\bdev\b", "development"),
    (r"\btest(?:ing)?\b|\bqa\b", "test"),
]

# ── Workflow status ───────────────────────────────────────────────────────────

WORKFLOW_PATTERNS = [
    (r"\bopen\s*(?:findings?|vulns?)?\b", "open"),
    (r"\bin.progress\b|\bbeing\s*worked\b|\bassigned\b", "in_progress"),
    (r"\baccepted?\s*risk\b|\brisk\s*accepted?\b", "accepted_risk"),
    (r"\bfalse\s*positives?\b|\bfp\b", "false_positive"),
    (r"\bexcepted\b|\bexception\b", "excepted"),
]

# ── Plugin family keywords ─────────────────────────────────────────────────────

FAMILY_PATTERNS = [
    (r"\bweb\s*(app|application|server)?\b", "Web Servers"),
    (r"\bdatabase\b|\bdb\b|\bsql\b|\bmysql\b|\bpostgres\b|\boracle\b", "Databases"),
    (r"\bsmb\b|\bsamba\b", "Windows"),
    (r"\bssl\b|\btls\b|\bcertificate?\b", "General"),
    (r"\bfirewall\b|\bfirewall\b", "Firewalls"),
    (r"\bdns\b", "DNS"),
    (r"\bftp\b", "FTP"),
    (r"\bssh\b", "SSH"),
    (r"\bsmtp\b|\bmail\b|\bemail\b", "SMTP problems"),
    (r"\bsnmp\b", "SNMP"),
    (r"\bvpn\b", "VPN"),
]

# ── Effort level ───────────────────────────────────────────────────────────────

EFFORT_PATTERNS = [
    (r"\bquick\s*wins?\b|\beasy\s*fix(?:es)?\b|\bquick\s*fix(?:es)?\b|\beasy\b", "quick_win"),
    (r"\bcomplex\b|\bdifficult\b|\bhard\b", "complex"),
    (r"\bmedium\s*effort\b", "medium"),
]

# ── SLA status ─────────────────────────────────────────────────────────────────

SLA_PATTERNS = [
    (r"\bsla\s*breached?\b|\boverdue\b|\bpast\s*due\b", "breached"),
    (r"\bat\s*risk\b|\bsla\s*at\s*risk\b", "at_risk"),
    (r"\bon\s*track\b", "on_track"),
    (r"\bresolved\b|\bfixed\b|\bclosed\b", "resolved"),
]

# ── Source / scanner type ──────────────────────────────────────────────────────

# Known aliases: input keyword → normalized source_systems value
SOURCE_ALIASES: dict[str, str] = {
    "nessus": "nessus",
    "vm": "vm_scanner",
    "vm scan": "vm_scanner",
    "vm scanner": "vm_scanner",
    "vm_scanner": "vm_scanner",
    "qualys": "qualys",
    "rapid7": "rapid7",
    "openvas": "openvas",
    "nexpose": "nexpose",
    "easm": "easm",
    "external attack surface": "easm",
    "attack surface management": "easm",
}

# Context words that introduce a source reference (positive)
_SOURCE_CTX = r"(?:found|discovered?|seen|reported?)\s+by|source(?:\s+is)?|scanned?\s+by|from|via"
# Context words that introduce a source exclusion (negative)
_EXCLUDE_SOURCE_CTX = r"not\s+(?:scanned?\s+by|found\s+by|discovered?\s+by|from|via)"

# ── Sort / ordering ────────────────────────────────────────────────────────────

SORT_PATTERNS = [
    (r"\bmost\s*critical\b|\bhighest\s*risk\b|\bworst\b|\bmost\s*severe\b", ("priority_score", "desc")),
    (r"\bnewest\b|\blatest\b|\brecent\b", ("created_at", "desc")),
    (r"\boldest\b|\bearli(?:est|er)\b", ("created_at", "asc")),
    (r"\bhighest\s*cvss\b|\bworst\s*cvss\b", ("cvss3_base_score", "desc")),
    (r"\bhighest\s*epss\b|\bmost\s*likely\s*exploited\b", ("epss_score", "desc")),
    (r"\bhighest\s*vpr\b|\bworst\s*vpr\b", ("vpr_score", "desc")),
    (r"\bquick(?:est)?\s*wins?\b", ("effort_level", "asc")),
    (r"\bmost\s*affected\b|\bmost\s*assets\b", ("risk_score", "desc")),
]


def _first_match(text: str, patterns: List[Tuple]) -> Optional[Any]:
    """Return the value of the first matching pattern."""
    for pattern, value in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return value
    return None


def _all_matches(text: str, patterns: List[Tuple]) -> List[Any]:
    return [value for pattern, value in patterns if re.search(pattern, text, re.IGNORECASE)]


def parse_nlp_query(query: str) -> dict:
    """
    Parse a natural language query into structured filter params.

    Returns:
        {
            "asset_filters": {...},   # params for /api/assets
            "finding_filters": {...}, # params for /api/findings
            "explanation": [{"label": str, "value": str, "color": str}],
            "original_query": str,
        }
    """
    q = query.strip()
    ql = q.lower()

    asset_filters: dict = {}
    finding_filters: dict = {}
    chips: list[dict] = []

    def chip(label: str, value: str, color: str = "#6366f1"):
        chips.append({"label": label, "value": value, "color": color})

    # ── CVE reference ──────────────────────────────────────────────────────────
    cve_match = re.search(r"\b(cve-\d{4}-\d{4,7})\b", ql, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(1).upper()
        finding_filters["cve"] = cve_id
        chip("CVE", cve_id, "#ef4444")

    # ── Severity (supports multiple: "critical and high") ───────────────────
    sev_value = None
    sev_colors = {4: "#ef4444", 3: "#f97316", 2: "#eab308", 1: "#6b7280", 0: "#6b7280"}
    matched_sevs = []
    for word, sev_int in SEVERITY_WORDS.items():
        if re.search(rf"\b{word}\b", ql):
            if sev_int not in [s for _, s in matched_sevs]:
                matched_sevs.append((word, sev_int))
    if len(matched_sevs) == 1:
        word, sev_int = matched_sevs[0]
        sev_value = sev_int
        finding_filters["severity"] = sev_int
        if sev_int == 4:
            asset_filters["min_critical"] = asset_filters.get("min_critical", 1)
        elif sev_int == 3:
            asset_filters["min_high"] = asset_filters.get("min_high", 1)
        chip("Severity", word.capitalize(), sev_colors.get(sev_int, "#6366f1"))
    elif len(matched_sevs) > 1:
        sev_ints = [s for _, s in matched_sevs]
        sev_value = max(sev_ints)
        finding_filters["severity_list"] = sev_ints
        labels = [w.capitalize() for w, _ in matched_sevs]
        chip("Severity", " + ".join(labels), sev_colors.get(max(sev_ints), "#6366f1"))
        if 4 in sev_ints:
            asset_filters["min_critical"] = asset_filters.get("min_critical", 1)
        if 3 in sev_ints:
            asset_filters["min_high"] = asset_filters.get("min_high", 1)

    # ── Exploit / KEV / Ransomware ─────────────────────────────────────────────
    if re.search(r"\bexploit(?:able|ed|s)?\b|\bweaponized\b|\bpoc\b|\bproof.of.concept\b", ql):
        finding_filters["has_exploit"] = True
        chip("Has Exploit", "Yes", "#dc2626")

    if re.search(r"\bkev\b|\bknown.exploit(?:ed)?\b|\bcisa\b", ql):
        finding_filters["is_kev"] = True
        chip("In KEV", "Yes", "#b91c1c")

    if re.search(r"\bransomware\b", ql):
        finding_filters["ransomware_linked"] = True
        chip("Ransomware", "Linked", "#7c3aed")

    if re.search(r"\btrending\b|\bin.the.news\b|\bnewsworthy\b", ql):
        finding_filters["trending_in_news"] = True
        chip("Trending", "Yes", "#0ea5e9")

    # ── Zero-day ──────────────────────────────────────────────────────────────
    if re.search(r"\bzero.?day\b|\b0.?day\b", ql):
        finding_filters["zero_day"] = True
        chip("Zero-Day", "Yes", "#dc2626")

    # ── Regression ────────────────────────────────────────────────────────────
    if re.search(r"\bregression\b|\bregressed\b|\breintroduced\b|\bcame\s*back\b", ql):
        finding_filters["is_regression"] = True
        chip("Regression", "Yes", "#ef4444")

    # ── Auto-resolved ─────────────────────────────────────────────────────────
    if re.search(r"\bauto.?resolved\b|\bautomatically\s*resolved\b", ql):
        finding_filters["auto_resolved"] = True
        chip("Auto-Resolved", "Yes", "#16a34a")

    # ── Workflow status ───────────────────────────────────────────────────────
    wf = _first_match(ql, WORKFLOW_PATTERNS)
    if wf:
        finding_filters["workflow_status"] = wf
        label_map = {
            "open": "Open", "in_progress": "In Progress",
            "accepted_risk": "Accepted Risk", "false_positive": "False Positive",
            "excepted": "Excepted",
        }
        chip("Workflow", label_map.get(wf, wf), "#3b82f6")

    # ── MITRE ATT&CK / TTPs ──────────────────────────────────────────────────
    if re.search(r"\batt&?ck\b|\bttps?\b|\bmitre\b|\btactics?\b|\btechniques?\b", ql):
        finding_filters["has_ttps"] = True
        chip("Has TTPs", "Yes", "#7c3aed")

    tactic_match = re.search(
        r"\b(initial.access|execution|persistence|privilege.escalation|"
        r"defense.evasion|credential.access|discovery|lateral.movement|"
        r"collection|exfiltration|command.and.control|impact|reconnaissance|"
        r"resource.development)\b", ql, re.IGNORECASE
    )
    if tactic_match:
        tactic_val = tactic_match.group(1).replace(" ", "-").replace(".", "-").title()
        finding_filters["tactic"] = tactic_val
        chip("Tactic", tactic_val, "#7c3aed")

    technique_match = re.search(r"\b(t\d{4}(?:\.\d{3})?)\b", ql, re.IGNORECASE)
    if technique_match:
        finding_filters["technique_id"] = technique_match.group(1).upper()
        chip("Technique", technique_match.group(1).upper(), "#7c3aed")

    # ── VPR score ─────────────────────────────────────────────────────────────
    vpr_match = re.search(r"\bvpr\b.*?(?:above|over|>|>=|at\s*least)?\s*(\d+(?:\.\d+)?)", ql) or \
                re.search(r"(?:above|over|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*vpr", ql)
    if vpr_match:
        vpr_val = float(vpr_match.group(1))
        finding_filters["min_vpr"] = vpr_val
        chip("Min VPR", str(vpr_val), "#f59e0b")

    # ── Internet-facing ───────────────────────────────────────────────────────
    if re.search(r"\binternet.?facing\b|\bpublic.?facing\b|\bexposed\b|\bexternally\s*accessible\b", ql):
        asset_filters["is_internet_facing"] = True
        chip("Internet-Facing", "Yes", "#ef4444")

    # ── Asset criticality ─────────────────────────────────────────────────────
    crit_match = re.search(r"\bcriticality\s*(?:above|over|>|>=|at\s*least)?\s*(\d+)", ql)
    if crit_match:
        crit_val = int(crit_match.group(1))
        asset_filters["criticality"] = crit_val
        chip("Min Criticality", str(crit_val), "#f97316")
    elif re.search(r"\bcritical\s*assets?\b|\bhigh.?value\s*assets?\b|\bhva\b", ql) and sev_value != 4:
        asset_filters["criticality"] = 8
        chip("High-Value Assets", "Criticality >= 8", "#f97316")

    # ── Source / scanner type ──────────────────────────────────────────────────
    # Works with any source value (integration builder sources, custom parsers, etc.)
    # Known aliases (e.g. "vm" → "vm_scanner", "tenable" → "nessus") are applied.
    # Handles both positive ("found by X") and negative ("not scanned by X") forms.

    def _resolve_source(raw: str) -> str:
        """Normalize a raw source keyword to its stored source_systems value."""
        key = raw.strip().lower()
        return SOURCE_ALIASES.get(key, key)

    def _extract_source_from_context(text: str, context_pattern: str) -> Optional[str]:
        """Extract the source name following a context phrase."""
        m = re.search(
            rf"(?:{context_pattern})\s+([a-z][a-z0-9_\s-]{{0,30}}?)(?:\s+(?:assets?|hosts?|scan(?:ner)?s?|findings?|but\b|and\b|,|$))",
            text, re.IGNORECASE
        )
        if m:
            return m.group(1).strip()
        # Also try end-of-string match
        m = re.search(rf"(?:{context_pattern})\s+([a-z][a-z0-9_-]{{1,30}})$", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return None

    _exclude_raw = _extract_source_from_context(ql, _EXCLUDE_SOURCE_CTX)
    _include_raw = _extract_source_from_context(ql, _SOURCE_CTX)

    # Also detect bare known source names used as primary filter (e.g. "easm assets", "nessus findings")
    if not _include_raw:
        for alias in sorted(SOURCE_ALIASES, key=len, reverse=True):  # longest first
            if re.search(rf"\b{re.escape(alias)}\b", ql, re.IGNORECASE):
                # Don't use it if it's already the exclude source
                resolved = SOURCE_ALIASES[alias]
                if not _exclude_raw or _resolve_source(_exclude_raw) != resolved:
                    _include_raw = alias
                    break

    if _include_raw:
        src_val = _resolve_source(_include_raw)
        asset_filters["source"] = src_val
        finding_filters["source"] = src_val
        chip("Source", src_val, "#0ea5e9")
    if _exclude_raw:
        excl_val = _resolve_source(_exclude_raw)
        asset_filters["exclude_source"] = excl_val
        finding_filters["exclude_source"] = excl_val
        chip("Not from", excl_val, "#6b7280")

    # ── Multi-source assets ───────────────────────────────────────────────────
    # Handles: "two sources", "more than one source", "multiple sources", etc.
    _NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
                     "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}

    # "more than N/word sources", "over N sources", "at least N sources"
    _multi_src_gt = re.search(
        r"(?:more\s+than|over|greater\s+than|>)\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?",
        ql, re.IGNORECASE
    )
    # "at least N sources", "N or more sources"
    _multi_src_gte = re.search(
        r"(?:at\s+least|>=)\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?|"
        r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+or\s+more\s+sources?",
        ql, re.IGNORECASE
    )
    # "N sources" (exact or bare: "two sources", "3 sources")
    _multi_src_exact = re.search(
        r"\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?\b",
        ql, re.IGNORECASE
    )
    # "multiple sources", "multi-source", "more than one source"
    _multi_src_generic = re.search(
        r"\bmulti(?:ple)?[\s-]sources?\b|\bmore\s+than\s+one\s+source\b|\bseveral\s+sources?\b",
        ql, re.IGNORECASE
    )

    _min_sources = None
    if _multi_src_gt:
        raw = _multi_src_gt.group(1).lower()
        n = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if n is not None:
            _min_sources = n + 1
    elif _multi_src_gte:
        raw = (_multi_src_gte.group(1) or _multi_src_gte.group(2) or "").lower()
        n = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if n is not None:
            _min_sources = n
    elif _multi_src_generic:
        _min_sources = 2
    elif _multi_src_exact:
        raw = _multi_src_exact.group(1).lower()
        n = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if n is not None and n >= 2:
            _min_sources = n

    if _min_sources is not None:
        asset_filters["min_sources"] = _min_sources
        chip("Min Sources", str(_min_sources), "#0ea5e9")

    # ── Stale assets ──────────────────────────────────────────────────────────
    # "not scanned by X" is a source filter above; bare "not scanned" = stale
    _not_scanned_by = re.search(r"\bnot\s+scanned\s+by\b", ql)
    if re.search(r"\bstale\b|\binactive\b", ql) or (
        re.search(r"\bnot\s*scanned\b", ql) and not _not_scanned_by
    ):
        asset_filters["asset_status"] = "stale"
        chip("Status", "Stale", "#6b7280")

    # ── Tags ──────────────────────────────────────────────────────────────────
    tag_match = re.search(r"\btag(?:ged)?\s*(?:with\s*|:\s*|=\s*)?[\"']?([a-zA-Z0-9_:, -]+)[\"']?", ql)
    if tag_match:
        tag_val = tag_match.group(1).strip().rstrip(",")
        asset_filters["tags"] = tag_val
        finding_filters["tags"] = tag_val
        chip("Tags", tag_val, "#14b8a6")

    # ── EPSS threshold ─────────────────────────────────────────────────────────
    epss_match = re.search(r"\bepss\b.*?(\d+(?:\.\d+)?)\s*%?", ql) or \
                 re.search(r"(\d+(?:\.\d+)?)\s*%?\s*epss", ql)
    if epss_match:
        epss_val = float(epss_match.group(1))
        if epss_val > 1:
            epss_val = epss_val / 100
        finding_filters["min_epss"] = epss_val
        chip("Min EPSS", f"{epss_val:.0%}", "#8b5cf6")

    # ── CVSS score ────────────────────────────────────────────────────────────
    cvss_match = re.search(r"\bcvss\b.*?(?:above|over|>|>=|at\s*least)?\s*(\d+(?:\.\d+)?)", ql) or \
                 re.search(r"(?:above|over|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*cvss", ql)
    if cvss_match:
        cvss_val = float(cvss_match.group(1))
        finding_filters["min_cvss"] = cvss_val  # handled in endpoint
        chip("Min CVSS", str(cvss_val), "#f59e0b")

    # ── Min count: "more than N critical / high" ───────────────────────────────
    count_match = re.search(
        r"(?:more\s*than|at\s*least|over|>\s*)\s*(\d+)\s*(critical|high|medium|low)", ql
    )
    if count_match:
        n = int(count_match.group(1))
        sev_word = count_match.group(2).lower()
        if sev_word == "critical":
            asset_filters["min_critical"] = n
            chip("Min Critical", str(n), "#ef4444")
        elif sev_word == "high":
            asset_filters["min_high"] = n
            chip("Min High", str(n), "#f97316")

    # ── Priority score ───────────────────────────────────────────────────────
    prio_match = re.search(r"priority\s*(?:score\s*)?(?:above|over|greater\s*than|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)", ql) or \
                 re.search(r"(?:above|over|greater\s*than|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*priority", ql)
    if prio_match:
        prio_val = float(prio_match.group(1))
        finding_filters["min_priority"] = prio_val
        chip("Min Priority", str(prio_val), "#f97316")

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_match = re.search(r"risk\s*(?:score\s*)?(?:above|over|greater\s*than|>|>=|at\s*least)?\s*(\d+(?:\.\d+)?)", ql) or \
                 re.search(r"(?:above|over|greater\s*than|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*risk", ql)
    if risk_match:
        risk_val = float(risk_match.group(1))
        asset_filters["min_risk"] = risk_val
        chip("Min Risk", str(risk_val), "#f97316")

    # ── OS / platform ─────────────────────────────────────────────────────────
    for pattern, os_label in OS_PATTERNS:
        if re.search(pattern, ql, re.IGNORECASE):
            asset_filters["search"] = os_label
            finding_filters["search"] = finding_filters.get("search") or os_label
            chip("OS", os_label, "#06b6d4")
            break

    # ── Environment ───────────────────────────────────────────────────────────
    env = _first_match(ql, ENV_PATTERNS)
    if env:
        asset_filters["environment"] = env
        chip("Environment", env.upper(), "#10b981")

    # ── Plugin family ─────────────────────────────────────────────────────────
    family = _first_match(ql, FAMILY_PATTERNS)
    if family and "search" not in finding_filters:
        finding_filters["plugin_family"] = family
        chip("Family", family, "#8b5cf6")

    # ── Effort level ──────────────────────────────────────────────────────────
    effort = _first_match(ql, EFFORT_PATTERNS)
    if effort:
        finding_filters["effort_level"] = effort
        label_map = {"quick_win": "Quick Win", "complex": "Complex", "medium": "Medium"}
        chip("Effort", label_map.get(effort, effort), "#0ea5e9")

    # ── SLA status ────────────────────────────────────────────────────────────
    sla = _first_match(ql, SLA_PATTERNS)
    if sla:
        finding_filters["sla_status"] = sla
        chip("SLA", sla.replace("_", " ").title(), "#f59e0b")

    # ── Plugin ID ──────────────────────────────────────────────────────────────
    plugin_match = re.search(r"\bplugin\s*(?:id)?\s*#?\s*(\d+)\b", ql) or \
                   re.search(r"\bnid\s*#?\s*(\d+)\b", ql)
    if plugin_match:
        pid = plugin_match.group(1)
        finding_filters["search"] = pid
        chip("Plugin ID", pid, "#8b5cf6")

    # ── Port number ──────────────────────────────────────────────────────────
    port_match = re.search(r"\bport\s*#?\s*(\d+)\b", ql)
    if port_match:
        port_val = port_match.group(1)
        finding_filters["port"] = port_val
        chip("Port", port_val, "#06b6d4")

    # ── IP address ───────────────────────────────────────────────────────────
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ql)
    if ip_match:
        ip_val = ip_match.group(1)
        asset_filters["search"] = ip_val
        chip("IP", ip_val, "#06b6d4")

    # ── Sort preference ───────────────────────────────────────────────────────
    sort_pref = _first_match(ql, SORT_PATTERNS)
    sort_result = None
    if sort_pref:
        sort_result = {"sort_by": sort_pref[0], "order": sort_pref[1]}

    # ── Bare-word text search (if nothing else caught it) ─────────────────────
    # Strip known keywords, what remains is a text search term
    residual = re.sub(
        r"\b(show|find|list|get|give\s*me|with|that\s*have|having|where|are|is|all|my|the|a|an|on|in|for|of|and|or|more|than|at|least|over|above|linked|one|two|three|four|five|six|seven|eight|nine|ten|several|multiple)\b",
        " ", ql, flags=re.IGNORECASE
    )
    # Remove already-parsed tokens (including their numeric args)
    residual = re.sub(
        r"\b(critical|high|medium|low|info|informational|severity|risk|score|"
        r"exploit(?:able|ed|s)?|weaponized|poc|proof.of.concept|kev|cisa|ransomware|"
        r"trending|news|newsworthy|quick\s*wins?|easy\s*fix(?:es)?|quick\s*fix(?:es)?|easy|complex|hard|difficult|"
        r"dmz|internal|cloud|external|production|prod|staging|stage|development|dev|test(?:ing)?|qa|"
        r"windows|linux|ubuntu|debian|centos|red\s*hat|rhel|macos?|osx|solaris|aix|freebsd|cisco|"
        r"sla|breached|overdue|resolved|fixed|closed|on\s*track|at\s*risk|past\s*due|"
        r"open|in.progress|assigned|accepted?\s*risk|false\s*positives?|fp|excepted|exception|"
        r"zero.?day|0.?day|regression|regressed|reintroduced|auto.?resolved|"
        r"att&?ck|ttps?|mitre|tactics?|techniques?|"
        r"initial.access|execution|persistence|privilege.escalation|defense.evasion|"
        r"credential.access|discovery|lateral.movement|collection|exfiltration|"
        r"command.and.control|impact|reconnaissance|resource.development|"
        r"internet.?facing|public.?facing|exposed|externally\s*accessible|"
        r"stale|inactive|not\s*scanned|criticality|high.?value|hva|"
        r"tagged?|"
        r"assets?|servers?|hosts?|findings?|vulnerabilit(?:y|ies)|vulns?|sources?|multi(?:ple)?[\s-]sources?|several|"
        r"plugin\s*(?:id)?|nid|port|priority|greater|vpr|"
        r"most|newest|latest|recent|oldest|earliest|worst|quickest|highest|likely|affected|"
        r"epss|cvss|cve-\d{4}-\d{4,7}|t\d{4}(?:\.\d{3})?|"
        r"nessus|vm\s*scan(?:ner)?|qualys|rapid\s*7|openvas|nexpose|"
        r"easm|external\s+attack\s+surface|attack\s+surface\s+management|"
        r"source(?:\s+is)?|scanned?\s+by|found\s+by|discovered?\s+by)\b",
        " ", residual, flags=re.IGNORECASE
    )
    # Remove standalone numbers (args to parsed patterns) but keep numbers
    # attached to words via hyphens (e.g. "MS17-010")
    residual = re.sub(r"(?<![\w-])#?\d+(?:\.\d+)?%?(?![\w-])", " ", residual)
    # Strip punctuation only between spaces (preserve intra-word hyphens like MS17-010)
    residual = re.sub(r"(?<!\w)[^\w\s]+(?!\w)", " ", residual)
    residual = re.sub(r"\s{2,}", " ", residual).strip()
    # Only use residual as text search if it's meaningful (> 2 chars) and no OS search set
    if len(residual) > 2 and "search" not in asset_filters:
        asset_filters["search"] = residual
        finding_filters["search"] = residual
        chip("Text", residual, "#6366f1")

    return {
        "asset_filters": asset_filters,
        "finding_filters": finding_filters,
        "sort": sort_result,
        "explanation": chips,
        "original_query": q,
    }
