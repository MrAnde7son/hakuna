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

# ── Sort / ordering ────────────────────────────────────────────────────────────

SORT_PATTERNS = [
    (r"\bmost\s*critical\b|\bhighest\s*risk\b|\bworst\b|\bmost\s*severe\b", ("priority_score", "desc")),
    (r"\bnewest\b|\blatest\b|\brecent\b", ("created_at", "desc")),
    (r"\boldest\b|\bearli(?:est|er)\b", ("created_at", "asc")),
    (r"\bhighest\s*cvss\b|\bworst\s*cvss\b", ("cvss3_base_score", "desc")),
    (r"\bquick(?:est)?\s*wins?\b", ("effort_level", "asc")),
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

    # ── Severity ───────────────────────────────────────────────────────────────
    sev_value = None
    for word, sev_int in SEVERITY_WORDS.items():
        if re.search(rf"\b{word}\b", ql):
            sev_value = sev_int
            finding_filters["severity"] = sev_int
            # For assets, map severity to min counts
            if sev_int == 4:
                asset_filters["min_critical"] = asset_filters.get("min_critical", 1)
                chip("Severity", word.capitalize(), "#ef4444")
            elif sev_int == 3:
                asset_filters["min_high"] = asset_filters.get("min_high", 1)
                chip("Severity", word.capitalize(), "#f97316")
            elif sev_int == 2:
                chip("Severity", word.capitalize(), "#eab308")
            elif sev_int in (0, 1):
                chip("Severity", word.capitalize(), "#6b7280")
            else:
                chip("Severity", word.capitalize(), "#6366f1")
            break

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

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_match = re.search(r"risk\s*(?:score\s*)?(?:above|over|>|>=|at\s*least)?\s*(\d+(?:\.\d+)?)", ql) or \
                 re.search(r"(?:above|over|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*risk", ql)
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

    # ── Sort preference ───────────────────────────────────────────────────────
    sort_pref = _first_match(ql, SORT_PATTERNS)
    sort_result = None
    if sort_pref:
        sort_result = {"sort_by": sort_pref[0], "order": sort_pref[1]}

    # ── Bare-word text search (if nothing else caught it) ─────────────────────
    # Strip known keywords, what remains is a text search term
    residual = re.sub(
        r"\b(show|find|list|get|give\s*me|with|that\s*have|having|where|are|is|all|my|the|a|an|on|in|for|of|and|or|more|than|at|least|over|above|linked)\b",
        " ", ql, flags=re.IGNORECASE
    )
    # Remove already-parsed tokens
    residual = re.sub(
        r"\b(critical|high|medium|low|info|informational|severity|risk|score|"
        r"exploit(?:able|ed|s)?|weaponized|poc|proof.of.concept|kev|cisa|ransomware|"
        r"trending|news|newsworthy|quick\s*wins?|easy\s*fix(?:es)?|quick\s*fix(?:es)?|easy|complex|hard|difficult|"
        r"dmz|internal|cloud|external|production|prod|"
        r"windows|linux|ubuntu|debian|centos|red\s*hat|rhel|macos?|osx|solaris|aix|freebsd|cisco|"
        r"sla|breached|overdue|resolved|fixed|closed|on\s*track|at\s*risk|past\s*due|"
        r"assets?|servers?|hosts?|findings?|vulnerabilit(?:y|ies)|vulns?|"
        r"epss|cvss|cve-\d{4}-\d{4,7}|\d+(?:\.\d+)?%?)\b",
        " ", residual, flags=re.IGNORECASE
    )
    # Strip leading dashes/punctuation
    residual = re.sub(r"[^\w\s]", " ", residual)
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
