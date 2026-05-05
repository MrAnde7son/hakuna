"""
NLP Search Parser — converts natural language queries into structured filter params.

Architecture: a declarative `FIELDS` registry drives the bulk of parsing. Each
entry describes a filter key, its target (asset/finding/both), and the regex
patterns that trigger it. Adding a new filter is a one-line registry entry —
the residual-text strip auto-derives consumed patterns from the registry, so
new fields don't silently leak into "Text:" search.

Complex / order-dependent rules (severity multi-match, source extraction,
multi-source counts, sort, residual text) remain as bespoke functions but
register their consumed patterns with the registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple

# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Rule classes — declarative field definitions                             │
# ╰──────────────────────────────────────────────────────────────────────────╯


@dataclass
class _BaseRule:
    target: str          # "finding" | "asset" | "both"
    key: str             # filter dict key
    chip_label: str
    chip_color: str = "#6366f1"

    # Filled by subclasses: regex patterns that this rule consumes from the query
    consumed_patterns: List[str] = field(default_factory=list)

    def _set(self, ctx: "ParseContext", value: Any) -> None:
        if self.target in ("finding", "both"):
            ctx.finding_filters[self.key] = value
        if self.target in ("asset", "both"):
            ctx.asset_filters[self.key] = value

    def apply(self, text: str, ctx: "ParseContext") -> bool:
        raise NotImplementedError


@dataclass
class BoolRule(_BaseRule):
    """Matches any of `aliases` and sets the filter key to `True`."""

    aliases: List[str] = field(default_factory=list)
    chip_value: str = "Yes"

    def __post_init__(self):
        self.consumed_patterns = list(self.aliases)

    def apply(self, text: str, ctx: "ParseContext") -> bool:
        for pat in self.aliases:
            if re.search(pat, text, re.IGNORECASE):
                self._set(ctx, True)
                ctx.chip(self.chip_label, self.chip_value, self.chip_color)
                return True
        return False


@dataclass
class EnumRule(_BaseRule):
    """First-match-wins lookup of (regex, value) pairs."""

    aliases: List[Tuple[str, Any]] = field(default_factory=list)
    label_map: dict = field(default_factory=dict)

    def __post_init__(self):
        self.consumed_patterns = [p for p, _ in self.aliases]

    def apply(self, text: str, ctx: "ParseContext") -> bool:
        for pat, value in self.aliases:
            if re.search(pat, text, re.IGNORECASE):
                self._set(ctx, value)
                disp = self.label_map.get(value, str(value).replace("_", " ").title())
                ctx.chip(self.chip_label, disp, self.chip_color)
                return True
        return False


@dataclass
class ThresholdRule(_BaseRule):
    """Captures a numeric threshold using a keyword anchor.

    Matches both "<keyword> above N" and "above N <keyword>" forms.
    """

    keyword: str = ""
    transform: Optional[Callable[[float], float]] = None
    chip_format: Callable[[float], str] = lambda v: str(v)

    def __post_init__(self):
        self.consumed_patterns = [
            rf"\b{self.keyword}\b.*?(?:above|over|>|>=|at\s*least)?\s*\d+(?:\.\d+)?%?",
            rf"(?:above|over|>|>=|at\s*least)\s*\d+(?:\.\d+)?%?\s*{self.keyword}\b",
        ]

    def apply(self, text: str, ctx: "ParseContext") -> bool:
        m = re.search(
            rf"\b{self.keyword}\b.*?(?:above|over|>|>=|at\s*least)?\s*(\d+(?:\.\d+)?)\s*%?",
            text, re.IGNORECASE,
        ) or re.search(
            rf"(?:above|over|>|>=|at\s*least)\s*(\d+(?:\.\d+)?)\s*%?\s*{self.keyword}\b",
            text, re.IGNORECASE,
        )
        if not m:
            return False
        val = float(m.group(1))
        if self.transform:
            val = self.transform(val)
        self._set(ctx, val)
        ctx.chip(self.chip_label, self.chip_format(val), self.chip_color)
        return True


@dataclass
class CapturedRule(_BaseRule):
    """Captures a string value via a single regex group."""

    pattern: str = ""
    transform: Optional[Callable[[str], str]] = None

    def __post_init__(self):
        self.consumed_patterns = [self.pattern]

    def apply(self, text: str, ctx: "ParseContext") -> bool:
        m = re.search(self.pattern, text, re.IGNORECASE)
        if not m:
            return False
        val = m.group(1)
        if self.transform:
            val = self.transform(val)
        self._set(ctx, val)
        ctx.chip(self.chip_label, val, self.chip_color)
        return True


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Parse context — accumulates filters/chips, shared across rules            │
# ╰──────────────────────────────────────────────────────────────────────────╯


@dataclass
class ParseContext:
    asset_filters: dict = field(default_factory=dict)
    finding_filters: dict = field(default_factory=dict)
    chips: List[dict] = field(default_factory=list)

    def chip(self, label: str, value: str, color: str = "#6366f1"):
        self.chips.append({"label": label, "value": value, "color": color})


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ FIELDS registry — adding a new filter is a one-line entry here            │
# ╰──────────────────────────────────────────────────────────────────────────╯

FIELDS: List[_BaseRule] = [
    # ── Threat intel (boolean) ────────────────────────────────────────────
    BoolRule("finding", "has_exploit", "Has Exploit", "#dc2626", aliases=[
        r"\bexploit(?:able|ed|s)?\b", r"\bweaponized\b",
        r"\bpoc\b", r"\bproof.of.concept\b",
    ]),
    BoolRule("finding", "is_kev", "In KEV", "#b91c1c", aliases=[
        r"\bkev\b", r"\bknown.exploit(?:ed)?\b", r"\bcisa\b",
    ]),
    BoolRule("finding", "ransomware_linked", "Ransomware", "#7c3aed",
             chip_value="Linked", aliases=[r"\bransomware\b"]),
    BoolRule("finding", "trending_in_news", "Trending", "#0ea5e9", aliases=[
        r"\btrending\b", r"\bin.the.news\b", r"\bnewsworthy\b",
    ]),
    BoolRule("finding", "zero_day", "Zero-Day", "#dc2626", aliases=[
        r"\bzero.?day\b", r"\b0.?day\b",
    ]),
    BoolRule("finding", "is_regression", "Regression", "#ef4444", aliases=[
        r"\bregression\b", r"\bregressed\b", r"\breintroduced\b", r"\bcame\s*back\b",
    ]),
    BoolRule("finding", "auto_resolved", "Auto-Resolved", "#16a34a", aliases=[
        r"\bauto.?resolved\b", r"\bautomatically\s*resolved\b",
    ]),
    BoolRule("finding", "has_ttps", "Has TTPs", "#7c3aed", aliases=[
        r"\batt&?ck\b", r"\bttps?\b", r"\bmitre\b",
        r"\btactics?\b", r"\btechniques?\b",
    ]),
    BoolRule("finding", "greynoise_seen", "GreyNoise", "#dc2626",
             chip_value="Seen", aliases=[
        r"\bgreynoise\b", r"\bactively\s*exploited\b",
        r"\bexploited\s*in\s*the\s*wild\b",
    ]),

    # ── LLM / Analyst validation (NEW) ────────────────────────────────────
    EnumRule("finding", "llm_verdict", "Validation", "#7c3aed", aliases=[
        # Specific verdicts win over generic "validated"
        (r"\btrue\s+positives?\b|\bvalidated\s+true\s+positives?\b", "true_positive"),
        (r"\bvalidated\s+false\s+positives?\b|\bllm.?fps?\b|\bai.?fps?\b", "false_positive"),
        (r"\b(?:needs?|need|requires?)\s+review\b|\bunder\s+review\b|\bpending\s+review\b", "needs_review"),
        (r"\bvalidated(?:\s+findings?|\s+vulns?|\s+vulnerabilit(?:y|ies))?\b|\bllm.?validated\b|\bai.?validated\b", "any"),
    ], label_map={
        "true_positive": "True Positive",
        "false_positive": "False Positive",
        "needs_review": "Needs Review",
        "any": "Validated",
    }),

    # ── Validated context — analyst-confirmed (NEW) ───────────────────────
    EnumRule("finding", "ctx_reachability", "Reachability", "#10b981", aliases=[
        (r"\binternet[-\s]facing\s+(?:reachability|context)\b", "internet_facing"),
        (r"\binternal[-\s]only(?:\s+reachable)?\b", "internal_only"),
        (r"\bunreachable\b", "unreachable"),
    ]),
    EnumRule("finding", "ctx_exploitability", "Exploitability", "#f59e0b", aliases=[
        (r"\beasily\s+exploitable\b", "easily_exploitable"),
        (r"\brequires\s+conditions?\b", "requires_conditions"),
        (r"\bnot\s+exploitable\b", "not_exploitable"),
    ]),
    EnumRule("finding", "ctx_accessibility", "Accessibility", "#06b6d4", aliases=[
        (r"\bpublic(?:ly)?\s+accessible\b", "public"),
        (r"\bauthenticated\s+only\b", "authenticated_only"),
        (r"\brestricted\s+access\b", "restricted"),
    ]),

    # ── Compensating controls (NEW) ───────────────────────────────────────
    EnumRule("finding", "control_mitigation_status", "Control", "#16a34a", aliases=[
        (r"\bfully\s+mitigated\b|\bmitigated\s+by\s+controls?\b", "mitigated"),
        (r"\bpartially\s+mitigated\b", "partially_mitigated"),
        (r"\bnot\s+mitigated\b|\bunmitigated\b", "not_mitigated"),
    ], label_map={
        "mitigated": "Mitigated",
        "partially_mitigated": "Partially Mitigated",
        "not_mitigated": "Not Mitigated",
    }),

    # ── SSVC decision (NEW) ───────────────────────────────────────────────
    EnumRule("finding", "ssvc_decision", "SSVC", "#7c3aed", aliases=[
        (r"\bssvc\s+act\b|\bact\s+priority\b", "Act"),
        (r"\bssvc\s+attend\b", "Attend"),
        (r"\bssvc\s+track\*", "Track*"),
        (r"\bssvc\s+track\b", "Track"),
    ]),

    # ── Exploit maturity level (NEW — distinct from has_exploit) ──────────
    EnumRule("finding", "exploit_maturity_level", "Exploit Maturity", "#dc2626", aliases=[
        (r"\bweaponized\s+exploits?\b", "weaponized"),
        (r"\bfunctional\s+exploits?\b", "functional"),
        (r"\bpoc\s+exploits?\b|\bproof.of.concept\s+exploits?\b", "poc"),
    ]),

    # ── Numeric thresholds ────────────────────────────────────────────────
    ThresholdRule("finding", "min_cvss", "Min CVSS", "#f59e0b", keyword="cvss"),
    ThresholdRule("finding", "min_vpr", "Min VPR", "#f59e0b", keyword="vpr"),
    ThresholdRule("finding", "min_priority", "Min Priority", "#f97316", keyword="priority"),
    ThresholdRule("asset", "min_risk", "Min Risk", "#f97316", keyword="risk"),
    ThresholdRule(
        "finding", "min_epss", "Min EPSS", "#8b5cf6", keyword="epss",
        transform=lambda v: v / 100 if v > 1 else v,
        chip_format=lambda v: f"{v:.0%}",
    ),
    ThresholdRule(
        "finding", "exploit_count_min", "Min Exploits", "#dc2626", keyword="exploit\\s*count",
    ),

    # ── Workflow / SLA / Effort ───────────────────────────────────────────
    EnumRule("finding", "workflow_status", "Workflow", "#3b82f6", aliases=[
        (r"(?<!\w)open\s+(?:findings?|vulns?|issues?|tickets?)\b", "open"),
        (r"\ball\s+open\b", "open"),
        (r"(?:^|(?<=\s))open(?:\s*$|(?=\s+(?:and|or|with|in|on|sorted|by)\b))", "open"),
        (r"\bin.progress\b|\bbeing\s*worked\b|\bassigned\b", "in_progress"),
        (r"\baccepted?\s*risk\b|\brisk\s*accepted?\b", "accepted_risk"),
        (r"\bfalse\s*positives?\b|\bfp\b", "false_positive"),
        (r"\bexcepted\b|\bexception\b", "excepted"),
    ], label_map={
        "open": "Open", "in_progress": "In Progress",
        "accepted_risk": "Accepted Risk", "false_positive": "False Positive",
        "excepted": "Excepted",
    }),
    EnumRule("finding", "sla_status", "SLA", "#f59e0b", aliases=[
        (r"\bsla\s*breached?\b|\boverdue\b|\bpast\s*due\b", "breached"),
        (r"\bat\s*risk\b|\bsla\s*at\s*risk\b", "at_risk"),
        (r"\bon\s*track\b", "on_track"),
        (r"\bresolved\b|\bfixed\b|\bclosed\b", "resolved"),
    ]),
    EnumRule("finding", "effort_level", "Effort", "#0ea5e9", aliases=[
        (r"\bquick\s*wins?\b|\beasy\s*fix(?:es)?\b|\bquick\s*fix(?:es)?\b|\beasy\b", "quick_win"),
        (r"\bcomplex\b|\bdifficult\b|\bhard\b", "complex"),
        (r"\bmedium\s*effort\b", "medium"),
    ], label_map={"quick_win": "Quick Win", "complex": "Complex", "medium": "Medium"}),

    # ── Plugin family ─────────────────────────────────────────────────────
    EnumRule("finding", "plugin_family", "Family", "#8b5cf6", aliases=[
        (r"\bweb\s*(app|application|server)?\b", "Web Servers"),
        (r"\bdatabase\b|\bdb\b|\bsql\b|\bmysql\b|\bpostgres\b|\boracle\b", "Databases"),
        (r"\bsmb\b|\bsamba\b", "Windows"),
        (r"\bssl\b|\btls\b|\bcertificate?\b", "General"),
        (r"\bfirewall\b", "Firewalls"),
        (r"\bdns\b", "DNS"),
        (r"\bftp\b", "FTP"),
        (r"\bssh\b", "SSH"),
        (r"\bsmtp\b|\bmail\b|\bemail\b", "SMTP problems"),
        (r"\bsnmp\b", "SNMP"),
        (r"\bvpn\b", "VPN"),
    ]),

    # ── Asset boolean / enum (incl. NEW credentialed, device_type, asset_type)
    BoolRule("asset", "is_internet_facing", "Internet-Facing", "#ef4444", aliases=[
        r"\binternet.?facing\b", r"\bpublic.?facing\b",
        r"\bexposed\b", r"\bexternally\s*accessible\b",
    ]),
    BoolRule("asset", "is_credentialed", "Credentialed", "#16a34a", aliases=[
        r"\bcredential(?:l?ed)?\s*(?:scans?|assets?|hosts?)\b",
        r"\bauthenticated\s*(?:scans?|assets?|hosts?)\b",
    ]),
    EnumRule("asset", "device_type", "Device Type", "#06b6d4", aliases=[
        (r"\bworkstations?\b|\bdesktops?\b|\blaptops?\b", "workstation"),
        (r"\brouters?\b", "router"),
        (r"\bswitch(?:es)?\b", "switch"),
        (r"\bprinters?\b", "printer"),
        (r"\bhypervisors?\b", "hypervisor"),
        (r"\bvoip\s+phones?\b", "voip"),
        (r"\bstorage\s+(?:array|device)s?\b|\bnas\s+devices?\b", "storage"),
    ]),
    EnumRule("asset", "asset_type", "Asset Type", "#06b6d4", aliases=[
        (r"\bweb\s+apps?\b|\bweb\s+applications?\b", "web_app"),
        (r"\bcloud\s+instances?\b|\bec2\s+instances?\b", "cloud_instance"),
        (r"\bapi\s+endpoints?\b", "api_endpoint"),
        (r"\bidentit(?:y|ies)\s+assets?\b", "identity"),
        (r"\bcontainer\s+images?\b", "container_image"),
        (r"\bcode\s+repos?\b|\bgit\s+repos?\b", "code_repo"),
        (r"\bk8s\s+workloads?\b|\bkubernetes\s+workloads?\b", "k8s_workload"),
    ]),
    EnumRule("asset", "environment", "Environment", "#10b981", aliases=[
        (r"\bdmz\b", "dmz"),
        (r"\binternal\b", "internal"),
        (r"\bcloud\b", "cloud"),
        (r"\bexternal\b", "external"),
        (r"\bproduction\b|\bprod\b", "production"),
        (r"\bstaging\b|\bstage\b", "staging"),
        (r"\bdevelopment\b|\bdev\b", "development"),
        (r"\btest(?:ing)?\b|\bqa\b", "test"),
    ], label_map={  # preserve historical chip-cap behavior
        "dmz": "DMZ", "internal": "INTERNAL", "cloud": "CLOUD",
        "external": "EXTERNAL", "production": "PRODUCTION",
        "staging": "STAGING", "development": "DEVELOPMENT", "test": "TEST",
    }),

    # ── Captured-value rules (NEW: business_context, owner, BU) ───────────
    CapturedRule("asset", "business_context", "Business Context", "#10b981",
                 pattern=r"\bbusiness\s+context\s*[:=]\s*[\"']?([a-zA-Z0-9 _-]{2,40}?)[\"']?(?:\s|$)"),
    CapturedRule("finding", "owner_suggestion", "Owner", "#0ea5e9",
                 pattern=r"\bowned?\s+by\s+([a-zA-Z0-9_-]{2,30})"),
]


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Constants used by bespoke parsers (severity, source, sort, intents)      │
# ╰──────────────────────────────────────────────────────────────────────────╯

SEVERITY_WORDS = {
    "critical": 4, "high": 3, "medium": 2, "med": 2, "low": 1,
    "info": 0, "informational": 0,
}

SEVERITY_CONSUMED = [rf"\b{w}\b" for w in SEVERITY_WORDS.keys()]

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
    "crowdstrike": "crowdstrike",
    "wiz": "wiz",
    "tenable": "nessus",
    "tenable_sc": "nessus",
}

_SOURCE_CTX = r"(?:found|discovered?|seen|reported?)\s+by|source(?:\s+is)?|scanned?\s+by|from|via"
_EXCLUDE_SOURCE_CTX = r"not\s+(?:scanned?\s+by|found\s+by|discovered?\s+by|from|via)"

WIDGET_INTENT_PATTERNS = [
    (r"\bfunnels?\b|\bprioritization\s*funnel\b", "funnel"),
    (r"\bheat\s*maps?\b|\bmatrix\b", "heatmap"),
    (r"\btree\s*maps?\b", "treemap"),
    (r"\bradar\s*charts?\b|\bspider\s*charts?\b", "radar"),
    (r"\bgauges?\b|\bdial\b", "gauge"),
    (r"\brisk\s*grades?\b|\b(?:org(?:anization)?\s*)?grade\b|\bletter\s*grade\b|\ba.?[-]f\s*grade\b", "risk_grade"),
    (r"\btrends?\b|\bover\s*time\b|\btimeline\b|\bhistorical\b", "trend"),
    (r"\bbreakdowns?\b|\bdistributions?\b|\bsplit\s*by\b", "breakdown"),
    (r"\btables?\b|\blist\b", "table"),
    (r"\bpie\s*charts?\b|\bdonuts?\b", "pie"),
    (r"\bbar\s*charts?\b", "bar"),
]

METRIC_INTENT_PATTERNS = [
    (r"\bmttr\b|\bmean\s*time\s*to\s*(?:remediate|repair|resolve|fix)\b|\btime\s*to\s*remediate\b", "mttr"),
    (r"\bremediation\s*velocity\b|\bvelocity\b|\bburn\s*down\b|\bburn[-\s]?up\b", "velocity"),
    (r"\b(?:assessment|scan)\s*coverage\b|\bcoverage\s*(?:percent|pct|rate)\b|\bcoverage\b", "coverage"),
    (r"\bcredential(?:l?ed)?\s*(?:assets?|scans?)\b|\bauthenticated\s*scans?\b", "credentialed"),
    (r"\bzombie\s*(?:vulns?|findings?|vulnerabilit(?:y|ies))?\b", "zombie"),
    (r"\b(?:finding|vulnerabilit(?:y|ies)|vuln)\s*age\b|\baging\b|\bage\s*distribution\b", "age"),
    (r"\bby\s*owner\b|\bper\s*owner\b|\bowners?\s*breakdown\b", "by_owner"),
    (r"\bby\s*business\s*unit\b|\bby\s*bu\b|\bby\s*team\b|\bby\s*department\b|\bby\s*tag\b", "by_business_unit"),
    (r"\btop\s*(?:risky\s*)?assets?\b|\briskiest\s*assets?\b|\bmost\s*at[-\s]?risk\s*assets?\b", "top_assets"),
    (r"\btop\s*(?:remediation\s*)?actions?\b|\baggregated\s*solutions?\b|\bsolutions?\s*by\s*owner\b", "remediation_actions"),
    (r"\bquick\s*win\s*actions?\b", "quick_win_actions"),
    (r"\bremediation\s*queue\b", "remediation_queue"),
]

INVENTORY_INTENT_PATTERNS = [
    (r"\bdomain\s*admins?\b", "domain_admins"),
    (r"\blocal\s*admins?\b", "local_admins"),
    (r"\bkerberoast(?:able|ing)?\b", "kerberoastable"),
    (r"\bpassword\s*never\s*expires?\b|\bpw\s*never\s*expires?\b", "pw_never_expires"),
    (r"\bnever\s*changed\s*passwords?\b|\bstale\s*passwords?\b", "pw_never_changed"),
    (r"\bweak\s*password\s*polic(?:y|ies)\b", "weak_pw_policies"),
    (r"\bdomain\s*controllers?\b|\bdcs?\b", "domain_controllers"),
    (r"\bprivileged\s*(?:users?|accounts?|groups?)\b", "privileged"),
    (r"\bexpired\s*certificates?\b|\bexpired\s*certs?\b", "expired_certs"),
    (r"\bexpiring\s*certificates?\b|\bexpiring\s*certs?\b|\bcerts?\s*expiring\s*soon\b", "expiring_certs"),
    (r"\bself.?signed\s*certs?\b|\bself.?signed\s*certificates?\b", "self_signed_certs"),
    (r"\bcertificates?\b|\bcerts?\b|\bssl\b|\btls\b", "certificates"),
    (r"\bwriteable\s*shares?\b|\bwritable\s*shares?\b", "writeable_shares"),
    (r"\bnetwork\s*shares?\b|\bsmb\s*shares?\b", "shares"),
    (r"\blateral\s*movement\b|\blateral\s*paths?\b", "lateral_paths"),
    (r"\bantivirus\b|\bav\s*coverage\b|\bendpoint\s*protection\b|\bedr\b", "av_coverage"),
    (r"\bmissing\s*patch(?:es)?\b|\bunpatched\b", "missing_patches"),
    (r"\bsoftware\s*vendors?\b|\binstalled\s*software\b|\bsoftware\s*inventory\b", "software_inventory"),
    (r"\bos\s*(?:family|families|distribution|breakdown)\b|\boperating\s*system(?:s)?\s*(?:family|families|distribution|breakdown)\b", "os_distribution"),
    (r"\bdevice\s*types?\b", "device_types"),
    (r"\b(?:ai|ml|llm|gen.?ai)\s*(?:tools?|risks?|attack\s*surface|findings?|vulns?|vulnerabilit(?:y|ies))?\b|"
     r"\bartificial\s*intelligence\b|\bmachine\s*learning\b|\bshadow\s*ai\b", "ai_ml"),
]

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

_NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
                 "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Helpers                                                                  │
# ╰──────────────────────────────────────────────────────────────────────────╯


def _first_match(text: str, patterns: List[Tuple]) -> Optional[Any]:
    for pattern, value in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return value
    return None


def _all_consumed_patterns() -> List[str]:
    """Aggregate every regex pattern any rule/intent/heuristic consumes.

    Used by the residual-text strip so new fields don't leak into "Text:" search.
    """
    out: List[str] = []
    for rule in FIELDS:
        out.extend(rule.consumed_patterns)
    out.extend(p for p, _ in WIDGET_INTENT_PATTERNS)
    out.extend(p for p, _ in METRIC_INTENT_PATTERNS)
    out.extend(p for p, _ in INVENTORY_INTENT_PATTERNS)
    out.extend(p for p, _ in SORT_PATTERNS)
    out.extend(p for p, _ in OS_PATTERNS)
    out.extend(SEVERITY_CONSUMED)
    out.extend(_source_alias_residuals())
    return out


# Stop-words and verbs to scrub from residual text (independent of any rule)
_RESIDUAL_STOPWORDS = (
    r"\b(show|find|list|get|give\s*me|with|that\s*have|having|where|are|is|"
    r"all|my|the|a|an|on|in|for|of|and|or|by|per|"
    r"more|than|at|least|over|above|"
    r"linked|one|two|three|four|five|six|seven|eight|nine|ten|several|multiple)\b"
)

# Generic noun forms parsed elsewhere — strip so they don't leak into Text
_RESIDUAL_NOUNS = (
    r"\b(assets?|servers?|hosts?|findings?|vulnerabilit(?:y|ies)|vulns?|"
    r"devices?|machines?|systems?|instances?|workloads?|"
    r"sources?|multi(?:ple)?[\s-]sources?|several|"
    r"plugin\s*(?:id)?|nid|port|priority|greater|"
    r"severity|score|"  # anchor words for sort/threshold rules
    r"most|newest|latest|recent|oldest|earliest|worst|quickest|highest|likely|affected|"
    r"cve-\d{4}-\d{4,7}|t\d{4}(?:\.\d{3})?|"
    r"source(?:\s+is)?|scanned?\s+by|found\s+by|discovered?\s+by|"
    r"stale|inactive|not\s*scanned|criticality|high.?value|hva|tagged?)\b"
)


def _source_alias_residuals() -> List[str]:
    """Source aliases (`nessus`, `qualys`, `easm`, …) consumed by _parse_source."""
    return [rf"\b{re.escape(alias)}\b" for alias in SOURCE_ALIASES.keys()]


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Bespoke parsers — order-dependent / multi-match logic                    │
# ╰──────────────────────────────────────────────────────────────────────────╯


def _parse_severity(ql: str, ctx: ParseContext) -> Optional[int]:
    """Severity supports multiple values + asset-side min_critical/min_high effects."""
    sev_colors = {4: "#ef4444", 3: "#f97316", 2: "#eab308", 1: "#6b7280", 0: "#6b7280"}
    matched = []
    for word, sev_int in SEVERITY_WORDS.items():
        if re.search(rf"\b{word}\b", ql) and sev_int not in [s for _, s in matched]:
            matched.append((word, sev_int))
    if not matched:
        return None
    if len(matched) == 1:
        word, sev_int = matched[0]
        ctx.finding_filters["severity"] = sev_int
        if sev_int == 4:
            ctx.asset_filters.setdefault("min_critical", 1)
        elif sev_int == 3:
            ctx.asset_filters.setdefault("min_high", 1)
        ctx.chip("Severity", word.capitalize(), sev_colors.get(sev_int, "#6366f1"))
        return sev_int
    sev_ints = [s for _, s in matched]
    ctx.finding_filters["severity_list"] = sev_ints
    labels = [w.capitalize() for w, _ in matched]
    ctx.chip("Severity", " + ".join(labels), sev_colors.get(max(sev_ints), "#6366f1"))
    if 4 in sev_ints:
        ctx.asset_filters.setdefault("min_critical", 1)
    if 3 in sev_ints:
        ctx.asset_filters.setdefault("min_high", 1)
    return max(sev_ints)


def _resolve_source(raw: str) -> str:
    return SOURCE_ALIASES.get(raw.strip().lower(), raw.strip().lower())


def _extract_source_from_context(text: str, ctx_pattern: str) -> Optional[str]:
    m = re.search(
        rf"(?:{ctx_pattern})\s+([a-z][a-z0-9_\s-]{{0,30}}?)(?:\s+(?:assets?|hosts?|scan(?:ner)?s?|findings?|but\b|and\b|,|$))",
        text, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    m = re.search(rf"(?:{ctx_pattern})\s+([a-z][a-z0-9_-]{{1,30}})$", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def _parse_source(ql: str, ctx: ParseContext) -> None:
    excl_raw = _extract_source_from_context(ql, _EXCLUDE_SOURCE_CTX)
    incl_raw = _extract_source_from_context(ql, _SOURCE_CTX)
    if not incl_raw:
        for alias in sorted(SOURCE_ALIASES, key=len, reverse=True):
            if re.search(rf"\b{re.escape(alias)}\b", ql, re.IGNORECASE):
                resolved = SOURCE_ALIASES[alias]
                if not excl_raw or _resolve_source(excl_raw) != resolved:
                    incl_raw = alias
                    break
    if incl_raw:
        v = _resolve_source(incl_raw)
        ctx.asset_filters["source"] = v
        ctx.finding_filters["source"] = v
        ctx.chip("Source", v, "#0ea5e9")
    if excl_raw:
        v = _resolve_source(excl_raw)
        ctx.asset_filters["exclude_source"] = v
        ctx.finding_filters["exclude_source"] = v
        ctx.chip("Not from", v, "#6b7280")


def _parse_multi_source(ql: str, ctx: ParseContext) -> None:
    gt = re.search(
        r"(?:more\s+than|over|greater\s+than|>)\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?",
        ql, re.IGNORECASE,
    )
    gte = re.search(
        r"(?:at\s+least|>=)\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?|"
        r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+or\s+more\s+sources?",
        ql, re.IGNORECASE,
    )
    exact = re.search(
        r"\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+sources?\b",
        ql, re.IGNORECASE,
    )
    generic = re.search(
        r"\bmulti(?:ple)?[\s-]sources?\b|\bmore\s+than\s+one\s+source\b|\bseveral\s+sources?\b",
        ql, re.IGNORECASE,
    )

    n = None
    if gt:
        raw = gt.group(1).lower()
        v = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if v is not None:
            n = v + 1
    elif gte:
        raw = (gte.group(1) or gte.group(2) or "").lower()
        v = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if v is not None:
            n = v
    elif generic:
        n = 2
    elif exact:
        raw = exact.group(1).lower()
        v = _NUMBER_WORDS.get(raw, int(raw) if raw.isdigit() else None)
        if v is not None and v >= 2:
            n = v

    if n is not None:
        ctx.asset_filters["min_sources"] = n
        ctx.chip("Min Sources", str(n), "#0ea5e9")


def _parse_one_shots(ql: str, ctx: ParseContext, sev_value: Optional[int]) -> None:
    """Captures, IPs, ports, plugin IDs, criticality, stale, tags, OS, family — order matters."""

    # CVE
    m = re.search(r"\b(cve-\d{4}-\d{4,7})\b", ql, re.IGNORECASE)
    if m:
        ctx.finding_filters["cve"] = m.group(1).upper()
        ctx.chip("CVE", m.group(1).upper(), "#ef4444")

    # MITRE tactic
    m = re.search(
        r"\b(initial.access|execution|persistence|privilege.escalation|"
        r"defense.evasion|credential.access|discovery|lateral.movement|"
        r"collection|exfiltration|command.and.control|impact|reconnaissance|"
        r"resource.development)\b", ql, re.IGNORECASE,
    )
    if m:
        tactic = m.group(1).replace(" ", "-").replace(".", "-").title()
        ctx.finding_filters["tactic"] = tactic
        ctx.chip("Tactic", tactic, "#7c3aed")

    # MITRE technique
    m = re.search(r"\b(t\d{4}(?:\.\d{3})?)\b", ql, re.IGNORECASE)
    if m:
        ctx.finding_filters["technique_id"] = m.group(1).upper()
        ctx.chip("Technique", m.group(1).upper(), "#7c3aed")

    # Min count: "more than N critical/high"
    m = re.search(r"(?:more\s*than|at\s*least|over|>\s*)\s*(\d+)\s*(critical|high|medium|low)", ql)
    if m:
        n, sev = int(m.group(1)), m.group(2).lower()
        if sev == "critical":
            ctx.asset_filters["min_critical"] = n
            ctx.chip("Min Critical", str(n), "#ef4444")
        elif sev == "high":
            ctx.asset_filters["min_high"] = n
            ctx.chip("Min High", str(n), "#f97316")

    # Criticality threshold
    m = re.search(r"\bcriticality\s*(?:above|over|>|>=|at\s*least)?\s*(\d+)", ql)
    if m:
        ctx.asset_filters["criticality"] = int(m.group(1))
        ctx.chip("Min Criticality", str(int(m.group(1))), "#f97316")
    elif re.search(r"\bcritical\s*assets?\b|\bhigh.?value\s*assets?\b|\bhva\b", ql) and sev_value != 4:
        ctx.asset_filters["criticality"] = 8
        ctx.chip("High-Value Assets", "Criticality >= 8", "#f97316")

    # Stale (avoid colliding with "not scanned by X")
    not_scanned_by = re.search(r"\bnot\s+scanned\s+by\b", ql)
    if re.search(r"\bstale\b|\binactive\b", ql) or (
        re.search(r"\bnot\s*scanned\b", ql) and not not_scanned_by
    ):
        ctx.asset_filters["asset_status"] = "stale"
        ctx.chip("Status", "Stale", "#6b7280")

    # Tags
    m = re.search(r"\btag(?:ged)?\s*(?:with\s*|:\s*|=\s*)?[\"']?([a-zA-Z0-9_:, -]+)[\"']?", ql)
    if m:
        v = m.group(1).strip().rstrip(",")
        ctx.asset_filters["tags"] = v
        ctx.finding_filters["tags"] = v
        ctx.chip("Tags", v, "#14b8a6")

    # Plugin / NID
    m = re.search(r"\bplugin\s*(?:id)?\s*#?\s*(\d+)\b", ql) or re.search(r"\bnid\s*#?\s*(\d+)\b", ql)
    if m:
        ctx.finding_filters["search"] = m.group(1)
        ctx.chip("Plugin ID", m.group(1), "#8b5cf6")

    # Port
    m = re.search(r"\bport\s*#?\s*(\d+)\b", ql)
    if m:
        ctx.finding_filters["port"] = m.group(1)
        ctx.chip("Port", m.group(1), "#06b6d4")

    # IP
    m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ql)
    if m:
        ctx.asset_filters["search"] = m.group(1)
        ctx.chip("IP", m.group(1), "#06b6d4")

    # OS — sets asset_filters.search
    for pattern, os_label in OS_PATTERNS:
        if re.search(pattern, ql, re.IGNORECASE):
            ctx.asset_filters["search"] = os_label
            ctx.finding_filters.setdefault("search", os_label)
            ctx.chip("OS", os_label, "#06b6d4")
            break

    # Plugin family — only if no other text search has claimed it
    if "plugin_family" not in ctx.finding_filters and "search" not in ctx.finding_filters:
        # Already handled by FIELDS registry, but skipped if search took priority above.
        # Re-check the family rule explicitly to preserve historical behavior.
        for rule in FIELDS:
            if isinstance(rule, EnumRule) and rule.key == "plugin_family":
                rule.apply(ql, ctx)
                break


def _parse_intents(ql: str, ctx: ParseContext) -> Tuple[List[str], List[str], List[str]]:
    widget_hints, metric_intents, inventory_intents = [], [], []
    for pattern, hint in WIDGET_INTENT_PATTERNS:
        if re.search(pattern, ql, re.IGNORECASE) and hint not in widget_hints:
            widget_hints.append(hint)

    metric_label = {
        "mttr": "MTTR", "velocity": "Velocity", "coverage": "Coverage",
        "credentialed": "Credentialed", "zombie": "Zombie Vulns",
        "age": "Finding Age", "by_owner": "By Owner",
        "by_business_unit": "By Business Unit", "top_assets": "Top Assets",
        "remediation_actions": "Top Actions", "quick_win_actions": "Quick Win Actions",
        "remediation_queue": "Remediation Queue",
    }
    for pattern, intent in METRIC_INTENT_PATTERNS:
        if re.search(pattern, ql, re.IGNORECASE) and intent not in metric_intents:
            metric_intents.append(intent)
    for m in metric_intents:
        ctx.chip("Topic", metric_label.get(m, m), "#0ea5e9")

    inv_label = {
        "domain_admins": "Domain Admins", "local_admins": "Local Admins",
        "kerberoastable": "Kerberoastable", "pw_never_expires": "Password Never Expires",
        "pw_never_changed": "Password Never Changed", "weak_pw_policies": "Weak PW Policies",
        "domain_controllers": "Domain Controllers", "privileged": "Privileged",
        "expired_certs": "Expired Certs", "expiring_certs": "Expiring Certs",
        "self_signed_certs": "Self-Signed Certs", "certificates": "Certificates",
        "writeable_shares": "Writeable Shares", "shares": "Network Shares",
        "lateral_paths": "Lateral Paths", "av_coverage": "AV Coverage",
        "missing_patches": "Missing Patches", "software_inventory": "Software Inventory",
        "os_distribution": "OS Distribution", "device_types": "Device Types",
        "ai_ml": "AI / ML",
    }
    for pattern, intent in INVENTORY_INTENT_PATTERNS:
        if re.search(pattern, ql, re.IGNORECASE) and intent not in inventory_intents:
            inventory_intents.append(intent)
    for i in inventory_intents:
        ctx.chip("Inventory", inv_label.get(i, i), "#14b8a6")
    if "ai_ml" in inventory_intents and "plugin_family" not in ctx.finding_filters:
        ctx.finding_filters["plugin_family"] = "Artificial Intelligence"

    return widget_hints, metric_intents, inventory_intents


def _residual_search(ql: str, ctx: ParseContext) -> None:
    """Strip everything any rule could have matched, keep the rest as text search.

    Order matters: rule-consumed patterns first (they may match multi-word phrases
    like "credentialed assets"), then noun/stopword scrubbing.
    """
    residual = ql
    # Two-pass: multi-word patterns first ("easily exploitable") so they consume
    # themselves before single-word patterns ("exploitable") leave fragments behind.
    all_pats = _all_consumed_patterns()
    multi_word = [p for p in all_pats if r"\s" in p or " " in p]
    single_word = [p for p in all_pats if p not in multi_word]
    for pat in multi_word + single_word:
        try:
            residual = re.sub(pat, " ", residual, flags=re.IGNORECASE)
        except re.error:
            continue
    residual = re.sub(_RESIDUAL_STOPWORDS, " ", residual, flags=re.IGNORECASE)
    residual = re.sub(_RESIDUAL_NOUNS, " ", residual, flags=re.IGNORECASE)
    # Strip standalone numbers (args to thresholds etc.) but preserve hyphenated tokens
    residual = re.sub(r"(?<![\w-])#?\d+(?:\.\d+)?%?(?![\w-])", " ", residual)
    residual = re.sub(r"(?<!\w)[^\w\s]+(?!\w)", " ", residual)
    residual = re.sub(r"\s{2,}", " ", residual).strip()
    if len(residual) > 2 and "search" not in ctx.asset_filters:
        ctx.asset_filters["search"] = residual
        ctx.finding_filters["search"] = residual
        ctx.chip("Text", residual, "#6366f1")


# ╭──────────────────────────────────────────────────────────────────────────╮
# │ Public entrypoint                                                        │
# ╰──────────────────────────────────────────────────────────────────────────╯


def parse_nlp_query(query: str) -> dict:
    """
    Parse a natural language query into structured filter params.

    Returns:
        {
            "asset_filters": {...},
            "finding_filters": {...},
            "sort": {sort_by, order} | None,
            "explanation": [{label, value, color}],
            "widget_hints": [...],
            "metric_intents": [...],
            "inventory_intents": [...],
            "original_query": str,
        }
    """
    q = query.strip()
    ql = q.lower()
    ctx = ParseContext()

    # Order matters: severity → registry rules → bespoke parsers
    sev_value = _parse_severity(ql, ctx)

    # Run all FIELDS — but skip plugin_family here; one-shots handles it after OS.
    for rule in FIELDS:
        if isinstance(rule, EnumRule) and rule.key == "plugin_family":
            continue
        rule.apply(ql, ctx)

    _parse_source(ql, ctx)
    _parse_multi_source(ql, ctx)
    _parse_one_shots(ql, ctx, sev_value)

    widget_hints, metric_intents, inventory_intents = _parse_intents(ql, ctx)

    sort_pref = _first_match(ql, SORT_PATTERNS)
    sort_result = {"sort_by": sort_pref[0], "order": sort_pref[1]} if sort_pref else None

    _residual_search(ql, ctx)

    return {
        "asset_filters": ctx.asset_filters,
        "finding_filters": ctx.finding_filters,
        "sort": sort_result,
        "explanation": ctx.chips,
        "widget_hints": widget_hints,
        "metric_intents": metric_intents,
        "inventory_intents": inventory_intents,
        "original_query": q,
    }
