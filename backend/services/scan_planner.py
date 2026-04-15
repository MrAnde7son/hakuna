"""Adaptive Scan Planner — LLM-driven per-asset scan planning.

Uses an LLM to analyze an asset's risk profile and generate an optimized
scan plan. The planner considers:
- Asset criticality and exposure
- Technology stack and services
- Historical findings and their severity
- Time since last scan
- Available scanning tools and their capabilities

Output is a structured ScanPlan that the VM scanner can execute.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime

from sqlalchemy import text, func
from sqlalchemy.orm import Session

from models.models import Asset, Finding, Scan

logger = logging.getLogger(__name__)


@dataclass
class ScanAction:
    """A single scanning action within a plan."""
    tool: str                          # nuclei, nmap, katana, testssl, nikto, etc.
    priority: int                      # 1-5 (1=highest)
    tags: list[str] = field(default_factory=list)        # nuclei tags to use
    templates: list[str] = field(default_factory=list)   # specific template paths
    flags: dict = field(default_factory=dict)             # tool-specific flags
    timeout: int = 600                 # seconds
    reasoning: str = ""                # why this action was chosen


@dataclass
class ScanPlan:
    """An adaptive scan plan for a single asset."""
    asset_id: int
    asset_hostname: str
    risk_tier: str                     # critical, high, medium, low
    actions: list[ScanAction] = field(default_factory=list)
    total_estimated_duration: int = 0  # seconds
    skip_reason: str | None = None     # if the planner recommends skipping
    reasoning: str = ""                # overall reasoning
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


# ── Risk tier thresholds ──
RISK_TIERS = {
    "critical": {"min_criticality": 8, "min_risk_score": 7.0},
    "high":     {"min_criticality": 6, "min_risk_score": 5.0},
    "medium":   {"min_criticality": 4, "min_risk_score": 3.0},
    "low":      {"min_criticality": 0, "min_risk_score": 0.0},
}

# ── Available tools and their capabilities ──
TOOL_CAPABILITIES = {
    "nuclei": {
        "description": "Template-based vulnerability scanner. Routes templates by CPE/tech/port.",
        "input": "URL, hostname, or IP",
        "strengths": "CVE detection, misconfiguration, exposure checks",
        "when_to_use": "Always — primary vuln scanner",
    },
    "nmap": {
        "description": "Network scanner with NSE scripts for service fingerprinting.",
        "input": "IP or hostname + ports",
        "strengths": "Service version detection, OS fingerprinting, banner grabbing",
        "when_to_use": "When service versions are unknown or ports need deeper inspection",
    },
    "katana": {
        "description": "Web crawler for endpoint discovery.",
        "input": "URL",
        "strengths": "Discovers hidden endpoints, API routes, JS-referenced paths",
        "when_to_use": "Web applications with complex routing, SPAs, API servers",
    },
    "testssl": {
        "description": "TLS/SSL configuration analyzer.",
        "input": "hostname:port",
        "strengths": "Weak ciphers, protocol issues, cert chain problems",
        "when_to_use": "HTTPS services, especially internet-facing ones handling sensitive data",
    },
    "nikto": {
        "description": "Web server scanner for dangerous files and misconfigurations.",
        "input": "URL",
        "strengths": "Legacy misconfigs, default files, dangerous HTTP methods",
        "when_to_use": "Older web servers, Apache/IIS/nginx with potential misconfigs",
    },
}

PLANNER_SYSTEM_PROMPT = """You are a penetration testing planner for an automated vulnerability scanning pipeline.

Your job is to analyze an asset's profile and create an optimized scanning plan.
You have access to these scanning tools:

{tool_descriptions}

RULES:
1. Always include nuclei as a scanning action (it's the primary scanner)
2. Adjust nuclei tags based on the detected technology stack and CPEs
3. Higher criticality assets should get deeper scanning (more tools, longer timeouts)
4. Skip tools that won't add value (e.g., don't run nikto on a pure API server)
5. Consider existing findings — if the asset already has many critical findings, prioritize validation over discovery
6. Internet-facing assets with web services should get katana + nuclei web templates
7. Assets with TLS should get testssl if they handle sensitive data
8. Set priority 1-5 for each action (1=do first, 5=do last)

Respond ONLY with a JSON object matching this schema:
{{
    "risk_tier": "critical|high|medium|low",
    "actions": [
        {{
            "tool": "nuclei|nmap|katana|testssl|nikto",
            "priority": 1-5,
            "tags": ["tag1", "tag2"],
            "flags": {{}},
            "timeout": 600,
            "reasoning": "why this action"
        }}
    ],
    "skip_reason": null or "reason to skip scanning entirely",
    "reasoning": "overall scan strategy explanation"
}}"""


def _build_tool_descriptions() -> str:
    lines = []
    for name, caps in TOOL_CAPABILITIES.items():
        lines.append(f"- **{name}**: {caps['description']}")
        lines.append(f"  Strengths: {caps['strengths']}")
        lines.append(f"  When to use: {caps['when_to_use']}")
    return "\n".join(lines)


async def generate_scan_plan(
    db: Session,
    org_id: int,
    asset_id: int,
    llm_provider: str = "anthropic",
) -> ScanPlan:
    """Generate an adaptive scan plan for a single asset using LLM reasoning.

    Falls back to a deterministic plan if the LLM is unavailable.
    """
    # Gather asset context
    asset_context = _gather_asset_context(db, org_id, asset_id)
    if not asset_context:
        return ScanPlan(
            asset_id=asset_id,
            asset_hostname="unknown",
            risk_tier="low",
            skip_reason="Asset not found",
        )

    # Try LLM-powered planning
    try:
        plan = await _llm_plan(asset_context, llm_provider)
        if plan:
            return plan
    except Exception as e:
        logger.warning("LLM scan planning failed for asset %d: %s, falling back to deterministic", asset_id, e)

    # Fallback to deterministic planning
    return _deterministic_plan(asset_context)


async def generate_batch_plans(
    db: Session,
    org_id: int,
    asset_ids: list[int] | None = None,
    top_n: int = 50,
    llm_provider: str = "anthropic",
) -> list[ScanPlan]:
    """Generate scan plans for multiple assets, prioritized by risk.

    If asset_ids is None, selects top N assets by risk score.
    """
    if asset_ids is None:
        rows = (
            db.query(Asset.id)
            .join(Scan, Asset.scan_id == Scan.id)
            .filter(
                Scan.org_id == org_id,
                Asset.asset_status == "active",
            )
            .order_by(Asset.risk_score.desc().nullslast(), Asset.criticality.desc())
            .limit(top_n)
            .all()
        )
        asset_ids = [row[0] for row in rows]

    plans = []
    for aid in asset_ids:
        plan = await generate_scan_plan(db, org_id, aid, llm_provider)
        plans.append(plan)

    # Sort by risk tier then by total actions (more actions = more important)
    tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plans.sort(key=lambda p: (tier_order.get(p.risk_tier, 4), -len(p.actions)))

    return plans


def _gather_asset_context(db: Session, org_id: int, asset_id: int) -> dict | None:
    """Gather all relevant context for scan planning."""
    asset = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Asset.id == asset_id, Scan.org_id == org_id)
        .first()
    )
    if not asset:
        return None

    easm = asset.easm_data or {}

    # Tech stack and open ports live inside easm_data JSON
    tech_stack = easm.get("tech_stack", [])
    if isinstance(tech_stack, dict):
        tech_stack = list(tech_stack.keys())
    elif not isinstance(tech_stack, list):
        tech_stack = []

    open_ports = easm.get("open_ports", [])
    if not isinstance(open_ports, list):
        open_ports = []

    # CPEs from the asset model directly
    cpes = asset.cpe or []

    # Build port details from easm_data services if available
    ports_data = []
    for svc in easm.get("services", []):
        if isinstance(svc, dict):
            ports_data.append({
                "port": svc.get("port"),
                "service": svc.get("name") or svc.get("service"),
                "version": svc.get("version"),
                "cpes": svc.get("cpes", []),
                "banner": (svc.get("banner") or "")[:200],
            })

    # Recent findings summary
    findings_summary = []
    try:
        summary_rows = (
            db.query(
                Finding.severity,
                func.count(Finding.id).label("cnt"),
            )
            .filter(
                Finding.asset_id == asset_id,
                Finding.status == "open",
            )
            .group_by(Finding.severity)
            .all()
        )
        for row in summary_rows:
            findings_summary.append({"severity": row.severity, "count": row.cnt})
    except Exception:
        logger.debug("Could not load findings summary for asset %d", asset_id)

    # Last scan time
    last_scan_time = None
    try:
        last_scan_row = (
            db.query(func.max(Scan.created_at))
            .join(Finding, Finding.scan_id == Scan.id)
            .filter(Finding.asset_id == asset_id, Scan.org_id == org_id)
            .scalar()
        )
        if last_scan_row:
            last_scan_time = last_scan_row.isoformat() if hasattr(last_scan_row, "isoformat") else str(last_scan_row)
    except Exception:
        logger.debug("Could not determine last scan time for asset %d", asset_id)

    return {
        "asset_id": asset.id,
        "hostname": asset.hostname or "",
        "ip": str(asset.ip) if asset.ip else "",
        "open_ports": open_ports,
        "tech_stack": tech_stack,
        "cpes": cpes,
        "criticality": asset.criticality or 5,
        "risk_score": float(asset.risk_score or 0),
        "environment": asset.environment_tag or "unknown",
        "asset_type": asset.asset_type or "host",
        "cdn_provider": easm.get("cdn_provider"),
        "is_internet_facing": asset.is_internet_facing,
        "device_type": asset.device_type,
        "critical_findings": asset.critical_count or 0,
        "high_findings": asset.high_count or 0,
        "medium_findings": asset.medium_count or 0,
        "ports_data": ports_data,
        "findings_summary": findings_summary,
        "last_scan": last_scan_time,
        "last_enriched": asset.last_enriched.isoformat() if asset.last_enriched else None,
        "easm_tech": tech_stack,
        "easm_waf": easm.get("waf"),
    }


async def _llm_plan(context: dict, provider: str) -> ScanPlan | None:
    """Use LLM to generate a scan plan from asset context."""
    system_prompt = PLANNER_SYSTEM_PROMPT.format(
        tool_descriptions=_build_tool_descriptions(),
    )

    user_prompt = f"""Analyze this asset and create an optimized scan plan:

Asset: {context['hostname']} ({context['ip']})
Type: {context['asset_type']} | Device: {context['device_type']}
Environment: {context['environment']} | Internet-facing: {context['is_internet_facing']}
Criticality: {context['criticality']}/10 | Risk Score: {context['risk_score']}/10
CDN/WAF: {context['cdn_provider'] or 'none'} / {context['easm_waf'] or 'none'}

Open Ports: {context['open_ports']}
Tech Stack: {context['tech_stack']}
EASM Tech: {context['easm_tech']}

Port Details:
{json.dumps(context['ports_data'], indent=2)}

Current Findings: {context['critical_findings']} critical, {context['high_findings']} high, {context['medium_findings']} medium
Finding Families: {json.dumps(context['findings_summary'], indent=2)}

Last Scan: {context['last_scan'] or 'never'}
Last Enriched: {context['last_enriched'] or 'never'}"""

    try:
        response = await _call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            provider=provider,
        )

        # Parse JSON response — strip markdown fences if present
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        plan_data = json.loads(text)

        actions = []
        for a in plan_data.get("actions", []):
            actions.append(ScanAction(
                tool=a["tool"],
                priority=a.get("priority", 3),
                tags=a.get("tags", []),
                templates=a.get("templates", []),
                flags=a.get("flags", {}),
                timeout=a.get("timeout", 600),
                reasoning=a.get("reasoning", ""),
            ))

        return ScanPlan(
            asset_id=context["asset_id"],
            asset_hostname=context["hostname"],
            risk_tier=plan_data.get("risk_tier", "medium"),
            actions=actions,
            total_estimated_duration=sum(a.timeout for a in actions),
            skip_reason=plan_data.get("skip_reason"),
            reasoning=plan_data.get("reasoning", ""),
        )

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to parse LLM scan plan: %s", e)
        return None


def _deterministic_plan(context: dict) -> ScanPlan:
    """Fallback deterministic scan plan when LLM is unavailable."""
    actions = []
    risk_tier = "low"

    crit = context.get("criticality", 5)
    risk = context.get("risk_score", 0)
    ports = set(context.get("open_ports", []))
    tech = [t.lower() for t in context.get("tech_stack", [])]
    is_web = bool(ports & {80, 443, 8080, 8443})
    is_internet = context.get("is_internet_facing", False)
    has_cdn = bool(context.get("cdn_provider"))

    # Determine risk tier
    if crit >= 8 or risk >= 7.0:
        risk_tier = "critical"
    elif crit >= 6 or risk >= 5.0:
        risk_tier = "high"
    elif crit >= 4 or risk >= 3.0:
        risk_tier = "medium"

    # Nuclei always runs
    nuclei_tags = ["generic", "exposure"]
    nuclei_timeout = 600

    # Add tech-specific tags
    for t in tech:
        if "wordpress" in t:
            nuclei_tags.extend(["wordpress", "cms", "php"])
        elif "nginx" in t:
            nuclei_tags.append("nginx")
        elif "apache" in t:
            nuclei_tags.append("apache")
        elif "node" in t or "express" in t:
            nuclei_tags.extend(["nodejs", "javascript"])
        elif "django" in t or "flask" in t:
            nuclei_tags.append("python")
        elif "spring" in t or "java" in t:
            nuclei_tags.extend(["java", "spring"])

    if is_web:
        nuclei_tags.extend(["http", "ssl"])

    # Critical assets get longer timeouts
    if risk_tier == "critical":
        nuclei_timeout = 900

    actions.append(ScanAction(
        tool="nuclei",
        priority=1,
        tags=list(set(nuclei_tags)),
        timeout=nuclei_timeout,
        reasoning="Primary vulnerability scanner — always included",
    ))

    # Web apps get katana
    if is_web and not has_cdn and risk_tier in ("critical", "high"):
        actions.append(ScanAction(
            tool="katana",
            priority=2,
            flags={"depth": 3 if risk_tier == "critical" else 2},
            timeout=300,
            reasoning="Web application needs endpoint discovery for thorough scanning",
        ))

    # Internet-facing TLS services get testssl
    if is_internet and is_web and risk_tier in ("critical", "high"):
        actions.append(ScanAction(
            tool="testssl",
            priority=3,
            timeout=120,
            reasoning="Internet-facing HTTPS service needs TLS configuration audit",
        ))

    # Older web servers get nikto
    old_servers = {"apache", "iis", "nginx", "tomcat"}
    if is_web and any(t in " ".join(tech).lower() for t in old_servers) and risk_tier != "low":
        actions.append(ScanAction(
            tool="nikto",
            priority=4,
            timeout=300,
            reasoning="Traditional web server detected — check for legacy misconfigurations",
        ))

    return ScanPlan(
        asset_id=context["asset_id"],
        asset_hostname=context["hostname"],
        risk_tier=risk_tier,
        actions=actions,
        total_estimated_duration=sum(a.timeout for a in actions),
        reasoning=f"Deterministic plan for {risk_tier}-risk {context.get('asset_type', 'host')}",
    )


# ── Lightweight LLM helper ──────────────────────────────────────────


async def _call_llm(
    system_prompt: str,
    user_prompt: str,
    provider: str = "anthropic",
    model: str | None = None,
    max_tokens: int = 2000,
) -> str:
    """Lightweight LLM call for scan planning.

    Tries the configured provider, falls back gracefully.
    """
    import httpx

    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model or "claude-sonnet-4-6",
                    "max_tokens": max_tokens,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model or "gpt-4o-mini",
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    raise RuntimeError(f"Unsupported LLM provider: {provider}")
