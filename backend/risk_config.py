"""
Configurable risk scoring and asset criticality engine.

Asset Risk Score formula (weighted sum, normalized to 0-10):
  severity       — weighted avg of finding severity scores
  exploitability — exploit availability + maturity (zero-day, PoC, functional, weaponized)
  intel          — real-world threat signals (KEV, EPSS, ransomware, trending, VPR)
  criticality    — asset criticality level (1-10) contribution
  controls       — penalty when compensating controls (AV/firewall) are absent
  reachability   — port-aware: checks if finding ports are listening/established on the asset

Asset criticality auto-rules:
  Rules are evaluated in order against asset properties.
  Modes: first_match | last_match | max

  Rule formats supported:
    Old (single-condition):
      {field, op, value, criticality}
    New (compound conditions):
      {conditions: [{field, op, value}, ...], logic: "AND"|"OR", criticality}

  Supported fields:
    String fields:  environment_tag, hostname, fqdn, ip, os, netbios_name
    Numeric fields: critical_count, high_count, medium_count, low_count, info_count, risk_score
    Tag field:      tag  (matches against "category:value" strings)

  Supported operators:
    String:  eq, neq, contains, not_contains, startswith, endswith, regex
    Numeric: eq, gt, lt, gte, lte
    Tag:     has_tag, not_has_tag
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import rule_engine as engine

logger = logging.getLogger(__name__)

RISK_CONFIG_PATH = Path(__file__).parent / "risk_config.json"

DEFAULT_RISK_CONFIG: dict[str, Any] = {
    # ── Formula weights (should sum to 1.0) ──
    "formula_weights": {
        "severity":       0.35,
        "exploitability": 0.25,
        "intel":          0.15,
        "criticality":    0.15,
        "controls":       0.05,
        "reachability":   0.05,
    },
    # ── Per-severity base scores (0-10) ──
    "severity_scores": {
        "critical": 10.0,
        "high":      7.0,
        "medium":    4.0,
        "low":       1.5,
        "info":      0.2,
    },
    # ── Exploit maturity → score contribution (0-1) ──
    "exploit_maturity_scores": {
        "weaponized": 1.0,
        "functional": 0.75,
        "poc":        0.50,
        "unproven":   0.25,
        "none":       0.0,
    },
    # ── Criticality level → final score multiplier ──
    "criticality_multipliers": {
        "1":  0.50,
        "2":  0.60,
        "3":  0.70,
        "4":  0.80,
        "5":  0.90,
        "6":  1.00,
        "7":  1.15,
        "8":  1.30,
        "9":  1.45,
        "10": 1.60,
    },
    # ── Severity source for the "severity" component ──
    # Which technical severity metric drives the severity weight in the finding formula.
    # Options: cvss_best | cvss2 | cvss3 | cvss4 | vpr | epss
    "severity_source": "cvss_best",
    # ── Finding priority score weights (should sum to 1.0) ──
    # Components:
    #   severity       — Technical severity from the selected source, normalized 0-1
    #   exploitability — exploit availability & maturity bonus
    #   intel          — threat intel signals (KEV, EPSS, ransomware, trending, VPR)
    #   criticality    — asset criticality (1-10) normalized 0-1
    #   family         — plugin family risk signal
    #   controls       — penalty when compensating controls absent (from asset inventory)
    #   reachability   — port-aware: finding port listening/established on asset
    "finding_formula_weights": {
        "severity":       0.25,
        "exploitability": 0.25,
        "intel":          0.20,
        "criticality":    0.10,
        "family":         0.10,
        "controls":       0.05,
        "reachability":   0.05,
    },
    # ── Criticality auto-assignment rules ──
    # Old format: {field, op, value, criticality}
    # New format: {conditions: [{field, op, value}], logic: "AND"|"OR", criticality}
    # field: environment_tag | hostname | fqdn | ip | os | netbios_name
    #        | critical_count | high_count | medium_count | low_count | info_count | risk_score
    #        | tag
    # op (string): eq | neq | contains | not_contains | startswith | endswith | regex
    # op (numeric): eq | gt | lt | gte | lte
    # op (tag): has_tag | not_has_tag
    "criticality_rules": [],
    # How multiple matching rules resolve: first_match | last_match | max
    "criticality_rule_mode": "max",
    # Apply rules automatically when a new scan is uploaded
    "auto_apply_rules_on_upload": True,
}

_SEV_MAP = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


# ─────────────────────────────────────────────
# Config I/O
# ─────────────────────────────────────────────

def load_config() -> dict:
    if RISK_CONFIG_PATH.exists():
        try:
            with open(RISK_CONFIG_PATH) as f:
                on_disk = json.load(f)
            # Shallow-merge top-level sections so new keys get defaults
            merged = dict(DEFAULT_RISK_CONFIG)
            for k, v in on_disk.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            return merged
        except Exception as e:
            logger.warning(f"Failed to load risk config: {e}; using defaults")
    return dict(DEFAULT_RISK_CONFIG)


def save_config(cfg: dict) -> None:
    with open(RISK_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ─────────────────────────────────────────────
# Criticality auto-rules
# ─────────────────────────────────────────────

def evaluate_criticality_rules(asset: dict, cfg: dict) -> int | None:
    """
    Apply criticality auto-rules to an asset dict.
    Returns the resolved criticality (int 1-10) or None if no rules match.

    Supports:
    - New compound format: {conditions: [{field, op, value}], logic: "AND"|"OR", criticality}
    - Old single-condition format: {field, op, value, criticality}  (treated as single condition)

    The asset dict may include:
      ip, hostname, fqdn, os, netbios_name, environment_tag,
      criticality, risk_score, critical_count, high_count, medium_count,
      low_count, info_count, tags (list of "category:value" strings)
    """
    rules = cfg.get("criticality_rules", [])
    mode  = cfg.get("criticality_rule_mode", "max")
    if not rules:
        return None

    asset_tags = asset.get("tags") or []
    matched: list[int] = []

    for rule in rules:
        crit = int(rule.get("criticality", 5))

        if "conditions" in rule:
            conditions = rule.get("conditions") or []
            if not conditions:
                continue
            logic = rule.get("logic", "AND")
        else:
            # Old single-condition format — wrap as single condition
            conditions = [rule]
            logic = "AND"

        rule_match = engine.evaluate_conditions(
            conditions, logic,
            asset_dict=asset,
            asset_tags=asset_tags,
        )

        if rule_match:
            if mode == "first_match":
                return crit
            matched.append(crit)

    if not matched:
        return None
    if mode == "last_match":
        return matched[-1]
    return max(matched)  # mode == "max"


# ─────────────────────────────────────────────
# Asset risk computation
# ─────────────────────────────────────────────

def compute_asset_risk_score(
    findings: list[dict],
    asset_criticality: int = 5,
    inventory: dict | None = None,
    cfg: dict | None = None,
) -> float:
    """
    Compute a risk score (0-10) for an asset.

    Args:
        findings:          list of finding dicts — must contain at minimum:
                           {severity, exploit_available, exploit_maturity, vpr_score}
        asset_criticality: 1-10 integer
        inventory:         optional dict with compensating/reachability context:
                           {has_av: bool|None, has_firewall: bool|None, established_connections: int}
        cfg:               loaded risk config (defaults loaded if None)
    """
    if cfg is None:
        cfg = load_config()

    weights    = cfg.get("formula_weights", DEFAULT_RISK_CONFIG["formula_weights"])
    sev_scores = cfg.get("severity_scores",  DEFAULT_RISK_CONFIG["severity_scores"])
    mat_scores = cfg.get("exploit_maturity_scores", DEFAULT_RISK_CONFIG["exploit_maturity_scores"])
    crit_mults = cfg.get("criticality_multipliers", DEFAULT_RISK_CONFIG["criticality_multipliers"])

    if not findings:
        return 0.0

    n = len(findings)

    # ── 1. Severity component ──
    # Exclude info-level findings from the average: they are informational (open ports,
    # software enumeration, etc.) and should not dilute the vulnerability severity score.
    non_info = [f for f in findings if f.get("severity", 0) > 0]
    if not non_info:
        severity_component = 0.0
    else:
        sev_total = sum(
            sev_scores.get(_SEV_MAP.get(f.get("severity", 0), "info"), 0.0)
            for f in non_info
        )
        # Quality: average severity of actual vulnerabilities (0-1)
        quality = sev_total / (len(non_info) * 10.0)
        # Volume bonus: rewards assets with many high/critical findings (caps at 10 criticals)
        critical_count = sum(1 for f in non_info if f.get("severity", 0) == 4)
        high_count     = sum(1 for f in non_info if f.get("severity", 0) == 3)
        medium_count   = sum(1 for f in non_info if f.get("severity", 0) == 2)
        volume = min(critical_count * 0.5 + high_count * 0.25 + medium_count * 0.05, 10.0) / 10.0
        severity_component = min(0.70 * quality + 0.30 * volume, 1.0)

    # ── 2. Exploitability component (can it be exploited?) ──
    exploit_total = 0.0
    for f in findings:
        if f.get("exploit_available") or f.get("zero_day"):
            mat = (f.get("exploit_maturity") or "none").lower()
            exploit_total += mat_scores.get(mat, mat_scores.get("none", 0.0))
            if f.get("zero_day"):
                exploit_total = max(exploit_total, 1.0)
    exploitability_component = min(exploit_total / n, 1.0)

    # ── 3. Intel component (is it being exploited / relevant right now?) ──
    # Uses real threat intel signals instead of raw VPR.
    intel_scores = []
    for f in findings:
        signals = []
        if f.get("is_kev"):
            signals.append(0.9)
        epss = f.get("epss_score")
        if epss is not None and epss > 0:
            signals.append(min(epss * 1.5, 1.0))
        if f.get("ransomware_linked"):
            signals.append(1.0)
        if f.get("trending_in_news"):
            signals.append(0.6)
        vpr = f.get("vpr_score")
        if vpr:
            signals.append(float(vpr) / 10.0)
        if signals:
            intel_scores.append(max(signals))
    intel_component = max(intel_scores) if intel_scores else 0.0

    # ── 4. Criticality component (normalize 1-10 → 0-1) ──
    criticality_component = (max(1, min(10, asset_criticality)) - 1) / 9.0

    # ── 5. Controls component ──
    inv = inventory or {}
    has_av       = inv.get("has_av")
    has_firewall = inv.get("has_firewall")
    if has_av is True or has_firewall is True:
        controls_component = 0.0    # compensating controls present → no penalty
    elif has_av is False and has_firewall is False:
        controls_component = 1.0    # neither present → full penalty
    else:
        controls_component = 0.5    # unknown → neutral

    # ── 6. Reachability component ──
    # For asset-level: proportion of finding ports that are reachable.
    listening_ports = inv.get("listening_ports") or set()
    established_ports = inv.get("established_ports") or set()
    if listening_ports or established_ports:
        reachable_count = 0
        port_findings = 0
        for f in findings:
            fp = f.get("port")
            if fp and str(fp).isdigit():
                port_findings += 1
                port_int = int(fp)
                if port_int in established_ports:
                    reachable_count += 1
                elif port_int in listening_ports:
                    reachable_count += 0.7
        reachability_component = (reachable_count / port_findings) if port_findings else 0.5
    else:
        # No port inventory data — fall back to connection count
        conns = int(inv.get("established_connections", 0))
        reachability_component = min(conns / 20.0, 1.0)

    # ── Weighted sum ──
    score = (
        weights.get("severity",       0.35) * severity_component +
        weights.get("exploitability",  0.25) * exploitability_component +
        weights.get("intel",           0.15) * intel_component +
        weights.get("criticality",     0.15) * criticality_component +
        weights.get("controls",        0.05) * controls_component +
        weights.get("reachability",    0.05) * reachability_component
    )

    # ── Criticality multiplier ──
    mult = float(crit_mults.get(str(asset_criticality), 1.0))
    score *= mult

    return round(min(score * 10.0, 10.0), 2)
