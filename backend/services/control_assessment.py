"""
Control Assessment Engine — evaluates whether findings are actually mitigated
by the security control policies configured on their assets.

Each product type has a dedicated evaluator that understands the policy config
format and maps ATT&CK techniques to specific prevention settings.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import (
    Finding, Asset, Scan,
    SecurityControlPolicy, SecurityControlPolicyAssignment, ControlAssessment,
)

logger = logging.getLogger(__name__)


# ── ATT&CK Technique → CrowdStrike Prevention Setting ──────────────────────

TECHNIQUE_TO_CS_PREVENTION = {
    # Exploitation
    "T1203": ["exploit_protection"],                              # Exploitation for Client Execution
    "T1190": ["exploit_protection"],                              # Exploit Public-Facing Application
    "T1210": ["exploit_protection", "lateral_movement"],          # Exploitation of Remote Services
    "T1068": ["exploit_protection"],                              # Exploitation for Privilege Escalation

    # Scripting / Execution
    "T1059": ["script_based_execution_monitoring"],               # Command and Scripting Interpreter
    "T1059.001": ["script_based_execution_monitoring", "malicious_powershell"],  # PowerShell
    "T1059.003": ["script_based_execution_monitoring"],           # Windows Command Shell
    "T1059.004": ["script_based_execution_monitoring"],           # Unix Shell
    "T1059.005": ["script_based_execution_monitoring"],           # Visual Basic
    "T1059.007": ["script_based_execution_monitoring"],           # JavaScript
    "T1204": ["behavioral_ioas"],                                 # User Execution

    # Credential Access
    "T1003": ["credential_dumping"],                              # OS Credential Dumping
    "T1003.001": ["credential_dumping"],                          # LSASS Memory
    "T1003.002": ["credential_dumping"],                          # SAM
    "T1003.003": ["credential_dumping"],                          # NTDS
    "T1558": ["credential_dumping"],                              # Steal or Forge Kerberos Tickets

    # Impact
    "T1486": ["ransomware"],                                      # Data Encrypted for Impact
    "T1490": ["ransomware"],                                      # Inhibit System Recovery

    # Lateral Movement
    "T1021": ["lateral_movement"],                                # Remote Services
    "T1021.001": ["lateral_movement"],                            # RDP
    "T1021.002": ["lateral_movement"],                            # SMB/Windows Admin Shares
    "T1021.006": ["lateral_movement"],                            # Windows Remote Management
    "T1570": ["lateral_movement"],                                # Lateral Tool Transfer

    # Persistence / Evasion
    "T1547": ["behavioral_ioas"],                                 # Boot or Logon Autostart Execution
    "T1053": ["behavioral_ioas"],                                 # Scheduled Task/Job
    "T1055": ["behavioral_ioas"],                                 # Process Injection
    "T1112": ["behavioral_ioas"],                                 # Modify Registry
}

# CrowdStrike API prevention level → our mode
CS_PREVENTION_LEVELS = {
    "AGGRESSIVE": "block",
    "MODERATE": "block",
    "CAUTIOUS": "block",
    "DISABLED": "detect",
    "EXTRA_AGGRESSIVE": "block",
}


# ── Product Evaluators ──────────────────────────────────────────────────────

def evaluate_crowdstrike(finding: Finding, policy: SecurityControlPolicy) -> dict:
    """Evaluate whether a CrowdStrike prevention policy mitigates this finding."""
    settings = policy.settings or {}
    techniques = _extract_techniques(finding)

    if not techniques:
        return {
            "verdict": "unknown",
            "confidence": "low",
            "explanation": f"No ATT&CK techniques mapped for this finding; cannot assess CrowdStrike coverage.",
            "matched_techniques": [],
        }

    blocked = []
    detected = []
    unmapped = []

    for ttp in techniques:
        cs_settings = TECHNIQUE_TO_CS_PREVENTION.get(ttp)
        if not cs_settings:
            unmapped.append(ttp)
            continue

        best_mode = None
        best_setting_name = None
        for setting_name in cs_settings:
            setting = settings.get(setting_name, {})
            if not setting.get("enabled"):
                continue
            mode = setting.get("mode", "detect")
            # Normalize CrowdStrike prevention levels
            if mode in CS_PREVENTION_LEVELS:
                mode = CS_PREVENTION_LEVELS[mode]
            if mode == "block":
                best_mode = "block"
                best_setting_name = setting_name
                break
            elif mode == "detect":
                best_mode = "detect"
                best_setting_name = setting_name

        if best_mode == "block":
            blocked.append((ttp, best_setting_name))
        elif best_mode == "detect":
            detected.append((ttp, best_setting_name))
        else:
            unmapped.append(ttp)

    # Determine verdict
    total_mapped = len(blocked) + len(detected)
    if total_mapped == 0:
        verdict = "unknown"
        confidence = "low"
        explanation = f"No CrowdStrike prevention settings map to techniques: {', '.join(unmapped)}"
    elif len(blocked) == total_mapped and not unmapped:
        verdict = "mitigated"
        confidence = "high"
        settings_desc = ", ".join(f"{s} (BLOCK)" for _, s in blocked[:3])
        explanation = f"CrowdStrike prevention blocks all {len(blocked)} matched technique(s): {settings_desc}"
    elif len(blocked) > 0:
        verdict = "partially_mitigated"
        confidence = "medium"
        explanation = (
            f"CrowdStrike blocks {len(blocked)} technique(s) but "
            f"{len(detected)} in detect-only mode"
            + (f", {len(unmapped)} unmapped" if unmapped else "")
        )
    elif len(detected) > 0:
        verdict = "not_mitigated"
        confidence = "medium"
        explanation = f"CrowdStrike detects {len(detected)} technique(s) but none are in prevention/block mode"
    else:
        verdict = "not_mitigated"
        confidence = "low"
        explanation = "No matching CrowdStrike prevention settings found"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "explanation": explanation,
        "matched_techniques": [t for t, _ in blocked] + [t for t, _ in detected],
    }


def evaluate_firewall(finding: Finding, policy: SecurityControlPolicy) -> dict:
    """Evaluate whether firewall rules mitigate this finding (by blocking the port)."""
    settings = policy.settings or {}
    rules = settings.get("rules", [])
    finding_port = finding.port
    finding_protocol = (finding.protocol or "tcp").lower()

    if not finding_port:
        return {
            "verdict": "unknown",
            "confidence": "low",
            "explanation": "Finding has no port; cannot assess firewall rules.",
            "matched_techniques": [],
        }

    for rule in rules:
        if rule.get("action") != "block":
            continue
        if rule.get("direction") not in ("inbound", "both"):
            continue
        rule_ports = rule.get("ports", [])
        rule_protocol = (rule.get("protocol") or "any").lower()
        if rule_protocol not in ("any", finding_protocol):
            continue
        if finding_port in rule_ports or "any" in rule_ports:
            return {
                "verdict": "mitigated",
                "confidence": "high",
                "explanation": f"Firewall rule '{rule.get('name', 'unnamed')}' blocks inbound {finding_protocol}/{finding_port}",
                "matched_techniques": [],
            }

    return {
        "verdict": "not_mitigated",
        "confidence": "medium",
        "explanation": f"No firewall rule blocks inbound {finding_protocol}/{finding_port}",
        "matched_techniques": [],
    }


def evaluate_defender(finding: Finding, policy: SecurityControlPolicy) -> dict:
    """Evaluate whether Microsoft Defender config mitigates this finding."""
    settings = policy.settings or {}

    techniques = _extract_techniques(finding)
    if not techniques:
        # Fall back to basic AV check
        if settings.get("real_time_protection", {}).get("enabled"):
            return {
                "verdict": "partially_mitigated",
                "confidence": "low",
                "explanation": "Defender real-time protection is enabled but no specific technique mapping.",
                "matched_techniques": [],
            }
        return {
            "verdict": "not_mitigated",
            "confidence": "medium",
            "explanation": "Defender real-time protection is disabled.",
            "matched_techniques": [],
        }

    protections = []
    if settings.get("real_time_protection", {}).get("enabled"):
        protections.append("real-time protection")
    if settings.get("cloud_protection", {}).get("enabled"):
        protections.append("cloud protection")
    if settings.get("tamper_protection", {}).get("enabled"):
        protections.append("tamper protection")
    if settings.get("exploit_protection", {}).get("enabled"):
        protections.append("exploit protection")

    if not protections:
        return {
            "verdict": "not_mitigated",
            "confidence": "medium",
            "explanation": "All Defender protections are disabled.",
            "matched_techniques": [],
        }

    return {
        "verdict": "partially_mitigated",
        "confidence": "low",
        "explanation": f"Defender has {', '.join(protections)} enabled. Partial coverage for {len(techniques)} technique(s).",
        "matched_techniques": techniques[:5],
    }


# ── Evaluator Registry ──────────────────────────────────────────────────────

PRODUCT_EVALUATORS = {
    "crowdstrike_falcon": evaluate_crowdstrike,
    "ms_defender": evaluate_defender,
    "windows_firewall": evaluate_firewall,
    "palo_alto_ngfw": evaluate_firewall,
    "fortinet_fortigate": evaluate_firewall,
}


# ── Main Assessment Function ────────────────────────────────────────────────

def assess_findings(db: Session, org_id: int, scan_id: Optional[int] = None, asset_id: Optional[int] = None) -> dict:
    """
    Run control assessment for findings.
    - If scan_id: assess all findings in that scan
    - If asset_id: assess all findings on that asset
    - Otherwise: assess all open findings for the org
    """
    # Get findings to assess
    fq = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Scan.org_id == org_id)
    if scan_id:
        fq = fq.filter(Finding.scan_id == scan_id)
    if asset_id:
        fq = fq.filter(Finding.asset_id == asset_id)
    findings = fq.all()

    if not findings:
        return {"assessed": 0, "mitigated": 0, "partial": 0, "not_mitigated": 0}

    # Get all policy assignments for relevant assets
    asset_ids = {f.asset_id for f in findings}
    assignments = (
        db.query(SecurityControlPolicyAssignment)
        .filter(SecurityControlPolicyAssignment.org_id == org_id)
        .filter(SecurityControlPolicyAssignment.asset_id.in_(asset_ids))
        .all()
    )

    if not assignments:
        return {"assessed": 0, "mitigated": 0, "partial": 0, "not_mitigated": 0}

    # Build asset → policies map
    asset_policies: dict[int, list[SecurityControlPolicy]] = {}
    policy_cache: dict[int, SecurityControlPolicy] = {}
    for a in assignments:
        if a.policy_id not in policy_cache:
            policy_cache[a.policy_id] = db.query(SecurityControlPolicy).filter(
                SecurityControlPolicy.id == a.policy_id
            ).first()
        policy = policy_cache[a.policy_id]
        if policy:
            asset_policies.setdefault(a.asset_id, []).append(policy)

    assessed = 0
    mitigated = 0
    partial = 0
    not_mitigated = 0

    for finding in findings:
        policies = asset_policies.get(finding.asset_id, [])
        if not policies:
            continue

        best_verdict = "not_mitigated"
        best_summary = None

        for policy in policies:
            evaluator = PRODUCT_EVALUATORS.get(policy.product_key)
            if not evaluator:
                continue

            result = evaluator(finding, policy)

            # Upsert ControlAssessment
            existing = db.query(ControlAssessment).filter(
                ControlAssessment.finding_id == finding.id,
                ControlAssessment.policy_id == policy.id,
            ).first()

            if existing:
                existing.verdict = result["verdict"]
                existing.confidence = result["confidence"]
                existing.explanation = result["explanation"]
                existing.matched_techniques = result["matched_techniques"]
                existing.policy_settings_snapshot = policy.settings
                existing.assessed_at = datetime.utcnow()
            else:
                db.add(ControlAssessment(
                    org_id=org_id,
                    finding_id=finding.id,
                    asset_id=finding.asset_id,
                    policy_id=policy.id,
                    verdict=result["verdict"],
                    confidence=result["confidence"],
                    explanation=result["explanation"],
                    matched_techniques=result["matched_techniques"],
                    policy_settings_snapshot=policy.settings,
                ))

            # Track best verdict
            if result["verdict"] == "mitigated":
                best_verdict = "mitigated"
                best_summary = f"Mitigated by {policy.product_name or policy.product_key} ({result['explanation'][:80]})"
            elif result["verdict"] == "partially_mitigated" and best_verdict != "mitigated":
                best_verdict = "partially_mitigated"
                best_summary = f"Partially mitigated by {policy.product_name or policy.product_key}"

        # Update denormalized columns on Finding
        finding.control_mitigation_status = best_verdict
        finding.control_mitigation_summary = best_summary
        assessed += 1

        if best_verdict == "mitigated":
            mitigated += 1
        elif best_verdict == "partially_mitigated":
            partial += 1
        else:
            not_mitigated += 1

    db.flush()
    return {"assessed": assessed, "mitigated": mitigated, "partial": partial, "not_mitigated": not_mitigated}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _extract_techniques(finding: Finding) -> list[str]:
    """Extract ATT&CK technique IDs from a finding's matched_ttps."""
    ttps = finding.matched_ttps or []
    techniques = []
    for ttp in ttps:
        if isinstance(ttp, dict):
            tid = ttp.get("technique_id")
            if tid:
                techniques.append(tid)
        elif isinstance(ttp, str):
            techniques.append(ttp)
    return techniques
