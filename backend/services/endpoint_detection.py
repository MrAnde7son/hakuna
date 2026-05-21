"""Endpoint-agent detection & response.

Turns a host-resident agent's check-in (installed software, running
processes, listening ports, security controls) into contextualized,
prioritized findings — and drives the response half of the loop.

The pipeline per check-in:

1. Upsert the host as an Asset under the agent's persistent Scan.
2. Rewrite the host inventory (software / processes / netconns / controls).
3. Detect: match installed software against the vulnerability KB.
4. Contextualize each detection — runtime (is the package's process live?),
   reachability (is a vulnerable service listening?), compensating controls.
5. Enrich with model-derived ('mythos') threat intelligence.
6. Reconcile findings (open new, auto-resolve gone) and prioritize.
7. Respond — auto-create EDR detections for critical KEV/forecast findings
   when the agent has auto-response enabled.
"""

import logging
import re
from datetime import datetime

from sqlalchemy.orm import Session

from models.models import (
    Asset, Scan, Finding, DetectionRule,
    InventorySoftware, InventoryProcess, InventoryNetConn, InventorySecurityControl,
)
from services import ai_threat_intel
from services.post_ingest import finalize_batch

logger = logging.getLogger(__name__)

SOURCE = "endpoint_agent"

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Ports that, when bound to a wildcard address, mark a host as effectively
# network-reachable for the listening service.
SERVICE_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 636,
                 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 8983, 9200}


# ─────────────────────────────────────────────────────────
# Vulnerability knowledge base
#
# A curated, scanner-agnostic set of well-known CVEs the agent can detect
# from installed-package versions alone. This is the "classic intelligence"
# half of the demo — the model-derived layer (ai_threat_intel) augments it.
# ─────────────────────────────────────────────────────────

VULN_KB = [
    {
        "names": ["log4j", "log4j-core", "log4j2", "apache-log4j"],
        "cve": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "cvss": 10.0, "severity": 4, "fixed_version": "2.17.1",
        "description": "Apache Log4j2 JNDI lookup feature allows unauthenticated remote code execution via crafted log messages.",
        "solution": "Upgrade Apache Log4j to 2.17.1 or later.",
        "has_public_exploit": True, "in_kev": True,
        "plugin_family": "Web Servers", "process_names": ["java"],
        "service_ports": [8080, 8443, 8983],
    },
    {
        "names": ["openssl", "libssl", "libssl1.1", "libssl3"],
        "cve": "CVE-2022-3602",
        "title": "OpenSSL X.509 Email Address Buffer Overflow",
        "cvss": 7.5, "severity": 3, "fixed_version": "3.0.7",
        "description": "A buffer overflow in OpenSSL X.509 certificate name-constraint checking can be triggered during certificate verification.",
        "solution": "Upgrade OpenSSL to 3.0.7 or later.",
        "has_public_exploit": False, "in_kev": False,
        "plugin_family": "Cryptography", "process_names": ["nginx", "httpd", "openssl"],
        "service_ports": [443, 8443],
    },
    {
        "names": ["sudo"],
        "cve": "CVE-2021-3156",
        "title": "Sudo Heap-Based Buffer Overflow (Baron Samedit)",
        "cvss": 7.8, "severity": 3, "fixed_version": "1.9.5p2",
        "description": "Heap-based buffer overflow in sudo allows local privilege escalation to root.",
        "solution": "Upgrade sudo to 1.9.5p2 or later.",
        "has_public_exploit": True, "in_kev": True,
        "plugin_family": "Privilege Escalation", "process_names": [],
        "service_ports": [],
    },
    {
        "names": ["openssh", "openssh-server", "openssh-client", "ssh"],
        "cve": "CVE-2024-6387",
        "title": "OpenSSH Unauthenticated Remote Code Execution (regreSSHion)",
        "cvss": 8.1, "severity": 4, "fixed_version": "9.8",
        "description": "A signal-handler race condition in OpenSSH's server allows unauthenticated remote code execution as root.",
        "solution": "Upgrade OpenSSH to 9.8p1 or later.",
        "has_public_exploit": True, "in_kev": False,
        "plugin_family": "Remote Access", "process_names": ["sshd"],
        "service_ports": [22],
    },
    {
        "names": ["curl", "libcurl", "libcurl4"],
        "cve": "CVE-2023-38545",
        "title": "curl SOCKS5 Heap Buffer Overflow",
        "cvss": 9.8, "severity": 4, "fixed_version": "8.4.0",
        "description": "A heap buffer overflow in curl's SOCKS5 proxy handshake can be triggered by an attacker-controlled hostname.",
        "solution": "Upgrade curl/libcurl to 8.4.0 or later.",
        "has_public_exploit": True, "in_kev": False,
        "plugin_family": "Networking", "process_names": [],
        "service_ports": [],
    },
    {
        "names": ["xz", "xz-utils", "liblzma", "liblzma5"],
        "cve": "CVE-2024-3094",
        "title": "XZ Utils Embedded Backdoor (Supply Chain)",
        "cvss": 10.0, "severity": 4,
        "vulnerable_versions": ["5.6.0", "5.6.1"],
        "fixed_version": "5.6.2",
        "description": "Malicious code introduced into the xz/liblzma build process backdoors sshd, enabling remote code execution.",
        "solution": "Downgrade or upgrade xz-utils to a build outside 5.6.0/5.6.1 (e.g. 5.6.2 or 5.4.x).",
        "has_public_exploit": True, "in_kev": True,
        "plugin_family": "Supply Chain", "process_names": ["sshd"],
        "service_ports": [22],
    },
    {
        "names": ["apache2", "httpd", "apache"],
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & RCE",
        "cvss": 7.5, "severity": 3, "fixed_version": "2.4.51",
        "description": "Path traversal in Apache HTTP Server 2.4.49/2.4.50 allows access to files outside the document root and remote code execution when CGI is enabled.",
        "solution": "Upgrade Apache HTTP Server to 2.4.51 or later.",
        "has_public_exploit": True, "in_kev": True,
        "plugin_family": "Web Servers", "process_names": ["httpd", "apache2"],
        "service_ports": [80, 443, 8080],
    },
    {
        "names": ["nginx"],
        "cve": "CVE-2021-23017",
        "title": "nginx DNS Resolver Off-by-One Heap Write",
        "cvss": 7.7, "severity": 3, "fixed_version": "1.21.0",
        "description": "An off-by-one error in nginx's DNS resolver can lead to memory corruption and potential remote code execution.",
        "solution": "Upgrade nginx to 1.21.0 or later.",
        "has_public_exploit": False, "in_kev": False,
        "plugin_family": "Web Servers", "process_names": ["nginx"],
        "service_ports": [80, 443, 8080],
    },
]


def _kb_for_software(name: str):
    """Return the KB entry whose package aliases match a software name."""
    if not name:
        return None
    n = name.strip().lower()
    for entry in VULN_KB:
        for alias in entry["names"]:
            if n == alias or n.startswith(alias):
                return entry
    return None


# ─────────────────────────────────────────────────────────
# Version comparison
# ─────────────────────────────────────────────────────────

def _parse_version(v) -> tuple:
    """Extract comparable numeric components from a version string.

    Handles Debian epochs and `pN` patch suffixes so the comparison is
    correct for OS-package version strings:
      "1.9.5p2" -> (1, 9, 5, 2); "9.6p1" -> (9, 6, 1);
      "1:9.6p1-3ubuntu13" -> (9, 6, 1); "2.4.49" -> (2, 4, 49)."""
    if not v:
        return ()
    s = str(v).strip()
    # Strip a Debian epoch ("1:9.6p1" -> "9.6p1").
    head, sep, tail = s.partition(":")
    if sep and head.isdigit():
        s = tail
    # Leading version token: dotted digits with an optional pN patch marker.
    m = re.match(r"[0-9]+(?:\.[0-9]+)*(?:p[0-9]+)?", s)
    if not m:
        return ()
    token = m.group(0).replace("p", ".")
    return tuple(int(x) for x in token.split(".") if x.isdigit())


def _version_lt(a, b) -> bool:
    """True if version a is strictly older than version b."""
    pa, pb = _parse_version(a), _parse_version(b)
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return pa < pb


def _is_vulnerable(entry: dict, version: str) -> bool:
    fixed = entry.get("vulnerable_versions")
    if fixed is not None:
        return str(version).strip() in fixed
    return _version_lt(version, entry["fixed_version"])


# ─────────────────────────────────────────────────────────
# Check-in pipeline
# ─────────────────────────────────────────────────────────

def process_checkin(db: Session, agent, payload: dict, source_ip: str = None) -> dict:
    """Process one agent check-in. Commits its own work and returns a summary
    dict including any host response actions the agent should now execute."""
    now = datetime.utcnow()
    org_id = agent.org_id

    scan = _resolve_scan(db, agent, payload)
    asset = _resolve_asset(db, agent, scan, payload, now)
    db.flush()

    _rewrite_inventory(db, scan, asset, payload)

    # Detect — match installed software against the KB.
    detections = []
    for sw in payload.get("software", []) or []:
        entry = _kb_for_software(sw.get("name"))
        if entry and _is_vulnerable(entry, sw.get("version")):
            detections.append((sw, entry))

    # Model-derived intelligence for every detected CVE.
    if detections:
        ai_threat_intel.generate_signals(db, [
            {
                "cve_id": e["cve"], "cvss": e["cvss"],
                "in_kev": e["in_kev"], "has_public_exploit": e["has_public_exploit"],
                "product": e["title"].split("(")[0].strip(),
                "description": e["description"],
            }
            for _, e in detections
        ])
    signal_by_cve = {
        s["cve_id"]: s
        for s in ai_threat_intel.get_signals_for_cves(db, [e["cve"] for _, e in detections])
    }

    processes = payload.get("processes", []) or []
    listening = payload.get("listening_ports", []) or []
    controls = payload.get("security_controls", []) or []
    edr_present = any(
        (c.get("type") or "").lower() in ("edr", "av", "antivirus") and c.get("enabled", True)
        for c in controls
    )

    # Reconcile findings against the existing endpoint-agent finding set.
    existing = {
        f.plugin_id: f
        for f in db.query(Finding).filter(
            Finding.asset_id == asset.id, Finding.source_type == SOURCE
        ).all()
    }
    detected_plugin_ids = set()
    touched_ids = []
    summary_rows = []

    for sw, entry in detections:
        plugin_id = f"endpoint-agent:{entry['cve']}"
        detected_plugin_ids.add(plugin_id)
        ctx = _contextualize(entry, sw, processes, listening, asset, edr_present)
        signal = signal_by_cve.get(entry["cve"])

        finding = existing.get(plugin_id)
        is_new = finding is None
        if is_new:
            finding = Finding(scan_id=scan.id, asset_id=asset.id, source_type=SOURCE)
            db.add(finding)
        elif finding.workflow_status == "resolved" or finding.auto_resolved:
            # Vulnerability re-appeared (e.g. package re-installed/downgraded).
            finding.is_regression = True
            finding.workflow_status = "open"
            finding.auto_resolved = False
            finding.auto_resolved_at = None

        _apply_finding(finding, scan, entry, sw, ctx, signal, now)
        db.flush()
        touched_ids.append(finding.id)
        if is_new:
            finding.first_seen = now
        else:
            finding.times_seen = (finding.times_seen or 1) + 1
        finding.last_seen = now

        summary_rows.append({
            "cve": entry["cve"],
            "finding_id": finding.id,
            "title": entry["title"],
            "severity": SEVERITY_LABELS[entry["severity"]],
            "runtime_active": ctx["runtime_active"],
            "network_reachable": ctx["network_reachable"],
            "ai_predicted_exploitation": bool(signal and signal["predicted_exploitation"]),
        })

    # Auto-resolve findings no longer detected this check-in.
    resolved_count = 0
    for plugin_id, finding in existing.items():
        if plugin_id not in detected_plugin_ids and finding.workflow_status != "resolved":
            finding.workflow_status = "resolved"
            finding.auto_resolved = True
            finding.auto_resolved_at = now
            finding.resolved_at = now
            resolved_count += 1

    agent.last_checkin_at = now
    agent.status = "active"
    agent.scan_id = scan.id
    agent.asset_id = asset.id
    db.commit()

    # Enrich + prioritize the touched findings through the standard pipeline.
    new_ids = [
        sr["finding_id"] for sr in summary_rows
    ]
    if new_ids:
        try:
            finalize_batch(db, scan.id, org_id=org_id, new_asset_ids=[asset.id],
                           new_finding_ids=new_ids)
        except Exception:
            logger.exception("finalize_batch failed for endpoint check-in scan=%s", scan.id)
            db.rollback()

    # Response — auto-create EDR detections for the worst findings.
    auto_detections = []
    if agent.auto_respond:
        for sr in summary_rows:
            finding = db.get(Finding, sr["finding_id"])
            if finding and _should_auto_respond(finding):
                rule = create_edr_detection(db, org_id, finding, origin="auto_respond")
                if rule:
                    auto_detections.append({"detection_rule_id": rule.id,
                                            "cve": sr["cve"], "name": rule.name})
        if auto_detections:
            db.commit()

    pending_actions = _dispatch_pending_actions(db, agent, now)
    db.commit()

    # Recompute summary post-prioritization.
    final = db.query(Finding).filter(
        Finding.asset_id == asset.id, Finding.source_type == SOURCE,
        Finding.workflow_status != "resolved",
    ).all()

    return {
        "scan_id": scan.id,
        "asset_id": asset.id,
        "checkin_interval": agent.checkin_interval or 300,
        "findings": {
            "total": len(final),
            "critical": sum(1 for f in final if (f.severity or 0) >= 4),
            "high": sum(1 for f in final if (f.severity or 0) == 3),
            "new": len([sr for sr in summary_rows
                        if sr["finding_id"] not in
                        {pid_f.id for pid_f in existing.values()}]),
            "resolved": resolved_count,
        },
        "detections": summary_rows,
        "auto_edr_detections": auto_detections,
        "pending_actions": pending_actions,
    }


def _resolve_scan(db: Session, agent, payload: dict) -> Scan:
    """One persistent Scan per agent — reused across check-ins."""
    scan = db.get(Scan, agent.scan_id) if agent.scan_id else None
    if scan is None:
        scan = Scan(
            org_id=agent.org_id,
            filename=f"endpoint-agent:{agent.id}",
            scan_name=f"Endpoint Agent — {agent.name}",
            scan_type="endpoint_agent",
            source_type="endpoint_agent",
            status="completed",
        )
        db.add(scan)
        db.flush()
    scan.scan_date = datetime.utcnow().isoformat()
    scan.last_run_at = datetime.utcnow()
    scan.run_count = (scan.run_count or 0) + 1
    return scan


def _resolve_asset(db: Session, agent, scan: Scan, payload: dict, now) -> Asset:
    """One persistent Asset per agent host — reused across check-ins."""
    asset = db.get(Asset, agent.asset_id) if agent.asset_id else None
    if asset is None:
        asset = Asset(scan_id=scan.id, asset_type="host", first_seen=now, times_seen=1)
        db.add(asset)
    else:
        asset.times_seen = (asset.times_seen or 1) + 1

    asset.hostname = payload.get("hostname") or agent.hostname or asset.hostname
    asset.ip = payload.get("ip_address") or asset.ip
    asset.fqdn = payload.get("fqdn") or asset.fqdn
    asset.os = payload.get("os_version") or asset.os
    asset.device_type = asset.device_type or "server"
    asset.source_system = SOURCE
    asset.source_systems = sorted(set((asset.source_systems or []) + [SOURCE]))
    asset.is_credentialed = True   # an on-host agent has full credentialed visibility
    asset.last_auth_run = now.isoformat()
    asset.last_seen = now
    asset.asset_status = "active"

    # Reachability — a service bound to a wildcard address on a known port.
    methods = []
    for lp in payload.get("listening_ports", []) or []:
        addr = (lp.get("address") or "").strip()
        if addr in ("0.0.0.0", "::", "*", "") and lp.get("port") in SERVICE_PORTS:
            methods.append(f"listening_port:{lp.get('port')}")
    if payload.get("public"):
        methods.append("agent_reported_public")
    if methods:
        asset.is_internet_facing = bool(payload.get("public"))
        asset.internet_facing_confidence = "confirmed" if payload.get("public") else "medium"
        asset.internet_facing_methods = methods
    return asset


def _rewrite_inventory(db: Session, scan: Scan, asset: Asset, payload: dict) -> None:
    """Replace this host's inventory rows with the latest check-in snapshot."""
    for model in (InventorySoftware, InventoryProcess, InventoryNetConn,
                  InventorySecurityControl):
        db.query(model).filter(
            model.scan_id == scan.id, model.asset_id == asset.id
        ).delete(synchronize_session=False)

    for sw in payload.get("software", []) or []:
        db.add(InventorySoftware(
            scan_id=scan.id, asset_id=asset.id,
            name=sw.get("name"), version=sw.get("version"),
            vendor=sw.get("vendor"), category=sw.get("category"),
            source_plugin=SOURCE,
        ))
    for proc in payload.get("processes", []) or []:
        db.add(InventoryProcess(
            scan_id=scan.id, asset_id=asset.id,
            process_name=proc.get("name"), pid=proc.get("pid"),
            ppid=proc.get("ppid"), parent_name=proc.get("parent_name"),
            source_plugin=SOURCE,
        ))
    for lp in payload.get("listening_ports", []) or []:
        db.add(InventoryNetConn(
            scan_id=scan.id, asset_id=asset.id,
            proto=lp.get("protocol", "tcp"), state="LISTEN",
            local_addr=lp.get("address"), local_port=lp.get("port"),
            pid=lp.get("pid"), source_plugin=SOURCE,
        ))
    for c in payload.get("security_controls", []) or []:
        db.add(InventorySecurityControl(
            scan_id=scan.id, asset_id=asset.id,
            control_type=(c.get("type") or "").lower(),
            product_name=c.get("product"), vendor=c.get("vendor"),
            version=c.get("version"), is_enabled=c.get("enabled", True),
            source_plugin=SOURCE,
        ))


def _contextualize(entry, sw, processes, listening, asset, edr_present) -> dict:
    """Compute runtime / reachability / control context for one detection."""
    proc_names = {p.lower() for p in entry.get("process_names", [])}
    running = [
        p for p in processes
        if (p.get("name") or "").lower() in proc_names
    ]
    runtime_active = bool(running) if proc_names else False

    svc_ports = set(entry.get("service_ports", []))
    open_ports = [
        lp for lp in listening
        if lp.get("port") in svc_ports
    ]
    network_reachable = bool(open_ports)

    if network_reachable and asset.is_internet_facing:
        reachability = "internet_facing"
    elif network_reachable:
        reachability = "internal_only"
    elif runtime_active:
        reachability = "internal_only"
    else:
        reachability = "unreachable"

    return {
        "detected_software": sw.get("name"),
        "installed_version": sw.get("version"),
        "fixed_version": entry.get("fixed_version"),
        "runtime_active": runtime_active,
        "running_processes": [
            {"name": p.get("name"), "pid": p.get("pid")} for p in running
        ],
        "network_reachable": network_reachable,
        "listening_ports": [lp.get("port") for lp in open_ports],
        "reachability": reachability,
        "edr_present": edr_present,
    }


def _apply_finding(finding, scan, entry, sw, ctx, signal, now) -> None:
    """Write detection + context + intel onto a Finding row."""
    sev = entry["severity"]
    finding.scan_id = scan.id
    finding.source_vuln_id = entry["cve"]
    finding.normalized_id = entry["cve"]
    finding.plugin_id = f"endpoint-agent:{entry['cve']}"
    finding.plugin_name = entry["title"]
    finding.plugin_family = entry["plugin_family"]
    finding.severity = sev
    finding.severity_label = SEVERITY_LABELS[sev]
    finding.risk_factor = SEVERITY_LABELS[sev]
    finding.cvss3_score = entry["cvss"]
    finding.cves = [entry["cve"]]
    finding.synopsis = entry["title"]
    finding.description = entry["description"]
    finding.solution = entry["solution"]
    finding.exploit_available = entry["has_public_exploit"]
    finding.is_kev = entry["in_kev"]
    if entry["has_public_exploit"]:
        finding.exploit_maturity_level = "functional"

    # Contextualization — drives the prioritizer's reachability weight.
    finding.ctx_reachability = ctx["reachability"]
    finding.ctx_exploitability = (
        "easily_exploitable" if (ctx["network_reachable"] and entry["has_public_exploit"])
        else "requires_conditions" if ctx["runtime_active"]
        else "not_exploitable" if ctx["reachability"] == "unreachable"
        else "unknown"
    )

    # Model-derived intelligence. A forecast of active exploitation that the
    # classic feeds have not yet caught up on is surfaced through the
    # `trending_in_news` channel so it feeds the prioritizer's intel weight.
    if signal and signal["predicted_exploitation"] and not entry["in_kev"]:
        finding.trending_in_news = True

    plugin_output = [
        f"Detected by Hakuna endpoint agent.",
        f"Package: {ctx['detected_software']} {ctx['installed_version']} "
        f"(fixed in {ctx['fixed_version']}).",
        f"Runtime: {'process active' if ctx['runtime_active'] else 'not currently running'}.",
        f"Reachability: {ctx['reachability']}.",
        f"EDR present: {'yes' if ctx['edr_present'] else 'no'}.",
    ]
    if signal:
        plugin_output.append(
            f"Model intel ({signal['generated_by_model']}): {signal['summary']}"
        )
    finding.plugin_output = "\n".join(plugin_output)

    finding.references = {
        "endpoint_context": {**ctx, "checked_in_at": now.isoformat()},
        "ai_threat_signal": signal,
    }
    if finding.workflow_status is None:
        finding.workflow_status = "open"


def _should_auto_respond(finding: Finding) -> bool:
    """A finding worth an automatic EDR detection: critical, and either
    KEV-listed or model-forecast for exploitation."""
    return (
        (finding.severity or 0) >= 4
        and (finding.is_kev or finding.trending_in_news)
        and finding.workflow_status != "resolved"
    )


def _dispatch_pending_actions(db: Session, agent, now) -> list:
    """Hand the agent any host response actions queued since its last
    check-in, marking them dispatched."""
    from models.models import EndpointAgentAction
    pending = db.query(EndpointAgentAction).filter(
        EndpointAgentAction.agent_id == agent.id,
        EndpointAgentAction.status == "pending",
    ).all()
    out = []
    for action in pending:
        action.status = "dispatched"
        action.dispatched_at = now
        out.append({
            "id": action.id,
            "action_type": action.action_type,
            "params": action.params or {},
            "finding_id": action.finding_id,
            "reason": action.reason,
        })
    return out


# ─────────────────────────────────────────────────────────
# Response — EDR detection creation
# ─────────────────────────────────────────────────────────

EDR_PUSH_CONNECTOR = "crowdstrike_create_detection"


def create_edr_detection(db: Session, org_id: int, finding: Finding,
                         origin: str = "manual") -> DetectionRule:
    """Close the loop by turning a finding into a detection rule.

    Creates a rule in Hakuna's detection engine and tags it with the EDR
    push connector that would deliver it to the endpoint-security tool.
    Idempotent per (org, finding)."""
    cve = (finding.cves or [None])[0] or finding.normalized_id
    existing = db.query(DetectionRule).filter(
        DetectionRule.org_id == org_id,
        DetectionRule.sigma_rule_id == f"endpoint-agent:{finding.id}",
    ).first()
    if existing:
        return existing

    ctx = (finding.references or {}).get("endpoint_context", {})
    sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    procs = [p["name"] for p in ctx.get("running_processes", []) if p.get("name")]

    rule = DetectionRule(
        org_id=org_id,
        name=f"Exploitation attempt: {finding.plugin_name}",
        description=(
            f"Auto-generated from endpoint-agent finding #{finding.id} "
            f"({cve}). Detects exploitation behavior associated with this "
            f"vulnerability. Stage to EDR via the '{EDR_PUSH_CONNECTOR}' "
            f"push connector. Origin: {origin}."
        ),
        severity=sev_map.get(finding.severity or 0, "medium"),
        enabled=True,
        query={
            "all": [
                {"field": "event.type", "op": "eq", "value": "process_exec"},
                {"field": "event.cve_context", "op": "contains", "value": cve},
            ]
        },
        window_seconds=300,
        threshold=1,
        group_by=["host.name", "process.name"],
        schedule_minutes=5,
        mitre_techniques=["T1190", "T1059"],
        asset_filter={"source_system": SOURCE},
        source="endpoint_agent",
        sigma_rule_id=f"endpoint-agent:{finding.id}",
    )
    db.add(rule)
    db.flush()
    logger.info("Created EDR detection rule %s from finding %s (%s)",
                rule.id, finding.id, origin)
    return rule
