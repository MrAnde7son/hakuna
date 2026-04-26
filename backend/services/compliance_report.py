"""Compliance report generation.

v1 design: the snapshot is the single source of truth.

  POST /api/compliance/reports
    → build_snapshot() captures (framework, controls, statuses, findings)
      at request time and freezes it into compliance_report_runs.snapshot
    → status flips to "succeeded" synchronously (snapshots are small)

  GET  /api/compliance/reports/{id}/download
    → serializes the stored snapshot into CSV or JSON on the fly
    → the snapshot guarantees a re-download returns identical bytes even if
      live state has moved on, which is what auditors need

PDF rendering is deferred — the snapshot will be the input to a Playwright
re-render in a follow-up PR. Until then GET .../download?format=pdf returns
501 with a clear "v1 supports csv|json" message.

Storage: rows live in Postgres. JSON snapshots are bounded (one framework's
controls + failing findings) — typical < 200 KB. We avoid MinIO + presigned
URLs for v1 to keep the surface area small; storage backend can flip later
without changing this module's shape.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import (
    Asset,
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceControlStatus,
    ComplianceFindingStatus,
    ComplianceFramework,
    ComplianceReportRun,
    Finding,
)


logger = logging.getLogger(__name__)


SUPPORTED_FORMATS = {"csv", "json"}


# ──────────────────────────────────────────────────────────────
# Snapshot
# ──────────────────────────────────────────────────────────────

def build_snapshot(
    db: Session,
    *,
    org_id: int,
    framework: ComplianceFramework,
) -> dict:
    """Freeze the current compliance posture for (org, framework) into a
    serializable dict. Stored on compliance_report_runs.snapshot so re-
    downloads are reproducible regardless of live state.

    Shape:
      {
        framework: {slug, name, version, authority, mapping_schema_version},
        generated_at: iso-8601,
        rollup: {total_controls, passing, failing, partial, compensating_control,
                 not_applicable, total_failing_findings, total_failing_assets},
        controls: [
          {
            id, ref, title, domain, testability, state,
            in_scope_asset_count, failing_finding_count, failing_asset_count,
            mapping_count,
            findings: [
              {finding_id, plugin_id, plugin_name, severity, severity_label,
               cves, cwe_ids, asset_id, asset_hostname, asset_ip,
               verdict, matched_via, mapping_key}
            ]
          }
        ]
      }
    """
    controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == framework.id)
        .order_by(ComplianceControl.ref)
        .all()
    )
    control_ids = [c.id for c in controls]

    statuses = {
        s.control_id: s for s in (
            db.query(ComplianceControlStatus)
            .filter(
                ComplianceControlStatus.org_id == org_id,
                ComplianceControlStatus.control_id.in_(control_ids),
            )
            .all() if control_ids else []
        )
    }

    mapping_counts: dict[int, int] = {}
    if control_ids:
        from sqlalchemy import func as sqla_func
        for cid, cnt in (
            db.query(
                ComplianceControlMapping.control_id,
                sqla_func.count(ComplianceControlMapping.id),
            )
            .filter(ComplianceControlMapping.control_id.in_(control_ids))
            .group_by(ComplianceControlMapping.control_id)
            .all()
        ):
            mapping_counts[cid] = cnt

    # Pull every finding-status row for this org+framework in two queries:
    # the statuses themselves, then the parent findings + assets keyed by id.
    cfs_rows = (
        db.query(ComplianceFindingStatus)
        .filter(
            ComplianceFindingStatus.org_id == org_id,
            ComplianceFindingStatus.control_id.in_(control_ids),
        )
        .all() if control_ids else []
    )
    finding_ids = {r.finding_id for r in cfs_rows}
    findings_by_id = {
        f.id: f for f in (
            db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
            if finding_ids else []
        )
    }
    asset_ids = {f.asset_id for f in findings_by_id.values()}
    assets_by_id = {
        a.id: a for a in (
            db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
            if asset_ids else []
        )
    }

    # Group statuses by control.
    statuses_by_control: dict[int, list[ComplianceFindingStatus]] = {}
    for r in cfs_rows:
        statuses_by_control.setdefault(r.control_id, []).append(r)

    rollup = {
        "total_controls": len(controls),
        "passing": 0,
        "failing": 0,
        "partial": 0,
        "compensating_control": 0,
        "not_applicable": 0,
        "total_failing_findings": 0,
        "total_failing_assets": 0,
    }

    control_dicts: list[dict] = []
    for c in controls:
        s = statuses.get(c.id)
        state = (s.state if s else "not_evaluated")
        if state in rollup:
            rollup[state] += 1
        if s:
            rollup["total_failing_findings"] += s.failing_finding_count or 0
            rollup["total_failing_assets"] += s.failing_asset_count or 0

        finding_dicts: list[dict] = []
        for cfs in statuses_by_control.get(c.id, []):
            f = findings_by_id.get(cfs.finding_id)
            if f is None:
                continue
            asset = assets_by_id.get(f.asset_id)
            finding_dicts.append({
                "finding_id": f.id,
                "plugin_id": f.plugin_id,
                "plugin_name": f.plugin_name,
                "plugin_family": f.plugin_family,
                "severity": f.severity,
                "severity_label": f.severity_label,
                "cves": list(f.cves or []),
                "cwe_ids": list(f.cwe_ids or []),
                "is_kev": bool(f.is_kev),
                "workflow_status": f.workflow_status,
                "sla_status": f.sla_status,
                "asset_id": f.asset_id,
                "asset_hostname": asset.hostname if asset else None,
                "asset_ip": asset.ip if asset else None,
                "verdict": cfs.verdict,
                "matched_via": cfs.matched_via,
                "mapping_key": cfs.mapping_key,
            })

        control_dicts.append({
            "id": c.id,
            "ref": c.ref,
            "title": c.title,
            "description": c.description,
            "domain": c.domain,
            "testability": c.testability,
            "canonical_guidance": c.canonical_guidance,
            "state": state,
            "in_scope_asset_count": (s.in_scope_asset_count if s else None),
            "failing_finding_count": (s.failing_finding_count if s else None),
            "failing_asset_count": (s.failing_asset_count if s else None),
            "last_evaluated_at": (s.last_evaluated_at.isoformat() + "Z" if s and s.last_evaluated_at else None),
            "mapping_count": mapping_counts.get(c.id, 0),
            "findings": finding_dicts,
        })

    return {
        "framework": {
            "slug": framework.slug,
            "name": framework.name,
            "version": framework.version,
            "authority": framework.authority,
            "mapping_schema_version": framework.mapping_schema_version,
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "rollup": rollup,
        "controls": control_dicts,
    }


# ──────────────────────────────────────────────────────────────
# Serializers
# ──────────────────────────────────────────────────────────────

_CSV_COLUMNS = [
    "framework_slug", "framework_name", "framework_version",
    "control_ref", "control_title", "control_domain", "control_state",
    "control_testability", "control_failing_finding_count",
    "finding_id", "plugin_id", "plugin_name", "plugin_family",
    "severity", "severity_label", "is_kev", "workflow_status", "sla_status",
    "cves", "cwe_ids",
    "asset_id", "asset_hostname", "asset_ip",
    "verdict", "matched_via", "mapping_key",
]


def snapshot_to_csv(snapshot: dict) -> str:
    """Serialize snapshot to a flat CSV: one row per (control × finding).

    Controls without findings still emit a single row with empty finding
    columns so auditors see passing/not_applicable controls in the export.
    """
    fw = snapshot.get("framework") or {}
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()

    base = {
        "framework_slug": fw.get("slug", ""),
        "framework_name": fw.get("name", ""),
        "framework_version": fw.get("version", ""),
    }

    for ctrl in snapshot.get("controls") or []:
        ctrl_base = {
            **base,
            "control_ref": ctrl.get("ref", ""),
            "control_title": ctrl.get("title", ""),
            "control_domain": ctrl.get("domain") or "",
            "control_state": ctrl.get("state", ""),
            "control_testability": ctrl.get("testability", ""),
            "control_failing_finding_count": ctrl.get("failing_finding_count") or 0,
        }
        findings = ctrl.get("findings") or []
        if not findings:
            row = {k: "" for k in _CSV_COLUMNS}
            row.update(ctrl_base)
            writer.writerow(row)
            continue
        for f in findings:
            row = {k: "" for k in _CSV_COLUMNS}
            row.update(ctrl_base)
            row.update({
                "finding_id": f.get("finding_id", ""),
                "plugin_id": f.get("plugin_id") or "",
                "plugin_name": f.get("plugin_name") or "",
                "plugin_family": f.get("plugin_family") or "",
                "severity": f.get("severity") if f.get("severity") is not None else "",
                "severity_label": f.get("severity_label") or "",
                "is_kev": "yes" if f.get("is_kev") else "no",
                "workflow_status": f.get("workflow_status") or "",
                "sla_status": f.get("sla_status") or "",
                "cves": ";".join(f.get("cves") or []),
                "cwe_ids": ";".join(f.get("cwe_ids") or []),
                "asset_id": f.get("asset_id") or "",
                "asset_hostname": f.get("asset_hostname") or "",
                "asset_ip": f.get("asset_ip") or "",
                "verdict": f.get("verdict") or "",
                "matched_via": f.get("matched_via") or "",
                "mapping_key": f.get("mapping_key") or "",
            })
            writer.writerow(row)

    return buf.getvalue()


def snapshot_to_json(snapshot: dict) -> str:
    """Serialize snapshot to indented JSON. Stable key order via sort_keys=False
    so the rollup → controls → findings hierarchy matches the in-memory shape."""
    return json.dumps(snapshot, indent=2, default=str)


def snapshot_sha256(serialized: str) -> str:
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ──────────────────────────────────────────────────────────────
# Generation
# ──────────────────────────────────────────────────────────────

def generate_report(
    db: Session,
    *,
    org_id: int,
    framework: ComplianceFramework,
    fmt: str,
    user_id: Optional[int] = None,
) -> ComplianceReportRun:
    """Build the snapshot, compute the artifact sha256, persist a
    compliance_report_runs row, and return it. Synchronous — snapshots are
    small enough for a request-scoped generation.

    fmt: csv | json (PDF deferred — see module docstring)
    """
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"format {fmt!r} not supported in v1; use one of {sorted(SUPPORTED_FORMATS)}"
        )

    snapshot = build_snapshot(db, org_id=org_id, framework=framework)
    serialized = snapshot_to_csv(snapshot) if fmt == "csv" else snapshot_to_json(snapshot)

    run = ComplianceReportRun(
        org_id=org_id,
        framework_id=framework.id,
        format=fmt,
        status="succeeded",
        sha256=snapshot_sha256(serialized),
        snapshot=snapshot,
        generated_by=user_id,
        generated_at=datetime.utcnow(),
    )
    db.add(run)
    db.flush()
    logger.info(
        "Compliance report %s generated for org=%s framework=%s sha=%s",
        fmt, org_id, framework.slug, run.sha256[:12],
    )
    return run


def serialize_run(run: ComplianceReportRun) -> str:
    """Re-serialize a stored run's snapshot. Caller picks Content-Type."""
    if run.format == "csv":
        return snapshot_to_csv(run.snapshot or {})
    if run.format == "json":
        return snapshot_to_json(run.snapshot or {})
    raise ValueError(f"unsupported run.format={run.format!r}")
