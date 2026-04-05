"""Run engine — orchestrates integration execution: transport → field mapper → upsert."""

import logging
import asyncio
from datetime import datetime

from sqlalchemy.orm import Session

from models.models import Integration, IntegrationRun, Scan, RelayAgent
from services.field_mapper import map_record, render_template
from services.upsert_handler import upsert, upsert_batch
from services import credential_vault
from services.transports.api_transport import ApiTransport
from services.transports.file_transport import FileTransport
from services.transports.sql_transport import SqlTransport
from services.transports.mcp_transport import McpTransport

logger = logging.getLogger(__name__)

# Transport registry
TRANSPORTS = {
    "api": ApiTransport,
    "file": FileTransport,
    "sql": SqlTransport,
    "mcp": McpTransport,
}


class RunProgress:
    """Tracks progress for SSE streaming."""
    def __init__(self):
        self.events = []

    def emit(self, event_type: str, **kwargs):
        event = {"type": event_type, **kwargs}
        self.events.append(event)
        logger.info("Run event: %s", event)


async def execute(db: Session, integration_id: str, triggered_by: str = "manual", run_id: str = None) -> str:
    """Execute an integration run. Returns run_id."""
    integration = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integration:
        raise ValueError(f"Integration {integration_id} not found")

    # Reuse pre-created run record or create a new one
    run = None
    if run_id:
        run = db.query(IntegrationRun).filter(IntegrationRun.id == run_id).first()
    if not run:
        run = IntegrationRun(integration_id=integration.id, status="running", triggered_by=triggered_by)
        db.add(run)
        db.commit()
        db.refresh(run)

    progress = RunProgress()

    try:
        # Load + decrypt credentials (auto-refresh OAuth2 if expired)
        credentials = {}
        if integration.credentials_id:
            from services.credential_manager import load_credentials
            credentials = await load_credentials(db, integration.credentials_id, integration.org_id)

        # Get transport
        if integration.transport_type == "relay":
            from services.transports.relay_transport import RelayTransport
            from services.relay_broker import get_relay_broker
            if not integration.relay_agent_id:
                raise ValueError("Integration uses relay transport but no relay agent is assigned")
            agent = db.query(RelayAgent).filter(RelayAgent.id == integration.relay_agent_id).first()
            if not agent:
                raise ValueError(f"Relay agent {integration.relay_agent_id} not found")
            broker = get_relay_broker()
            if not broker.is_connected(agent.id):
                raise ConnectionError(f"Relay agent '{agent.name}' is offline")
            transport = RelayTransport(
                agent_id=agent.id,
                credentials_mode=agent.credentials_mode or "agent_local",
            )
        else:
            transport_cls = TRANSPORTS.get(integration.transport_type)
            if not transport_cls:
                raise ValueError(f"Unknown transport type: {integration.transport_type}")
            transport = transport_cls(db=db) if integration.transport_type == "file" else transport_cls()

        config = integration.transport_config or {}
        config["records_path"] = integration.records_path

        pull_scan_id = None
        if integration.direction == "pull":
            pull_scan_id = await _execute_pull(
                db, transport, config, credentials, integration, run, progress
            )
        elif integration.direction == "push":
            await _execute_push(
                db, transport, config, credentials, integration, run, progress
            )

        # Run full post-ingest pipeline on pulled data
        if integration.direction == "pull":
            from services.post_ingest import finalize_scan
            finalize_scan(db, scan_id=pull_scan_id, org_id=integration.org_id)

        # Mark success
        run.status = "success" if not run.errors else "partial"
        run.finished_at = datetime.utcnow()
        run.duration_ms = int((run.finished_at - run.started_at).total_seconds() * 1000) if run.started_at else None
        integration.last_run_at = datetime.utcnow()
        integration.last_run_status = run.status
        integration.last_run_records = run.records_fetched
        db.commit()

        progress.emit("complete", status=run.status,
                      records_fetched=run.records_fetched,
                      records_inserted=run.records_inserted,
                      records_updated=run.records_updated,
                      records_skipped=run.records_skipped,
                      error_count=len(run.errors or []))

        # Fire workflow triggers for integration completion
        _fire_integration_workflows(db, integration, run)

    except Exception as e:
        logger.exception("Run %s failed", run.id)
        run.status = "error"
        run.finished_at = datetime.utcnow()
        run.duration_ms = int((run.finished_at - run.started_at).total_seconds() * 1000) if run.started_at else None
        run.error_message = str(e)
        run.errors = (run.errors or []) + [{"message": str(e)}]
        integration.last_run_at = datetime.utcnow()
        integration.last_run_status = "error"
        db.commit()
        progress.emit("error", message=str(e))

        # Fire workflow triggers for integration failure
        _fire_integration_workflows(db, integration, run)

    return run.id


def _fire_integration_workflows(db: Session, integration: Integration, run: IntegrationRun):
    """Fire workflows with on_integration_execution (or legacy) triggers."""
    try:
        import services.workflow_engine as workflow_engine
        workflow_engine.fire_event_workflows(db, "on_integration_execution", {
            "integration_id": integration.id,
            "integration_name": integration.name,
            "run_id": run.id,
            "status": run.status,
            "records_fetched": run.records_fetched,
            "records_inserted": run.records_inserted,
            "records_updated": run.records_updated,
            "error_message": run.error_message,
            "triggered_by": run.triggered_by,
        })
    except Exception as e:
        logger.warning("Failed to fire integration workflows: %s", e)


async def _execute_pull(db, transport, config, credentials, integration, run, progress):
    """Execute a pull integration: fetch → map → upsert."""
    progress.emit("step", message="Connecting and validating credentials...")

    # Validate connection
    result = await transport.connect(config, credentials)
    if not result.success:
        raise RuntimeError(f"Connection failed: {result.error}")

    progress.emit("step", message="Fetching records...")

    field_map = integration.field_map or []
    dedup_key = integration.dedup_key or []
    entity = integration.entity
    source_system = integration.template_id or "custom"

    # Check if this connector requires LLM extraction (unstructured sources)
    llm_extract_config = config.get("llm_extract")

    # Create a placeholder scan so assets/findings have a valid scan_id FK
    placeholder_scan = Scan(
        org_id=integration.org_id,
        filename=f"integration:{integration.name or integration.id}",
        source_type=source_system,
        status="completed",
    )
    db.add(placeholder_scan)
    db.flush()
    scan_id = placeholder_scan.id

    batch = []
    batch_size = 500
    total_fetched = 0
    total_inserted = 0
    total_updated = 0
    total_skipped = 0
    errors = []

    # ── Unstructured source path: collect → extract → map → upsert ──
    if llm_extract_config:
        raw_records = []
        async for raw_record in transport.fetch_all(config, credentials, integration.params):
            total_fetched += 1
            raw_records.append(raw_record)

            if total_fetched % 50 == 0:
                progress.emit("progress", records_fetched=total_fetched, records_processed=0)

        progress.emit("step", message=f"Fetched {total_fetched} records. Running AI extraction...")

        # Prepare text for LLM
        from services.llm_extractor import extract_findings_with_llm, prepare_text_for_extraction

        text_field = llm_extract_config.get("text_field", "body")
        title_field = llm_extract_config.get("title_field")
        url_field = llm_extract_config.get("url_field")

        combined_text = prepare_text_for_extraction(
            raw_records, text_field, title_field, url_field
        )

        if not combined_text.strip():
            logger.warning("No text content extracted from %d records", total_fetched)
            run.records_fetched = total_fetched
            run.records_inserted = 0
            run.records_updated = 0
            run.records_skipped = total_fetched
            run.step_log = progress.events
            return scan_id

        # Run LLM extraction
        extracted_findings = extract_findings_with_llm(db, combined_text, prompt_type="unstructured")

        progress.emit("step", message=f"AI extracted {len(extracted_findings)} findings. Processing...")

        # Process extracted findings through normal field map → upsert pipeline
        for i, finding_record in enumerate(extracted_findings):
            result = map_record(finding_record, field_map)
            mapped = result["mapped"]

            if "source_system" not in mapped or not mapped.get("source_system"):
                mapped["source_system"] = source_system
            if "source_id" not in mapped or not mapped.get("source_id"):
                mapped["source_id"] = finding_record.get("finding_id", str(i + 1))

            for err in result["errors"]:
                if err["level"] == "error":
                    errors.append({"record_index": i + 1, **err})

            batch.append(mapped)

            if len(batch) >= batch_size:
                counts = upsert_batch(db, entity, batch, dedup_key, integration.id, scan_id=scan_id)
                total_inserted += counts["inserted"]
                total_updated += counts["updated"]
                total_skipped += counts["skipped"]
                errors.extend(counts["errors"])
                batch = []

        # Final batch
        if batch:
            counts = upsert_batch(db, entity, batch, dedup_key, integration.id, scan_id=scan_id)
            total_inserted += counts["inserted"]
            total_updated += counts["updated"]
            total_skipped += counts["skipped"]
            errors.extend(counts["errors"])

    # ── Structured source path: fetch → map → upsert ──
    else:
        async for raw_record in transport.fetch_all(config, credentials, integration.params):
            total_fetched += 1

            # Apply field mapper
            result = map_record(raw_record, field_map)
            mapped = result["mapped"]

            # Inject source_system if not mapped
            if "source_system" not in mapped or not mapped.get("source_system"):
                mapped["source_system"] = source_system
            if "source_id" not in mapped or not mapped.get("source_id"):
                mapped["source_id"] = str(total_fetched)

            # Collect mapping errors
            for err in result["errors"]:
                if err["level"] == "error":
                    errors.append({"record_index": total_fetched, **err})

            batch.append(mapped)

            if len(batch) >= batch_size:
                counts = upsert_batch(db, entity, batch, dedup_key, integration.id, scan_id=scan_id)
                total_inserted += counts["inserted"]
                total_updated += counts["updated"]
                total_skipped += counts["skipped"]
                errors.extend(counts["errors"])
                batch = []

                progress.emit("progress", records_fetched=total_fetched,
                              records_processed=total_inserted + total_updated + total_skipped)

            # Periodic progress
            if total_fetched % 100 == 0:
                progress.emit("progress", records_fetched=total_fetched,
                              records_processed=total_inserted + total_updated + total_skipped)

        # Final batch
        if batch:
            counts = upsert_batch(db, entity, batch, dedup_key, integration.id, scan_id=scan_id)
            total_inserted += counts["inserted"]
            total_updated += counts["updated"]
            total_skipped += counts["skipped"]
            errors.extend(counts["errors"])

    # Update run record
    run.records_fetched = total_fetched
    run.records_inserted = total_inserted
    run.records_updated = total_updated
    run.records_skipped = total_skipped
    run.errors = errors[:100]  # cap stored errors
    run.step_log = progress.events

    return scan_id


async def _execute_push(db, transport, config, credentials, integration, run, progress):
    """Execute a push integration: load findings → render template → push."""
    from models.models import Finding, Asset

    progress.emit("step", message="Loading findings to push...")

    # Load findings matching params
    query = db.query(Finding).join(Asset, Finding.asset_id == Asset.id)

    params = integration.params or {}
    if params.get("severity"):
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        query = query.filter(Finding.severity >= sev_map.get(params["severity"], 0))
    if params.get("status"):
        query = query.filter(Finding.workflow_status == params["status"])

    findings = query.limit(params.get("limit", 100)).all()

    progress.emit("step", message=f"Pushing {len(findings)} findings...")

    total_fetched = len(findings)
    total_inserted = 0
    errors = []

    template = config.get("body", {})

    for i, finding in enumerate(findings):
        asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

        finding_data = {
            "cve_id": (finding.cves[0] if finding.cves else "") if finding.cves else "",
            "title": finding.plugin_name or "",
            "severity": finding.severity_label or "info",
            "solution": finding.solution or "",
            "cvss_score": finding.cvss3_score or 0,
            "description": finding.description or "",
        }
        asset_data = {
            "hostname": asset.hostname if asset else "",
            "ip_address": asset.ip if asset else "",
            "environment": asset.environment_tag if asset else "",
        }

        payload = render_template(template, finding_data, asset_data)

        result = await transport.push(config, credentials, payload)
        if result.success:
            total_inserted += 1
        else:
            errors.append({"record_index": i, "message": result.error})

        if (i + 1) % 10 == 0:
            progress.emit("progress", records_fetched=total_fetched, records_processed=i + 1)

    run.records_fetched = total_fetched
    run.records_inserted = total_inserted
    run.records_skipped = 0
    run.records_updated = 0
    run.errors = errors[:100]
    run.step_log = progress.events
