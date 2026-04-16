"""Scanner adapters — register existing scanners in the registry.

Each adapter wraps an existing `_do_<name>` stage function (from
`app/tasks/discovery.py` or `app/tasks/enrichment.py`) and its underlying
`BaseRunner` subclass (from `app/runner/tools.py`) as a `ScannerSpec`.

Imports are done lazily inside the register function to avoid circular
import issues (tasks modules import from runner, runner doesn't import tasks).
"""

from __future__ import annotations

import logging

from app.runner.registry import ScannerSpec, register_scanner

logger = logging.getLogger(__name__)


def register_enrichment_scanners() -> None:
    """Register the enrichment-stage scanners.

    Group indexes match the existing hardcoded step_groups in
    app/tasks/enrichment.py so the registry-driven DAG output matches
    the current behavior.

    Current hardcoded layout (for reference):
      Group 0: tlsx, httpx, cdncheck
      Group 1: js_fingerprint, favicon_fingerprint, endpoint_probe,
               protocol_probe, katana, kiterunner
      Group 2: trufflehog, llm_js_extraction
      Group 3: classify_assets
      Group 4: nmap_dispatch (special-cased — handled by _dispatch_nmap)
    """
    # Lazy imports to avoid circular deps
    from app.runner.tools import (
        CdncheckRunner,
        HttpxRunner,
        KatanaRunner,
        KiterunnerRunner,
        TlsxRunner,
        TrufflehogRunner,
    )
    from app.tasks.enrichment import (
        _do_cdncheck,
        _do_classify_assets,
        _do_endpoint_probe,
        _do_favicon_fingerprint,
        _do_httpx,
        _do_js_fingerprint,
        _do_katana,
        _do_kiterunner,
        _do_llm_js_extraction,
        _do_protocol_probe,
        _do_tlsx,
        _do_trufflehog,
    )

    # ── Group 0: TLS/HTTP baseline (run in parallel) ──
    register_scanner(ScannerSpec(
        name="tlsx",
        stage="enrichment",
        group=0,
        stage_fn=_do_tlsx,
        runner_class=TlsxRunner,
        inputs=["hostname", "open_ports"],
        outputs=["tls_cert", "jarm_hash"],
        port_filter=None,  # scans all open ports
        cdn_safe=True,
        estimated_cost="medium",
    ))

    register_scanner(ScannerSpec(
        name="httpx",
        stage="enrichment",
        group=0,
        stage_fn=_do_httpx,
        runner_class=HttpxRunner,
        inputs=["hostname"],
        outputs=["http_status", "tech_stack", "page_title", "screenshot_path"],
        cdn_safe=True,
        estimated_cost="medium",
    ))

    register_scanner(ScannerSpec(
        name="cdncheck",
        stage="enrichment",
        group=0,
        stage_fn=_do_cdncheck,
        runner_class=CdncheckRunner,
        inputs=["hostname"],
        outputs=["cdn_provider"],
        cdn_safe=True,
        estimated_cost="low",
    ))

    # ── Group 1: Fingerprinting + crawling (run in parallel, after HTTP baseline) ──
    register_scanner(ScannerSpec(
        name="js_fingerprint",
        stage="enrichment",
        group=1,
        stage_fn=_do_js_fingerprint,
        inputs=["hostname", "open_ports"],
        outputs=["cpe_list"],
        depends_on=["httpx"],
        port_filter={80, 443, 8080, 8443},
        cdn_safe=True,
        estimated_cost="medium",
    ))

    register_scanner(ScannerSpec(
        name="favicon_fingerprint",
        stage="enrichment",
        group=1,
        stage_fn=_do_favicon_fingerprint,
        inputs=["hostname", "open_ports"],
        outputs=["cpe_list"],
        depends_on=["httpx"],
        port_filter={80, 443, 8080, 8443},
        cdn_safe=True,
        estimated_cost="low",
    ))

    register_scanner(ScannerSpec(
        name="endpoint_probe",
        stage="enrichment",
        group=1,
        stage_fn=_do_endpoint_probe,
        inputs=["hostname", "open_ports"],
        outputs=["cpe_list"],
        depends_on=["httpx"],
        port_filter={80, 443, 8080, 8443},
        cdn_safe=False,  # endpoint probes skip CDN assets
        estimated_cost="medium",
    ))

    register_scanner(ScannerSpec(
        name="protocol_probe",
        stage="enrichment",
        group=1,
        stage_fn=_do_protocol_probe,
        inputs=["hostname", "open_ports"],
        outputs=["protocol_detections"],
        port_filter=None,  # checks OT/IoT/AI ports specifically (see PROTOCOL_PROBES)
        cdn_safe=True,
        estimated_cost="low",
    ))

    register_scanner(ScannerSpec(
        name="katana",
        stage="enrichment",
        group=1,
        stage_fn=_do_katana,
        runner_class=KatanaRunner,
        inputs=["hostname", "open_ports"],
        outputs=["asset_endpoints"],
        depends_on=["httpx"],
        port_filter={80, 443, 8080, 8443},
        cdn_safe=False,
        estimated_cost="high",
    ))

    register_scanner(ScannerSpec(
        name="kiterunner",
        stage="enrichment",
        group=1,
        stage_fn=_do_kiterunner,
        runner_class=KiterunnerRunner,
        inputs=["hostname", "open_ports"],
        outputs=["asset_endpoints"],
        depends_on=["httpx"],
        port_filter={80, 443, 8080, 8443},
        cdn_safe=False,
        estimated_cost="high",
    ))

    # ── Group 2: Post-katana analysis (trufflehog + LLM depend on katana JS URLs) ──
    register_scanner(ScannerSpec(
        name="trufflehog",
        stage="enrichment",
        group=2,
        stage_fn=_do_trufflehog,
        runner_class=TrufflehogRunner,
        inputs=["asset_endpoints"],
        outputs=["findings"],
        depends_on=["katana"],
        cdn_safe=True,
        estimated_cost="high",
    ))

    register_scanner(ScannerSpec(
        name="llm_js_extraction",
        stage="enrichment",
        group=2,
        stage_fn=_do_llm_js_extraction,
        inputs=["asset_endpoints"],
        outputs=["asset_endpoints"],
        depends_on=["katana"],
        cdn_safe=True,
        estimated_cost="high",
    ))

    # ── Group 3: Classification (needs all fingerprinting data) ──
    register_scanner(ScannerSpec(
        name="classify_assets",
        stage="enrichment",
        group=3,
        stage_fn=_do_classify_assets,
        inputs=["tech_stack", "cpe_list", "protocol_detections"],
        outputs=["asset_type"],
        depends_on=[
            "httpx", "js_fingerprint", "favicon_fingerprint",
            "endpoint_probe", "protocol_probe",
        ],
        cdn_safe=True,
        estimated_cost="low",
    ))

    # ── Group 4: Nmap dispatch (special-cased — stage_fn=None) ──
    # The orchestrator handles 'nmap_dispatch' specifically via _dispatch_nmap.
    # We still register it so it appears in the registry inventory.
    register_scanner(ScannerSpec(
        name="nmap_dispatch",
        stage="enrichment",
        group=4,
        stage_fn=None,  # handled by _dispatch_nmap in enrichment.py
        inputs=["hostname", "open_ports"],
        outputs=["os_fingerprint", "service_versions"],
        depends_on=["classify_assets"],
        cdn_safe=True,
        estimated_cost="high",
    ))


def register_all() -> None:
    """Register all known scanners. Called on module import via __init__."""
    register_enrichment_scanners()
    logger.info("Scanner registry: registered %d enrichment scanners", len(
        [s for s in __import__("app.runner.registry", fromlist=["SCANNER_REGISTRY"]).SCANNER_REGISTRY.values()
         if s.stage == "enrichment"]
    ))
