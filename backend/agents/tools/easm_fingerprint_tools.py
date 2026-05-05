"""EASM fingerprint family — metadata-only ProtocolAudit registration.

Phase 2 of the protocol audit roadmap (Family F). Unlike every other audit
family, this one runs entirely in the scanner — see
``hakuna-scanner/app/ingest/{ssh_banner, rdp_nla_probe, mail_banner,
printer_banner, tr069_upnp_probe, db_banner}.py`` and the
``_do_banner_grab`` step in ``hakuna-scanner/app/tasks/enrichment.py``.

The registration here exists so that:

  * The audit appears in the registry list / kickoff UI (grouped under
    "EASM fingerprinting" alongside other ``mode="fingerprint"`` audits)
  * Compliance auto-tagging picks up the family's ``compliance_tags``
    when the scanner emits banner-derived findings
  * The single dispatch surface (``dispatch_audit_run``) sees a
    consistent registration shape — no parallel "scanner-only" type

Because there are no LLM tools and no relay handler, attempting to
dispatch this audit must be a no-op. ``audit_runner.dispatch_audit_run``
should short-circuit on ``audit.mode == "fingerprint"`` (TODO — open
follow-up).
"""

from __future__ import annotations

from agents.audit_registry import ProtocolAudit, register_audit


register_audit(ProtocolAudit(
    protocol="easm_fingerprint",
    label="EASM Fingerprinting",
    description=(
        "Scanner-driven banner-depth fingerprinter for SSH, RDP, mail "
        "(SMTP/IMAP/POP3), IPP printers, TR-069/UPnP CPE devices, and "
        "PostgreSQL/MySQL. Output feeds the CVE correlator via "
        "assets.easm_data.banner_findings. Findings emitted only for "
        "auth-hygiene issues (RDP without NLA, missing STARTTLS, exposed "
        "UPnP descriptors); pure version banners are correlation-only."
    ),
    supported_os=["any"],
    auth_modes=["anonymous"],
    relay_method="",  # never dispatched — runs in the scanner
    credential_connector_ids=[],
    tool_names=[],
    missions=[],
    required_ports=(
        22, 25, 110, 143, 465, 587, 631,
        993, 995, 1900, 3306, 3389, 5432, 7547,
    ),
    safety_class="anon_standard",
    mode="fingerprint",
    auto_trigger_policy="manual",
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ds"),
))
