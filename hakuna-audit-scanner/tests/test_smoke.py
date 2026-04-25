"""Smoke tests — verify the package imports cleanly and registers tools.

These are the cheapest possible safety net while the rest of the
audit-scanner package is being filled in. They catch import-time
breakage (circular imports, stale references to backend modules) and
the most common port mistakes.
"""

from __future__ import annotations


def test_package_imports():
    """Every public module must import without touching backend/."""
    from scanner.audit import (
        agent_context,
        audit_engine,
        audit_registry,
        audit_worker,
        celery_app,
        config,
        db,
        llm_provider,
        mission_loader,
        relay_client,
    )
    # Touch each module so unused-import linters don't strip them; the
    # actual assertion is that the `from` lines above succeeded.
    for m in (
        agent_context, audit_engine, audit_registry, audit_worker,
        celery_app, config, db, llm_provider, mission_loader, relay_client,
    ):
        assert m.__name__.startswith("scanner.audit")


def test_ssh_tools_registers():
    from scanner.audit import tools  # noqa: F401 — side-effect import
    from scanner.audit.audit_engine import TOOL_REGISTRY
    from scanner.audit.audit_registry import AUDITS

    assert "ssh" in AUDITS
    audit = AUDITS["ssh"]
    assert audit.relay_method == "ssh_query"
    assert any(m.key == "hardening_posture" for m in audit.missions)

    # The phase-1 palette plus emit_finding must all be in the tool registry.
    for name in audit.tool_names:
        assert name in TOOL_REGISTRY, f"tool {name!r} declared on audit but not registered"


def test_yaml_missions_load():
    from scanner.audit import mission_loader

    mission_loader.load_missions()
    # The bundled SSH hardening mission has prompt_key ssh_audit_hardening_posture.
    prompt = mission_loader.get_prompt("ssh_audit_hardening_posture")
    assert prompt is not None
    assert "credentialed Linux hardening auditor" in prompt
