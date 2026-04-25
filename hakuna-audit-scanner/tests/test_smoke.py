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
        publisher,
        quota,
        relay_client,
    )
    for m in (
        agent_context, audit_engine, audit_registry, audit_worker,
        celery_app, config, db, llm_provider, mission_loader,
        publisher, quota, relay_client,
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


def test_publisher_factory():
    """make_publisher returns Null when no Redis URL is configured."""
    from scanner.audit.publisher import (
        NullPublisher,
        make_publisher,
        event,
    )

    p = make_publisher(url=None)
    assert isinstance(p, NullPublisher)
    # NullPublisher.publish must accept any dict without raising.
    p.publish("run-x", event("thinking", "run-x", iteration=1))
    p.close()


def test_quota_in_memory():
    """InMemoryQuotaProvider records and trips QuotaExceeded at the limit."""
    from scanner.audit.quota import (
        InMemoryQuotaProvider,
        NullQuotaProvider,
        QuotaExceeded,
    )

    null = NullQuotaProvider()
    null.check("anything")  # never raises
    null.record("anything", 1000, 2000)

    p = InMemoryQuotaProvider(limit=1000)
    p.check("org-1")  # under limit
    p.record("org-1", 600, 500)  # 1100 > 1000
    try:
        p.check("org-1")
    except QuotaExceeded:
        pass
    else:
        raise AssertionError("expected QuotaExceeded")
    # Different org isolated.
    p.check("org-2")


def test_relay_transport_default_is_null_without_url():
    """Without HAKUNA_RELAY_URL, get_transport returns Null (not Http)."""
    import importlib
    import scanner.audit.relay_client as rc

    # Reset module-level state for the test.
    rc._transport = None
    importlib.reload(rc)
    rc._transport = None
    transport = rc.get_transport()
    assert isinstance(transport, rc.NullRelayTransport)
    assert transport.is_connected("any") is False


def test_engine_quota_exceeded_short_circuits():
    """Engine raises stop_reason=quota_exceeded before calling adapter."""
    import asyncio

    from scanner.audit.agent_context import AuditContext
    from scanner.audit.audit_engine import run_audit
    from scanner.audit.llm_provider import LLMAdapter
    from scanner.audit.publisher import NullPublisher
    from scanner.audit.quota import InMemoryQuotaProvider

    class _BoomAdapter(LLMAdapter):
        provider_name = "test"

        def turn(self, **kwargs):
            raise AssertionError("adapter must not be called when quota is exhausted")

    quota = InMemoryQuotaProvider(limit=1)
    quota.record("org-x", 1, 1)  # already over

    ctx = AuditContext(
        run_id="run-0",
        agent_id="run-0",
        org_id="org-x",
        asset={"id": "a-0"},
        target="example.test",
        target_port=None,
        relay_agent_id=None,
        credential_id=None,
        credentials={},
        protocol="ssh",
        mission_key="hardening_posture",
        publisher=NullPublisher(),
        quota=quota,
    )

    result = asyncio.run(run_audit(
        ctx=ctx,
        adapter=_BoomAdapter(),
        system_prompt="x",
        initial_user_message="x",
        tool_names=[],
        max_steps=5,
        wallclock_s=10,
    ))
    assert result["stop_reason"] == "quota_exceeded"


def test_shared_tools_registered():
    """The four shared tools (correlate_software_to_cves, get_asset_profile,
    read/write_scratchpad, request_clarification) all register."""
    from scanner.audit import tools  # noqa: F401
    from scanner.audit.audit_engine import TOOL_REGISTRY

    for name in (
        "correlate_software_to_cves",
        "get_asset_profile",
        "read_scratchpad",
        "write_scratchpad",
        "clear_scratchpad",
        "request_clarification",
    ):
        assert name in TOOL_REGISTRY, f"shared tool {name!r} not registered"
