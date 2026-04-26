"""Protocol Audit registry — single source of truth for ReAct-driven,
credentialed audits per network protocol.

A **Protocol Audit** is a ReAct agent with:
  - a network protocol it speaks (wmi, ldap, smb, kerberos, snmp, winrm, …)
  - a fixed tool palette scoped to that protocol
  - one or more *mission* templates (system prompts) the user picks from
  - a relay method key — whatever the relay executor dispatches to

This file is deliberately *just* a registry + dataclasses. It doesn't import
any protocol-specific code — each protocol module (`agents/tools/wmi_tools.py`,
`agents/tools/ldap_tools.py`, …) self-registers into AUDITS at import time.

Adding a new protocol is three things: (1) write its tool palette, (2) write
its mission prompts in agent_prompts.ENHANCED_PROMPTS, (3) append a call to
`register_audit(ProtocolAudit(...))` in the protocol's tools module. No route
or frontend changes required — the generic `/api/audits/run` route and the
"New Scan → Authenticated Audit" submenu read from AUDITS.

## Safety classes

Each audit declares a ``safety_class`` that drives credential gating, rate
limits, auto-trigger policy, and frontend grouping. The classes form a
deliberate hierarchy from "must have credentials" to "must never write a
single PDU":

  - ``credentialed``       — needs creds (WMI, LDAP, SSH, WinRM, cloud)
  - ``anon_standard``      — anonymous OK, normal blast radius (SMB, SNMP)
  - ``anon_datastore``     — anonymous OK, target is a data store
                              (Redis, Mongo, etcd, k8s API, …)
  - ``anon_ai_exposure``   — anonymous OK, target is an AI/ML service
                              (Ollama, Jupyter, Ray, MLflow, …)
  - ``anon_ipmi``          — anonymous OK, BMC/IPMI Cipher Zero class
  - ``anon_lan_local``     — anonymous OK, only valid when the relay is on
                              the same broadcast domain (NetBIOS, mDNS)
  - ``ot_safe``            — OT/ICS, read-only PDUs only, requires per-asset
                              consent and aggressive rate limiting
  - ``ot_passive_only``    — OT/ICS, fingerprint via banner only — never
                              craft a protocol PDU (Yokogawa, CC-Link IE)

Anything other than ``credentialed`` may dispatch with ``credential_id=None``;
the ``safety_class != "credentialed"`` predicate replaces what used to be a
hardcoded ``_ANON_CAPABLE_PROTOCOLS`` set in audit_runner.

## Auto-trigger policy

  - ``manual``               — only kicked off by a user
  - ``auto_org_opt_in``      — fires from scanner_event_bridge when the
                                relevant org-level setting is on
                                (e.g. settings.auto_audit_anon)
  - ``per_asset_consent``    — never fires without a fresh per-asset consent
                                record on Asset.easm_data (used for OT)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MissionTemplate:
    """One mission (system prompt template) the agent can run for a protocol.

    The `prompt_key` is a lookup into `agents.agent_prompts.ENHANCED_PROMPTS`
    so prompts stay co-located with the rest of the agent prompts rather than
    scattered across protocol modules.

    `suggested_budget` is the default `max_steps` the kickoff UI pre-fills;
    `cost_hint` drives the rough $ estimate shown before the user starts.
    """
    key: str                        # "identity" | "privesc" | "software_cve" | "network_hygiene" | "explore"
    label: str                      # "Identity Audit"
    description: str
    prompt_key: str                 # e.g. "wmi_audit_identity"
    suggested_budget: int = 20
    cost_hint: str = "medium"       # "low" | "medium" | "high"


@dataclass(frozen=True)
class ProtocolAudit:
    """All the metadata the kickoff route + agent engine need to run one
    protocol audit end-to-end.

    `tool_names` is the allowlist handed to the Agent record — the agent sees
    only these tools plus the shared read-only context set (scratchpad,
    clarification, get_asset_profile). This keeps WMI tools unavailable to
    unrelated agents and vice versa.

    `required_ports` is the list of TCP (or UDP for SNMP) ports the protocol
    depends on. Used by the audit_runner preflight: if the asset has been
    port-scanned and none of these ports are open, the audit is marked
    unreachable before any scratch agent is dispatched — saving an LLM loop
    that would certainly fail. Empty open_ports (asset never scanned) is
    treated conservatively: skip preflight and dispatch as usual.
    """
    protocol: str                   # "wmi" | "ldap" | "smb" | ...
    label: str                      # "WMI Audit"
    description: str
    supported_os: list[str]
    auth_modes: list[str]           # e.g. ["basic"] for WMI, ["kerberos","basic"] for LDAP
    relay_method: str               # dispatch key the relay executor looks up
    credential_connector_ids: list[str]  # valid IntegrationCredential.connector_id values
    tool_names: list[str]           # palette registered with @agent_tool
    missions: list[MissionTemplate]
    default_model: str = "claude-sonnet-4-6"
    default_wallclock_s: int = 600
    required_ports: tuple[int, ...] = ()  # ports the protocol listens on

    # ── Safety / lifecycle metadata ─────────────────────────────
    # Default ``credentialed`` so existing audits (WMI, LDAP, SSH, cloud)
    # keep their behavior unchanged. Anonymous-capable protocols opt in
    # by overriding to anon_* / ot_* values; see module docstring.
    safety_class: str = "credentialed"
    # ``agentic`` runs the LLM ReAct loop. ``fingerprint`` registrations
    # are metadata-only — they surface in the audit list but have no
    # tools/missions and aren't dispatched (used by the EASM scanner
    # extension family).
    mode: str = "agentic"
    # Per-(asset, protocol) cooldown enforced by the auto-trigger.
    # 24h is right for fast-changing surface (SMB share flips, AI service
    # restarts). OT raises this to 7 days so we don't hammer PLCs.
    cooldown_hours: int = 24
    # See module docstring. ``manual`` keeps current default for any audit
    # whose registration doesn't override it.
    auto_trigger_policy: str = "manual"
    # Tags consumed by the compliance evaluator to map findings to control
    # frameworks (e.g. ("cis_benchmarks","nist_csf_pr_ac") for datastores,
    # ("iec_62443_3_3","meti_ot_security_guideline_v3") for OT).
    compliance_tags: tuple[str, ...] = ()

    def is_anonymous_capable(self) -> bool:
        """True iff this audit can dispatch without a credential.

        Replaces the old ``_ANON_CAPABLE_PROTOCOLS`` literal set in
        ``audit_runner``. The single source of truth is now the audit's
        own declared ``safety_class``.
        """
        return self.safety_class != "credentialed"

    def requires_per_asset_consent(self) -> bool:
        """True iff dispatch must check ``Asset.easm_data['ot_audit_consent']``
        regardless of org-level auto-trigger settings."""
        return self.auto_trigger_policy == "per_asset_consent"

    def mission(self, key: str) -> MissionTemplate | None:
        for m in self.missions:
            if m.key == key:
                return m
        return None

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "label": self.label,
            "description": self.description,
            "supported_os": list(self.supported_os),
            "auth_modes": list(self.auth_modes),
            "relay_method": self.relay_method,
            "credential_connector_ids": list(self.credential_connector_ids),
            "missions": [
                {
                    "key": m.key,
                    "label": m.label,
                    "description": m.description,
                    "suggested_budget": m.suggested_budget,
                    "cost_hint": m.cost_hint,
                }
                for m in self.missions
            ],
            "default_model": self.default_model,
            "default_wallclock_s": self.default_wallclock_s,
            "safety_class": self.safety_class,
            "mode": self.mode,
            "cooldown_hours": self.cooldown_hours,
            "auto_trigger_policy": self.auto_trigger_policy,
            "compliance_tags": list(self.compliance_tags),
        }


AUDITS: dict[str, ProtocolAudit] = {}


def register_audit(audit: ProtocolAudit) -> None:
    """Register a protocol audit. Called from each protocol's tools module."""
    if not audit.protocol:
        raise ValueError("ProtocolAudit.protocol is required")
    AUDITS[audit.protocol] = audit


def get_audit(protocol: str) -> ProtocolAudit:
    if protocol not in AUDITS:
        raise KeyError(
            f"Unknown protocol audit {protocol!r}. Registered: {sorted(AUDITS.keys())}"
        )
    return AUDITS[protocol]


def list_audits() -> list[str]:
    return sorted(AUDITS.keys())


def describe_all() -> list[dict]:
    return [AUDITS[p].to_dict() for p in list_audits()]


__all__ = [
    "MissionTemplate",
    "ProtocolAudit",
    "AUDITS",
    "register_audit",
    "get_audit",
    "list_audits",
    "describe_all",
]
