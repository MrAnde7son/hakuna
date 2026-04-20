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
