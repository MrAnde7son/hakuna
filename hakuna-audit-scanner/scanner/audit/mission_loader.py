"""YAML mission loader.

Phase-1 nice-to-have: replace the backend's 3.7 k-line ``agent_prompts.py``
dictionary with on-disk YAML files. Each file defines one mission for one
protocol; loaded files register themselves into ``audit_registry.AUDITS``
and populate this module's ``_PROMPT_CACHE`` so the engine can resolve
``mission.prompt_key`` at run time.

Layout::

    templates/missions/<protocol>_<mission>.yaml
    templates/custom/missions/*.yaml          # operator-supplied overrides

Each file::

    protocol: ssh
    mission_key: hardening_posture
    label: Hardening Posture
    description: sshd_config weaknesses, SUID/SGID anomalies, ...
    prompt_key: ssh_audit_hardening_posture
    suggested_budget: 20
    cost_hint: medium
    system_prompt: |
        You are a Linux hardening auditor...
    # Optional — when present, overrides the protocol's static tool palette
    # for this mission only:
    tool_names: [ssh_get_system_info, ssh_get_sshd_config, ...]

Custom missions are loaded after the bundled set so operators can
override the system_prompt without forking the package. Calling
``load_missions()`` is idempotent.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import yaml

from scanner.audit.audit_registry import (
    AUDITS,
    MissionTemplate,
    ProtocolAudit,
    register_audit,
)
from scanner.audit.config import CUSTOM_MISSIONS_DIR, MISSIONS_DIR

logger = logging.getLogger(__name__)


_PROMPT_CACHE: dict[str, str] = {}
_LOADED = False


def get_prompt(prompt_key: str) -> str | None:
    """Return the system prompt for a mission, or None if unknown.

    Triggers ``load_missions`` on first call so the worker doesn't have
    to wire startup hooks — the engine asks for a prompt, the loader
    populates lazily.
    """
    if not _LOADED:
        load_missions()
    return _PROMPT_CACHE.get(prompt_key)


def load_missions() -> None:
    """Walk MISSIONS_DIR + CUSTOM_MISSIONS_DIR, load every *.yaml,
    register prompts, and merge mission templates into AUDITS entries.

    A mission YAML can also bootstrap a brand-new protocol audit when
    no Python tools file has registered one yet — the file's
    ``protocol`` field becomes the audit key. The downside is that an
    audit with no tools registered will hand the LLM an empty palette,
    which the engine logs as a warning. So new protocols still need
    their tools file imported (via ``scanner.audit.tools.__init__``).
    """
    global _LOADED
    if _LOADED:
        return
    for directory in (MISSIONS_DIR, CUSTOM_MISSIONS_DIR):
        if not os.path.isdir(directory):
            continue
        for fname in sorted(os.listdir(directory)):
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(directory, fname)
            try:
                _load_one(path)
            except Exception:
                logger.exception("mission_loader: failed to load %s", path)
    _LOADED = True


def _load_one(path: str) -> None:
    with open(path, "r") as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    protocol = data.get("protocol")
    mission_key = data.get("mission_key") or data.get("key")
    prompt_key = data.get("prompt_key")
    system_prompt = data.get("system_prompt")
    if not (protocol and mission_key and prompt_key and system_prompt):
        logger.warning(
            "mission_loader: %s missing required fields (protocol, mission_key, prompt_key, system_prompt) — skipping",
            path,
        )
        return

    _PROMPT_CACHE[prompt_key] = system_prompt

    mission = MissionTemplate(
        key=mission_key,
        label=data.get("label") or mission_key,
        description=data.get("description") or "",
        prompt_key=prompt_key,
        suggested_budget=int(data.get("suggested_budget") or 20),
        cost_hint=data.get("cost_hint") or "medium",
    )

    existing = AUDITS.get(protocol)
    if existing is None:
        # No Python tools file has registered this protocol yet — create
        # a stub audit so kickoff routes can list it. Tool palette is
        # whatever the YAML supplies; empty palettes will produce a
        # warning at run time.
        register_audit(ProtocolAudit(
            protocol=protocol,
            label=data.get("audit_label") or protocol.upper(),
            description=data.get("audit_description") or "",
            supported_os=list(data.get("supported_os") or []),
            auth_modes=list(data.get("auth_modes") or []),
            relay_method=data.get("relay_method") or f"{protocol}_query",
            credential_connector_ids=list(data.get("credential_connector_ids") or []),
            tool_names=list(data.get("tool_names") or []),
            missions=[mission],
            required_ports=tuple(data.get("required_ports") or ()),
        ))
        return

    # Merge: append mission if not already present, override the
    # existing entry when keys collide so YAML wins over Python-default.
    new_missions = [m for m in existing.missions if m.key != mission_key] + [mission]
    # ProtocolAudit is frozen — replace the entry rather than mutating.
    AUDITS[protocol] = ProtocolAudit(
        protocol=existing.protocol,
        label=existing.label,
        description=existing.description,
        supported_os=existing.supported_os,
        auth_modes=existing.auth_modes,
        relay_method=existing.relay_method,
        credential_connector_ids=existing.credential_connector_ids,
        tool_names=list(data.get("tool_names") or existing.tool_names),
        missions=new_missions,
        default_model=existing.default_model,
        default_wallclock_s=existing.default_wallclock_s,
        required_ports=existing.required_ports,
    )
