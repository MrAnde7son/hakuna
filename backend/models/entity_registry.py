"""
Entity model map — maps dedup entity_type strings to their SQLAlchemy model,
list fields, and boolean fields.

Extracted from app.py so that services can reference it without importing
the application entrypoint (proper dependency direction).

Extensibility — register new inventory types without editing this file:
    register_inventory_type(
        entity_key="ai_tools",
        model=InventoryAITool,
        list_fields=[],
        bool_fields=["is_approved"],
        dedup_key_fields=["tool_name", "asset_id"],
        dedup_strategy="keep_last",
    )
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from models.models import (
    Asset, Finding, AssetRelationship, SBOMComponent,
    InventoryUser, InventoryGroup, InventoryComputer, InventoryService,
    InventorySoftware, InventoryShare, InventoryNetConn, InventoryPatch,
    InventorySecurityControl, InventoryPasswordPolicy, InventoryLoggedOn,
    InventoryScheduledTask, InventoryEnvVar, InventoryCertificate,
    InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
)

logger = logging.getLogger(__name__)

ENTITY_MODEL_MAP: dict = {
    # Tuple format: (Model, list_fields, bool_fields, dict_fields)
    # dict_fields are deep-merged during dedup (new keys win on conflict)
    "assets": (
        Asset,
        ["inferred_admin_contacts", "source_systems"],
        ["is_internet_facing", "is_credentialed"],
        ["asset_identity", "asset_attributes"],
    ),
    "findings": (
        Finding,
        ["cves", "source_systems"],
        [],
    ),
    "users": (
        InventoryUser,
        ["spns", "member_of"],
        ["is_local_admin", "is_domain_admin", "is_privileged", "is_disabled",
         "password_never_expires", "never_logged_in", "never_changed_password"],
    ),
    "groups": (
        InventoryGroup,
        ["members"],
        ["is_privileged"],
    ),
    "computers": (
        InventoryComputer,
        [],
        ["is_domain_controller", "is_disabled"],
    ),
    "services": (
        InventoryService,
        [],
        ["is_running"],
    ),
    "software": (
        InventorySoftware,
        [],
        [],
    ),
    "shares": (
        InventoryShare,
        ["acl"],
        ["is_writeable", "is_default_share"],
    ),
    "netconns": (
        InventoryNetConn,
        [],
        [],
    ),
    "patches": (
        InventoryPatch,
        ["cves"],
        [],
    ),
    "security_controls": (
        InventorySecurityControl,
        [],
        ["is_enabled", "is_up_to_date"],
    ),
    "password_policies": (
        InventoryPasswordPolicy,
        [],
        ["complexity_enabled", "reversible_encryption", "is_weak"],
    ),
    "logged_on": (
        InventoryLoggedOn,
        [],
        [],
    ),
    "scheduled_tasks": (
        InventoryScheduledTask,
        [],
        ["is_enabled"],
    ),
    "env_vars": (
        InventoryEnvVar,
        [],
        ["is_sensitive"],
    ),
    "certificates": (
        InventoryCertificate,
        ["subject_alt_names"],
        ["is_expired", "is_ca", "is_self_signed"],
    ),
    "processes": (
        InventoryProcess,
        [],
        [],
    ),
    "database_instances": (
        InventoryDatabaseInstance,
        [],
        ["is_running"],
    ),
    "credentials": (
        InventoryCredential,
        [],
        [],
    ),
    "asset_relationships": (
        AssetRelationship,
        [],
        [],
        ["source_detail"],
    ),
    "sbom_components": (
        SBOMComponent,
        [],
        ["is_running"],
    ),
}


# ─────────────────────────────────────────────────────────
# Dedup defaults for dynamically registered inventory types
# ─────────────────────────────────────────────────────────

_DEDUP_DEFAULTS: dict[str, dict] = {}
"""Populated by register_inventory_type(); keyed by entity_key.
Each value: {"key_fields": [...], "strategy": "...", "enabled": True}
"""


def register_inventory_type(
    entity_key: str,
    model: Any,
    list_fields: list[str] | None = None,
    bool_fields: list[str] | None = None,
    dict_fields: list[str] | None = None,
    dedup_key_fields: list[str] | None = None,
    dedup_strategy: str = "keep_last",
    dedup_enabled: bool = True,
) -> None:
    """Register an inventory type in one call.

    This populates:
      1. ENTITY_MODEL_MAP — used by run_db_dedup and _dedup_inventory_on_assets
      2. _DEDUP_DEFAULTS — used by dedup_inventory as fallback when the key
         is absent from dedup_config.json

    After calling this, the only remaining step is defining the SQLAlchemy model
    itself (which must happen before this call).

    Example::

        register_inventory_type(
            entity_key="ai_tools",
            model=InventoryAITool,
            bool_fields=["is_approved"],
            dedup_key_fields=["tool_name", "asset_id"],
            dedup_strategy="keep_last",
        )
    """
    ENTITY_MODEL_MAP[entity_key] = (
        model,
        list_fields or [],
        bool_fields or [],
        dict_fields or [],
    )
    if dedup_key_fields is not None:
        _DEDUP_DEFAULTS[entity_key] = {
            "enabled": dedup_enabled,
            "key_fields": dedup_key_fields,
            "strategy": dedup_strategy,
        }
    logger.debug("Registered inventory type %r → %s", entity_key, model.__name__)


def get_dedup_defaults() -> dict[str, dict]:
    """Return dedup config defaults for all dynamically registered types."""
    return dict(_DEDUP_DEFAULTS)
