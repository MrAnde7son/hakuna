"""
Entity model map — maps dedup entity_type strings to their SQLAlchemy model,
list fields, and boolean fields.

Extracted from app.py so that services can reference it without importing
the application entrypoint (proper dependency direction).
"""

from models.models import (
    Asset, Finding, AssetRelationship,
    InventoryUser, InventoryGroup, InventoryComputer, InventoryService,
    InventorySoftware, InventoryShare, InventoryNetConn, InventoryPatch,
    InventorySecurityControl, InventoryPasswordPolicy, InventoryLoggedOn,
    InventoryScheduledTask, InventoryEnvVar, InventoryCertificate,
    InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
)


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
}
