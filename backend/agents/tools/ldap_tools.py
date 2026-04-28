"""LDAP tool palette for the LDAP Audit ReAct agent.

Two generic primitives:

  - ``ldap_search`` — arbitrary LDAP SEARCH. Filter, attributes, optional
    base-DN override, optional scope/size cap. The relay rejects any
    modify/add/delete at the protocol level, so this is the universal
    read-side primitive.
  - ``ldap_get_object_acl`` — fetch the ``nTSecurityDescriptor`` of one DN
    decoded into ACEs (with SID→sAMAccountName resolution + ``dangerous``
    flagging). Carved out as its own op because SDDL parsing belongs on
    the relay, not the LLM.

Mission-specific recipes (Kerberoast, ACL, delegation, GPO walks, etc.)
live in the prompt files — the agent picks the right filter for the
question rather than choosing among 15 named tools that overlap.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset
from agents.agent_tools import agent_tool, NeedsApproval
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_LDAP_TIMEOUT_S = 60


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_LDAP_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_ldap(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    target, target_port = resolve_asset_target(asset)
    if not target:
        raise ValueError(f"asset {asset_id} has no hostname or ip")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")
    if not credential_id:
        raise ValueError("credential_id missing from audit context")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    raw_creds = await load_credentials(db, credential_id, org_id)
    if not raw_creds or not raw_creds.get("username"):
        raise ValueError(f"credential {credential_id} missing or has no username")

    ldap_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", ""),
        "domain": raw_creds.get("domain", "") or "",
    }

    config: dict[str, Any] = {"target": target}
    if target_port:
        config["port"] = target_port

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ldap_query",
        config=config,
        credentials=ldap_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _LDAP_TIMEOUT_S},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _trim(rows: list, limit: int = 30) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Generic search ────────────────────────────────────────────────────


@agent_tool(
    "ldap_search",
    "Run an arbitrary LDAP SEARCH. The relay enforces read-only — no "
    "modify/add/delete is possible. Use this for ALL directory queries: "
    "RootDSE/domain info, user/group/computer lookups, Kerberoast hunts, "
    "delegation searches, ACL prep, GPO walks, password policy, trusts, OUs. "
    "Pass `base_dn=\"\"` for RootDSE; omit `base_dn` to default to the "
    "domain root. Filter is standard RFC 4515; AD bitwise-AND matching uses "
    "OID `1.2.840.113556.1.4.803`. Returns up to `size_limit` entries (cap "
    "1000). Common recipes:\n"
    "  • Kerberoastable: `(&(objectCategory=user)(servicePrincipalName=*)"
    "(!(sAMAccountName=krbtgt)))` with attrs `[sAMAccountName, "
    "servicePrincipalName, userAccountControl, memberOf]`.\n"
    "  • AS-REP roastable: `(&(objectCategory=user)"
    "(userAccountControl:1.2.840.113556.1.4.803:=4194304))`.\n"
    "  • Unconstrained delegation: `(&(|(objectCategory=user)"
    "(objectCategory=computer))(userAccountControl:1.2.840.113556.1.4.803:"
    "=524288))`.\n"
    "  • Constrained delegation: `(msDS-AllowedToDelegateTo=*)`.\n"
    "  • RBCD: `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)`.\n"
    "  • Privileged groups: filter `(&(objectCategory=group)(|"
    "(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins)"
    "(sAMAccountName=Administrators)…))` with attrs `[member, "
    "sAMAccountName]`.\n"
    "  • Password policy: filter `(objectClass=domainDNS)` against the "
    "domain root with attrs `[minPwdLength, pwdHistoryLength, lockoutThreshold, "
    "lockoutDuration, maxPwdAge, minPwdAge, pwdProperties]`.\n"
    "  • Trusts: `(objectClass=trustedDomain)`.\n"
    "  • GPOs: `(objectClass=groupPolicyContainer)` with attrs `[displayName, "
    "cn, gPCFileSysPath, gPCMachineExtensionNames, flags]`.\n"
    "  • RootDSE: `base_dn=\"\"`, filter `(objectClass=*)`, attrs `[namingContexts, "
    "supportedSASLMechanisms, supportedLDAPVersion, dnsHostName]`.",
    {
        "asset_id": {"type": "integer"},
        "filter": {"type": "string", "description": "RFC 4515 LDAP filter"},
        "attributes": {
            "type": "array",
            "description": "Attributes to return (omit/empty for all)",
            "items": {"type": "string"},
        },
        "base_dn": {
            "type": "string",
            "description": "Base DN override; \"\" for RootDSE; omitted = domain root",
        },
        "scope": {
            "type": "string",
            "enum": ["base", "one", "sub"],
            "description": "Search scope (default sub)",
        },
        "size_limit": {
            "type": "integer",
            "description": "Max entries to return (default 200, cap 1000)",
        },
    },
)
def ldap_search_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params: dict[str, Any] = {
        "filter": params.get("filter") or "(objectClass=*)",
        "attributes": params.get("attributes") or [],
    }
    if params.get("base_dn") is not None:
        op_params["base_dn"] = params["base_dn"]
    if params.get("scope"):
        op_params["scope"] = params["scope"]
    size_limit = params.get("size_limit")
    if isinstance(size_limit, int) and size_limit > 0:
        op_params["size_limit"] = min(size_limit, 1000)

    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", op_params, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "filter": op_params["filter"],
        "base_dn": op_params.get("base_dn"),
        "entries": _trim(entries, 50),
    }


@agent_tool(
    "ldap_get_object_acl",
    "Return the nTSecurityDescriptor of one AD object, decoded into ACEs "
    "with trustee SIDs resolved to sAMAccountName. Use on Domain Admins, "
    "AdminSDHolder, krbtgt, the domain root — any non-expected principal "
    "with GenericAll/GenericWrite/WriteDACL/WriteOwner or extended rights "
    "like DS-Replication-Get-Changes(-All) (DCSync) is a critical finding. "
    "ACEs flagged `dangerous=true` are surfaced first.",
    {
        "asset_id": {"type": "integer"},
        "dn": {"type": "string", "description": "distinguishedName of the object"},
    },
)
def ldap_get_object_acl_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    dn = (params.get("dn") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "acl", {"dn": dn}, relay, cred))
    if not isinstance(result, dict) or result.get("_errors"):
        return result
    aces = result.get("aces") or []
    dangerous = [a for a in aces if a.get("dangerous")]
    benign = [a for a in aces if not a.get("dangerous")]
    return {
        "dn": result.get("dn"),
        "owner": result.get("owner"),
        "owner_sid": result.get("owner_sid"),
        "ace_count": result.get("ace_count"),
        "dangerous_ace_count": result.get("dangerous_ace_count"),
        "dangerous_aces": dangerous,
        "other_aces": _trim(benign, 30),
    }


# ── Write ops (always behind NeedsApproval) ──────────────────────────


@agent_tool(
    "ldap_modify",
    "Modify attributes of an existing LDAP/AD object. ALWAYS PAUSES for "
    "user approval. `changes` is `{attr: [{action: 'replace'|'add'|'delete', "
    "values: [...]}]}`. Common uses: reset a password "
    "(`unicodePwd` with quoted UTF-16-LE encoded value), disable an account "
    "(replace `userAccountControl` to add 0x2), strip an SPN, remove a "
    "kerberoastable user from a privileged group.",
    {
        "asset_id": {"type": "integer"},
        "dn": {"type": "string", "description": "distinguishedName of the object"},
        "changes": {
            "type": "object",
            "description": (
                "Per-attribute change list, e.g. "
                "{\"userAccountControl\": [{\"action\":\"replace\",\"values\":[514]}]}"
            ),
        },
    },
)
def ldap_modify_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    dn = (params.get("dn") or "").strip()
    changes = params.get("changes") or {}
    if not dn or not changes:
        return {"error": "dn and changes are required"}
    if not params.get("_approved"):
        raise NeedsApproval(
            reason=f"LDAP modify on {dn}: {sorted(changes.keys())}",
            category="ldap_modify",
            details={"dn": dn, "changes": changes},
        )
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(
        db, org_id, asset_id, "modify",
        {"dn": dn, "changes": changes}, relay, cred,
    ))
    return result


@agent_tool(
    "ldap_add",
    "Create a new LDAP/AD object. ALWAYS PAUSES for user approval. "
    "Pass `object_class` as a list (e.g. `['top','user']`) and `attributes` "
    "as a dict (e.g. `{'sAMAccountName': 'svc-x', 'cn': 'svc-x'}`).",
    {
        "asset_id": {"type": "integer"},
        "dn": {"type": "string", "description": "distinguishedName of the new object"},
        "object_class": {"type": "array", "items": {"type": "string"}},
        "attributes": {"type": "object"},
    },
)
def ldap_add_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    dn = (params.get("dn") or "").strip()
    object_class = params.get("object_class") or []
    attributes = params.get("attributes") or {}
    if not dn:
        return {"error": "dn is required"}
    if not params.get("_approved"):
        raise NeedsApproval(
            reason=f"LDAP add object {dn} (objectClass={object_class})",
            category="ldap_add",
            details={"dn": dn, "object_class": object_class, "attributes": attributes},
        )
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(
        db, org_id, asset_id, "add",
        {"dn": dn, "object_class": object_class, "attributes": attributes},
        relay, cred,
    ))
    return result


@agent_tool(
    "ldap_delete",
    "Delete an LDAP/AD object. ALWAYS PAUSES for user approval. Removes the "
    "object at `dn`; the operation fails if the object has children "
    "(perform a tree delete via specific drilling operations instead).",
    {
        "asset_id": {"type": "integer"},
        "dn": {"type": "string", "description": "distinguishedName of the object to delete"},
    },
)
def ldap_delete_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    dn = (params.get("dn") or "").strip()
    if not dn:
        return {"error": "dn is required"}
    if not params.get("_approved"):
        raise NeedsApproval(
            reason=f"LDAP delete object {dn}",
            category="ldap_delete",
            details={"dn": dn},
        )
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(
        db, org_id, asset_id, "delete",
        {"dn": dn}, relay, cred,
    ))
    return result


# ── Registry ──────────────────────────────────────────────────────────


_LDAP_TOOL_NAMES = [
    "ldap_search",
    "ldap_get_object_acl",
    # Write/exec primitives — every call routes through user approval.
    "ldap_modify", "ldap_add", "ldap_delete",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ldap",
    label="LDAP Audit",
    description=(
        "Credentialed Active Directory audit via LDAP. A ReAct agent uses "
        "arbitrary LDAP SEARCH + nTSecurityDescriptor decode to hunt for "
        "identity, delegation, and ACL exposures."
    ),
    supported_os=["windows"],          # target is a DC
    auth_modes=["basic"],               # simple bind / NTLM from relay side
    relay_method="ldap_query",
    credential_connector_ids=["windows_host", "windows-host"],
    tool_names=_LDAP_TOOL_NAMES,
    required_ports=(389, 636, 3268, 3269),  # LDAP, LDAPS, Global Catalog, GC LDAPS
    missions=[
        MissionTemplate(
            key="exposure_audit",
            label="Exposure Audit",
            description=(
                "End-to-end AD exposure hunt: identity (Kerberoast / AS-REP / "
                "weak Kerberos enc / PASSWD_NOTREQD / stale admins), "
                "structure (trusts, MachineAccountQuota, password policy), "
                "delegation + ACLs (unconstrained / constrained / RBCD, "
                "dangerous ACEs on privileged objects)."
            ),
            prompt_key="ldap_audit_exposure_audit",
            suggested_budget=50,
            cost_hint="high",
        ),
    ],
))
