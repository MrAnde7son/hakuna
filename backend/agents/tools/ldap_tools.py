"""LDAP tool palette for the LDAP Audit ReAct agent.

Each tool dispatches a `method=ldap_query` task to the relay. The relay handler
(hakuna-relay-agent/agent/ldap_query.py) opens one impacket LDAP connection per
target and routes the task's `op` to the matching impacket operation:

  - `op="domain_info"` — base DN query, functional levels
  - `op="search"` — LDAP SEARCH with scoping + size-bound
  - `op="password_policy"` — domain NTDS policy
  - `op="acl"` — nTSecurityDescriptor decode for one DN

The tools here don't talk to impacket directly — that runs on the relay. Each
tool shapes a summary-friendly response (counts + flagged rows + sample) rather
than dumping the full LDAP result to the LLM.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset
from agents.agent_tools import agent_tool
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


def _trim(rows: list, limit: int = 20) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Orientation tools ─────────────────────────────────────────────────


@agent_tool(
    "ldap_get_domain_info",
    "Return the AD domain's base DN, NetBIOS name, functional level, and forest "
    "root. Use once at the start of every LDAP audit — the domain's age and "
    "functional level shape what findings matter.",
    {"asset_id": {"type": "integer"}},
)
def ldap_get_domain_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "domain_info", {}, relay, cred))
    return result


@agent_tool(
    "ldap_get_password_policy",
    "Return the domain's default password policy (length, complexity, lockout, "
    "history). Flag weak policies in your finding rubric.",
    {"asset_id": {"type": "integer"}},
)
def ldap_get_password_policy_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "password_policy", {}, relay, cred))
    return result


# ── User / group tools ────────────────────────────────────────────────


@agent_tool(
    "ldap_find_kerberoastable",
    "Return user accounts with a non-empty `servicePrincipalName` attribute "
    "(excluding krbtgt and computer accounts). Every hit is a potential Kerberoast "
    "target — cracking the TGS reveals the account's plaintext password.",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_kerberoastable_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # Impacket-side filter:
    #   (&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
        "attributes": ["sAMAccountName", "servicePrincipalName", "userAccountControl",
                       "memberOf", "distinguishedName", "lastLogonTimestamp"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "kerberoastable": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                "spns": e.get("servicePrincipalName") or [],
                "uac": e.get("userAccountControl"),
                "is_disabled": bool((e.get("userAccountControl") or 0) & 0x2),
                "member_of": e.get("memberOf") or [],
            }
            for e in entries
        ]),
    }


@agent_tool(
    "ldap_find_asrep_roastable",
    "Return user accounts with UAC flag DONT_REQUIRE_PREAUTH set — these are "
    "AS-REP roastable (an attacker can request an AS-REP without pre-auth and "
    "crack the user's password offline).",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_asrep_roastable_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "memberOf", "lastLogonTimestamp"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "asrep_roastable": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                "uac": e.get("userAccountControl"),
                "is_disabled": bool((e.get("userAccountControl") or 0) & 0x2),
                "member_of": e.get("memberOf") or [],
            }
            for e in entries
        ]),
    }


@agent_tool(
    "ldap_list_privileged_groups",
    "Return standard AD privileged groups with member counts: Domain Admins, "
    "Enterprise Admins, Schema Admins, Administrators (built-in), Account "
    "Operators, Backup Operators, Server Operators, Print Operators, "
    "DnsAdmins. For each, use ldap_get_group_members to list members.",
    {"asset_id": {"type": "integer"}},
)
def ldap_list_privileged_groups_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": (
            "(&(objectCategory=group)(|"
            "(sAMAccountName=Domain Admins)"
            "(sAMAccountName=Enterprise Admins)"
            "(sAMAccountName=Schema Admins)"
            "(sAMAccountName=Administrators)"
            "(sAMAccountName=Account Operators)"
            "(sAMAccountName=Backup Operators)"
            "(sAMAccountName=Server Operators)"
            "(sAMAccountName=Print Operators)"
            "(sAMAccountName=DnsAdmins)"
            "))"
        ),
        "attributes": ["sAMAccountName", "distinguishedName", "member"],
    }, relay, cred))
    groups = [
        {
            "name": e.get("sAMAccountName"),
            "dn": e.get("distinguishedName"),
            "member_count": len(e.get("member") or []),
        }
        for e in (result.get("entries") or [])
    ]
    return {"groups": groups}


@agent_tool(
    "ldap_get_group_members",
    "Return all members of one group by sAMAccountName. Use after "
    "ldap_list_privileged_groups to drill into 'Domain Admins' etc.",
    {
        "asset_id": {"type": "integer"},
        "group_name": {"type": "string", "description": "sAMAccountName (e.g. 'Domain Admins')"},
    },
)
def ldap_get_group_members_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    group_name = (params.get("group_name") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": f"(&(objectCategory=group)(sAMAccountName={_ldap_escape(group_name)}))",
        "attributes": ["sAMAccountName", "distinguishedName", "member"],
    }, relay, cred))
    entries = result.get("entries") or []
    if not entries:
        return {"error": f"group {group_name!r} not found"}
    group = entries[0]
    return {
        "group": group.get("sAMAccountName"),
        "dn": group.get("distinguishedName"),
        "members": _trim(group.get("member") or [], 50),
        "member_count": len(group.get("member") or []),
    }


@agent_tool(
    "ldap_get_user",
    "Return full detail for one user by sAMAccountName. Decoded UAC flags, SPNs, "
    "group membership, lastLogonTimestamp.",
    {
        "asset_id": {"type": "integer"},
        "sam_account_name": {"type": "string"},
    },
)
def ldap_get_user_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    sam = (params.get("sam_account_name") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": f"(&(objectCategory=user)(sAMAccountName={_ldap_escape(sam)}))",
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "servicePrincipalName", "memberOf", "lastLogonTimestamp",
                       "pwdLastSet", "description", "msDS-AllowedToDelegateTo",
                       "msDS-AllowedToActOnBehalfOfOtherIdentity"],
    }, relay, cred))
    entries = result.get("entries") or []
    if not entries:
        return {"error": f"user {sam!r} not found"}
    u = entries[0]
    uac = u.get("userAccountControl") or 0
    return {
        "sam": u.get("sAMAccountName"),
        "dn": u.get("distinguishedName"),
        "uac": uac,
        "uac_flags": _decode_uac(uac),
        "spns": u.get("servicePrincipalName") or [],
        "member_of": u.get("memberOf") or [],
        "last_logon_ts": u.get("lastLogonTimestamp"),
        "pwd_last_set": u.get("pwdLastSet"),
        "description": u.get("description"),
        "allowed_to_delegate_to": u.get("msDS-AllowedToDelegateTo") or [],
        "rbcd_raw": u.get("msDS-AllowedToActOnBehalfOfOtherIdentity"),
    }


# ── Delegation / ACL tools ────────────────────────────────────────────


@agent_tool(
    "ldap_find_unconstrained_delegation",
    "Return principals (users or computers) with TRUSTED_FOR_DELEGATION in UAC "
    "— unconstrained delegation. Critical on any non-DC principal.",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_unconstrained_delegation_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # UAC 0x80000 = TRUSTED_FOR_DELEGATION
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(&(|(objectCategory=user)(objectCategory=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "objectClass"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "principals": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                "type": "computer" if "computer" in (e.get("objectClass") or []) else "user",
            }
            for e in entries
        ], 50),
    }


@agent_tool(
    "ldap_find_constrained_delegation",
    "Return principals with a non-empty msDS-AllowedToDelegateTo (constrained "
    "delegation). Flag delegation targets that are DCs, krbtgt, or other sensitive "
    "SPNs.",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_constrained_delegation_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(msDS-AllowedToDelegateTo=*)",
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "msDS-AllowedToDelegateTo"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "principals": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                "delegates_to": e.get("msDS-AllowedToDelegateTo") or [],
            }
            for e in entries
        ], 50),
    }


@agent_tool(
    "ldap_find_rbcd",
    "Return principals with a non-empty msDS-AllowedToActOnBehalfOfOtherIdentity "
    "— resource-based constrained delegation. Check WHICH principal is allowed to "
    "act on whose behalf — if a low-priv account can act on a DC's behalf, that's "
    "a full domain compromise.",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_rbcd_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "attributes": ["sAMAccountName", "distinguishedName",
                       "msDS-AllowedToActOnBehalfOfOtherIdentity"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "principals": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                # Raw SDDL — requires SID→name resolution, which the relay can do on request.
                "rbcd_raw": e.get("msDS-AllowedToActOnBehalfOfOtherIdentity"),
            }
            for e in entries
        ], 50),
    }


@agent_tool(
    "ldap_get_object_acl",
    "Return the nTSecurityDescriptor of one AD object, decoded into ACEs with "
    "trustee SIDs resolved to sAMAccountName. Use on Domain Admins, AdminSDHolder, "
    "krbtgt, the domain root — any non-expected principal with GenericAll/"
    "GenericWrite/WriteDACL/WriteOwner or extended rights like "
    "DS-Replication-Get-Changes(-All) (DCSync) is a critical finding.",
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
    # Surface dangerous ACEs first; keep the full list but trim for the LLM.
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


# ── Hygiene tools ─────────────────────────────────────────────────────


@agent_tool(
    "ldap_find_weak_kerberos_encryption",
    "Return user/computer accounts whose msDS-SupportedEncryptionTypes is missing "
    "AES bits (AES128=0x08, AES256=0x10). Accounts stuck on RC4/DES are "
    "Kerberoast-friendly (RC4 is cheap to crack offline) and indicate an old "
    "config. Value 0 = not set (defaults to RC4 on most DCs).",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_weak_kerberos_encryption_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # Ask for everyone that has the attribute OR lacks it and could be affected.
    # Principals without the attribute default to RC4 on most DCs, so we include
    # user + computer + managed service accounts and filter client-side.
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(&(|(objectCategory=user)(objectCategory=computer))(|(servicePrincipalName=*)(objectCategory=computer)))",
        "attributes": ["sAMAccountName", "distinguishedName", "objectClass",
                       "msDS-SupportedEncryptionTypes", "userAccountControl",
                       "servicePrincipalName"],
    }, relay, cred))
    entries = result.get("entries") or []
    # Bits: 0x01 DES-CRC, 0x02 DES-MD5, 0x04 RC4-HMAC, 0x08 AES128, 0x10 AES256.
    aes_bits = 0x08 | 0x10
    weak: list[dict] = []
    for e in entries:
        if (e.get("userAccountControl") or 0) & 0x2:
            continue  # disabled
        enc = e.get("msDS-SupportedEncryptionTypes")
        # Normalize: missing/None/0 = default (RC4 only).
        enc_int = enc if isinstance(enc, int) else 0
        if enc_int & aes_bits:
            continue
        weak.append({
            "sam": e.get("sAMAccountName"),
            "dn": e.get("distinguishedName"),
            "enc_types": enc_int,
            "enc_default_rc4": enc_int == 0,
            "uses_des": bool(enc_int & 0x03),
            "uses_rc4_only": enc_int == 0x04,
            "is_computer": "computer" in (e.get("objectClass") or []),
            "spn_count": len(e.get("servicePrincipalName") or []),
        })
    return {"total": len(weak), "accounts": _trim(weak, 50)}


@agent_tool(
    "ldap_find_password_not_required",
    "Return enabled user accounts with UAC flag PASSWD_NOTREQD (0x20) — the "
    "account may have an empty password. Near-always a critical finding on any "
    "non-disabled user.",
    {"asset_id": {"type": "integer"}},
)
def ldap_find_password_not_required_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # UAC bit 0x20 via bitwise-AND matching rule; also exclude disabled (0x2).
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": (
            "(&(objectCategory=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=32)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        ),
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "memberOf", "lastLogonTimestamp", "pwdLastSet"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "accounts": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dn": e.get("distinguishedName"),
                "uac": e.get("userAccountControl"),
                "member_of": e.get("memberOf") or [],
                "last_logon_ts": e.get("lastLogonTimestamp"),
                "pwd_last_set": e.get("pwdLastSet"),
            }
            for e in entries
        ], 50),
    }


@agent_tool(
    "ldap_find_stale_accounts",
    "Return enabled user accounts with lastLogonTimestamp older than the given "
    "days threshold (default 180). Stale enabled accounts are takeover targets. "
    "Especially bad if combined with DONT_EXPIRE_PASSWORD or admin group "
    "membership.",
    {
        "asset_id": {"type": "integer"},
        "days": {"type": "integer", "description": "Staleness threshold in days (default 180)"},
    },
)
def ldap_find_stale_accounts_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    days = int(params.get("days") or 180)
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        # Enabled normal users only (exclude disabled 0x2, workstation/server
        # trust accounts 0x1000/0x2000 so we don't catch computers).
        "filter": (
            "(&(objectCategory=user)(sAMAccountType=805306368)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        ),
        "attributes": ["sAMAccountName", "distinguishedName", "userAccountControl",
                       "lastLogonTimestamp", "pwdLastSet", "memberOf",
                       "adminCount"],
    }, relay, cred))
    entries = result.get("entries") or []
    # AD timestamps are 100-ns intervals since 1601-01-01 UTC.
    # threshold_ts = now - days → convert to AD filetime.
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    threshold = now - _dt.timedelta(days=days)
    epoch_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
    threshold_ft = int((threshold - epoch_1601).total_seconds() * 10_000_000)

    stale: list[dict] = []
    for e in entries:
        ts = e.get("lastLogonTimestamp") or 0
        if not isinstance(ts, int):
            continue
        # ts == 0 means "never logged on" — also stale if account is old.
        if ts != 0 and ts >= threshold_ft:
            continue
        uac = e.get("userAccountControl") or 0
        stale.append({
            "sam": e.get("sAMAccountName"),
            "dn": e.get("distinguishedName"),
            "last_logon_ts": ts,
            "never_logged_on": ts == 0,
            "uac": uac,
            "pwd_never_expires": bool(uac & 0x10000),
            "is_admin": bool(e.get("adminCount")),
            "member_of_count": len(e.get("memberOf") or []),
        })
    return {"total": len(stale), "threshold_days": days, "accounts": _trim(stale, 50)}


# ── Structure tools ───────────────────────────────────────────────────


@agent_tool(
    "ldap_list_trusts",
    "Return trustedDomain objects — outgoing + incoming trusts and their attributes. "
    "Flag trusts without SID filtering or to unexpected third-party forests.",
    {"asset_id": {"type": "integer"}},
)
def ldap_list_trusts_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(objectClass=trustedDomain)",
        "attributes": ["name", "trustPartner", "trustDirection",
                       "trustType", "trustAttributes"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "trusts": [
            {
                "name": e.get("name"),
                "partner": e.get("trustPartner"),
                "direction": _trust_direction(e.get("trustDirection")),
                "type": e.get("trustType"),
                "attributes_raw": e.get("trustAttributes"),
            }
            for e in entries
        ],
    }


@agent_tool(
    "ldap_list_ous",
    "Return the organizational-unit tree (top two levels). Use to understand "
    "the shape of the directory; drill into specific OUs with ldap_get_object_acl "
    "if you suspect delegation issues.",
    {"asset_id": {"type": "integer"}},
)
def ldap_list_ous_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(objectCategory=organizationalUnit)",
        "attributes": ["name", "distinguishedName", "description"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "ous": _trim([
            {"name": e.get("name"), "dn": e.get("distinguishedName"),
             "description": e.get("description")}
            for e in entries
        ], 40),
    }


@agent_tool(
    "ldap_list_computers",
    "Return computer accounts with last-logon summary. Flag stale (lastLogon > 180d).",
    {"asset_id": {"type": "integer"}},
)
def ldap_list_computers_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", {
        "filter": "(objectCategory=computer)",
        "attributes": ["sAMAccountName", "dNSHostName", "operatingSystem",
                       "lastLogonTimestamp", "pwdLastSet", "userAccountControl"],
    }, relay, cred))
    entries = result.get("entries") or []
    return {
        "total": len(entries),
        "computers": _trim([
            {
                "sam": e.get("sAMAccountName"),
                "dns": e.get("dNSHostName"),
                "os": e.get("operatingSystem"),
                "last_logon_ts": e.get("lastLogonTimestamp"),
                "pwd_last_set": e.get("pwdLastSet"),
                "is_disabled": bool((e.get("userAccountControl") or 0) & 0x2),
            }
            for e in entries
        ], 50),
    }


# ── RootDSE / naming contexts / LDAPS posture ────────────────────────


@agent_tool(
    "ldap_get_rootdse",
    "Read the server's RootDSE (anonymous LDAP base entry) for infrastructure "
    "inventory: all naming contexts (defaultNamingContext, configurationNC, "
    "schemaNC, DomainDnsZones, ForestDnsZones), supported LDAP versions and "
    "SASL mechanisms, supported controls, and — critically — DC capabilities. "
    "Pair with `bind_transport` to report whether the session is LDAPS vs "
    "plaintext LDAP. Findings: DCs still allowing unsigned ldap:// binds, "
    "missing channel binding enforcement, unexpected additional NCs (often "
    "reveal AD LDS instances you didn't know about).",
    {"asset_id": {"type": "integer"}},
)
def ldap_get_rootdse_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params = {
        "base_dn": "",
        "filter": "(objectClass=*)",
        "attributes": [
            "namingContexts",
            "defaultNamingContext", "rootDomainNamingContext",
            "configurationNamingContext", "schemaNamingContext",
            "domainFunctionality", "forestFunctionality",
            "domainControllerFunctionality",
            "dnsHostName", "serverName",
            "supportedLDAPVersion", "supportedSASLMechanisms",
            "supportedControl", "supportedCapabilities",
            "supportedLDAPPolicies",
            "ldapServiceName", "currentTime",
            "isGlobalCatalogReady", "isSynchronized",
        ],
    }
    _, result = _run_async(_dispatch_ldap(
        db, org_id, asset_id, "search", op_params, relay, cred,
    ))
    entries = result.get("entries") or []
    if not entries:
        return {"error": "RootDSE query returned no entries — server may not be an LDAP/AD server"}
    d = entries[0]

    def _listify(v) -> list[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]

    naming_contexts = _listify(d.get("namingContexts"))
    default_nc = d.get("defaultNamingContext")
    config_nc = d.get("configurationNamingContext")
    schema_nc = d.get("schemaNamingContext")
    # "Extra" naming contexts = anything beyond the three standard ones.
    # AD LDS instances, DomainDnsZones, ForestDnsZones, app-specific NCs
    # show up here and are often overlooked in audits.
    standard = {str(x) for x in [default_nc, config_nc, schema_nc] if x}
    extras = [nc for nc in naming_contexts if nc not in standard]

    return {
        "dns_host_name": d.get("dnsHostName"),
        "server_name": d.get("serverName"),
        "default_naming_context": default_nc,
        "configuration_nc": config_nc,
        "schema_nc": schema_nc,
        "naming_contexts": naming_contexts,
        "extra_naming_contexts": extras,
        "supported_ldap_versions": _listify(d.get("supportedLDAPVersion")),
        "supported_sasl_mechanisms": _listify(d.get("supportedSASLMechanisms")),
        "supported_controls": _listify(d.get("supportedControl"))[:40],
        "supported_capabilities": _listify(d.get("supportedCapabilities")),
        "domain_functionality": d.get("domainFunctionality"),
        "forest_functionality": d.get("forestFunctionality"),
        "dc_functionality": d.get("domainControllerFunctionality"),
        "is_global_catalog_ready": d.get("isGlobalCatalogReady"),
        "is_synchronized": d.get("isSynchronized"),
    }


# ── Group Policy Objects ─────────────────────────────────────────────


@agent_tool(
    "ldap_list_gpos",
    "Enumerate Group Policy Objects under CN=Policies,CN=System. Returns "
    "one entry per GPO with displayName, GUID, file-system path "
    "(gPCFileSysPath — points to SYSVOL), flags, and version. The file-system "
    "side of each GPO often contains scripts, preference XML (including "
    "legacy GPP cpassword!), and registry.pol files with security settings — "
    "use smb_list_share_contents on SYSVOL for the GUID folder of any "
    "suspicious GPO. Flag: GPOs with gPCMachineExtensionNames referencing "
    "Group Policy Preferences (legacy cpassword risk), GPOs disabled but "
    "still linked, GPOs with broad apply ACLs.",
    {"asset_id": {"type": "integer"}},
)
def ldap_list_gpos_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params = {
        # The base_dn override targets the Policies container directly — no
        # need to walk the whole domain. The relay expands <BASE> if needed;
        # here we pass an empty override and use the filter to scope.
        "filter": "(objectClass=groupPolicyContainer)",
        "attributes": [
            "displayName", "cn", "name",
            "gPCFileSysPath", "gPCFunctionalityVersion",
            "gPCMachineExtensionNames", "gPCUserExtensionNames",
            "flags", "versionNumber",
            "whenCreated", "whenChanged",
        ],
        "size_limit": 500,
    }
    _, result = _run_async(_dispatch_ldap(
        db, org_id, asset_id, "search", op_params, relay, cred,
    ))
    entries = result.get("entries") or []

    # GPP cpassword was deprecated in MS14-025 — any GPO with the Group
    # Policy Preferences CSE GUID ({17D89FEC-5C44-4972-B12D-241CAEF74509} and
    # friends) is worth investigating on SYSVOL for legacy cpassword.
    gpp_guids = {
        "{17d89fec-5c44-4972-b12d-241caef74509}",  # Drive Maps, Files, etc.
        "{e437bc1c-aa7d-11d2-a382-00c04f991e27}",  # core GP
        "{f3ccc681-b74c-4060-9f26-cd84525dca2a}",  # Audit Policy
    }

    gpos: list[dict] = []
    for e in entries:
        machine_exts = str(e.get("gPCMachineExtensionNames") or "").lower()
        user_exts = str(e.get("gPCUserExtensionNames") or "").lower()
        flags = e.get("flags")
        # flags bit 0: user config disabled. bit 1: computer config disabled.
        try:
            flags_int = int(flags) if flags is not None else None
        except Exception:
            flags_int = None
        has_gpp = any(g in machine_exts or g in user_exts for g in gpp_guids)
        gpos.append({
            "display_name": e.get("displayName"),
            "guid": e.get("cn") or e.get("name"),
            "sysvol_path": e.get("gPCFileSysPath"),
            "version": e.get("versionNumber"),
            "flags": flags_int,
            "user_config_disabled": bool(flags_int & 0x1) if flags_int is not None else None,
            "computer_config_disabled": bool(flags_int & 0x2) if flags_int is not None else None,
            "uses_group_policy_preferences": has_gpp,
            "when_created": e.get("whenCreated"),
            "when_changed": e.get("whenChanged"),
        })

    return {
        "total": len(gpos),
        "gpos": _trim(gpos, 30),
        "gpp_candidate_count": sum(1 for g in gpos if g["uses_group_policy_preferences"]),
        "note": (
            "GPOs flagged `uses_group_policy_preferences=true` may contain legacy "
            "cpassword in registry.xml/Groups.xml/etc. on SYSVOL — inspect with "
            "smb_list_share_contents on the GUID path under \\\\<dc>\\SYSVOL."
        ),
    }


# ── Escape hatch ──────────────────────────────────────────────────────


@agent_tool(
    "ldap_raw_search",
    "Run an arbitrary LDAP SEARCH filter. READ-ONLY — the relay rejects any "
    "modify/add/delete. Use when the focused tools don't cover what you need.",
    {
        "asset_id": {"type": "integer"},
        "filter": {"type": "string", "description": "LDAP filter, e.g. '(objectClass=user)'"},
        "attributes": {"type": "array", "description": "Attributes to return", "items": {"type": "string"}},
        "base_dn": {"type": "string", "description": "Optional base DN override; defaults to domain root"},
    },
)
def ldap_raw_search_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params = {
        "filter": params.get("filter") or "(objectClass=*)",
        "attributes": params.get("attributes") or [],
    }
    if params.get("base_dn"):
        op_params["base_dn"] = params["base_dn"]
    _, result = _run_async(_dispatch_ldap(db, org_id, asset_id, "search", op_params, relay, cred))
    entries = result.get("entries") or []
    return {"total": len(entries), "entries": _trim(entries, 30)}


# ── Helpers ───────────────────────────────────────────────────────────


_UAC_FLAGS = [
    (0x0001, "SCRIPT"),
    (0x0002, "ACCOUNTDISABLE"),
    (0x0008, "HOMEDIR_REQUIRED"),
    (0x0010, "LOCKOUT"),
    (0x0020, "PASSWD_NOTREQD"),
    (0x0040, "PASSWD_CANT_CHANGE"),
    (0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x0100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x0200, "NORMAL_ACCOUNT"),
    (0x0800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x1000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x2000, "SERVER_TRUST_ACCOUNT"),
    (0x10000, "DONT_EXPIRE_PASSWORD"),
    (0x20000, "MNS_LOGON_ACCOUNT"),
    (0x40000, "SMARTCARD_REQUIRED"),
    (0x80000, "TRUSTED_FOR_DELEGATION"),
    (0x100000, "NOT_DELEGATED"),
    (0x200000, "USE_DES_KEY_ONLY"),
    (0x400000, "DONT_REQUIRE_PREAUTH"),
    (0x800000, "PASSWORD_EXPIRED"),
    (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
]


def _decode_uac(uac: int) -> list[str]:
    if not isinstance(uac, int):
        return []
    return [name for mask, name in _UAC_FLAGS if uac & mask]


def _trust_direction(v) -> str:
    # 0 = disabled, 1 = inbound, 2 = outbound, 3 = bidirectional
    return {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}.get(v, f"unknown({v})")


def _ldap_escape(s: str) -> str:
    """Minimal LDAP filter escaping — backslash, asterisk, paren, NUL."""
    if not s:
        return ""
    return (s.replace("\\", "\\5c").replace("*", "\\2a")
             .replace("(", "\\28").replace(")", "\\29")
             .replace("\x00", "\\00"))


# ── Registry ──────────────────────────────────────────────────────────


_LDAP_TOOL_NAMES = [
    # Orientation
    "ldap_get_domain_info", "ldap_get_password_policy",
    # Identity
    "ldap_find_kerberoastable", "ldap_find_asrep_roastable",
    "ldap_find_weak_kerberos_encryption",
    "ldap_find_password_not_required", "ldap_find_stale_accounts",
    "ldap_list_privileged_groups", "ldap_get_group_members",
    "ldap_get_user",
    # Delegation / ACL
    "ldap_find_unconstrained_delegation", "ldap_find_constrained_delegation",
    "ldap_find_rbcd", "ldap_get_object_acl",
    # Structure
    "ldap_list_trusts", "ldap_list_ous", "ldap_list_computers",
    # RootDSE / infrastructure inventory
    "ldap_get_rootdse", "ldap_list_gpos",
    # Escape hatch
    "ldap_raw_search",
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
        "Credentialed Active Directory audit via LDAP. A ReAct agent queries "
        "users, groups, delegation, ACLs, and trusts to hunt for identity and "
        "privilege-escalation exposures."
    ),
    supported_os=["windows"],          # target is a DC
    auth_modes=["basic"],               # simple bind / NTLM from relay side
    relay_method="ldap_query",
    credential_connector_ids=["windows_host", "windows-host"],
    tool_names=_LDAP_TOOL_NAMES,
    required_ports=(389, 636, 3268, 3269),  # LDAP, LDAPS, Global Catalog, GC LDAPS
    missions=[
        MissionTemplate(
            key="identity",
            label="Identity Audit",
            description="Kerberoastable, AS-REP roastable, privileged group bloat, weak password policy.",
            prompt_key="ldap_audit_identity",
            suggested_budget=25,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="ad_structure",
            label="AD Structure",
            description="Trusts, MachineAccountQuota, stale computers, OU sanity, functional level.",
            prompt_key="ldap_audit_ad_structure",
            suggested_budget=15,
            cost_hint="low",
        ),
        MissionTemplate(
            key="acl_audit",
            label="ACL & Delegation",
            description="Dangerous ACEs on privileged objects, unconstrained/constrained/RBCD delegation.",
            prompt_key="ldap_audit_acl_audit",
            suggested_budget=25,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about AD exposures.",
            prompt_key="ldap_audit_explore",
            suggested_budget=30,
            cost_hint="high",
        ),
    ],
))
