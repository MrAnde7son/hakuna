"""LDAP transport — connects to LDAP/Active Directory servers via ldap3."""

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import AsyncIterator

from services.transports.base import BaseTransport, ConnectResult

logger = logging.getLogger(__name__)

# AD FILETIME epoch: Jan 1, 1601
_AD_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_TICKS_PER_SECOND = 10_000_000

# Attributes that should remain as lists rather than being joined
MULTI_VALUE_KEEP = {"memberOf", "member", "objectClass", "servicePrincipalName"}

# userAccountControl flag bits
UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_NORMAL_ACCOUNT = 0x0200
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_PASSWORD_EXPIRED = 0x800000

# groupType bitmask
_GROUP_SCOPE_BITS = {
    0x00000001: "builtin_local",
    0x00000002: "global",
    0x00000004: "domain_local",
    0x00000008: "universal",
}
_GROUP_TYPE_SECURITY = 0x80000000

# Service account detection patterns
_SVC_ACCOUNT_PATTERNS = re.compile(
    r"(^svc[_\-]|[_\-]svc$|^sa[_\-]|[_\-]sa$)", re.IGNORECASE
)

# Privileged group CNs
_PRIVILEGED_GROUPS = {"Domain Admins", "Enterprise Admins", "Administrators"}


def filetime_to_iso(value) -> str | None:
    """Convert AD FILETIME (100-ns ticks since 1601-01-01) to ISO 8601.

    Also handles GeneralizedTime strings (YYYYMMDDHHmmss.0Z).
    Returns None for zero / never-set values.
    """
    if value is None:
        return None

    # String form — either GeneralizedTime or already ISO
    if isinstance(value, str):
        value = value.strip()
        if not value or value == "0":
            return None
        # GeneralizedTime: 20231015143022.0Z
        if re.match(r"^\d{14}", value):
            try:
                clean = value.split(".")[0]
                dt = datetime.strptime(clean, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                return value
        return value  # already ISO or other format

    # Integer FILETIME
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None

    if ticks <= 0 or ticks == 9223372036854775807:  # 0 or max-int = "never"
        return None

    try:
        dt = _AD_EPOCH + timedelta(microseconds=ticks // 10)
        return dt.isoformat()
    except (OverflowError, OSError):
        return None


def filetime_to_days_ago(value) -> int | None:
    """Convert AD FILETIME to number of days ago from now."""
    iso = filetime_to_iso(value)
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except (ValueError, TypeError):
        return None


def decode_uac(uac_value) -> dict:
    """Decode userAccountControl integer into boolean flags."""
    try:
        uac = int(uac_value) if uac_value else 0
    except (TypeError, ValueError):
        uac = 0
    return {
        "is_enabled": not bool(uac & UAC_ACCOUNTDISABLE),
        "is_locked": bool(uac & UAC_LOCKOUT),
        "password_not_required": bool(uac & UAC_PASSWD_NOTREQD),
        "password_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWD),
        "smartcard_required": bool(uac & UAC_SMARTCARD_REQUIRED),
        "password_expired": bool(uac & UAC_PASSWORD_EXPIRED),
        "raw": uac,
    }


def decode_group_type(group_type_value) -> dict:
    """Decode groupType bitmask into scope and type."""
    try:
        gt = int(group_type_value) if group_type_value else 0
    except (TypeError, ValueError):
        gt = 0

    # Determine scope (lower bits)
    scope = "unknown"
    for bit, name in _GROUP_SCOPE_BITS.items():
        if gt & bit:
            scope = name
            break

    return {
        "group_scope": scope,
        "group_type": "security" if gt & _GROUP_TYPE_SECURITY else "distribution",
    }


def is_service_account(record: dict) -> bool:
    """Heuristic detection of service accounts.

    Checks: has SPN, title contains 'service', sAMAccountName ends with '$',
    or sAMAccountName matches svc_*/sa_* patterns.
    """
    spns = record.get("servicePrincipalName")
    if spns and (isinstance(spns, list) and len(spns) > 0):
        return True

    sam = str(record.get("sAMAccountName", ""))
    if sam.endswith("$"):
        return True
    if _SVC_ACCOUNT_PATTERNS.search(sam):
        return True

    title = str(record.get("title", "")).lower()
    if "service" in title:
        return True

    return False


def _is_admin(member_of: list) -> bool:
    """Check if any memberOf entry contains a privileged group CN."""
    for dn in (member_of or []):
        for pg in _PRIVILEGED_GROUPS:
            if f"CN={pg}" in str(dn):
                return True
    return False


def _flatten_value(attr_name: str, value):
    """Flatten ldap3 attribute values: keep multi-value for known attrs, join others."""
    if attr_name in MULTI_VALUE_KEEP:
        if isinstance(value, list):
            return value
        return [value] if value else []

    if isinstance(value, list):
        if len(value) == 0:
            return None
        if len(value) == 1:
            return value[0]
        return ", ".join(str(v) for v in value)
    return value


class LdapTransport(BaseTransport):
    """LDAP/Active Directory transport using ldap3 (pure Python, no platform deps)."""

    def __init__(self):
        self.conn = None
        self._manager_cache: dict[str, str | None] = {}

    def _connect(self, credentials: dict):
        """Establish LDAP connection. Stores on self.conn."""
        import ldap3
        from ldap3 import Server, Connection, SAFE_SYNC, Tls
        import ssl

        host = credentials["host"]
        port = int(credentials.get("port", 636))
        use_ssl = credentials.get("use_ssl", True)
        use_starttls = credentials.get("use_starttls", False)
        verify_ssl = credentials.get("verify_ssl", True)
        auth_mode = credentials.get("auth_mode", "simple_bind")

        # TLS configuration
        tls_config = None
        if use_ssl or use_starttls:
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED if verify_ssl else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
            )

        server = Server(
            host,
            port=port,
            use_ssl=use_ssl,
            tls=tls_config,
            get_info=ldap3.ALL,
            connect_timeout=10,
        )

        # Authentication
        if auth_mode == "ntlm":
            ntlm_domain = credentials.get("ntlm_domain", "")
            bind_user = credentials.get("bind_dn", "")
            # NTLM expects DOMAIN\\user format
            if "\\" not in bind_user and ntlm_domain:
                bind_user = f"{ntlm_domain}\\{bind_user}"
            self.conn = Connection(
                server,
                user=bind_user,
                password=credentials.get("bind_password", ""),
                authentication=ldap3.NTLM,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                raise_exceptions=True,
            )
        elif auth_mode == "anonymous":
            self.conn = Connection(
                server,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                raise_exceptions=True,
            )
        else:
            # simple_bind (default)
            self.conn = Connection(
                server,
                user=credentials.get("bind_dn", ""),
                password=credentials.get("bind_password", ""),
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                raise_exceptions=True,
            )

        if use_starttls and not use_ssl:
            self.conn.start_tls()

    def _search_paged(self, base_dn: str, filter_str: str, attributes: list,
                      scope: str = "SUBTREE", page_size: int = 500):
        """Paged LDAP search yielding flat dicts. Never unbounded."""
        import ldap3

        scope_map = {
            "BASE": ldap3.BASE,
            "LEVEL": ldap3.LEVEL,
            "SUBTREE": ldap3.SUBTREE,
        }
        ldap_scope = scope_map.get(scope.upper(), ldap3.SUBTREE)

        # Use ldap3's built-in paged search
        entry_generator = self.conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=ldap_scope,
            attributes=attributes,
            paged_size=page_size,
            generator=True,
        )

        for entry in entry_generator:
            # Skip search references
            if entry.get("type") == "searchResRef":
                continue
            attrs = entry.get("attributes", {})
            dn = entry.get("dn", "")

            flat = {"distinguishedName": dn}
            for attr_name, attr_val in attrs.items():
                flat[attr_name] = _flatten_value(attr_name, attr_val)

                # Normalize timestamp attributes inline
                if attr_name in (
                    "whenCreated", "whenChanged", "pwdLastSet",
                    "lastLogonTimestamp", "accountExpires", "lockoutTime",
                ):
                    flat[attr_name] = filetime_to_iso(attr_val)

            yield flat

    def _resolve_manager(self, manager_dn: str, base_dn: str) -> str | None:
        """Resolve a manager DN to sAMAccountName, with caching."""
        if not manager_dn:
            return None

        if manager_dn in self._manager_cache:
            return self._manager_cache[manager_dn]

        try:
            status, result, response, _ = self.conn.search(
                search_base=manager_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["sAMAccountName"],
            )
            if response:
                sam = response[0].get("attributes", {}).get("sAMAccountName")
                if isinstance(sam, list):
                    sam = sam[0] if sam else None
                self._manager_cache[manager_dn] = sam
                return sam
        except Exception:
            pass

        self._manager_cache[manager_dn] = None
        return None

    def _post_process_user(self, record: dict, base_dn: str) -> dict:
        """Post-process a raw AD user record into normalized fields."""
        uac = decode_uac(record.get("userAccountControl"))
        member_of = record.get("memberOf") or []
        svc = is_service_account(record)

        # Resolve manager DN → sAMAccountName
        manager_sam = self._resolve_manager(record.get("manager"), base_dn)

        # Password age
        pwd_last_set = record.get("pwdLastSet")
        password_age_days = filetime_to_days_ago(
            record.get("_raw_pwdLastSet", record.get("pwdLastSet"))
        )

        # lastLogonTimestamp is replicated across DCs every 9-14 days by default,
        # so the value may be up to 14 days stale.
        last_logon_days_ago = filetime_to_days_ago(
            record.get("_raw_lastLogonTimestamp", record.get("lastLogonTimestamp"))
        )

        return {
            **record,
            "is_enabled": uac["is_enabled"],
            "is_locked": uac["is_locked"],
            "is_admin": _is_admin(member_of),
            "is_service_account": svc,
            "identity_type": "non_human" if svc else "human",
            "manager_sam": manager_sam,
            "password_age_days": password_age_days,
            "last_logon_days_ago": last_logon_days_ago,
            "password_never_expires": uac["password_never_expires"],
        }

    def _post_process_computer(self, record: dict) -> dict:
        """Post-process a raw AD computer record."""
        uac = decode_uac(record.get("userAccountControl"))
        sam = str(record.get("sAMAccountName", ""))
        hostname = sam.rstrip("$")

        os_str = str(record.get("operatingSystem", "")).lower()
        if "server" in os_str:
            os_family = "windows_server"
        elif "windows" in os_str:
            os_family = "windows_workstation"
        else:
            os_family = "unknown"

        last_seen_days_ago = filetime_to_days_ago(
            record.get("_raw_lastLogonTimestamp", record.get("lastLogonTimestamp"))
        )

        return {
            **record,
            "hostname": hostname,
            "is_enabled": uac["is_enabled"],
            "os_family": os_family,
            "last_seen_days_ago": last_seen_days_ago,
        }

    def _post_process_group(self, record: dict) -> dict:
        """Post-process a raw AD group record."""
        gt = decode_group_type(record.get("groupType"))
        members = record.get("member") or []

        return {
            **record,
            **gt,
            "member_count": len(members) if isinstance(members, list) else 0,
        }

    def _disconnect(self):
        """Unbind if connected."""
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass
            self.conn = None

    # ---------- BaseTransport interface ----------

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Test connection: bind + root DSE query + sample records."""
        try:
            self._connect(credentials)

            # Read root DSE for domain info
            domain = ""
            server_version = ""
            if self.conn.server.info:
                info = self.conn.server.info
                naming = getattr(info, "naming_contexts", None)
                if naming:
                    domain = str(naming[0]) if naming else ""
                vendor = getattr(info, "vendor_name", None)
                if vendor:
                    server_version = str(vendor[0]) if isinstance(vendor, list) else str(vendor)

            # Fetch a few sample records based on mode
            mode = config.get("mode", "users")
            base_dn = credentials.get("base_dn", domain)
            page_size = int(config.get("page_size", 500))

            if mode == "computers":
                filt = "(&(objectClass=computer))"
                attrs = ["sAMAccountName", "dNSHostName", "operatingSystem",
                         "operatingSystemVersion", "distinguishedName"]
            elif mode == "groups":
                filt = "(&(objectClass=group))"
                attrs = ["sAMAccountName", "distinguishedName", "description", "groupType"]
            else:
                filt = "(&(objectClass=user)(objectCategory=person))"
                attrs = ["sAMAccountName", "userPrincipalName", "displayName",
                         "mail", "department", "title"]

            # Append custom filter if provided
            custom_filter = config.get("custom_filter")
            if custom_filter:
                filt = f"(&{filt}{custom_filter})"

            samples = []
            for rec in self._search_paged(base_dn, filt, attrs, page_size=min(page_size, 5)):
                samples.append(rec)
                if len(samples) >= 5:
                    break

            return ConnectResult(
                success=True,
                sample_records=samples,
                raw_response={"domain": domain, "server_version": server_version},
            )

        except Exception as e:
            error_msg = _format_ldap_error(e)
            return ConnectResult(success=False, error=error_msg)
        finally:
            self._disconnect()

    async def fetch_all(self, config: dict, credentials: dict, params: dict) -> AsyncIterator:
        """Stream all AD records with post-processing."""
        try:
            self._connect(credentials)

            mode = config.get("mode", "users")
            base_dn = credentials.get("base_dn", "")
            page_size = int(config.get("page_size", 500))
            custom_filter = config.get("custom_filter")

            if mode == "computers":
                filt = "(&(objectClass=computer))"
                attrs = [
                    "sAMAccountName", "dNSHostName", "operatingSystem",
                    "operatingSystemVersion", "distinguishedName", "whenCreated",
                    "whenChanged", "lastLogonTimestamp", "userAccountControl",
                    "objectSid", "objectGUID", "memberOf",
                ]
            elif mode == "groups":
                filt = "(&(objectClass=group))"
                attrs = [
                    "sAMAccountName", "distinguishedName", "description", "member",
                    "memberOf", "groupType", "whenCreated", "whenChanged", "objectSid",
                ]
            else:
                filt = "(&(objectClass=user)(objectCategory=person))"
                attrs = [
                    "sAMAccountName", "userPrincipalName", "displayName", "mail",
                    "department", "title", "manager", "memberOf", "distinguishedName",
                    "whenCreated", "whenChanged", "pwdLastSet", "lastLogonTimestamp",
                    "userAccountControl", "objectSid", "objectGUID",
                    "servicePrincipalName",
                ]

            # Merge custom attributes
            custom_attrs = config.get("custom_attributes")
            if custom_attrs:
                if isinstance(custom_attrs, str):
                    custom_attrs = [a.strip() for a in custom_attrs.split(",") if a.strip()]
                attrs = list(set(attrs + custom_attrs))

            if custom_filter:
                filt = f"(&{filt}{custom_filter})"

            count = 0
            for raw in self._search_paged(base_dn, filt, attrs, page_size=page_size):
                # Preserve raw FILETIME values before normalization for days-ago calc
                if "pwdLastSet" in raw:
                    raw["_raw_pwdLastSet"] = raw.get("pwdLastSet")
                if "lastLogonTimestamp" in raw:
                    raw["_raw_lastLogonTimestamp"] = raw.get("lastLogonTimestamp")

                # Post-process based on mode
                if mode == "computers":
                    record = self._post_process_computer(raw)
                    record_type = "computer"
                elif mode == "groups":
                    record = self._post_process_group(raw)
                    record_type = "group"
                else:
                    record = self._post_process_user(raw, base_dn)
                    record_type = "user"

                # Clean up internal keys
                record.pop("_raw_pwdLastSet", None)
                record.pop("_raw_lastLogonTimestamp", None)

                # Yield in connector record format
                yield {
                    "source": "active_directory",
                    "source_id": str(record.get("objectGUID", record.get("distinguishedName", ""))),
                    "record_type": record_type,
                    "raw": raw,
                    "normalized": record,
                }
                count += 1

            logger.info("LDAP fetch complete: %d %s records", count, mode)

        except Exception as e:
            error_msg = _format_ldap_error(e)
            logger.error("LDAP fetch failed: %s", error_msg)
            raise RuntimeError(error_msg) from e
        finally:
            self._disconnect()

    async def push(self, config: dict, credentials: dict, payload: dict):
        """LDAP transport is pull-only."""
        raise NotImplementedError("LDAP transport does not support push operations")


def test_ldap_connection(credentials: dict) -> dict:
    """Standalone test-connection for the API endpoint.

    Returns {ok, domain, server_version, user_count_estimate, error}.
    """
    import ldap3

    transport = LdapTransport()
    try:
        transport._connect(credentials)

        # Read root DSE
        domain = ""
        server_version = ""
        if transport.conn.server.info:
            info = transport.conn.server.info
            naming = getattr(info, "naming_contexts", None)
            if naming:
                domain = str(naming[0]) if naming else ""
            vendor = getattr(info, "vendor_name", None)
            if vendor:
                server_version = str(vendor[0]) if isinstance(vendor, list) else str(vendor)

        # Estimate user count via paged search (fetch only objectClass to minimize data)
        base_dn = credentials.get("base_dn", domain)
        user_count = 0
        try:
            for _ in transport._search_paged(
                base_dn,
                "(&(objectClass=user)(objectCategory=person))",
                ["objectClass"],
                page_size=500,
            ):
                user_count += 1
        except Exception as count_err:
            logger.warning("Could not estimate user count: %s", count_err)

        result = {
            "ok": True,
            "domain": domain,
            "server_version": server_version,
            "user_count_estimate": user_count,
        }

        # Warn for very large directories
        if user_count > 50000:
            result["warning"] = (
                f"Large directory detected ({user_count:,} users). "
                "Consider scoping base_dn to a specific OU for better performance."
            )

        return result

    except Exception as e:
        return {
            "ok": False,
            "domain": "",
            "server_version": "",
            "user_count_estimate": 0,
            "error": _format_ldap_error(e),
        }
    finally:
        transport._disconnect()


def _format_ldap_error(exc: Exception) -> str:
    """Format LDAP exceptions into user-friendly messages."""
    msg = str(exc)

    # AD-specific error codes embedded in LDAP messages
    if "data 52e" in msg or "INVALID_CREDENTIALS" in msg.upper():
        return "Invalid bind DN or password"
    if "data 532" in msg:
        return "Password expired for the bind account"
    if "data 533" in msg or "ACCOUNT_DISABLED" in msg.upper():
        return "Bind account is disabled"
    if "data 701" in msg:
        return "Bind account has expired"
    if "data 775" in msg:
        return "Bind account is locked out"

    # ldap3 exception types
    exc_type = type(exc).__name__
    if "LDAPInvalidCredentialsResult" in exc_type:
        return "Invalid bind DN or password"
    if "LDAPUnwillingToPerformResult" in exc_type:
        return "Account locked or disabled — server refused the operation"
    if "LDAPOperationsErrorResult" in exc_type:
        return f"LDAP operations error: {msg}"

    # Connection / TLS errors
    if "LDAPSocketOpenError" in exc_type or "connect" in msg.lower():
        if "SSL" in msg or "certificate" in msg.lower() or "CERT" in msg:
            return (
                f"TLS certificate error: {msg}. "
                "Check that verify_ssl is disabled for self-signed certs, "
                "or ensure the certificate CN matches the server hostname."
            )
        return f"Cannot connect to LDAP server: {msg}"
    if "timeout" in msg.lower():
        return f"Connection timed out: {msg}"

    return f"LDAP error: {msg}"
