"""Unit tests for LDAP transport: FILETIME parsing, UAC flag decoding,
service account heuristic, and group type decoding."""

import pytest
from services.transports.ldap_transport import (
    filetime_to_iso,
    filetime_to_days_ago,
    decode_uac,
    decode_group_type,
    is_service_account,
    _is_admin,
    _flatten_value,
    UAC_ACCOUNTDISABLE,
    UAC_LOCKOUT,
    UAC_DONT_EXPIRE_PASSWD,
)


# ─── FILETIME parsing ───────────────────────────────────


class TestFiletimeToIso:
    def test_normal_filetime(self):
        # 2023-10-15 12:00:00 UTC in FILETIME ticks
        # 1601-01-01 to 2023-10-15 12:00:00 = 133,418,448,000,000,000 ticks
        ticks = 133418448000000000
        result = filetime_to_iso(ticks)
        assert result is not None
        assert "2023-10-15" in result

    def test_zero_filetime(self):
        assert filetime_to_iso(0) is None

    def test_none_filetime(self):
        assert filetime_to_iso(None) is None

    def test_max_int_filetime(self):
        # 9223372036854775807 = "never" in AD
        assert filetime_to_iso(9223372036854775807) is None

    def test_string_zero(self):
        assert filetime_to_iso("0") is None

    def test_empty_string(self):
        assert filetime_to_iso("") is None

    def test_generalized_time(self):
        result = filetime_to_iso("20231015143022.0Z")
        assert result is not None
        assert "2023-10-15" in result
        assert "14:30:22" in result

    def test_generalized_time_no_fraction(self):
        result = filetime_to_iso("20231015143022")
        assert result is not None
        assert "2023-10-15" in result

    def test_already_iso(self):
        iso = "2023-10-15T14:30:22+00:00"
        assert filetime_to_iso(iso) == iso

    def test_negative_filetime(self):
        assert filetime_to_iso(-1) is None

    def test_string_ticks(self):
        # Pass as string representation of ticks
        result = filetime_to_iso("133413288000000000")
        # Should try to parse as GeneralizedTime, fail, then return as-is
        assert result is not None


class TestFiletimeToDaysAgo:
    def test_none_returns_none(self):
        assert filetime_to_days_ago(None) is None

    def test_zero_returns_none(self):
        assert filetime_to_days_ago(0) is None

    def test_max_int_returns_none(self):
        assert filetime_to_days_ago(9223372036854775807) is None


# ─── userAccountControl decoding ────────────────────────


class TestDecodeUac:
    def test_normal_enabled_account(self):
        # NORMAL_ACCOUNT (0x200) = 512
        result = decode_uac(512)
        assert result["is_enabled"] is True
        assert result["is_locked"] is False
        assert result["password_never_expires"] is False

    def test_disabled_account(self):
        # NORMAL_ACCOUNT + ACCOUNTDISABLE = 512 + 2 = 514
        result = decode_uac(514)
        assert result["is_enabled"] is False
        assert result["is_locked"] is False

    def test_locked_account(self):
        # NORMAL_ACCOUNT + LOCKOUT = 512 + 16 = 528
        result = decode_uac(528)
        assert result["is_enabled"] is True
        assert result["is_locked"] is True

    def test_disabled_and_locked(self):
        # 512 + 2 + 16 = 530
        result = decode_uac(530)
        assert result["is_enabled"] is False
        assert result["is_locked"] is True

    def test_password_never_expires(self):
        # 512 + 65536 = 66048
        result = decode_uac(66048)
        assert result["is_enabled"] is True
        assert result["password_never_expires"] is True

    def test_none_uac(self):
        result = decode_uac(None)
        assert result["is_enabled"] is True  # 0 = no disable flag
        assert result["is_locked"] is False
        assert result["raw"] == 0

    def test_string_uac(self):
        result = decode_uac("514")
        assert result["is_enabled"] is False

    def test_invalid_uac(self):
        result = decode_uac("not_a_number")
        assert result["raw"] == 0


# ─── groupType decoding ─────────────────────────────────


class TestDecodeGroupType:
    def test_global_security(self):
        # -2147483646 = 0x80000002 (SECURITY | GLOBAL)
        result = decode_group_type(-2147483646)
        assert result["group_scope"] == "global"
        assert result["group_type"] == "security"

    def test_domain_local_security(self):
        # -2147483644 = 0x80000004 (SECURITY | DOMAIN_LOCAL)
        result = decode_group_type(-2147483644)
        assert result["group_scope"] == "domain_local"
        assert result["group_type"] == "security"

    def test_universal_security(self):
        # -2147483640 = 0x80000008 (SECURITY | UNIVERSAL)
        result = decode_group_type(-2147483640)
        assert result["group_scope"] == "universal"
        assert result["group_type"] == "security"

    def test_global_distribution(self):
        # 2 = GLOBAL (no security bit)
        result = decode_group_type(2)
        assert result["group_scope"] == "global"
        assert result["group_type"] == "distribution"

    def test_none_group_type(self):
        result = decode_group_type(None)
        assert result["group_scope"] == "unknown"
        assert result["group_type"] == "distribution"

    def test_string_group_type(self):
        result = decode_group_type("-2147483646")
        assert result["group_scope"] == "global"
        assert result["group_type"] == "security"


# ─── Service account heuristic ──────────────────────────


class TestIsServiceAccount:
    def test_has_spn(self):
        record = {"servicePrincipalName": ["HTTP/web01.corp.example.com"]}
        assert is_service_account(record) is True

    def test_empty_spn_list(self):
        record = {"servicePrincipalName": [], "sAMAccountName": "jdoe"}
        assert is_service_account(record) is False

    def test_sam_ends_with_dollar(self):
        record = {"sAMAccountName": "DC01$"}
        assert is_service_account(record) is True

    def test_sam_svc_prefix(self):
        record = {"sAMAccountName": "svc_backup", "servicePrincipalName": []}
        assert is_service_account(record) is True

    def test_sam_svc_suffix(self):
        record = {"sAMAccountName": "backup_svc", "servicePrincipalName": []}
        assert is_service_account(record) is True

    def test_sam_sa_prefix(self):
        record = {"sAMAccountName": "sa_monitoring", "servicePrincipalName": []}
        assert is_service_account(record) is True

    def test_title_service(self):
        record = {
            "sAMAccountName": "appuser",
            "title": "Application Service Account",
            "servicePrincipalName": [],
        }
        assert is_service_account(record) is True

    def test_normal_user(self):
        record = {
            "sAMAccountName": "jdoe",
            "title": "Software Engineer",
            "servicePrincipalName": [],
        }
        assert is_service_account(record) is False

    def test_no_fields(self):
        record = {}
        assert is_service_account(record) is False


# ─── Admin detection ────────────────────────────────────


class TestIsAdmin:
    def test_domain_admins(self):
        member_of = ["CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"]
        assert _is_admin(member_of) is True

    def test_enterprise_admins(self):
        member_of = ["CN=Enterprise Admins,CN=Users,DC=corp,DC=example,DC=com"]
        assert _is_admin(member_of) is True

    def test_administrators(self):
        member_of = ["CN=Administrators,CN=Builtin,DC=corp,DC=example,DC=com"]
        assert _is_admin(member_of) is True

    def test_not_admin(self):
        member_of = [
            "CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com",
            "CN=IT-Staff,OU=Groups,DC=corp,DC=example,DC=com",
        ]
        assert _is_admin(member_of) is False

    def test_empty_member_of(self):
        assert _is_admin([]) is False

    def test_none_member_of(self):
        assert _is_admin(None) is False


# ─── Attribute flattening ───────────────────────────────


class TestFlattenValue:
    def test_single_value_list(self):
        assert _flatten_value("mail", ["user@example.com"]) == "user@example.com"

    def test_multi_value_list_joined(self):
        result = _flatten_value("department", ["IT", "Engineering"])
        assert result == "IT, Engineering"

    def test_multi_value_keep(self):
        result = _flatten_value("memberOf", ["CN=Group1", "CN=Group2"])
        assert isinstance(result, list)
        assert len(result) == 2

    def test_empty_list(self):
        assert _flatten_value("mail", []) is None

    def test_scalar_value(self):
        assert _flatten_value("mail", "user@example.com") == "user@example.com"

    def test_member_of_single(self):
        result = _flatten_value("memberOf", "CN=Group1")
        assert isinstance(result, list)
        assert result == ["CN=Group1"]

    def test_member_of_empty(self):
        result = _flatten_value("memberOf", None)
        assert result == []
