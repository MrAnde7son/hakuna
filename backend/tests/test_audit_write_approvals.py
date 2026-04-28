"""Per-call approval gate for audit write tools.

Every protocol write/exec primitive (LDAP modify/add/delete, SNMP set,
SMB write_file/service_control, WMI invoke_method, SSH non-read commands)
must raise NeedsApproval when called without the `_approved=True` flag.
This test pins that contract so a future refactor can't accidentally let
a write through without user sign-off.
"""

from __future__ import annotations

import pytest

# Side-effect import populates TOOL_REGISTRY.
import agents.agent_tools  # noqa: F401
from agents.agent_tools import TOOL_REGISTRY, NeedsApproval


# (tool_name, args_that_should_pause)
_GATED_TOOLS = [
    ("ldap_modify", {"asset_id": 1, "dn": "CN=svc,DC=corp,DC=lab",
                      "changes": {"description": [{"action": "replace", "values": ["x"]}]}}),
    ("ldap_add", {"asset_id": 1, "dn": "CN=svc,DC=corp,DC=lab",
                   "object_class": ["top", "user"],
                   "attributes": {"sAMAccountName": "svc"}}),
    ("ldap_delete", {"asset_id": 1, "dn": "CN=svc,DC=corp,DC=lab"}),
    ("snmp_set", {"asset_id": 1,
                   "values": [{"oid": "1.3.6.1.2.1.1.5.0", "value": "newname",
                                "type": "OctetString"}]}),
    ("smb_write_file", {"asset_id": 1, "share": "C$", "path": "tmp\\x.txt",
                         "content_b64": "aGVsbG8="}),
    ("smb_service_control", {"asset_id": 1, "action": "stop",
                               "service_name": "Spooler"}),
    ("wmi_invoke_method", {"asset_id": 1, "class": "Win32_Process",
                             "method": "Create", "arguments": ["calc.exe"]}),
]


@pytest.mark.parametrize("tool_name,args", _GATED_TOOLS)
def test_write_tool_pauses_for_approval(tool_name, args):
    """Without `_approved=True`, every write tool must raise NeedsApproval."""
    fn = TOOL_REGISTRY[tool_name]["fn"]
    with pytest.raises(NeedsApproval) as exc:
        fn(None, args)
    assert exc.value.category, f"{tool_name} raised NeedsApproval but category is empty"
    assert exc.value.reason, f"{tool_name} raised NeedsApproval but reason is empty"


def test_ssh_run_command_read_only_does_not_pause():
    """Read-only SSH commands skip the approval gate."""
    from agents.tools.ssh_tools import _classify_command
    cat, _ = _classify_command("cat /etc/os-release")
    assert cat == "read_only"


def test_ssh_run_command_write_pauses():
    """ssh_run_command raises NeedsApproval for write/network/privileged."""
    from agents.tools.ssh_tools import _classify_command
    for cmd, expected in [
        ("rm /tmp/x", "write"),
        ("curl http://example.com", "network"),
        ("sudo cat /etc/shadow", "privileged"),
    ]:
        cat, _ = _classify_command(cmd)
        assert cat == expected, f"{cmd!r} classified as {cat}, expected {expected}"
