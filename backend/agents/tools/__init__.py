"""Protocol-scoped tool palettes for ReAct audit agents.

Each submodule (wmi_tools, ldap_tools, smb_tools, …) registers its tools via
`@agent_tool` and registers its `ProtocolAudit` entry via `register_audit`.
Loading this package triggers those side effects, so the registries are
populated before routes or agent_engine read from them.
"""

# Side-effect imports — order here matters only for debuggability, not correctness.
from agents.tools import emit_finding  # noqa: F401
from agents.tools import wmi_tools  # noqa: F401
from agents.tools import ldap_tools  # noqa: F401
from agents.tools import smb_tools  # noqa: F401
from agents.tools import snmp_tools  # noqa: F401
from agents.tools import ssh_tools  # noqa: F401
from agents.tools import cloud_tools  # noqa: F401
from agents.tools import exposed_datastore_tools  # noqa: F401
from agents.tools import exposed_ai_service_tools  # noqa: F401
from agents.tools import exposed_anon_protocol_tools  # noqa: F401
from agents.tools import ipmi_tools  # noqa: F401
from agents.tools import netbios_local_tools  # noqa: F401
from agents.tools import ot_protocol_tools  # noqa: F401
from agents.tools import ot_passive_tools  # noqa: F401
from agents.tools import easm_fingerprint_tools  # noqa: F401
