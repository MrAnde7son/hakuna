"""Protocol-scoped tool palettes for the audit ReAct agents.

Importing this package triggers each protocol module's side-effect
registrations: tools register into ``audit_engine.TOOL_REGISTRY`` via
``@agent_tool`` and protocol audits register into
``audit_registry.AUDITS`` via ``register_audit``. Routes and the
worker read from those registries — order here only matters for
debuggability.
"""

from scanner.audit.tools import emit_finding  # noqa: F401
from scanner.audit.tools import ssh_tools  # noqa: F401

# Phase 2 — port the rest one at a time:
# from scanner.audit.tools import wmi_tools  # noqa: F401
# from scanner.audit.tools import ldap_tools  # noqa: F401
# from scanner.audit.tools import smb_tools  # noqa: F401
# from scanner.audit.tools import snmp_tools  # noqa: F401
# from scanner.audit.tools import cloud_tools  # noqa: F401
