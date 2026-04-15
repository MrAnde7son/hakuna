"""
Canonical ownership role / team list.

Single source of truth for the `owner_role` field on AssetOwnership, FindingOwnership,
OwnershipRule, Finding.owner_suggestion, and workflow/rule engine action configs.

Keep this list in sync with:
  - frontend/src/components/shared/ui.jsx  → OWNERSHIP_ROLE_OPTIONS
  - frontend/public/locales/en/translation.json → roles.*
"""
from __future__ import annotations

# Ordered by category: Infrastructure & Ops → Security → Engineering → Custom.
OWNERSHIP_ROLES: list[str] = [
    # Infrastructure & Operations (fixers)
    "IT",          # endpoint / workstation patching, general IT
    "HelpDesk",    # service desk / user support, endpoint remediation
    "DevOps",      # CI/CD, deployment pipelines, container platforms
    "SRE",         # site reliability, availability, platform incident response
    "Platform",    # platform engineering, infra-as-code, shared tooling
    "Networking",  # network engineering — switches, routers, firewalls (infra)
    "CloudOps",    # cloud infrastructure operations (AWS/Azure/GCP ops)
    "DBA",         # database administration
    # Security (finders & fixers)
    "VM",          # vulnerability management — owns scanners (Nessus/Qualys/Nuclei) and scan findings
    "SecOps",      # operational security, hardening, configuration
    "SOC",         # security operations center — monitoring, alert triage, IR
    "AppSec",      # application security, code-level findings, SDLC
    "CloudSec",    # cloud security posture (distinct from CloudOps)
    "IAM",         # identity & access management — credentials, MFA, stale accounts
    "GRC",         # governance, risk & compliance — audit, policy, frameworks
    # Engineering (fixers)
    "Engineering", # general software engineering — owns code that AppSec flags
    "Mobile",      # mobile engineering / MDM
    "Data",        # data engineering, data platform, analytics pipelines
    # Escape hatch for org-specific teams not in the catalog
    "Custom",
]

# Enum options formatted for the rule engine / workflow catalog UI.
OWNERSHIP_ROLE_ENUM_OPTIONS = [
    {"label": role, "value": role} for role in OWNERSHIP_ROLES if role != "Custom"
]
