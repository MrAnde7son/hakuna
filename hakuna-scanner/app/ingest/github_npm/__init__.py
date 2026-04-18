"""GitHub + npm attribution and discovery for EASM.

Takes a domain, finds GitHub orgs/users/repos and npm packages attributable
to the target, and emits a unified result payload for Pipeline B (code_repo
scanning) in hakuna-vm-scanner to consume.

Public surface:
    from app.ingest.github_npm import EASMEngine, DiscoveryResult, Mode
"""

from app.ingest.github_npm.engine import EASMEngine, Mode
from app.ingest.github_npm.models import (
    AttributedNpmPackage,
    AttributedOrg,
    AttributedRepo,
    AttributedUser,
    DiscoveryResult,
)

__all__ = [
    "EASMEngine",
    "Mode",
    "DiscoveryResult",
    "AttributedOrg",
    "AttributedRepo",
    "AttributedUser",
    "AttributedNpmPackage",
]
