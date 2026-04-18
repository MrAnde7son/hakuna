"""code_repo scanning pipeline.

Consumes attributed GitHub repos / npm packages produced by hakuna-scanner's
EASM engine (Pipeline A) and runs:
  - TruffleHog secrets scan on a shallow clone
  - .github/workflows audit (pull_request_target, unpinned actions, self-hosted)
  - npm supply-chain checks (unmaintained, dependency CVEs)
  - Nuclei template/command generation for verifying discovered secrets
"""

from scanner.vm.code_repo.engine import RepoScanResult, scan_npm_package, scan_repo

__all__ = ["scan_repo", "scan_npm_package", "RepoScanResult"]
