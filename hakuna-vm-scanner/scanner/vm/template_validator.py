"""Validate custom Nuclei templates for correctness and required metadata."""

import subprocess
from dataclasses import dataclass, field

import yaml

from scanner.vm.config import NUCLEI_BIN


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_custom_template(path: str) -> ValidationResult:
    """Validate a custom Nuclei template.

    1. Run nuclei -validate against the template
    2. Parse YAML and assert required metadata
    3. Warn if not verified
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Step 1: nuclei -validate
    try:
        result = subprocess.run(
            [NUCLEI_BIN, "-validate", "-t", path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            errors.append(f"nuclei -validate failed (exit {result.returncode}): {stderr[:500]}")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)
    except FileNotFoundError:
        errors.append(f"nuclei binary not found at {NUCLEI_BIN}")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)
    except subprocess.TimeoutExpired:
        errors.append("nuclei -validate timed out after 30s")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)

    # Step 2: Parse YAML and check required metadata
    try:
        with open(path) as f:
            template = yaml.safe_load(f)
    except Exception as exc:
        errors.append(f"YAML parse error: {exc}")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)

    if not isinstance(template, dict):
        errors.append("Template root must be a YAML mapping")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)

    info = template.get("info", {})
    if not isinstance(info, dict):
        errors.append("Missing or invalid 'info' block")
        return ValidationResult(valid=False, errors=errors, warnings=warnings)

    # Required: info.metadata.source must be "custom"
    metadata = info.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append("Missing info.metadata block")
    else:
        source = metadata.get("source")
        if source != "custom":
            errors.append(f"info.metadata.source must be 'custom', got '{source}'")

    # Required: info.tags or info.metadata.cpe must be present (for routing)
    has_tags = bool(info.get("tags"))
    has_cpe = bool(metadata.get("cpe")) if isinstance(metadata, dict) else False
    if not has_tags and not has_cpe:
        errors.append("Template must have info.tags or info.metadata.cpe for routing")

    # Step 3: Warn if not verified
    if isinstance(metadata, dict) and metadata.get("verified") is not True:
        warnings.append("info.metadata.verified is not true — template is unverified")

    valid = len(errors) == 0
    return ValidationResult(valid=valid, errors=errors, warnings=warnings)
