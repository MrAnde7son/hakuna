"""Structural checks for the curated VPN-appliance template set.

These templates must satisfy three contracts so the prioritizer + family
classifier behave correctly:

  1. Every template tags ``vpn-appliance`` (the tag pre-pass in
     backend/services/vm_scanner._classify_nuclei_plugin_family routes off
     this tag, including for public CVE templates whose path would otherwise
     match ``cves/`` and collapse to the generic CVE family).
  2. Every CVE template carries ``info.metadata.kev: true`` and the
     ``info.classification.cve-id`` field — these feed the intel signal in
     services.prioritizer.compute_priority_score.
  3. Templates are detection-only — no POST/PUT/DELETE methods that would
     send exploit payloads. Pipeline A's contract with customers is that we
     find exposed appliances; we do not exploit them.
"""

from __future__ import annotations

import os

import pytest
import yaml


_HERE = os.path.dirname(__file__)
_VPN_DIR = os.path.normpath(
    os.path.join(_HERE, "..", "..", "templates", "custom", "vpn-appliance")
)


def _yaml_files() -> list[str]:
    return sorted(
        os.path.join(_VPN_DIR, f)
        for f in os.listdir(_VPN_DIR)
        if f.endswith(".yaml")
    )


def _load(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def _tag_set(template: dict) -> set[str]:
    raw = (template.get("info") or {}).get("tags", "")
    if isinstance(raw, list):
        items = raw
    else:
        items = str(raw).split(",")
    return {t.strip().lower() for t in items if t and t.strip()}


@pytest.fixture(scope="module")
def vpn_templates() -> list[tuple[str, dict]]:
    files = _yaml_files()
    assert files, f"no VPN templates found under {_VPN_DIR}"
    return [(p, _load(p)) for p in files]


def test_directory_exists():
    assert os.path.isdir(_VPN_DIR), f"missing curated dir: {_VPN_DIR}"


def test_every_template_tags_vpn_appliance(vpn_templates):
    # Without this tag the family classifier falls through to "CVE" or
    # "Nuclei" and the VPN-appliance family weight is lost — the whole
    # point of the curated set evaporates.
    for path, tpl in vpn_templates:
        assert "vpn-appliance" in _tag_set(tpl), (
            f"{os.path.basename(path)}: info.tags must include 'vpn-appliance'"
        )


def test_every_template_has_required_metadata(vpn_templates):
    for path, tpl in vpn_templates:
        info = tpl.get("info") or {}
        meta = info.get("metadata") or {}
        assert meta.get("source") == "custom", (
            f"{os.path.basename(path)}: info.metadata.source must be 'custom'"
        )
        assert meta.get("verified") is True, (
            f"{os.path.basename(path)}: info.metadata.verified must be true"
        )


def test_cve_templates_advertise_kev_and_cve_id(vpn_templates):
    # The detection-name file is the only template without a CVE — every
    # other file in this directory targets a specific KEV-listed CVE and
    # must carry both signals so the prioritizer can pick them up.
    for path, tpl in vpn_templates:
        name = os.path.basename(path)
        if "cve-" not in name.lower():
            continue
        info = tpl.get("info") or {}
        meta = info.get("metadata") or {}
        cls = info.get("classification") or {}
        assert meta.get("kev") is True, (
            f"{name}: info.metadata.kev must be true for CVE templates"
        )
        cve_id = cls.get("cve-id") or cls.get("cve_id")
        assert isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"), (
            f"{name}: info.classification.cve-id must be a CVE-XXXX-XXXX string"
        )


def test_templates_are_detection_only(vpn_templates):
    # No POST/PUT/DELETE — Pipeline A's contract is to detect exposure,
    # not to exploit customer infrastructure. Catching this in CI prevents
    # an enthusiastic future template from crossing the line silently.
    forbidden = {"POST", "PUT", "DELETE", "PATCH"}
    for path, tpl in vpn_templates:
        for block in tpl.get("http") or []:
            method = (block.get("method") or "GET").upper()
            assert method not in forbidden, (
                f"{os.path.basename(path)}: detection-only — found {method}"
            )
