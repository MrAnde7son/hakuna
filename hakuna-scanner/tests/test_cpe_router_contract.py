"""Contract test: the CPE inference layer must produce CPEs that the
hakuna-vm-scanner Nuclei router actually routes on, for the curated set of
products with Nuclei templates.

This test is the contract between two repos:
  - hakuna-scanner/app/ingest/cpe_map.json (alias table)
  - hakuna-vm-scanner/templates/routing_table.json (router template map)
  - hakuna-scanner/tests/test_cpe_infer.py::COVERAGE_FIXTURES (fixture table)

Note on scope: inference is intentionally open-ended — it emits speculative
CPEs for any Server header token, including products the router has no
templates for. The router silently ignores vendor:product pairs it doesn't
know (see router.py:_route_from_cpe). These tests only verify the curated
slice: every routing_table key must have a fixture row, and every fixture
row must round-trip correctly through inference → router.
"""

import json
import os
from pathlib import Path

import pytest

from app.ingest.cpe_infer import infer_cpes
from tests.test_cpe_infer import COVERAGE_FIXTURES, _has_cpe


def _find_routing_table() -> Path | None:
    """Locate routing_table.json in the sibling hakuna-vm-scanner repo.

    Layout assumed:
        <root>/hakuna-scanner/...   (this file lives here)
        <root>/hakuna-vm-scanner/templates/routing_table.json

    Also honor an env override for CI scenarios where the layout differs.
    """
    env_override = os.environ.get("HAKUNA_ROUTING_TABLE")
    if env_override:
        p = Path(env_override)
        return p if p.exists() else None

    here = Path(__file__).resolve()
    # tests/ -> hakuna-scanner/ -> <root>/
    candidates = [
        here.parents[2] / "hakuna-vm-scanner" / "templates" / "routing_table.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


_ROUTING_PATH = _find_routing_table()
_skip_if_missing = pytest.mark.skipif(
    _ROUTING_PATH is None,
    reason="hakuna-vm-scanner/templates/routing_table.json not found — set HAKUNA_ROUTING_TABLE to override",
)


def _routing_cpe_map() -> dict[str, list[str]]:
    assert _ROUTING_PATH is not None
    with open(_ROUTING_PATH) as f:
        return json.load(f).get("cpe_map", {})


@_skip_if_missing
def test_every_router_cpe_key_is_reachable_from_a_fixture():
    """Every vendor:product key in routing_table.json's cpe_map must be
    matched by at least one fixture row in COVERAGE_FIXTURES."""
    router_keys = set(_routing_cpe_map().keys())
    fixture_keys = {f"{v}:{p}" for v, p, _, _ in COVERAGE_FIXTURES}

    missing = router_keys - fixture_keys
    assert not missing, (
        f"routing_table.json cpe_map has {len(missing)} keys with no fixture: "
        f"{sorted(missing)}. Add a row to COVERAGE_FIXTURES in test_cpe_infer.py."
    )


@_skip_if_missing
def test_inference_output_routes_through_router():
    """End-to-end: feed each fixture through inference, then through the
    router's CPE-matching logic, and assert the right tags come out.

    This guards against bugs like inference emitting CPE 2.2 when the router
    expects 2.3, or wrong vendor casing.
    """
    cpe_map = _routing_cpe_map()

    for vendor, product, httpx_entry, tls_cert in COVERAGE_FIXTURES:
        result = infer_cpes(httpx_entry, tls_cert)
        cpes = result.cpe_list
        assert cpes, f"inference produced no CPEs for {vendor}:{product}"

        # Replicate router._route_from_cpe locally to avoid importing
        # hakuna-vm-scanner from this test (different package, different deps).
        matched_tags: set[str] = set()
        for cpe in cpes:
            parts = cpe.split(":")
            if len(parts) >= 5 and parts[1] == "2.3":
                vp = f"{parts[3]}:{parts[4]}"
                if vp in cpe_map:
                    matched_tags.update(cpe_map[vp])

        expected_tags = set(cpe_map.get(f"{vendor}:{product}", []))
        assert expected_tags.issubset(matched_tags), (
            f"Inference output {cpes!r} for fixture {vendor}:{product} did not "
            f"yield expected router tags. Expected superset of {expected_tags}, "
            f"got {matched_tags}."
        )
