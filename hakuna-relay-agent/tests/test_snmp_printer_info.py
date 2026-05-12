"""Unit tests for the PRINTER-MIB op in agent.snmp_query.

pysnmp itself is mocked — we only exercise the parsing / shaping logic
inside ``_op_printer_info``. Verifies:
  - happy path returns name, serial, page count, supplies with percent
  - partial data (e.g. only model name) still yields a usable result
  - percent_remaining handles both fixed-max and "level is percent" forms
  - missing OID branches surface as _errors without raising
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from agent import snmp_query


# ── Helpers ──────────────────────────────────────────────────────────


def _flat(rows):
    """Shape a list of (oid_suffix, value) into the (full_oid, value) tuples
    that ``_walk_flat`` returns for a given base OID. Tests pass the suffix
    relative to the base for readability."""
    return rows


def _walk_columns_stub(payload):
    """Return a fake ``_walk_columns`` that yields a dict of {index: {col: val}}
    when called regardless of which columns dict it's invoked with — the column
    names match the keys in `payload`'s inner dicts."""
    def _stub(mods, target, port, auth, oid_map, *args, **kwargs):
        return payload
    return _stub


def _walk_flat_stub(by_base_oid):
    """Return a fake ``_walk_flat`` that picks results based on the base OID
    passed in. Unknown bases yield an empty list."""
    def _stub(mods, target, port, auth, base_oid, *args, **kwargs):
        return by_base_oid.get(base_oid, [])
    return _stub


# ── Happy path ───────────────────────────────────────────────────────


def test_full_printer_info_returns_complete_payload():
    walk_flat_payload = {
        snmp_query._OID_PRT_GENERAL_PRINTER_NAME: [("1.3.6.1.2.1.43.5.1.1.16.1", "HP LaserJet M404n")],
        snmp_query._OID_PRT_GENERAL_SERIAL_NUMBER: [("1.3.6.1.2.1.43.5.1.1.17.1", "VNC1234567")],
        snmp_query._OID_PRT_MARKER_LIFE_COUNT: [("1.3.6.1.2.1.43.10.2.1.4.1.1", 42157)],
        snmp_query._OID_PRT_ALERT_DESC: [
            ("1.3.6.1.2.1.43.18.1.1.8.1.1", "Toner Low: Black"),
        ],
    }
    columns_payload = {
        "1": {"description": "Black Toner Cartridge",
              "unit_code": 19,           # percent
              "max_capacity": 100,
              "level": 42},
        "2": {"description": "Imaging Drum",
              "unit_code": 7,            # impressions
              "max_capacity": 20000,
              "level": 18500},
    }
    trays_payload = {
        "1": {"description": "Tray 1 (Multi-purpose)", "level": 250},
        "2": {"description": "Tray 2", "level": 480},
    }

    # _walk_columns is called twice (supplies, then trays). Use a list of
    # return values so each call picks the right payload.
    walk_columns_returns = iter([columns_payload, trays_payload])

    with patch.object(snmp_query, "_walk_flat", _walk_flat_stub(walk_flat_payload)), \
         patch.object(snmp_query, "_walk_columns", lambda *a, **kw: next(walk_columns_returns)):
        out = snmp_query._op_printer_info(mods={}, target="10.0.0.5", port=161, auth=None)

    assert out["printer_name"] == "HP LaserJet M404n"
    assert out["serial_number"] == "VNC1234567"
    assert out["total_pages"] == 42157
    assert out["page_counts"][0]["page_count"] == 42157

    supplies = {s["description"]: s for s in out["supplies"]}
    # Toner is reported with level=42 against max=100 → 42.0%.
    assert supplies["Black Toner Cartridge"]["percent_remaining"] == 42.0
    assert supplies["Black Toner Cartridge"]["unit"] == "percent"
    # Drum 18500/20000 → 92.5%.
    assert supplies["Imaging Drum"]["percent_remaining"] == 92.5
    assert supplies["Imaging Drum"]["unit"] == "impressions"

    trays = {t["description"]: t for t in out["input_trays"]}
    assert trays["Tray 1 (Multi-purpose)"]["level"] == 250
    assert trays["Tray 2"]["level"] == 480

    assert out["alerts"] == ["Toner Low: Black"]
    assert "_errors" not in out


# ── Partial data ─────────────────────────────────────────────────────


def test_printer_with_only_name_still_returns_useful_data():
    walk_flat_payload = {
        snmp_query._OID_PRT_GENERAL_PRINTER_NAME: [("1.3.6.1.2.1.43.5.1.1.16.1", "Brother HL-L2350DW")],
        # serial, page count, alerts: all absent
    }
    walk_columns_returns = iter([{}, {}])  # supplies + trays both empty

    with patch.object(snmp_query, "_walk_flat", _walk_flat_stub(walk_flat_payload)), \
         patch.object(snmp_query, "_walk_columns", lambda *a, **kw: next(walk_columns_returns)):
        out = snmp_query._op_printer_info(mods={}, target="10.0.0.6", port=161, auth=None)

    assert out["printer_name"] == "Brother HL-L2350DW"
    assert "serial_number" not in out
    assert "total_pages" not in out
    assert "supplies" not in out
    assert "input_trays" not in out
    assert "alerts" not in out
    assert "_errors" not in out  # absence-of-data is not an error


# ── Percent calculation edge cases ───────────────────────────────────


def test_supply_with_level_as_percent_and_max_minus_one():
    """RFC 3805 §6.3.2.6: prtMarkerSuppliesMaxCapacity = -1 means the level
    column is already a percentage (some Ricoh/Konica firmwares do this)."""
    columns_payload = {
        "1": {"description": "Cyan Toner",
              "unit_code": 19,
              "max_capacity": -1,
              "level": 78},
    }
    walk_columns_returns = iter([columns_payload, {}])

    with patch.object(snmp_query, "_walk_flat", _walk_flat_stub({})), \
         patch.object(snmp_query, "_walk_columns", lambda *a, **kw: next(walk_columns_returns)):
        out = snmp_query._op_printer_info(mods={}, target="x", port=161, auth=None)

    cyan = out["supplies"][0]
    assert cyan["percent_remaining"] == 78.0
    assert cyan["max_capacity"] == -1


def test_supply_with_unknown_level_omits_percent_remaining():
    """Level codes -3 (unknown), -2 (out of range), -1 (no data) are sentinels
    that the parser must not treat as numeric percentages."""
    columns_payload = {
        "1": {"description": "Magenta Toner",
              "unit_code": 19,
              "max_capacity": 100,
              "level": -3},  # unknown
    }
    walk_columns_returns = iter([columns_payload, {}])

    with patch.object(snmp_query, "_walk_flat", _walk_flat_stub({})), \
         patch.object(snmp_query, "_walk_columns", lambda *a, **kw: next(walk_columns_returns)):
        out = snmp_query._op_printer_info(mods={}, target="x", port=161, auth=None)

    magenta = out["supplies"][0]
    assert "percent_remaining" not in magenta
    assert magenta["level"] == -3


# ── Error isolation ──────────────────────────────────────────────────


def test_one_failing_section_does_not_break_others():
    """Each PRINTER-MIB sub-tree has its own try/except; a failure walking
    one column must not abort the others."""
    walk_flat_payload = {
        snmp_query._OID_PRT_GENERAL_PRINTER_NAME: [("1.3.6.1.2.1.43.5.1.1.16.1", "Xerox WorkCentre 6515")],
    }

    def _walk_columns_explodes_on_supplies(mods, target, port, auth, oid_map, *a, **kw):
        if oid_map.get("description") == snmp_query._OID_PRT_MARKER_SUPPLIES_DESC:
            raise RuntimeError("simulated SNMP timeout on supplies walk")
        return {"1": {"description": "Bypass Tray", "level": 50}}

    with patch.object(snmp_query, "_walk_flat", _walk_flat_stub(walk_flat_payload)), \
         patch.object(snmp_query, "_walk_columns", _walk_columns_explodes_on_supplies):
        out = snmp_query._op_printer_info(mods={}, target="x", port=161, auth=None)

    assert out["printer_name"] == "Xerox WorkCentre 6515"
    # Trays succeeded.
    assert out["input_trays"][0]["description"] == "Bypass Tray"
    # Supplies failed and surfaced via _errors.
    assert "_errors" in out
    assert "supplies" in out["_errors"]
    assert "RuntimeError" in out["_errors"]["supplies"]
