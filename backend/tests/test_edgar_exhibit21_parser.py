"""Regression tests for the EDGAR Exhibit 21 parser.

Bug: the original parser stripped HTML tags, split on newlines, and treated
each non-empty line as a potential subsidiary. For Booking Holdings the
Exhibit 21 is a 3-column HTML table (Name | % Owned | Jurisdiction), so the
naive split produced entries like:

  - "Percent"           (column header)
  - "100%"              (ownership percentage)
  - "The Netherlands"   (jurisdiction)
  - "Delaware"          (jurisdiction)

These then flowed into `_associate_subsidiary_domains` which DNS-probed
``percent.com``, ``100.io``, ``delaware.io`` and persisted them.
"""

from threat_intel.edgar_sync import _parse_exhibit21


def _bkng_exhibit21_html() -> str:
    """Minimal HTML mirroring Booking Holdings' 3-column Exhibit 21 table.

    Each data row has: <Name>, <% Owned>, <Jurisdiction>.
    """
    return """
    <html><body>
    <p>Exhibit 21 - List of Subsidiaries</p>
    <table>
      <tr>
        <th>Name</th>
        <th>Percent Ownership</th>
        <th>Jurisdiction of Incorporation</th>
      </tr>
      <tr>
        <td>Agoda Company Pte. Ltd.</td>
        <td>100%</td>
        <td>Singapore</td>
      </tr>
      <tr>
        <td>Booking.com Holding B.V.</td>
        <td>100%</td>
        <td>The Netherlands</td>
      </tr>
      <tr>
        <td>KAYAK Software Corporation</td>
        <td>100%</td>
        <td>Delaware</td>
      </tr>
      <tr>
        <td>OpenTable, Inc.</td>
        <td>100%</td>
        <td>Delaware</td>
      </tr>
      <tr>
        <td>Priceline.com Bookings Acquisition Company Limited</td>
        <td>100%</td>
        <td>United Kingdom</td>
      </tr>
    </table>
    <p>* As of December 31, 2025</p>
    </body></html>
    """


def test_parses_three_column_table_cleanly():
    subs = _parse_exhibit21(_bkng_exhibit21_html())
    names = [s["name"] for s in subs]

    assert "Agoda Company Pte. Ltd." in names
    assert "Booking.com Holding B.V." in names
    assert "KAYAK Software Corporation" in names
    assert "OpenTable, Inc." in names
    assert "Priceline.com Bookings Acquisition Company Limited" in names


def test_percentages_are_not_treated_as_entities():
    subs = _parse_exhibit21(_bkng_exhibit21_html())
    names = [s["name"] for s in subs]
    assert "100%" not in names
    assert not any(n.strip().endswith("%") for n in names)


def test_bare_jurisdictions_are_not_treated_as_entities():
    subs = _parse_exhibit21(_bkng_exhibit21_html())
    names = [s["name"] for s in subs]
    for bad in ("Delaware", "The Netherlands", "Singapore",
                "United Kingdom", "Netherlands"):
        assert bad not in names, f"bare jurisdiction leaked into names: {bad}"


def test_column_headers_are_not_treated_as_entities():
    subs = _parse_exhibit21(_bkng_exhibit21_html())
    names = [s["name"] for s in subs]
    for bad in ("Name", "Percent Ownership", "Percent",
                "Jurisdiction of Incorporation", "LIST OF SUBSIDIARIES"):
        assert bad not in names
        assert bad.lower() not in {n.lower() for n in names}


def test_jurisdictions_map_to_correct_entities():
    subs_by_name = {s["name"]: s["jurisdiction"] for s in _parse_exhibit21(_bkng_exhibit21_html())}
    assert subs_by_name["Agoda Company Pte. Ltd."] == "Singapore"
    assert subs_by_name["Booking.com Holding B.V."] == "The Netherlands"
    assert subs_by_name["KAYAK Software Corporation"] == "Delaware"
    assert subs_by_name["OpenTable, Inc."] == "Delaware"


def test_date_footnote_is_not_treated_as_entity():
    subs = _parse_exhibit21(_bkng_exhibit21_html())
    names = [s["name"].lower() for s in subs]
    assert not any("as of december" in n for n in names)


def test_two_column_table_without_percent_column():
    html_two_col = """
    <table>
      <tr><th>Subsidiary Name</th><th>Jurisdiction</th></tr>
      <tr><td>Acme Holdings LLC</td><td>Delaware</td></tr>
      <tr><td>Acme Labs Ltd</td><td>Ireland</td></tr>
    </table>
    """
    subs = _parse_exhibit21(html_two_col)
    by_name = {s["name"]: s["jurisdiction"] for s in subs}
    assert by_name == {
        "Acme Holdings LLC": "Delaware",
        "Acme Labs Ltd": "Ireland",
    }


def test_plain_text_fallback_still_works():
    """Older filings / free-form text should fall through to the line parser."""
    plain = """
    Exhibit 21 - List of Subsidiaries

    Acme Holdings LLC
    Delaware

    Globex Corporation
    California
    """
    subs = _parse_exhibit21(plain)
    by_name = {s["name"]: s["jurisdiction"] for s in subs}
    # Accept the subsidiaries even if jurisdiction pairing is imperfect.
    assert "Acme Holdings LLC" in by_name
    assert "Globex Corporation" in by_name
    # Ensure bare jurisdictions didn't become names.
    assert "Delaware" not in by_name
    assert "California" not in by_name


def test_entity_names_containing_jurisdiction_words_are_kept():
    """'Delaware Holdings LLC' is a valid entity name despite containing
    'Delaware'. Only *bare* jurisdiction tokens are rejected."""
    html_mixed = """
    <table>
      <tr><th>Name</th><th>Jurisdiction</th></tr>
      <tr><td>Delaware Holdings LLC</td><td>Delaware</td></tr>
      <tr><td>The Netherlands Group B.V.</td><td>The Netherlands</td></tr>
    </table>
    """
    subs = _parse_exhibit21(html_mixed)
    names = [s["name"] for s in subs]
    assert "Delaware Holdings LLC" in names
    assert "The Netherlands Group B.V." in names
