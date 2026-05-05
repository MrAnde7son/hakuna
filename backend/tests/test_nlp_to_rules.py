"""Unit tests for services/nlp_to_rules.py — nlp_to_conditions()."""

from services.nlp_to_rules import nlp_to_conditions


def _conds(query: str) -> list[dict]:
    return nlp_to_conditions(query)["conditions"]


def _has_condition(conds, field, op=None, value=None):
    for c in conds:
        if c["field"] != field:
            continue
        if op is not None and c["op"] != op:
            continue
        if value is not None and c["value"] != value:
            continue
        return True
    return False


# ── Boolean finding fields ───────────────────────────────────────────────────

def test_has_exploit():
    assert _has_condition(_conds("exploitable findings"), "finding.exploit", "is_true")


def test_kev():
    assert _has_condition(_conds("KEV vulnerabilities"), "finding.is_kev", "is_true")


def test_zero_day():
    assert _has_condition(_conds("zero-day exposure"), "finding.zero_day", "is_true")


def test_ransomware_linked():
    assert _has_condition(_conds("ransomware-linked vulns"), "finding.ransomware_linked", "is_true")


# ── Severity ─────────────────────────────────────────────────────────────────

def test_single_severity():
    assert _has_condition(_conds("critical findings"), "finding.severity", "eq", 4)


def test_severity_list_uses_gte_min():
    # "critical and high" → severity gte 3
    assert _has_condition(_conds("critical and high findings"), "finding.severity", "gte", 3)


# ── Numeric thresholds ───────────────────────────────────────────────────────

def test_min_cvss():
    assert _has_condition(_conds("cvss above 7"), "finding.cvss3", "gte", 7.0)


def test_min_epss_percentage_normalized():
    # NLP normalizes "epss > 50" as 0.5 (probability)
    conds = _conds("epss above 50")
    epss = next(c for c in conds if c["field"] == "finding.epss_score")
    assert epss["op"] == "gte"
    assert 0 < epss["value"] <= 1


# ── Asset-side ───────────────────────────────────────────────────────────────

def test_internet_facing():
    assert _has_condition(
        _conds("internet-facing servers"),
        "inventory.is_internet_facing", "is_true",
    )


def test_environment_dmz():
    assert _has_condition(_conds("DMZ assets"), "environment_tag", "eq", "dmz")


def test_min_critical_count():
    # "more than 3 critical" → asset min_critical=3
    conds = _conds("assets with more than 3 critical findings")
    assert _has_condition(conds, "critical_count", "gte", 3)


# ── Combined queries ─────────────────────────────────────────────────────────

def test_combined_query():
    result = nlp_to_conditions("critical Windows servers with exploits in DMZ")
    conds = result["conditions"]
    fields = [c["field"] for c in conds]
    assert "finding.severity" in fields
    assert "finding.exploit" in fields
    assert "environment_tag" in fields
    assert result["query_logic"] == "AND"
    assert len(result["chips"]) > 0


def test_empty_query_returns_empty_conditions():
    assert nlp_to_conditions("")["conditions"] == []


def test_unmappable_query_drops_silently():
    # Pure noise should produce few or no conditions, never error
    result = nlp_to_conditions("xyzzy quuxbar")
    assert isinstance(result["conditions"], list)
