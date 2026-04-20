"""vm_scanner.py — CVE + CVSS extraction from Nuclei results.

Pins the normalization behavior that feeds threat-intel enrichment:
without `cves` populated on a Finding, enrich_findings_from_threat_intel
skips it and the UI shows empty CVSS3/EPSS/KEV columns for VM-scanner
findings.
"""

from services.vm_scanner import _extract_nuclei_cves, _extract_nuclei_cvss


class TestExtractNucleiCves:
    def test_cve_id_list_in_classification(self):
        f = {
            "template_id": "openssh-terrapin",
            "classification": {"cve-id": ["CVE-2023-48795"]},
        }
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_cve_id_string_in_classification(self):
        f = {
            "template_id": "openssh-terrapin",
            "classification": {"cve-id": "CVE-2023-48795"},
        }
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_template_id_fallback_when_classification_missing(self):
        f = {"template_id": "CVE-2023-48795"}
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_template_id_with_yaml_suffix(self):
        f = {"template_id": "CVE-2023-48795.yaml"}
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_classification_and_template_id_dedupe(self):
        f = {
            "template_id": "CVE-2023-48795",
            "classification": {"cve-id": ["CVE-2023-48795"]},
        }
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_multiple_cves_in_classification_preserved(self):
        f = {
            "template_id": "multi-cve-chain",
            "classification": {"cve-id": ["CVE-2021-44228", "CVE-2021-45046"]},
        }
        assert _extract_nuclei_cves(f) == ["CVE-2021-44228", "CVE-2021-45046"]

    def test_lowercase_cve_normalized_to_upper(self):
        f = {"template_id": "cve-2023-48795"}
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]

    def test_non_cve_template_returns_empty(self):
        f = {
            "template_id": "weak-cipher-suites",
            "classification": {},
        }
        assert _extract_nuclei_cves(f) == []

    def test_missing_classification_and_non_cve_template(self):
        f = {"template_id": "apache-detect"}
        assert _extract_nuclei_cves(f) == []

    def test_null_classification_cve_id(self):
        f = {
            "template_id": "apache-detect",
            "classification": {"cve-id": None},
        }
        assert _extract_nuclei_cves(f) == []

    def test_malformed_classification_not_a_dict(self):
        f = {"template_id": "CVE-2023-48795", "classification": "oops"}
        assert _extract_nuclei_cves(f) == ["CVE-2023-48795"]


class TestExtractNucleiCvss:
    def test_score_and_vector_present(self):
        f = {
            "classification": {
                "cvss-score": 5.9,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            }
        }
        score, vector = _extract_nuclei_cvss(f)
        assert score == 5.9
        assert vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_score_as_string(self):
        f = {"classification": {"cvss-score": "7.5"}}
        score, vector = _extract_nuclei_cvss(f)
        assert score == 7.5
        assert vector is None

    def test_missing_classification(self):
        assert _extract_nuclei_cvss({}) == (None, None)

    def test_classification_without_cvss(self):
        f = {"classification": {"cve-id": ["CVE-2023-48795"]}}
        assert _extract_nuclei_cvss(f) == (None, None)

    def test_unparseable_score_returns_none(self):
        f = {"classification": {"cvss-score": "n/a"}}
        score, vector = _extract_nuclei_cvss(f)
        assert score is None
        assert vector is None
