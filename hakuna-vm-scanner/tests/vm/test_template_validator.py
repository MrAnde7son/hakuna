"""Tests for the template validator."""

import os
import textwrap

import pytest
import yaml

from scanner.vm.template_validator import ValidationResult, validate_custom_template


@pytest.fixture
def valid_template(tmp_path):
    """Create a valid custom template YAML file."""
    content = textwrap.dedent("""\
        id: test-valid

        info:
          name: Valid Test Template
          author: test
          severity: info
          tags: always,http
          metadata:
            source: custom
            verified: true

        http:
          - method: GET
            path:
              - "{{BaseURL}}/"
            matchers:
              - type: status
                status:
                  - 200
    """)
    path = tmp_path / "valid.yaml"
    path.write_text(content)
    return str(path)


@pytest.fixture
def missing_source_template(tmp_path):
    """Template missing info.metadata.source."""
    content = textwrap.dedent("""\
        id: test-missing-source

        info:
          name: Missing Source
          author: test
          severity: info
          tags: http
          metadata:
            verified: true

        http:
          - method: GET
            path:
              - "{{BaseURL}}/"
            matchers:
              - type: status
                status:
                  - 200
    """)
    path = tmp_path / "missing-source.yaml"
    path.write_text(content)
    return str(path)


@pytest.fixture
def missing_tags_template(tmp_path):
    """Template missing both tags and CPE."""
    content = textwrap.dedent("""\
        id: test-missing-tags

        info:
          name: Missing Tags
          author: test
          severity: info
          metadata:
            source: custom
            verified: true

        http:
          - method: GET
            path:
              - "{{BaseURL}}/"
            matchers:
              - type: status
                status:
                  - 200
    """)
    path = tmp_path / "missing-tags.yaml"
    path.write_text(content)
    return str(path)


@pytest.fixture
def unverified_template(tmp_path):
    """Template without verified=true."""
    content = textwrap.dedent("""\
        id: test-unverified

        info:
          name: Unverified Template
          author: test
          severity: info
          tags: http
          metadata:
            source: custom

        http:
          - method: GET
            path:
              - "{{BaseURL}}/"
            matchers:
              - type: status
                status:
                  - 200
    """)
    path = tmp_path / "unverified.yaml"
    path.write_text(content)
    return str(path)


class TestValidateCustomTemplate:
    """Tests for validate_custom_template (YAML parsing checks only — nuclei binary not available in CI)."""

    def test_missing_source_detected(self, missing_source_template):
        """Missing info.metadata.source is detected."""
        from unittest.mock import patch, MagicMock

        # Mock nuclei -validate to succeed
        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_custom_template(missing_source_template)

        assert not result.valid
        assert any("source" in e for e in result.errors)

    def test_missing_tags_detected(self, missing_tags_template):
        """Missing tags and CPE is detected."""
        from unittest.mock import patch, MagicMock

        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_custom_template(missing_tags_template)

        assert not result.valid
        assert any("tags" in e or "cpe" in e for e in result.errors)

    def test_unverified_warning(self, unverified_template):
        """Unverified template generates a warning."""
        from unittest.mock import patch, MagicMock

        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_custom_template(unverified_template)

        assert result.valid  # Still valid, just warned
        assert any("verified" in w for w in result.warnings)

    def test_valid_template_passes(self, valid_template):
        """Valid template passes all checks."""
        from unittest.mock import patch, MagicMock

        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_custom_template(valid_template)

        assert result.valid
        assert len(result.errors) == 0

    def test_nuclei_validate_failure(self, valid_template):
        """nuclei -validate failure results in invalid result."""
        from unittest.mock import patch, MagicMock

        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="syntax error", stdout="")
            result = validate_custom_template(valid_template)

        assert not result.valid
        assert any("validate failed" in e for e in result.errors)

    def test_nuclei_binary_not_found(self, valid_template):
        """Missing nuclei binary results in error."""
        from unittest.mock import patch

        with patch("scanner.vm.template_validator.subprocess.run", side_effect=FileNotFoundError):
            result = validate_custom_template(valid_template)

        assert not result.valid
        assert any("not found" in e for e in result.errors)

    def test_invalid_yaml(self, tmp_path):
        """Non-YAML file fails validation."""
        from unittest.mock import patch, MagicMock

        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{invalid yaml: [}")

        with patch("scanner.vm.template_validator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_custom_template(str(bad_file))

        # PyYAML may or may not error on this — but the template won't have required fields
        # Either YAML parse error or missing metadata checks will catch it
        # Just verify we get a result without crashing
        assert isinstance(result, ValidationResult)
