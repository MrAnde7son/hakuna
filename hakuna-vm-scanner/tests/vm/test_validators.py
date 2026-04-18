"""Tests for secret-validation template generation."""

from scanner.vm.code_repo.validators import build_validation, has_recipe


class TestBuildValidation:
    def test_slack_recipe_returns_template(self):
        v = build_validation("Slack", "xox***")
        assert v is not None
        assert "auth.test" in v["template_yaml"]
        assert "{{secret}}" in v["template_yaml"]
        assert v["placeholder"] == "{{secret}}"
        # Template must carry the hakuna-validation tag so operators can filter
        assert "hakuna" in v["template_yaml"]

    def test_github_recipe(self):
        v = build_validation("GitHub", "ghp_***")
        assert v is not None
        assert "api.github.com/user" in v["template_yaml"]

    def test_unknown_detector_returns_none(self):
        assert build_validation("UnknownXYZ", "x") is None

    def test_raw_secret_never_in_output(self):
        """The raw secret must never appear — only the {{secret}} placeholder."""
        v = build_validation("Slack", "xoxb-real-looking-token-12345")
        assert "xoxb-real-looking-token-12345" not in v["template_yaml"]
        assert "xoxb-real-looking-token-12345" not in v["nuclei_cli"]

    def test_has_recipe_known(self):
        assert has_recipe("Slack")
        assert has_recipe("GitHub")

    def test_has_recipe_unknown(self):
        assert not has_recipe("MyCustomDetector")
