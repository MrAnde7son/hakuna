"""Tests for the Template Router."""

import json
import os
from unittest.mock import patch

import pytest

from scanner.vm.router import TemplateRouter, _extract_tags_from_yaml, reload_routing_table


@pytest.fixture(autouse=True)
def reset_routing_table():
    """Reset cached routing table before each test."""
    reload_routing_table()
    yield
    reload_routing_table()


class TestTemplateRouter:
    """Tests for TemplateRouter.get_templates_for_asset."""

    def test_cpe_routing_apache(self, templates_dir):
        """CPE for Apache httpd maps to apache + http tags."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                tech_stack=None,
                open_ports=[80, 443],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "apache" in tags
            assert "http" in tags

    def test_cpe_routing_cpe22_format(self, templates_dir):
        """CPE 2.2 format is also parsed correctly."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:/a:nginx:nginx:1.21"],
                tech_stack=None,
                open_ports=[80],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "nginx" in tags

    def test_tech_stack_fallback(self, templates_dir):
        """When no CPE, tech_stack is used for routing."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack={"nginx": "1.21", "node.js": "16"},
                open_ports=[80, 443],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "nginx" in tags
            assert "nodejs" in tags

    def test_tech_stack_as_list(self, templates_dir):
        """tech_stack as a list of strings."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack=["Apache", "WordPress"],
                open_ports=[80],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "apache" in tags
            assert "wordpress" in tags

    def test_port_gating_removes_web_tags(self, templates_dir):
        """Without web ports, http/ssl tags are removed."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                tech_stack=None,
                open_ports=[22, 3306],  # No web ports
            )
            # http tag should be removed by port gating
            if "-tags" in args:
                tag_str = args[args.index("-tags") + 1]
                tags = set(tag_str.split(","))
                assert "http" not in tags
                assert "ssl" not in tags

    def test_port_gating_removes_smb_tags(self, templates_dir):
        """Without port 445, smb tags are removed."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            # Manually add smb to derived tags by testing gate removal
            tags_before = {"smb", "apache"}
            rt = json.loads((templates_dir / "routing_table.json").read_text())
            result = router._apply_port_gates(tags_before, [80, 443], rt)
            assert "smb" not in result
            assert "apache" in result

    def test_port_gating_removes_db_tags(self, templates_dir):
        """Without DB ports, db tags are removed."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            tags_before = {"db", "http"}
            rt = json.loads((templates_dir / "routing_table.json").read_text())
            result = router._apply_port_gates(tags_before, [80, 443], rt)
            assert "db" not in result
            assert "http" in result

    def test_fallback_to_generic(self, templates_dir):
        """No CPE, no tech_stack, no ports → fallback to generic,exposure."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack=None,
                open_ports=[],
            )
            assert args == ["-tags", "generic,exposure"]

    def test_custom_templates_always_tag(self, templates_dir, sample_custom_template):
        """Custom templates tagged 'always' are always included."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack={"nginx": "1.0"},
                open_ports=[80],
            )
            # Should include the custom template path via -t
            assert "-t" in args
            t_index = args.index("-t")
            assert "test-custom.yaml" in args[t_index + 1]

    def test_custom_templates_matching_tags(self, templates_dir):
        """Custom templates matching derived tags are included."""
        # Create a custom template with apache tag (not 'always')
        apache_template = """\
id: apache-specific

info:
  name: Apache Specific Check
  author: test
  severity: low
  tags: apache
  metadata:
    source: custom
    verified: true

http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers:
      - type: status
        status:
          - 200
"""
        (templates_dir / "custom" / "apache-check.yaml").write_text(apache_template)

        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                tech_stack=None,
                open_ports=[80],
            )
            # Should include the apache-check template
            t_indices = [i for i, a in enumerate(args) if a == "-t"]
            custom_paths = [args[i + 1] for i in t_indices]
            assert any("apache-check.yaml" in p for p in custom_paths)

    def test_never_returns_empty(self, templates_dir):
        """get_templates_for_asset never returns an empty list."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(None, None, [])
            assert len(args) > 0

    def test_port_routing_modbus(self, templates_dir):
        """Open port 502 routes to modbus/ot tags even without CPE/tech."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack=None,
                open_ports=[502],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "modbus" in tags
            assert "ot" in tags

    def test_port_routing_ollama(self, templates_dir):
        """Open port 11434 routes to ollama/llm/ai tags."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=None,
                tech_stack=None,
                open_ports=[11434],
            )
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "ollama" in tags
            assert "ai" in tags

    def test_port_routing_additive_with_cpe(self, templates_dir):
        """Port-derived tags are added on top of CPE tags."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
                tech_stack=None,
                open_ports=[80, 502],
            )
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "apache" in tags  # from CPE
            assert "http" in tags    # from CPE
            assert "modbus" in tags  # from port_map

    def test_port_routing_debug_includes_port_tags(self, templates_dir):
        """get_routing_debug reports port_tags separately."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            info = router.get_routing_debug(
                cpe_list=None,
                tech_stack=None,
                open_ports=[6333],
            )
            assert "qdrant" in info["port_tags"]
            assert "qdrant" in info["final_tags"]

    def test_cpe_routing_takes_priority_over_tech(self, templates_dir):
        """When CPE matches, tech_stack is NOT used (CPE preferred)."""
        with patch("scanner.vm.router.TEMPLATES_DIR", str(templates_dir)):
            router = TemplateRouter()
            args = router.get_templates_for_asset(
                cpe_list=["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"],
                tech_stack={"wordpress": "5.0"},  # Should be ignored
                open_ports=[80],
            )
            assert "-tags" in args
            tag_str = args[args.index("-tags") + 1]
            tags = set(tag_str.split(","))
            assert "apache" in tags
            # wordpress should NOT be in tags since CPE matched
            assert "wordpress" not in tags


class TestExtractTagsFromYaml:
    """Tests for _extract_tags_from_yaml helper."""

    def test_simple_tags(self):
        content = "id: test\ninfo:\n  tags: foo,bar,baz\n"
        assert _extract_tags_from_yaml(content) == {"foo", "bar", "baz"}

    def test_quoted_tags(self):
        content = 'id: test\ninfo:\n  tags: "foo,bar"\n'
        assert _extract_tags_from_yaml(content) == {"foo", "bar"}

    def test_no_tags(self):
        content = "id: test\ninfo:\n  name: test\n"
        assert _extract_tags_from_yaml(content) == set()

    def test_always_tag(self):
        content = "id: test\ninfo:\n  tags: always,http\n"
        result = _extract_tags_from_yaml(content)
        assert "always" in result
        assert "http" in result
