"""Template Router — selects Nuclei templates based on asset fingerprint."""

import glob
import json
import logging
import os

from scanner.vm.config import TEMPLATES_DIR

logger = logging.getLogger(__name__)

_routing_table: dict | None = None

# Web-serving ports that cause DAST templates under custom/dast/ to be
# auto-included. Kept deliberately conservative — ports here should be
# the same ones gated by the "web" entry in routing_table.json port_gates,
# plus common dev/framework ports where web apps frequently listen.
_WEB_PORTS: frozenset[int] = frozenset({80, 443, 3000, 5000, 8000, 8001, 8080, 8443})


def _load_routing_table() -> dict:
    global _routing_table
    if _routing_table is not None:
        return _routing_table
    path = os.path.join(TEMPLATES_DIR, "routing_table.json")
    if not os.path.exists(path):
        logger.warning("Routing table not found at %s — using empty defaults", path)
        _routing_table = {"cpe_map": {}, "tech_map": {}, "port_map": {}, "port_gates": {}}
        return _routing_table
    with open(path) as f:
        _routing_table = json.load(f)
    return _routing_table


def reload_routing_table() -> None:
    """Force reload of routing table (after template sync)."""
    global _routing_table
    _routing_table = None


class TemplateRouter:
    """Selects Nuclei CLI args for an asset based on CPE, tech stack, and ports."""

    def get_routing_debug(
        self,
        cpe_list: list[str] | None,
        tech_stack: dict | None,
        open_ports: list[int],
    ) -> dict:
        """Return a human-readable explanation of how templates were selected.

        Returns a dict with:
          - cpe_tags: tags matched from CPE data
          - tech_tags: tags matched from tech stack
          - gated_tags: tags removed by port gating
          - final_tags: tags used in the nuclei command
          - fallback: whether the generic fallback was used
          - reason: one-line summary
        """
        rt = _load_routing_table()

        cpe_tags = self._route_from_cpe(cpe_list, rt)
        if cpe_tags:
            tech_tags: set[str] = set()
        else:
            tech_tags = self._route_from_tech(tech_stack, rt)

        port_tags = self._route_from_ports(open_ports, rt)

        pre_gate_tags = cpe_tags | tech_tags | port_tags
        final_tags = self._apply_port_gates(set(pre_gate_tags), open_ports, rt)
        gated_tags = pre_gate_tags - final_tags

        custom_paths = self._get_custom_templates(final_tags, open_ports)
        fallback = not final_tags and not custom_paths

        if fallback:
            if not cpe_list and not tech_stack and not port_tags:
                reason = "No CPE, tech stack, or mapped ports — fell back to generic,exposure tags"
            elif gated_tags:
                reason = f"All tags removed by port gating (missing ports) — fell back to generic,exposure. Gated: {', '.join(sorted(gated_tags))}"
            else:
                reason = "No matching CPE/tech/port entries in routing table — fell back to generic,exposure tags"
        elif gated_tags:
            reason = f"Tags selected: {', '.join(sorted(final_tags))} (gated out: {', '.join(sorted(gated_tags))})"
        else:
            reason = f"Tags selected: {', '.join(sorted(final_tags))}"

        return {
            "cpe_list": cpe_list or [],
            "tech_stack_keys": list(tech_stack.keys()) if isinstance(tech_stack, dict) else (tech_stack or []),
            "open_ports": list(open_ports or []),
            "cpe_tags": sorted(cpe_tags),
            "tech_tags": sorted(tech_tags),
            "port_tags": sorted(port_tags),
            "gated_tags": sorted(gated_tags),
            "final_tags": sorted(final_tags),
            "custom_templates": custom_paths,
            "fallback": fallback,
            "reason": reason,
        }

    def get_templates_for_asset(
        self,
        cpe_list: list[str] | None,
        tech_stack: dict | None,
        open_ports: list[int],
    ) -> list[str]:
        """Return Nuclei CLI args for template selection.

        Priority:
        1. CPE routing (preferred) — map CPE vendor/product to Nuclei tags
        2. Tech stack fallback — map tech names to Nuclei tags
        3. Port routing (always applied, additive) — map open ports to tags
           (e.g. 502 → modbus, 11434 → ollama). Required for OT/IoT/AI
           templates where CPE/tech fingerprinting often isn't available.
        4. Port gating — remove tags whose required ports aren't open
        5. Custom templates (always appended) — glob templates/custom/**/*.yaml

        Never returns empty — falls back to ["-tags", "generic,exposure"].
        """
        rt = _load_routing_table()
        tags: set[str] = set()

        # 1. CPE routing
        cpe_matched = self._route_from_cpe(cpe_list, rt)
        tags.update(cpe_matched)

        # 2. Tech stack fallback (when no CPE tags found)
        if not cpe_matched:
            tags.update(self._route_from_tech(tech_stack, rt))

        # 3. Port-based routing (additive — always applied)
        tags.update(self._route_from_ports(open_ports, rt))

        # 4. Port gating — remove tags whose required ports aren't open
        tags = self._apply_port_gates(tags, open_ports, rt)

        # 4. Custom templates
        custom_paths = self._get_custom_templates(tags, open_ports)

        # Build CLI args
        args: list[str] = []

        if tags:
            args.extend(["-tags", ",".join(sorted(tags))])

        for path in custom_paths:
            args.extend(["-t", path])

        # Fallback — never return empty
        if not args:
            args = ["-tags", "generic,exposure"]

        return args

    def _route_from_cpe(self, cpe_list: list[str] | None, rt: dict) -> set[str]:
        """Map CPE strings to Nuclei tags via routing table cpe_map."""
        if not cpe_list:
            return set()

        tags: set[str] = set()
        cpe_map = rt.get("cpe_map", {})

        for cpe in cpe_list:
            # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
            # CPE 2.2 format: cpe:/a:vendor:product:version
            parts = cpe.split(":")
            vendor_product = None
            if len(parts) >= 5 and parts[1] == "2.3":
                # cpe:2.3:a:vendor:product
                vendor_product = f"{parts[3]}:{parts[4]}"
            elif len(parts) >= 4 and parts[1].startswith("/"):
                # cpe:/a:vendor:product
                vendor_product = f"{parts[2]}:{parts[3]}"

            if vendor_product and vendor_product in cpe_map:
                tags.update(cpe_map[vendor_product])

        return tags

    def _route_from_tech(self, tech_stack: dict | None, rt: dict) -> set[str]:
        """Map tech stack keys/values to Nuclei tags via routing table tech_map."""
        if not tech_stack:
            return set()

        tags: set[str] = set()
        tech_map = rt.get("tech_map", {})

        # tech_stack may be a dict like {"Apache": "2.4.51"} or a list
        tech_names: list[str] = []
        if isinstance(tech_stack, dict):
            tech_names = list(tech_stack.keys())
        elif isinstance(tech_stack, list):
            tech_names = [str(t) for t in tech_stack]

        for name in tech_names:
            key = name.strip().lower()
            if key in tech_map:
                tags.update(tech_map[key])

        return tags

    def _route_from_ports(self, open_ports: list[int], rt: dict) -> set[str]:
        """Map open ports to Nuclei tags via routing table port_map.

        Unlike port_gates (which filters), port_map adds tags. This is how
        port-only protocols (Modbus 502, OPC-UA 4840, Ollama 11434, etc.)
        route to their templates when CPE/tech fingerprinting is absent.
        """
        if not open_ports:
            return set()
        tags: set[str] = set()
        port_map = rt.get("port_map", {})
        for port in open_ports:
            for key in (str(port), port):
                if key in port_map:
                    tags.update(port_map[key])
                    break
        return tags

    def _apply_port_gates(self, tags: set[str], open_ports: list[int], rt: dict) -> set[str]:
        """Remove gated tags if the asset doesn't have the required ports open."""
        port_gates = rt.get("port_gates", {})
        ports_set = set(open_ports or [])

        for gate_name, gate in port_gates.items():
            gate_ports = set(gate.get("ports", []))
            gate_tags = set(gate.get("tags", []))

            # If none of the gate's ports are open, exclude those tags
            if not ports_set.intersection(gate_ports):
                tags -= gate_tags

        return tags

    def _get_custom_templates(
        self,
        derived_tags: set[str],
        open_ports: list[int] | None = None,
    ) -> list[str]:
        """Glob custom templates. Include a template when any of:

        - it carries the ``always`` tag,
        - its tags intersect ``derived_tags``, or
        - it lives under ``custom/dast/`` and the asset has a web-serving
          port open.

        The ``dast/`` carve-out exists because third-party DAST templates
        (e.g. the reewardius set synced by ``scheduler.dast_template_sync``)
        use tags like ``xss``, ``sqli``, ``ssrf`` that aren't derived from
        CPE/tech fingerprinting. Path-based inclusion gives them the same
        auto-apply semantics as ``always`` — scoped to web assets so we
        don't fire HTTP probes at non-HTTP targets — without modifying
        upstream templates (which would get overwritten on next sync).
        """
        custom_dir = os.path.join(TEMPLATES_DIR, "custom")
        if not os.path.isdir(custom_dir):
            return []

        dast_dir_prefix = os.path.join(custom_dir, "dast") + os.sep
        has_web_port = bool(set(open_ports or []) & _WEB_PORTS)

        paths: list[str] = []
        for yaml_path in sorted(glob.glob(os.path.join(custom_dir, "**", "*.yaml"), recursive=True)):
            # DAST path-based inclusion — bypass tag check when asset is web-facing.
            if yaml_path.startswith(dast_dir_prefix):
                if has_web_port:
                    paths.append(yaml_path)
                continue
            try:
                with open(yaml_path) as f:
                    content = f.read()
                # Quick tag extraction — avoid full YAML parse dependency
                template_tags = _extract_tags_from_yaml(content)
                if "always" in template_tags or template_tags.intersection(derived_tags):
                    paths.append(yaml_path)
            except Exception:
                logger.warning("Failed to read custom template: %s", yaml_path, exc_info=True)

        return paths


def _extract_tags_from_yaml(content: str) -> set[str]:
    """Extract tags from a Nuclei template YAML without a full YAML parser.

    Looks for a line like:  tags: foo,bar,baz
    """
    tags: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("tags:"):
            value = stripped[len("tags:"):].strip().strip('"').strip("'")
            tags.update(t.strip() for t in value.split(",") if t.strip())
            break
    return tags
