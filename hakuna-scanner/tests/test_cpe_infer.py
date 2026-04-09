"""Unit tests for the CPE inference layer.

The fixture table at the bottom enumerates every vendor:product key in
routing_table.json — see the contract test in test_cpe_router_contract.py
which enforces that this file covers all of them.
"""

import pytest

from app.ingest.cpe_infer import infer_cpes


def _has_cpe(cpes: list[str], vendor: str, product: str) -> bool:
    """True if the list contains a CPE for this vendor:product (any version)."""
    needle = f"cpe:2.3:a:{vendor}:{product}:"
    return any(c.startswith(needle) for c in cpes)


# ---------------------------------------------------------------------------
# Empty / null inputs
# ---------------------------------------------------------------------------


class TestEmptyInputs:
    def test_none_inputs(self):
        assert infer_cpes(None, None) == []

    def test_empty_dict(self):
        assert infer_cpes({}, None) == []

    def test_empty_dict_empty_tls(self):
        assert infer_cpes({}, {}) == []

    def test_unrelated_fields(self):
        assert infer_cpes({"status_code": 200, "title": "Hello"}, None) == []

    def test_unknown_tech(self):
        assert infer_cpes({"tech": ["SomeUnknownThing", "AlsoUnknown"]}, None) == []


# ---------------------------------------------------------------------------
# httpx tech tokens
# ---------------------------------------------------------------------------


class TestTechTokens:
    def test_simple_name_only_token(self):
        cpes = infer_cpes({"tech": ["Nginx"]}, None)
        assert _has_cpe(cpes, "nginx", "nginx")
        assert cpes == ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]

    def test_name_with_version_token(self):
        cpes = infer_cpes({"tech": ["Nginx:1.18.0"]}, None)
        assert cpes == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"]

    def test_case_insensitive(self):
        for tok in ("nginx", "NGINX", "NgInX"):
            assert _has_cpe(infer_cpes({"tech": [tok]}, None), "nginx", "nginx")

    def test_multi_word_alias(self):
        cpes = infer_cpes({"tech": ["Apache HTTPD"]}, None)
        assert _has_cpe(cpes, "apache", "http_server")

    def test_dedup_same_vendor_product(self):
        # Two tokens that map to the same vendor:product → one entry
        cpes = infer_cpes({"tech": ["Nginx", "nginx"]}, None)
        assert len(cpes) == 1

    def test_multi_tech_independent_products(self):
        cpes = infer_cpes({"tech": ["Nginx", "WordPress", "PHP"]}, None)
        assert _has_cpe(cpes, "nginx", "nginx")
        assert _has_cpe(cpes, "wordpress", "wordpress")
        assert _has_cpe(cpes, "php", "php")
        assert len(cpes) == 3

    def test_dict_form_tech(self):
        # Some httpx versions emit a dict
        cpes = infer_cpes({"technologies": {"Nginx": "1.18.0"}}, None)
        assert _has_cpe(cpes, "nginx", "nginx")

    def test_garbage_version_falls_back_to_star(self):
        # A non-numeric version string is unsafe — should be replaced with *
        cpes = infer_cpes({"tech": ["Nginx:not-a-real-version $"]}, None)
        assert cpes == ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]


# ---------------------------------------------------------------------------
# HTTP Server header
# ---------------------------------------------------------------------------


class TestServerHeader:
    def test_nginx_with_version(self):
        cpes = infer_cpes({"webserver": "nginx/1.18.0"}, None)
        assert cpes == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"]

    def test_nginx_with_distro_suffix(self):
        cpes = infer_cpes({"webserver": "nginx/1.18.0 (Ubuntu)"}, None)
        assert _has_cpe(cpes, "nginx", "nginx")

    def test_apache_with_version(self):
        cpes = infer_cpes({"webserver": "Apache/2.4.49 (Unix)"}, None)
        assert _has_cpe(cpes, "apache", "http_server")
        assert "2.4.49" in cpes[0]

    def test_apache_coyote_routes_to_tomcat(self):
        cpes = infer_cpes({"webserver": "Apache-Coyote/1.1"}, None)
        # Specific match must win over the generic 'apache' match
        assert _has_cpe(cpes, "apache", "tomcat")
        assert not _has_cpe(cpes, "apache", "http_server")

    def test_microsoft_iis(self):
        cpes = infer_cpes({"webserver": "Microsoft-IIS/10.0"}, None)
        assert _has_cpe(cpes, "microsoft", "iis")

    def test_alt_field_name(self):
        cpes = infer_cpes({"web_server": "nginx/1.18.0"}, None)
        assert _has_cpe(cpes, "nginx", "nginx")

    def test_no_match_returns_empty(self):
        cpes = infer_cpes({"webserver": "SomeWeirdServer/9.9"}, None)
        assert cpes == []


# ---------------------------------------------------------------------------
# Tech + header dedup
# ---------------------------------------------------------------------------


class TestDedup:
    def test_tech_and_header_same_product_dedups(self):
        # Both inputs say nginx — one CPE, version from whichever ran first
        cpes = infer_cpes(
            {"tech": ["Nginx"], "webserver": "nginx/1.18.0"}, None,
        )
        assert len(cpes) == 1
        assert _has_cpe(cpes, "nginx", "nginx")

    def test_dedup_keys_on_vendor_product_not_version(self):
        cpes = infer_cpes(
            {"tech": ["Nginx:1.18.0"], "webserver": "nginx/1.20.0"}, None,
        )
        # First-seen wins (tech tokens run first)
        assert len(cpes) == 1
        assert "1.18.0" in cpes[0]


# ---------------------------------------------------------------------------
# TLS subject
# ---------------------------------------------------------------------------


class TestTlsSubject:
    def test_jenkins_subject(self):
        cpes = infer_cpes(None, {"subject": "CN=Jenkins,O=Acme"})
        assert _has_cpe(cpes, "jenkins", "jenkins")

    def test_subject_dn_alt_field(self):
        cpes = infer_cpes(None, {"subject_dn": "CN=Jenkins"})
        assert _has_cpe(cpes, "jenkins", "jenkins")

    def test_unrelated_subject(self):
        cpes = infer_cpes(None, {"subject": "CN=example.com"})
        assert cpes == []

    def test_tls_supplements_httpx(self):
        # httpx detected something else, TLS adds another product
        cpes = infer_cpes(
            {"tech": ["Nginx"]},
            {"subject": "CN=Jenkins"},
        )
        assert _has_cpe(cpes, "nginx", "nginx")
        assert _has_cpe(cpes, "jenkins", "jenkins")


# ---------------------------------------------------------------------------
# Coverage matrix — every routing_table.json cpe_map key reachable.
#
# This is a flat fixture table. The contract test in
# test_cpe_router_contract.py reads routing_table.json and asserts every key
# in its cpe_map is matched by at least one row here.
# ---------------------------------------------------------------------------


COVERAGE_FIXTURES = [
    # (vendor, product, httpx_entry, tls_cert)
    ("apache", "http_server",      {"tech": ["Apache"]},                None),
    ("apache", "http_server",      {"webserver": "Apache/2.4.49"},      None),
    ("apache", "tomcat",           {"tech": ["Apache Tomcat"]},         None),
    ("apache", "tomcat",           {"webserver": "Apache-Coyote/1.1"},  None),
    ("nginx", "nginx",             {"tech": ["Nginx"]},                 None),
    ("nginx", "nginx",             {"webserver": "nginx/1.18.0"},       None),
    ("wordpress", "wordpress",     {"tech": ["WordPress"]},             None),
    ("microsoft", "iis",           {"tech": ["IIS"]},                   None),
    ("microsoft", "iis",           {"webserver": "Microsoft-IIS/10.0"}, None),
    ("microsoft", "exchange",      {"tech": ["Outlook Web App"]},       None),
    ("openssh", "openssh",         {"tech": ["OpenSSH"]},               None),
    ("openssl", "openssl",         {"tech": ["OpenSSL"]},               None),
    ("php", "php",                 {"tech": ["PHP"]},                   None),
    ("oracle", "mysql",            {"tech": ["MySQL"]},                 None),
    ("postgresql", "postgresql",   {"tech": ["PostgreSQL"]},            None),
    ("redis", "redis",             {"tech": ["Redis"]},                 None),
    ("mongodb", "mongodb",         {"tech": ["MongoDB"]},               None),
    ("elastic", "elasticsearch",   {"tech": ["Elasticsearch"]},         None),
    ("jenkins", "jenkins",         {"tech": ["Jenkins"]},               None),
    ("jenkins", "jenkins",         None,                                {"subject": "CN=Jenkins"}),
    ("grafana", "grafana",         {"tech": ["Grafana"]},               None),
    ("docker", "docker",           {"tech": ["Docker"]},                None),
    ("hashicorp", "consul",        {"tech": ["Consul"]},                None),
    ("hashicorp", "vault",         {"tech": ["Vault"]},                 None),
]


@pytest.mark.parametrize("vendor,product,httpx_entry,tls_cert", COVERAGE_FIXTURES)
def test_coverage_fixture(vendor, product, httpx_entry, tls_cert):
    cpes = infer_cpes(httpx_entry, tls_cert)
    assert _has_cpe(cpes, vendor, product), (
        f"Expected CPE for {vendor}:{product}, got {cpes!r} from "
        f"httpx={httpx_entry!r} tls={tls_cert!r}"
    )
