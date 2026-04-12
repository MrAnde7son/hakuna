"""Unit tests for the CPE inference layer.

The fixture table at the bottom enumerates every vendor:product key in
routing_table.json — see the contract test in test_cpe_router_contract.py
which enforces that this file covers all of them.
"""

import pytest

from app.ingest.cpe_infer import CpeInferResult, infer_cpes


def _has_cpe(cpes: list[str], vendor: str, product: str) -> bool:
    """True if the list contains a CPE for this vendor:product (any version)."""
    needle = f"cpe:2.3:a:{vendor}:{product}:"
    return any(c.startswith(needle) for c in cpes)


# ---------------------------------------------------------------------------
# Empty / null inputs
# ---------------------------------------------------------------------------


class TestEmptyInputs:
    def test_none_inputs(self):
        result = infer_cpes(None, None)
        assert isinstance(result, CpeInferResult)
        assert result.cpe_list == []
        assert result.detected_technologies == []

    def test_empty_dict(self):
        result = infer_cpes({}, None)
        assert result.cpe_list == []

    def test_empty_dict_empty_tls(self):
        result = infer_cpes({}, {})
        assert result.cpe_list == []

    def test_unrelated_fields(self):
        result = infer_cpes({"status_code": 200, "title": "Hello"}, None)
        assert result.cpe_list == []

    def test_unknown_versionless_tech_goes_to_detected_only(self):
        # Open-ended tokens without a version are too speculative for CVE
        # matching — they go to detected_technologies only.
        result = infer_cpes({"tech": ["SomeUnknownThing", "AlsoUnknown"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "someunknownthing", "someunknownthing")
        assert _has_cpe(result.detected_technologies, "alsounknown", "alsounknown")

    def test_unknown_versioned_tech_emits_cpe(self):
        # Open-ended tokens WITH a version still get a CPE — the matcher
        # in the backend does its own NVD lookup.
        result = infer_cpes({"tech": ["SomeUnknownThing:1.2.3"]}, None)
        assert _has_cpe(result.cpe_list, "someunknownthing", "someunknownthing")
        assert "1.2.3" in result.cpe_list[0]
        # Also appears in detected_technologies.
        assert _has_cpe(result.detected_technologies, "someunknownthing", "someunknownthing")

    def test_denylisted_token_dropped(self):
        # Generic deployment labels are deny-listed — too noisy to correlate.
        result = infer_cpes({"tech": ["Server", "Unknown"]}, None)
        assert result.cpe_list == []
        assert result.detected_technologies == []


# ---------------------------------------------------------------------------
# httpx tech tokens
# ---------------------------------------------------------------------------


class TestTechTokens:
    def test_simple_name_only_token(self):
        # "Nginx" without version — this is an aliased token (known product),
        # so it still gets a CPE even without a version.
        result = infer_cpes({"tech": ["Nginx"]}, None)
        assert _has_cpe(result.cpe_list, "nginx", "nginx")
        assert result.cpe_list == ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]

    def test_name_with_version_token(self):
        result = infer_cpes({"tech": ["Nginx:1.18.0"]}, None)
        assert result.cpe_list == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"]

    def test_case_insensitive(self):
        for tok in ("nginx", "NGINX", "NgInX"):
            result = infer_cpes({"tech": [tok]}, None)
            assert _has_cpe(result.cpe_list, "nginx", "nginx")

    def test_multi_word_alias(self):
        result = infer_cpes({"tech": ["Apache HTTPD"]}, None)
        assert _has_cpe(result.cpe_list, "apache", "http_server")

    def test_dedup_same_vendor_product(self):
        # Two tokens that map to the same vendor:product → one entry
        result = infer_cpes({"tech": ["Nginx", "nginx"]}, None)
        assert len(result.cpe_list) == 1

    def test_multi_tech_independent_products(self):
        result = infer_cpes({"tech": ["Nginx", "WordPress", "PHP"]}, None)
        assert _has_cpe(result.cpe_list, "nginx", "nginx")
        assert _has_cpe(result.cpe_list, "wordpress", "wordpress")
        assert _has_cpe(result.cpe_list, "php", "php")
        assert len(result.cpe_list) == 3

    def test_dict_form_tech(self):
        # Some httpx versions emit a dict
        result = infer_cpes({"technologies": {"Nginx": "1.18.0"}}, None)
        assert _has_cpe(result.cpe_list, "nginx", "nginx")

    def test_garbage_version_falls_back_to_star(self):
        # A non-numeric version string is unsafe — should be replaced with *
        result = infer_cpes({"tech": ["Nginx:not-a-real-version $"]}, None)
        assert result.cpe_list == ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]


# ---------------------------------------------------------------------------
# HTTP Server header
# ---------------------------------------------------------------------------


class TestServerHeader:
    def test_nginx_with_version(self):
        result = infer_cpes({"webserver": "nginx/1.18.0"}, None)
        assert result.cpe_list == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"]

    def test_nginx_with_distro_suffix(self):
        result = infer_cpes({"webserver": "nginx/1.18.0 (Ubuntu)"}, None)
        assert _has_cpe(result.cpe_list, "nginx", "nginx")

    def test_apache_with_version(self):
        result = infer_cpes({"webserver": "Apache/2.4.49 (Unix)"}, None)
        assert _has_cpe(result.cpe_list, "apache", "http_server")
        assert "2.4.49" in result.cpe_list[0]

    def test_apache_coyote_routes_to_tomcat(self):
        result = infer_cpes({"webserver": "Apache-Coyote/1.1"}, None)
        # Specific match must win over the generic 'apache' match
        assert _has_cpe(result.cpe_list, "apache", "tomcat")
        assert not _has_cpe(result.cpe_list, "apache", "http_server")

    def test_microsoft_iis(self):
        result = infer_cpes({"webserver": "Microsoft-IIS/10.0"}, None)
        assert _has_cpe(result.cpe_list, "microsoft", "iis")

    def test_alt_field_name(self):
        result = infer_cpes({"web_server": "nginx/1.18.0"}, None)
        assert _has_cpe(result.cpe_list, "nginx", "nginx")

    def test_unknown_server_with_version_emits_cpe(self):
        # The motivating case: Yaws (and every other obscure web server) is
        # not in the alias table, but the matcher should still get a chance
        # to correlate it against NVD — as long as it has a version.
        result = infer_cpes({"webserver": "Yaws 2.0.6"}, None)
        assert result.cpe_list == ["cpe:2.3:a:yaws:yaws:2.0.6:*:*:*:*:*:*:*"]

    def test_unknown_server_no_version_goes_to_detected_only(self):
        # Versionless unknown server → detected_technologies only.
        result = infer_cpes({"webserver": "SomeWeirdServer"}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "someweirdserver", "someweirdserver")

    def test_unknown_server_with_slash_version(self):
        result = infer_cpes({"webserver": "Caddy/2.7.5"}, None)
        assert result.cpe_list == ["cpe:2.3:a:caddyserver:caddy:2.7.5:*:*:*:*:*:*:*"]


# ---------------------------------------------------------------------------
# Tech + header dedup
# ---------------------------------------------------------------------------


class TestDedup:
    def test_tech_and_header_same_product_dedups(self):
        # Both inputs say nginx — one CPE, version from whichever ran first
        result = infer_cpes(
            {"tech": ["Nginx"], "webserver": "nginx/1.18.0"}, None,
        )
        assert len(result.cpe_list) == 1
        assert _has_cpe(result.cpe_list, "nginx", "nginx")

    def test_dedup_keys_on_vendor_product_not_version(self):
        result = infer_cpes(
            {"tech": ["Nginx:1.18.0"], "webserver": "nginx/1.20.0"}, None,
        )
        # First-seen wins (tech tokens run first)
        assert len(result.cpe_list) == 1
        assert "1.18.0" in result.cpe_list[0]


# ---------------------------------------------------------------------------
# TLS subject
# ---------------------------------------------------------------------------


class TestTlsSubject:
    def test_jenkins_subject(self):
        result = infer_cpes(None, {"subject": "CN=Jenkins,O=Acme"})
        assert _has_cpe(result.cpe_list, "jenkins", "jenkins")

    def test_subject_dn_alt_field(self):
        result = infer_cpes(None, {"subject_dn": "CN=Jenkins"})
        assert _has_cpe(result.cpe_list, "jenkins", "jenkins")

    def test_unrelated_subject(self):
        result = infer_cpes(None, {"subject": "CN=example.com"})
        assert result.cpe_list == []

    def test_tls_supplements_httpx(self):
        # httpx detected something else, TLS adds another product
        result = infer_cpes(
            {"tech": ["Nginx"]},
            {"subject": "CN=Jenkins"},
        )
        assert _has_cpe(result.cpe_list, "nginx", "nginx")
        assert _has_cpe(result.cpe_list, "jenkins", "jenkins")


# ---------------------------------------------------------------------------
# Non-software filtering (skip_cpe)
# ---------------------------------------------------------------------------


class TestNonSoftwareFiltering:
    def test_cloudflare_excluded_from_cpe_list(self):
        result = infer_cpes({"tech": ["Cloudflare"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "cloudflare", "cloudflare")

    def test_hsts_excluded_from_cpe_list(self):
        result = infer_cpes({"tech": ["HSTS"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "hsts", "hsts")

    def test_recaptcha_excluded_from_cpe_list(self):
        result = infer_cpes({"tech": ["reCAPTCHA"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "google", "recaptcha")

    def test_google_analytics_excluded(self):
        result = infer_cpes({"tech": ["Google Analytics"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "google", "analytics")

    def test_google_tag_manager_excluded(self):
        result = infer_cpes({"tech": ["Google Tag Manager"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "google", "tag_manager")

    def test_akamai_excluded(self):
        result = infer_cpes({"tech": ["Akamai"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "akamai", "akamai")

    def test_mixed_software_and_non_software(self):
        # Real libraries should be in cpe_list; CDNs/analytics in detected_technologies only.
        result = infer_cpes(
            {"tech": ["jQuery:3.1.1", "Cloudflare", "HSTS", "Moment.js:2.29.1"]},
            None,
        )
        # cpe_list: only real software
        assert _has_cpe(result.cpe_list, "jquery", "jquery")
        assert _has_cpe(result.detected_technologies, "jquery", "jquery")
        assert _has_cpe(result.cpe_list, "momentjs", "moment")
        assert not _has_cpe(result.cpe_list, "cloudflare", "cloudflare")
        assert not _has_cpe(result.cpe_list, "hsts", "hsts")
        # detected_technologies: everything
        assert _has_cpe(result.detected_technologies, "cloudflare", "cloudflare")
        assert _has_cpe(result.detected_technologies, "hsts", "hsts")
        assert _has_cpe(result.detected_technologies, "momentjs", "moment")

    def test_versionless_unknown_not_in_cpe_list(self):
        # A versionless token not in the alias table (open-ended path)
        # goes to detected_technologies only.
        result = infer_cpes({"tech": ["Microsoft"]}, None)
        assert result.cpe_list == []
        assert _has_cpe(result.detected_technologies, "microsoft", "microsoft")

    def test_detected_technologies_is_superset_of_cpe_list(self):
        result = infer_cpes(
            {"tech": ["Nginx:1.18.0", "jQuery:3.6.0", "Cloudflare"]}, None,
        )
        # Everything in cpe_list must also be in detected_technologies
        for cpe in result.cpe_list:
            assert cpe in result.detected_technologies


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
    ("openssh", "openssh",          {"tech": ["OpenSSH"]},               None),
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
    result = infer_cpes(httpx_entry, tls_cert)
    assert _has_cpe(result.cpe_list, vendor, product), (
        f"Expected CPE for {vendor}:{product}, got {result.cpe_list!r} from "
        f"httpx={httpx_entry!r} tls={tls_cert!r}"
    )
