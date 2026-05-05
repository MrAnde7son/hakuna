"""Tests for the deterministic response-signature extractor.

Covers each signal class in isolation against representative real-world
response shapes:

  - FRAMEWORK from cookies, headers, body chrome
  - WEB_ROOT from stack traces in five language families
  - PARAM_REFLECTION across raw / html / json / header encodings
  - VALIDATION_RULE for FastAPI/DRF/Rails error shapes
  - ROUTE_TEMPLATE emission per probed path

Goal: pin down extractor invariants so future framework additions
can't silently regress detection on existing stacks. The extractor is
load-bearing — if it stops detecting Django, every Django-target scan
loses validation-rule capture and the prompt loses guidance.
"""

from __future__ import annotations

from scanner.vm.capabilities import CapabilityStore, CapabilityType
from scanner.vm.response_signals import commit_signals, extract_signals


def _resp(**overrides) -> dict:
    base = {
        "url": "https://example.com/api/users",
        "method": "GET",
        "status_code": 200,
        "elapsed_ms": 12,
        "headers": {},
        "body": "",
        "body_length": 0,
    }
    base.update(overrides)
    return base


def _types(caps) -> list[str]:
    return [c.type for c in caps]


class TestRouteTemplate:
    def test_every_real_response_emits_route(self):
        """Even a vanilla 200 with empty body must emit ROUTE_TEMPLATE
        — that's the structural primitive everything else builds on."""
        caps = extract_signals(
            method="GET", url="https://x.example.com/api/users",
            request_body=None, response=_resp(status_code=200),
            asset_id="a-1",
        )
        routes = [c for c in caps if c.type == CapabilityType.ROUTE_TEMPLATE]
        assert len(routes) == 1
        assert routes[0].value["path"] == "/api/users"
        assert routes[0].value["method"] == "GET"
        assert routes[0].value["status"] == 200

    def test_no_route_when_no_status(self):
        """Connection errors give us status=None — those don't tell us
        the route exists, so the row would be misleading."""
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(status_code=None),
            asset_id="a-1",
        )
        assert all(c.type != CapabilityType.ROUTE_TEMPLATE for c in caps)

    def test_query_string_collapsed_into_path(self):
        """Re-probes with different query strings should produce ONE
        route row (after dedup) — the path is the routing fact, not
        the query."""
        store = CapabilityStore()
        for v in ("1", "2", "3"):
            commit_signals(store, extract_signals(
                method="GET", url=f"https://x/api/users?id={v}",
                request_body=None, response=_resp(status_code=200),
                asset_id="a-1",
            ))
        routes = store.query(type=CapabilityType.ROUTE_TEMPLATE)
        assert len(routes) == 1
        assert routes[0].value["path"] == "/api/users"


class TestFrameworkFromCookies:
    def test_php_session_cookie(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"set-cookie": "PHPSESSID=abc; Path=/"}),
            asset_id="a-1",
        )
        fw = [c for c in caps if c.type == CapabilityType.FRAMEWORK]
        assert any(c.value["name"] == "php" for c in fw)
        # Cookie evidence is the highest-confidence signal we surface.
        assert all(c.confidence >= 0.85 for c in fw)

    def test_django_dual_cookie(self):
        """Django sets both csrftoken and sessionid; we shouldn't
        emit "django" twice."""
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={
                "set-cookie": "csrftoken=abc; Path=/, sessionid=xyz; Path=/"
            }),
            asset_id="a-1",
        )
        fw = [c for c in caps if c.type == CapabilityType.FRAMEWORK
              and c.value["name"] == "django"]
        assert len(fw) == 1

    def test_express_connect_sid(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"set-cookie": "connect.sid=abc"}),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "express" in names

    def test_rails_session_cookie(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"set-cookie": "_session_id=abc"}),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "rails" in names


class TestFrameworkFromHeaders:
    def test_x_powered_by_php(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"x-powered-by": "PHP/8.1.0"}),
            asset_id="a-1",
        )
        php = [c for c in caps if c.type == CapabilityType.FRAMEWORK
               and c.value["name"] == "php"]
        assert php
        assert php[0].value.get("version") == "8.1.0"

    def test_x_powered_by_express(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"x-powered-by": "Express"}),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "express" in names

    def test_server_uvicorn(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(headers={"server": "uvicorn"}),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "asgi" in names


class TestFrameworkFromBody:
    def test_django_debug_page(self):
        body = "You are seeing this error because you have DEBUG = True"
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(status_code=500, body=body),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "django" in names

    def test_laravel_whoops(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(status_code=500,
                           body="Whoops, looks like something went wrong."),
            asset_id="a-1",
        )
        names = {c.value["name"] for c in caps if c.type == CapabilityType.FRAMEWORK}
        assert "laravel" in names

    def test_no_false_positive_on_neutral_body(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(body="<html><body>hello</body></html>"),
            asset_id="a-1",
        )
        assert all(c.type != CapabilityType.FRAMEWORK for c in caps)


class TestWebRootExtraction:
    def test_php_stack_trace(self):
        body = (
            "<b>Fatal error</b>: Uncaught Exception in "
            "/var/www/html/app/Controller.php:42\n"
        )
        caps = extract_signals(
            method="GET", url="https://x/api", request_body=None,
            response=_resp(status_code=500, body=body),
            asset_id="a-1",
        )
        wr = [c for c in caps if c.type == CapabilityType.WEB_ROOT]
        assert wr
        assert wr[0].value["path"] == "/var/www/html/app"
        assert wr[0].value.get("language") == "php"

    def test_python_stack_trace(self):
        body = (
            'Traceback (most recent call last):\n'
            '  File "/srv/app/views.py", line 42, in get_user\n'
            '    raise ValueError("nope")\n'
        )
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(status_code=500, body=body),
            asset_id="a-1",
        )
        wr = [c for c in caps if c.type == CapabilityType.WEB_ROOT]
        assert wr and wr[0].value["path"] == "/srv/app"

    def test_ruby_stack_trace(self):
        body = "from /home/deploy/app/controllers/users_controller.rb:25:in `index'"
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(status_code=500, body=body),
            asset_id="a-1",
        )
        wr = [c for c in caps if c.type == CapabilityType.WEB_ROOT]
        assert wr and "/home/deploy/app/controllers" == wr[0].value["path"]

    def test_no_extraction_without_stack_trace(self):
        caps = extract_signals(
            method="GET", url="https://x/", request_body=None,
            response=_resp(body="ok"),
            asset_id="a-1",
        )
        assert all(c.type != CapabilityType.WEB_ROOT for c in caps)


class TestParamReflection:
    def test_raw_reflection_in_body(self):
        """Sent ?q=hakuna-test, response echoes it raw — the high-signal
        case that XSS / injection specialists need to know about."""
        caps = extract_signals(
            method="GET", url="https://x/search?q=hakuna-test",
            request_body=None,
            response=_resp(body="<p>You searched for: hakuna-test</p>"),
            asset_id="a-1",
        )
        refl = [c for c in caps if c.type == CapabilityType.PARAM_REFLECTION]
        assert len(refl) == 1
        assert refl[0].value["param"] == "q"
        assert refl[0].value["encoding"] == "raw"

    def test_html_encoded_reflection(self):
        """Filter present but param IS reflected — useful for filter-
        bypass exploration. Detected by the encoded form appearing
        when the raw form does not."""
        caps = extract_signals(
            method="GET", url="https://x/search?q=%3Cscript%3E",
            request_body=None,
            response=_resp(body="searched: &lt;script&gt;"),
            asset_id="a-1",
        )
        refl = [c for c in caps if c.type == CapabilityType.PARAM_REFLECTION]
        assert refl and refl[0].value["encoding"] == "html"

    def test_json_body_reflection(self):
        caps = extract_signals(
            method="POST", url="https://x/users",
            request_body={"name": "hakuna-marker-XYZ"},
            response=_resp(body='{"created":{"name":"hakuna-marker-XYZ"}}'),
            asset_id="a-1",
        )
        refl = [c for c in caps if c.type == CapabilityType.PARAM_REFLECTION]
        # Detected as raw because the literal value substring appears.
        assert refl and refl[0].value["param"] == "name"

    def test_header_reflection(self):
        """A header value can leak param input — open redirect on
        Location, X-Echo headers, etc."""
        caps = extract_signals(
            method="GET", url="https://x/r?next=hakuna-redirect-test",
            request_body=None,
            response=_resp(
                status_code=302,
                headers={"location": "https://attacker.example/?from=hakuna-redirect-test"},
            ),
            asset_id="a-1",
        )
        refl = [c for c in caps if c.type == CapabilityType.PARAM_REFLECTION]
        assert refl and refl[0].value["location"] == "header"

    def test_short_values_skipped(self):
        """id=1 reflects everywhere — would dominate the cap store and
        carry zero signal. Threshold 3 chars discards it."""
        caps = extract_signals(
            method="GET", url="https://x/?id=1",
            request_body=None, response=_resp(body="page id 1"),
            asset_id="a-1",
        )
        assert all(c.type != CapabilityType.PARAM_REFLECTION for c in caps)


class TestValidationRule:
    def test_fastapi_pydantic_shape(self):
        body = (
            '{"detail":[{"loc":["body","email"],'
            '"msg":"value is not a valid email address",'
            '"type":"value_error.email"}]}'
        )
        caps = extract_signals(
            method="POST", url="https://x/users", request_body={"email": "x"},
            response=_resp(status_code=422, body=body, headers={"content-type": "application/json"}),
            asset_id="a-1",
        )
        rules = [c for c in caps if c.type == CapabilityType.VALIDATION_RULE]
        assert rules
        assert rules[0].value["param"] == "email"
        assert "email" in rules[0].value["rule"].lower()
        assert rules[0].value["rejected_with"] == 422

    def test_django_drf_shape(self):
        body = '{"username":["This field is required."]}'
        caps = extract_signals(
            method="POST", url="https://x/login", request_body={"password": "x"},
            response=_resp(status_code=400, body=body),
            asset_id="a-1",
        )
        rules = [c for c in caps if c.type == CapabilityType.VALIDATION_RULE]
        assert rules and rules[0].value["param"] == "username"

    def test_rails_errors_shape(self):
        body = '{"errors":{"name":["can\'t be blank"],"email":["is invalid"]}}'
        caps = extract_signals(
            method="POST", url="https://x/users", request_body={},
            response=_resp(status_code=422, body=body),
            asset_id="a-1",
        )
        rules = [c for c in caps if c.type == CapabilityType.VALIDATION_RULE]
        params = {r.value["param"] for r in rules}
        assert {"name", "email"}.issubset(params)

    def test_skipped_for_2xx(self):
        """Validation extraction only on 4xx — 200 with the same body
        shape would be a false positive."""
        caps = extract_signals(
            method="POST", url="https://x/", request_body={"a": "b"},
            response=_resp(status_code=200, body='{"detail":[{"loc":["body","x"]}]}'),
            asset_id="a-1",
        )
        assert all(c.type != CapabilityType.VALIDATION_RULE for c in caps)

    def test_method_not_allowed_plain_text(self):
        caps = extract_signals(
            method="POST", url="https://x/users", request_body=None,
            response=_resp(status_code=405, body="Method Not Allowed"),
            asset_id="a-1",
        )
        rules = [c for c in caps if c.type == CapabilityType.VALIDATION_RULE]
        assert rules and rules[0].value["rule"] == "method_not_allowed"


class TestCommitSignals:
    def test_dedup_across_repeat_probes(self):
        """The whole point of the capability store wiring: re-probing the
        same endpoint shouldn't multiply rows. If this regresses, every
        long-running scan's prompt blows up."""
        store = CapabilityStore()
        for _ in range(5):
            commit_signals(store, extract_signals(
                method="GET", url="https://x/api/users",
                request_body=None,
                response=_resp(headers={"set-cookie": "PHPSESSID=abc"}),
                asset_id="a-1",
            ))
        # 1 ROUTE_TEMPLATE + 1 FRAMEWORK after dedup.
        types = [c.type for c in store.all()]
        assert types.count(CapabilityType.ROUTE_TEMPLATE) == 1
        assert types.count(CapabilityType.FRAMEWORK) == 1
