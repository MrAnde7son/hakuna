"""API tests for the VM scanner's non-routable-target gate.

The VM scanner dispatches from its own network location, so a cloud-hosted
scanner cannot reach RFC1918 space. These tests pin the behaviour that keeps
that from failing silently: the route must classify targets *before* CIDR
expansion and either warn or refuse, per deployment policy.
"""
import pytest

from services.target_expander import PRIVATE_TARGET_POLICY_ENV


@pytest.fixture
def captured_dispatch(monkeypatch):
    """Stub out the scanner dispatch and record the targets it was handed."""
    calls = []

    async def _fake_start_vm_scan(db, org, targets, **kwargs):
        calls.append(targets)
        return {"scan_id": 1, "job_ids": ["j1"], "targets_queued": len(targets), "status": "running"}

    monkeypatch.setattr("routes.vm_routes.start_vm_scan", _fake_start_vm_scan)
    return calls


class TestTargetPolicyEndpoint:
    def test_reports_default_policy(self, authed_client, monkeypatch):
        monkeypatch.delenv(PRIVATE_TARGET_POLICY_ENV, raising=False)
        resp = authed_client.get("/api/vm/target-policy")
        assert resp.status_code == 200
        assert resp.json() == {"private_targets": "warn"}

    def test_reports_configured_policy(self, authed_client, monkeypatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        resp = authed_client.get("/api/vm/target-policy")
        assert resp.json() == {"private_targets": "block"}

    def test_requires_auth(self, client):
        assert client.get("/api/vm/target-policy").status_code == 401


class TestBlockPolicy:
    def test_private_cidr_is_refused(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["192.168.1.0/24"]})
        assert resp.status_code == 400
        # The message must quote the subnet as typed, not 254 expanded hosts.
        assert "192.168.1.0/24" in resp.json()["detail"]
        assert "192.168.1.1" not in resp.json()["detail"]

    def test_refusal_happens_before_dispatch(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        authed_client.post("/api/vm/scan", json={"targets": ["10.0.0.0/24"]})
        assert captured_dispatch == []

    def test_public_targets_still_dispatch(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["example.com"]})
        assert resp.status_code == 200
        assert captured_dispatch == [["example.com"]]

    def test_mixed_list_is_refused_wholesale(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        resp = authed_client.post(
            "/api/vm/scan", json={"targets": ["example.com", "10.0.0.5"]}
        )
        assert resp.status_code == 400
        assert captured_dispatch == []


class TestWarnPolicy:
    def test_dispatches_but_returns_a_warning(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "warn")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["192.168.1.0/30"]})
        assert resp.status_code == 200
        warnings = resp.json()["warnings"]
        assert len(warnings) == 1
        assert "192.168.1.0/30" in warnings[0]
        # Warning must not suppress the scan — expansion still happened.
        assert captured_dispatch == [["192.168.1.1", "192.168.1.2"]]

    def test_public_targets_get_no_warning(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "warn")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["example.com"]})
        assert "warnings" not in resp.json()


class TestAllowPolicy:
    def test_silent_passthrough(self, authed_client, monkeypatch, captured_dispatch):
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "allow")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["192.168.1.5"]})
        assert resp.status_code == 200
        assert "warnings" not in resp.json()
        assert captured_dispatch == [["192.168.1.5"]]


class TestHostnameTargets:
    def test_hostnames_are_never_gated(self, authed_client, monkeypatch, captured_dispatch):
        # The lab compose reaches its targets by Docker hostname; gating those
        # would break local E2E runs even though they resolve to private IPs.
        monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
        resp = authed_client.post("/api/vm/scan", json={"targets": ["dvwa", "tomcat"]})
        assert resp.status_code == 200
        assert captured_dispatch == [["dvwa", "tomcat"]]
