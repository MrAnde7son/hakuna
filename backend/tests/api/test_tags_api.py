"""API tests for tag management endpoints."""
import pytest


class TestListTags:
    def test_list_tags(self, authed_client, test_tags):
        resp = authed_client.get("/api/tags")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 3

    def test_list_tags_unauthenticated(self, client):
        resp = client.get("/api/tags")
        assert resp.status_code == 401


class TestCreateTag:
    def test_create_tag(self, authed_client):
        resp = authed_client.post("/api/tags", json={
            "category": "custom",
            "value": "new-tag",
            "color": "#ef4444",
        })
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["value"] == "new-tag"

    def test_create_duplicate_tag(self, authed_client, test_tags):
        resp = authed_client.post("/api/tags", json={
            "category": "environment",
            "value": "production",
            "color": "#3b82f6",
        })
        assert resp.status_code in (400, 409)


class TestDeleteTag:
    def test_delete_tag(self, authed_client, test_tags):
        tag = test_tags[0]
        resp = authed_client.delete(f"/api/tags/{tag.id}")
        assert resp.status_code == 200

    def test_delete_tag_not_found(self, authed_client):
        resp = authed_client.delete("/api/tags/99999")
        assert resp.status_code == 404


class TestTagAssignment:
    def test_assign_tag_to_asset(self, authed_client, test_tags, test_assets):
        tag = test_tags[0]
        asset = test_assets[0]
        resp = authed_client.post("/api/tags/assign", json={
            "tag_ids": [tag.id],
            "asset_ids": [asset.id],
        })
        assert resp.status_code == 200

    def test_assign_tag_to_finding(self, authed_client, test_tags, test_findings):
        tag = test_tags[1]
        finding = test_findings[0]
        resp = authed_client.post("/api/tags/assign", json={
            "tag_ids": [tag.id],
            "finding_ids": [finding.id],
        })
        assert resp.status_code == 200
