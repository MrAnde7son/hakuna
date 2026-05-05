"""Coverage for _promote_easm_subassets — first-class child Asset emission
from EASM scanner classifier output (ai_agent / mcp_server / cloud_storage_bucket).
"""
from datetime import datetime

from models.models import Asset
from services.easm import (
    _BUCKET_CNAME_PATTERNS,
    _build_subasset_lookup,
    _detect_bucket_from_cname,
    _promote_easm_subassets,
)


def test_detect_bucket_from_cname_matches_known_providers():
    assert _detect_bucket_from_cname("mybucket.s3.amazonaws.com") == ("aws_s3", "mybucket")
    assert _detect_bucket_from_cname("app-static.s3.us-east-1.amazonaws.com") == ("aws_s3", "app-static")
    assert _detect_bucket_from_cname("data.storage.googleapis.com") == ("gcs", "data")
    assert _detect_bucket_from_cname("site.blob.core.windows.net") == ("azure_blob", "site")
    assert _detect_bucket_from_cname("img.r2.cloudflarestorage.com") == ("cloudflare_r2", "img")


def test_detect_bucket_from_cname_rejects_non_buckets():
    assert _detect_bucket_from_cname("cdn.cloudflare.com") is None
    assert _detect_bucket_from_cname("api.acme.com") is None
    assert _detect_bucket_from_cname("") is None
    assert _detect_bucket_from_cname(None) is None


def test_bucket_patterns_cover_major_providers():
    providers = {p for _, p in _BUCKET_CNAME_PATTERNS}
    assert {"aws_s3", "gcs", "azure_blob", "cloudflare_r2"}.issubset(providers)


def test_promote_creates_ai_agent_child_with_parent_link(db_session, test_scan):
    host = Asset(
        scan_id=test_scan.id,
        hostname="agents.acme.com",
        ip="1.2.3.4",
        asset_type="host",
        environment_tag="external",
        criticality=5,
        is_internet_facing=True,
    )
    db_session.add(host)
    db_session.flush()

    ea = {
        "asset_type": "ai_agent",
        "hostname": "agents.acme.com",
        "http_url": "https://agents.acme.com",
        "tech_stack": ["flowise"],
    }
    existing = _build_subasset_lookup(test_scan.id, db_session)
    new_ids = _promote_easm_subassets(db_session, test_scan, host, ea, datetime.utcnow(), existing)

    assert len(new_ids) == 1
    child = db_session.query(Asset).filter(Asset.id == new_ids[0]).one()
    assert child.asset_type == "ai_agent"
    assert child.asset_identity["url"] == "https://agents.acme.com"
    assert child.asset_attributes["parent_asset_id"] == host.id


def test_promote_is_idempotent_within_scan(db_session, test_scan):
    host = Asset(
        scan_id=test_scan.id, hostname="mcp.acme.com", asset_type="host",
        environment_tag="external", criticality=5,
    )
    db_session.add(host)
    db_session.flush()

    ea = {"asset_type": "mcp_server", "hostname": "mcp.acme.com", "http_url": "https://mcp.acme.com"}
    existing = _build_subasset_lookup(test_scan.id, db_session)

    first = _promote_easm_subassets(db_session, test_scan, host, ea, datetime.utcnow(), existing)
    second = _promote_easm_subassets(db_session, test_scan, host, ea, datetime.utcnow(), existing)

    assert len(first) == 1
    assert len(second) == 0  # no new row on the second call
    children = db_session.query(Asset).filter(
        Asset.scan_id == test_scan.id, Asset.asset_type == "mcp_server",
    ).all()
    assert len(children) == 1


def test_promote_creates_storage_bucket_from_cname(db_session, test_scan):
    host = Asset(
        scan_id=test_scan.id, hostname="cdn.acme.com", asset_type="host",
        environment_tag="external", criticality=5,
    )
    db_session.add(host)
    db_session.flush()

    ea = {
        "asset_type": "host",
        "hostname": "cdn.acme.com",
        "dns_records": {"CNAME": ["acme-static.s3.amazonaws.com"]},
    }
    existing = _build_subasset_lookup(test_scan.id, db_session)
    new_ids = _promote_easm_subassets(db_session, test_scan, host, ea, datetime.utcnow(), existing)

    assert len(new_ids) == 1
    bucket = db_session.query(Asset).filter(Asset.id == new_ids[0]).one()
    assert bucket.asset_type == "cloud_storage_bucket"
    assert bucket.asset_identity == {"provider": "aws_s3", "bucket_name": "acme-static"}
    assert bucket.asset_attributes["parent_asset_id"] == host.id
    assert bucket.asset_attributes["fronting_host"] == "cdn.acme.com"


def test_promote_skips_when_no_classifier_signal(db_session, test_scan):
    host = Asset(
        scan_id=test_scan.id, hostname="plain.acme.com", asset_type="host",
        environment_tag="external", criticality=5,
    )
    db_session.add(host)
    db_session.flush()

    ea = {
        "asset_type": "host",
        "hostname": "plain.acme.com",
        "dns_records": {"A": ["1.2.3.4"], "CNAME": ["edge.cloudflare.net"]},
    }
    existing = _build_subasset_lookup(test_scan.id, db_session)
    new_ids = _promote_easm_subassets(db_session, test_scan, host, ea, datetime.utcnow(), existing)

    assert new_ids == []
