"""Unit tests for agent.datastore_probe.

Each datastore's client library is mocked — we don't open real sockets.
The contract under test is:

  - The handler's op allowlist rejects unknown ops.
  - Each probe returns the expected decisive field for the agent
    (`auth_required`, `anon_namespaces`, `auth_enabled`, `reachable`)
    given a mocked client response.
  - Auth-required responses (NOAUTH from Redis, 401 from HTTP, etc.)
    map to the right boolean.
  - Connection failures surface as a structured `_errors` field rather
    than raising.

We never reach the real network — every test patches the client library
the probe imports.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from agent import datastore_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Handler dispatch / allowlist ─────────────────────────────────────


def test_handler_rejects_unknown_op():
    """The relay-side allowlist is the second wall behind the backend tool
    palette — calling with a made-up op must raise without ever touching
    the network."""
    with pytest.raises(datastore_probe.DatastoreProbeError, match="unknown datastore probe op"):
        _run(datastore_probe.datastore_probe_handler(
            ws=None, task={}, transport_config={"target": "x", "port": 1},
            credentials={}, params={"op": "drop_keyspace"},
        ))


def test_handler_requires_target():
    with pytest.raises(datastore_probe.DatastoreProbeError, match="target is required"):
        _run(datastore_probe.datastore_probe_handler(
            ws=None, task={}, transport_config={}, credentials={}, params={"op": "redis"},
        ))


def test_handler_op_allowlist_matches_phase_1a_and_1b_scope():
    """The allowlist must list exactly the 10 probes shipped through Phase 1b.
    Adding a new op deliberately requires updating this test — that's the
    point of the second wall."""
    assert set(datastore_probe._OP_HANDLERS.keys()) == {
        # Phase 1a
        "redis", "mongo", "elastic", "docker", "k8s", "etcd",
        # Phase 1b
        "memcached", "kibana", "kubelet", "couchdb",
    }


# ── Redis ────────────────────────────────────────────────────────────


def test_redis_probe_returns_auth_not_required_when_ping_succeeds():
    """A successful PING + INFO without sending AUTH is the unauthenticated
    case — the decisive field is auth_required=False."""
    fake_redis = MagicMock()
    fake_client = MagicMock()
    fake_client.ping.return_value = True
    fake_client.info.side_effect = [
        {"redis_version": "7.2.4", "redis_mode": "standalone", "os": "Linux 5.15", "arch_bits": "64"},
        {"role": "master"},
    ]
    fake_redis.Redis.return_value = fake_client
    fake_redis.exceptions = MagicMock(
        AuthenticationError=type("AuthErr", (Exception,), {}),
        ResponseError=type("RespErr", (Exception,), {}),
    )

    with patch.dict("sys.modules", {"redis": fake_redis}):
        result = datastore_probe._probe_redis("10.0.0.1", 6379, {}, timeout_s=5)

    assert result["auth_required"] is False
    assert result["version"] == "7.2.4"
    assert result["role"] == "master"


def test_redis_probe_returns_auth_required_on_noauth_response():
    """Redis returning NOAUTH means auth IS configured — auth_required=True."""
    class _RespErr(Exception):
        pass

    fake_redis = MagicMock()
    fake_client = MagicMock()
    fake_client.ping.side_effect = _RespErr("NOAUTH Authentication required.")
    fake_redis.Redis.return_value = fake_client
    fake_redis.exceptions = MagicMock(
        AuthenticationError=type("AuthErr", (Exception,), {}),
        ResponseError=_RespErr,
    )

    with patch.dict("sys.modules", {"redis": fake_redis}):
        result = datastore_probe._probe_redis("10.0.0.1", 6379, {}, timeout_s=5)

    assert result["auth_required"] is True


def test_redis_probe_handles_connection_refused():
    """Network-layer failures must not raise — they go in _errors so the
    agent reasons about them."""
    fake_redis = MagicMock()
    fake_client = MagicMock()
    fake_client.ping.side_effect = ConnectionRefusedError("refused")
    fake_redis.Redis.return_value = fake_client
    fake_redis.exceptions = MagicMock(
        AuthenticationError=type("AuthErr", (Exception,), {}),
        ResponseError=type("RespErr", (Exception,), {}),
    )

    with patch.dict("sys.modules", {"redis": fake_redis}):
        # ConnectionRefused happens inside ping(), not at Redis() init in our
        # wrapper — verify it's caught at the outer try
        result = datastore_probe._probe_redis("10.0.0.1", 6379, {}, timeout_s=5)

    # Either path — caught at outer connect or returns a result with
    # auth_required=None — must be safe.
    assert "auth_required" in result or "_errors" in result


# ── MongoDB ──────────────────────────────────────────────────────────


def test_mongo_probe_returns_auth_not_required_when_listdatabases_succeeds():
    """listDatabases returning the database list means auth is OFF — the
    finding is critical-tier."""
    fake_pymongo = MagicMock()
    fake_client = MagicMock()
    fake_client.admin.command.side_effect = [
        {"version": "7.0.5", "maxWireVersion": 21},
        {"databases": [
            {"name": "admin", "sizeOnDisk": 1024},
            {"name": "prod_users", "sizeOnDisk": 12345678},
        ]},
    ]
    fake_pymongo.MongoClient.return_value = fake_client

    fake_errors = MagicMock(
        OperationFailure=type("OpFail", (Exception,), {"code": 0}),
        PyMongoError=Exception,
    )

    with patch.dict("sys.modules", {
        "pymongo": fake_pymongo,
        "pymongo.errors": fake_errors,
    }):
        result = datastore_probe._probe_mongo("10.0.0.2", 27017, {}, timeout_s=5)

    assert result["auth_required"] is False
    assert result["version"] == "7.0.5"
    assert any(d["name"] == "prod_users" for d in result["databases"])


def test_mongo_probe_returns_auth_required_on_unauthorized():
    """OperationFailure with auth-related message → auth_required=True."""
    class _OpFail(Exception):
        def __init__(self, msg, code=13):
            super().__init__(msg)
            self.code = code

    fake_pymongo = MagicMock()
    fake_client = MagicMock()
    fake_client.admin.command.side_effect = [
        {"version": "7.0.5", "maxWireVersion": 21},
        _OpFail("not authorized on admin", code=13),
    ]
    fake_pymongo.MongoClient.return_value = fake_client

    fake_errors = MagicMock(OperationFailure=_OpFail, PyMongoError=Exception)

    with patch.dict("sys.modules", {
        "pymongo": fake_pymongo,
        "pymongo.errors": fake_errors,
    }):
        result = datastore_probe._probe_mongo("10.0.0.2", 27017, {}, timeout_s=5)

    assert result["auth_required"] is True


# ── Elasticsearch ────────────────────────────────────────────────────


def test_elastic_probe_returns_auth_not_required_when_indices_listable():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    root_resp = MagicMock(status_code=200)
    root_resp.json.return_value = {
        "version": {"number": "8.12.0"},
        "cluster_name": "prod-cluster",
    }
    indices_resp = MagicMock(status_code=200)
    indices_resp.json.return_value = [
        {"index": "prod-pii-2026", "docs.count": "120000", "store.size": "999000000"},
        {"index": "logs-2026", "docs.count": "5000", "store.size": "12000"},
    ]
    fake_client.get.side_effect = [root_resp, indices_resp]
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_elastic("10.0.0.3", 9200, {}, timeout_s=5)

    assert result["auth_required"] is False
    assert result["version"] == "8.12.0"
    assert result["cluster_name"] == "prod-cluster"
    assert any(i["name"] == "prod-pii-2026" for i in result["indices"])


def test_elastic_probe_returns_auth_required_on_401():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx
    root_resp = MagicMock(status_code=401)
    fake_client.get.return_value = root_resp
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_elastic("10.0.0.3", 9200, {}, timeout_s=5)

    assert result["auth_required"] is True


# ── Docker ───────────────────────────────────────────────────────────


def test_docker_probe_returns_reachable_with_engine_metadata():
    """Reachable Docker API on TCP without TLS = critical finding by itself.
    The probe just needs to confirm reachable=True and pull version metadata."""
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    ver = MagicMock(status_code=200)
    ver.json.return_value = {
        "Version": "25.0.3", "ApiVersion": "1.44",
        "KernelVersion": "5.15.0", "Os": "linux", "Arch": "amd64",
    }
    info = MagicMock(status_code=200)
    info.json.return_value = {
        "Containers": 12, "ContainersRunning": 8, "Images": 30,
        "SecurityOptions": ["apparmor"], "ServerVersion": "25.0.3",
    }
    fake_client.get.side_effect = [ver, info]
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_docker("10.0.0.4", 2375, {}, timeout_s=5)

    assert result["reachable"] is True
    assert result["version"] == "25.0.3"
    assert result["total_containers"] == 12


# ── Kubernetes ───────────────────────────────────────────────────────


def test_k8s_probe_flags_anon_namespaces_when_listable():
    """If GET /api/v1/namespaces returns 200 anonymously, anonymous-auth is
    cluster-wide on — the decisive flag the agent emits a finding from."""
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    ver = MagicMock(status_code=200)
    ver.json.return_value = {
        "gitVersion": "v1.29.2", "gitCommit": "abc123", "platform": "linux/amd64",
    }
    ns = MagicMock(status_code=200)
    ns.json.return_value = {
        "items": [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "prod"}},
        ],
    }
    fake_client.get.side_effect = [ver, ns]
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_k8s("10.0.0.5", 6443, {}, timeout_s=5)

    assert result["anon_namespaces"] is True
    assert result["version"] == "v1.29.2"
    assert "prod" in result["namespaces"]


def test_k8s_probe_secure_when_namespaces_403():
    """403/401 on the namespaces endpoint = correctly secured cluster."""
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    ver = MagicMock(status_code=200)
    ver.json.return_value = {"gitVersion": "v1.29.2"}
    ns = MagicMock(status_code=403)
    fake_client.get.side_effect = [ver, ns]
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_k8s("10.0.0.5", 6443, {}, timeout_s=5)

    assert result["anon_namespaces"] is False


# ── etcd ─────────────────────────────────────────────────────────────


# ── Memcached (Phase 1b) ─────────────────────────────────────────────


def test_memcached_probe_returns_reachable_with_stats():
    """Memcached has no auth in the wire protocol — reachability is the
    finding. The probe must parse VERSION + STAT lines correctly."""
    fake_sock = MagicMock()
    # First recv after `version\r\n` — single line
    # Second recv after `stats\r\n` — many STAT lines + END\r\n
    stats_body = (
        b"STAT pid 1234\r\n"
        b"STAT uptime 86400\r\n"
        b"STAT version 1.6.18\r\n"
        b"STAT curr_items 12345\r\n"
        b"STAT total_items 999999\r\n"
        b"STAT bytes 524288000\r\n"
        b"STAT limit_maxbytes 1073741824\r\n"
        b"STAT curr_connections 8\r\n"
        b"END\r\n"
    )
    recv_calls = [b"VERSION 1.6.18\r\n", stats_body, b""]
    fake_sock.recv.side_effect = recv_calls

    with patch("agent.datastore_probe.socket.create_connection", return_value=fake_sock):
        result = datastore_probe._probe_memcached("10.0.0.7", 11211, {}, timeout_s=5)

    assert result["reachable"] is True
    assert result["version"] == "1.6.18"
    assert result["uptime_s"] == 86400
    assert result["curr_items"] == 12345
    assert result["bytes_used"] == 524288000
    assert result["max_bytes"] == 1073741824


def test_memcached_probe_returns_error_on_unexpected_response():
    """If the server doesn't speak Memcached text protocol, we return an
    error rather than misclassifying as reachable."""
    fake_sock = MagicMock()
    fake_sock.recv.side_effect = [b"GARBAGE\r\n", b""]

    with patch("agent.datastore_probe.socket.create_connection", return_value=fake_sock):
        result = datastore_probe._probe_memcached("10.0.0.7", 11211, {}, timeout_s=5)

    assert "_errors" in result
    # Error path returns a fresh dict — `reachable` is absent rather than False
    assert "reachable" not in result or result["reachable"] is False


def test_memcached_probe_handles_connect_failure():
    with patch(
        "agent.datastore_probe.socket.create_connection",
        side_effect=ConnectionRefusedError("refused"),
    ):
        result = datastore_probe._probe_memcached("10.0.0.7", 11211, {}, timeout_s=5)
    assert "_errors" in result


# ── Kibana (Phase 1b) ────────────────────────────────────────────────


def test_kibana_probe_returns_auth_not_required_when_status_200():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    status = MagicMock(status_code=200)
    status.json.return_value = {
        "version": {"number": "8.12.0", "build_hash": "abcd1234", "build_number": 12345},
    }
    fake_client.get.return_value = status
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_kibana("10.0.0.8", 5601, {}, timeout_s=5)

    assert result["auth_required"] is False
    assert result["version"] == "8.12.0"
    assert result["build_hash"] == "abcd1234"


def test_kibana_probe_returns_auth_required_on_401():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx
    fake_client.get.return_value = MagicMock(status_code=401)
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_kibana("10.0.0.8", 5601, {}, timeout_s=5)

    assert result["auth_required"] is True


# ── kubelet (Phase 1b) ───────────────────────────────────────────────


def test_kubelet_probe_flags_anon_pods_when_listable():
    """GET /pods returning 200 anonymously = anon-auth on kubelet = critical
    (full pod exec/log access)."""
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    pods = MagicMock(status_code=200)
    pods.json.return_value = {
        "items": [
            {"metadata": {"name": "p1", "namespace": "default"}},
            {"metadata": {"name": "p2", "namespace": "kube-system"}},
            {"metadata": {"name": "p3", "namespace": "prod"}},
        ],
    }
    fake_client.get.return_value = pods
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_kubelet("10.0.0.9", 10250, {}, timeout_s=5)

    assert result["anon_pods"] is True
    assert result["pod_count"] == 3
    assert "prod" in result["namespaces"]


def test_kubelet_probe_secure_when_pods_403():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx
    fake_client.get.return_value = MagicMock(status_code=403)
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_kubelet("10.0.0.9", 10250, {}, timeout_s=5)

    assert result["anon_pods"] is False


# ── CouchDB (Phase 1b) ───────────────────────────────────────────────


def test_couchdb_probe_returns_auth_not_required_when_all_dbs_listable():
    """admin-party CouchDB returns the database list anonymously."""
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    root = MagicMock(status_code=200)
    root.json.return_value = {
        "version": "3.3.2",
        "vendor": {"name": "The Apache Software Foundation"},
    }
    dbs = MagicMock(status_code=200)
    dbs.json.return_value = ["_users", "_replicator", "prod_orders", "audit_log"]
    fake_client.get.side_effect = [root, dbs]
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_couchdb("10.0.0.10", 5984, {}, timeout_s=5)

    assert result["auth_required"] is False
    assert result["version"] == "3.3.2"
    assert "prod_orders" in result["databases"]


def test_couchdb_probe_returns_auth_required_on_root_401():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx
    fake_client.get.return_value = MagicMock(status_code=401)
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_couchdb("10.0.0.10", 5984, {}, timeout_s=5)

    assert result["auth_required"] is True


# ── etcd ─────────────────────────────────────────────────────────────


def test_etcd_probe_reports_auth_disabled_when_status_returns_enabled_false():
    fake_httpx = MagicMock()
    fake_client_ctx = MagicMock()
    fake_client = MagicMock()
    fake_client_ctx.__enter__.return_value = fake_client
    fake_client_ctx.__exit__.return_value = None
    fake_httpx.Client.return_value = fake_client_ctx

    ver = MagicMock(status_code=200)
    ver.json.return_value = {"etcdserver": "3.5.12", "etcdcluster": "3.5.0"}
    auth_status = MagicMock(status_code=200)
    auth_status.json.return_value = {"enabled": False}
    fake_client.get.return_value = ver
    fake_client.post.return_value = auth_status
    fake_httpx.TimeoutException = type("Timeout", (Exception,), {})
    fake_httpx.ConnectError = type("ConnectErr", (Exception,), {})

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        result = datastore_probe._probe_etcd("10.0.0.6", 2379, {}, timeout_s=5)

    assert result["auth_enabled"] is False
    assert result["version"] == "3.5.12"
    assert result["cluster_version"] == "3.5.0"
