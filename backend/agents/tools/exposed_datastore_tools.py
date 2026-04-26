"""Exposed-Datastore tool palette for the Exposed-Datastore Audit ReAct agent.

Single audit family covering the most-commonly-misconfigured network-reachable
data planes:

  - Redis            (TCP 6379)   — `redis_probe`
  - MongoDB          (TCP 27017)  — `mongo_probe`
  - Elasticsearch    (TCP 9200)   — `elastic_probe`
  - Docker Engine API (TCP 2375)  — `docker_api_probe`
  - Kubernetes API    (TCP 6443)  — `k8s_api_probe`
  - etcd             (TCP 2379)   — `etcd_probe`

Each tool dispatches a `method=datastore_probe` task to the relay. The relay
handler (hakuna-relay-agent/agent/datastore_probe.py) wraps the appropriate
client per op and returns a small dict — never bulk dumps. Op selection is
driven by the `op` param so a single relay method covers all six datastores.

## Safety stance

Every op is **read-only and non-iterating**:
  - No `KEYS *` / `SCAN` / `find()` / cluster-wide list-everything calls
  - No write/exec endpoints (Docker `/containers/*/exec`, k8s `/exec`)
  - Per-call hard timeouts at the relay (default 8s)
  - Connection attempt only — abandoned cleanly on failure

The audit's purpose is *exposure triage*: confirm whether the service is
listening anonymously, classify what an unauthenticated caller would see,
emit a finding sized to the impact. If the agent wants to enumerate further,
that's a follow-up credentialed audit, not this mission.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Optional

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target, split_host_port
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


# Per-op default timeout. Datastore probes are connect-and-read-once; if
# they don't answer in 8s the service is overloaded or filtered, and
# retrying won't help.
_PROBE_TIMEOUT_S = 8


def _run_async(coro):
    """Bridge from sync agent_tool to async relay broker. Mirrors the
    pattern in snmp_tools/smb_tools — the broker is async-only, the
    @agent_tool contract is sync."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PROBE_TIMEOUT_S + 15)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[Optional[str], Optional[str]]:
    """Pull relay agent + credential id from the run context. Credential is
    optional for this audit family — anonymous probes are the whole point —
    but downstream Tier 2 audits may pass one through."""
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


async def _dispatch_probe(
    db,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: Optional[str],
    default_port: int,
) -> tuple[Asset, dict]:
    """Send a single datastore probe through the relay and return its result.

    The relay-side handler picks a client library by `op`. Connection
    target is derived from the asset's identity, falling back to the
    user-supplied audit port if the discovery scan didn't see the
    standard port.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    raw_target = asset.ip or asset.fqdn or asset.hostname
    if not raw_target:
        raise ValueError(f"asset {asset_id} has no ip or hostname")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")

    target, target_port = split_host_port(raw_target)
    if target_port is None:
        _, target_port = resolve_asset_target(asset)
    port = target_port or default_port

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="datastore_probe",
        config={"target": target, "port": port},
        credentials={},  # all ops in Phase 1a are anonymous
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── Redis ────────────────────────────────────────────────────────────


@agent_tool(
    "redis_probe",
    "Probe an exposed Redis server (default 6379) for unauthenticated access. "
    "Sends `PING` then `INFO server` — if PING returns +PONG without auth, the "
    "instance is unauthenticated. The `INFO server` response reveals version, "
    "OS, role (master/slave/sentinel) for impact triage. NEVER calls `KEYS`, "
    "`SCAN`, `CONFIG SET`, or `EVAL`. Returns: "
    "`{auth_required: bool, version: str, role: str, os: str, _errors?: dict}`. "
    "An `auth_required: false` result is the finding lead.",
    {"asset_id": {"type": "integer"}},
)
def redis_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "redis", {}, relay, 6379))
    return result


# ── MongoDB ──────────────────────────────────────────────────────────


@agent_tool(
    "mongo_probe",
    "Probe an exposed MongoDB server (default 27017) for unauthenticated access. "
    "Connects with no creds and runs `isMaster` + `listDatabases` (admin command). "
    "If `listDatabases` returns the database list without auth, the instance is "
    "unauthenticated and exposing every database name. NEVER runs `find()` or any "
    "data-read query. Returns: `{auth_required: bool, version: str, "
    "databases: [{name, sizeOnDisk}], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def mongo_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "mongo", {}, relay, 27017))
    return result


# ── Elasticsearch ────────────────────────────────────────────────────


@agent_tool(
    "elastic_probe",
    "Probe an exposed Elasticsearch instance (default 9200) for unauthenticated "
    "access. Hits `GET /` (cluster info — version, build), `GET /_cluster/health`, "
    "and `GET /_cat/indices?format=json&bytes=b` to enumerate index names + sizes. "
    "Index names alone are often sensitive (e.g. `prod-pii-2026`). NEVER reads "
    "documents (`/_search`). Tries plain HTTP and HTTPS. Returns: "
    "`{auth_required: bool, version: str, cluster_name: str, indices: [{name, "
    "docs_count, store_size_bytes}], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def elastic_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "elastic", {}, relay, 9200))
    return result


# ── Docker Engine API ────────────────────────────────────────────────


@agent_tool(
    "docker_api_probe",
    "Probe a TCP-exposed Docker Engine API (default 2375) for unauthenticated "
    "access. Calls `GET /version` and `GET /info` only — returns engine version, "
    "OS/arch, container/image counts, and security options (AppArmor/SELinux/"
    "userns). NEVER touches `/containers/*` or `/exec` — those would be both "
    "data-reading and remote-code-execution-equivalent. An accessible Docker "
    "API on TCP without TLS is **always** a critical finding (full host RCE via "
    "container escape). Returns: `{reachable: bool, version: str, api_version: "
    "str, kernel_version: str, total_containers: int, total_images: int, "
    "security_options: [str], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def docker_api_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "docker", {}, relay, 2375))
    return result


# ── Kubernetes API ───────────────────────────────────────────────────


@agent_tool(
    "k8s_api_probe",
    "Probe a Kubernetes API server (default 6443) for unauthenticated access. "
    "Hits `GET /version` (always anonymous-readable, just confirms it's k8s) and "
    "`GET /api/v1/namespaces` *as anonymous* — if the latter returns 200 with a "
    "namespace list, anonymous-auth is enabled at cluster level (a critical "
    "finding). 401/403 is the expected/secure response. NEVER reads pod specs, "
    "secrets, or configmaps. Returns: `{anon_namespaces: bool, version: str, "
    "git_version: str, namespaces: [str] (only if anon_namespaces=true), "
    "_errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def k8s_api_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "k8s", {}, relay, 6443))
    return result


# ── etcd ─────────────────────────────────────────────────────────────


@agent_tool(
    "etcd_probe",
    "Probe an etcd server (default 2379) for unauthenticated access. Hits "
    "`GET /version` (cluster + server version) and `GET /v3/auth/status` (via "
    "POST {} on the gRPC-gateway endpoint) to determine whether RBAC is enabled. "
    "etcd without auth on TCP = full cluster secrets disclosure (k8s, CoreDNS, "
    "Patroni). NEVER reads keyspace. Returns: `{auth_enabled: bool, version: "
    "str, cluster_version: str, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def etcd_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "etcd", {}, relay, 2379))
    return result


# ── Memcached ────────────────────────────────────────────────────────


@agent_tool(
    "memcached_probe",
    "Probe an exposed Memcached server (default 11211) for unauthenticated "
    "access. Speaks the text protocol — sends `version` then `stats` then "
    "`stats settings`. Memcached has no auth in the wire protocol (SASL is "
    "rare in practice); reachability *is* the finding. NEVER calls `flush_all`, "
    "`set`, `delete`, or any iteration. Also useful: an exposed Memcached on "
    "the public internet is a UDP amplification source if UDP is enabled. "
    "Returns: `{reachable: bool, version: str, uptime_s: int, curr_items: int, "
    "total_items: int, bytes_used: int, max_bytes: int, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def memcached_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "memcached", {}, relay, 11211))
    return result


# ── Kibana ───────────────────────────────────────────────────────────


@agent_tool(
    "kibana_probe",
    "Probe a Kibana instance (default 5601) for unauthenticated access. Hits "
    "`GET /api/status` — if it returns 200 with a JSON body containing "
    "version, the UI is anonymous-readable, which means dashboards (often "
    "containing prod data) are also anonymous-readable. Tries plain HTTP "
    "and HTTPS. NEVER fetches dashboards or queries any underlying index. "
    "Returns: `{auth_required: bool, version: str, build_hash: str, scheme: "
    "str, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def kibana_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "kibana", {}, relay, 5601))
    return result


# ── kubelet ──────────────────────────────────────────────────────────


@agent_tool(
    "kubelet_probe",
    "Probe a Kubernetes kubelet (default 10250) for unauthenticated access. "
    "Hits `GET /pods` over HTTPS without a bearer token — if it returns 200 "
    "with a pod list, the kubelet has anonymous-auth enabled (a critical "
    "misconfiguration: kubelet anon = full pod exec/log access on every "
    "container on the node). 401/403 is the expected/secure response. NEVER "
    "calls `/exec`, `/run`, or `/logs`. Returns: `{anon_pods: bool, pod_count: "
    "int, namespaces: [str] (only if anon_pods=true), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def kubelet_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "kubelet", {}, relay, 10250))
    return result


# ── CouchDB ──────────────────────────────────────────────────────────


@agent_tool(
    "couchdb_probe",
    "Probe a CouchDB instance (default 5984) for unauthenticated access. Hits "
    "`GET /` (server info — version, vendor) and `GET /_all_dbs` to enumerate "
    "database names. Pre-3.0 CouchDB shipped with no admin (the 'admin party') "
    "and many deployments still run unsecured. Database names alone are often "
    "sensitive. NEVER reads documents (`GET /<db>/<doc>` or `_find`). Returns: "
    "`{auth_required: bool, version: str, vendor: str, databases: [str], "
    "_errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def couchdb_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "couchdb", {}, relay, 5984))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_EXPOSED_DATASTORE_TOOL_NAMES = [
    # Phase 1a
    "redis_probe",
    "mongo_probe",
    "elastic_probe",
    "docker_api_probe",
    "k8s_api_probe",
    "etcd_probe",
    # Phase 1b
    "memcached_probe",
    "kibana_probe",
    "kubelet_probe",
    "couchdb_probe",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="exposed_datastore",
    label="Exposed Datastore Audit",
    description=(
        "Anonymous-probe audit for network-reachable data planes that ship "
        "auth-disabled by default (Redis, MongoDB, Elasticsearch, Memcached, "
        "Kibana, kubelet, CouchDB, Docker API, Kubernetes API, etcd). The "
        "mission is exposure triage: confirm whether the service is listening "
        "without auth and emit a finding sized to the impact. Read-only; never "
        "enumerates contents."
    ),
    supported_os=["linux", "windows", "container"],
    auth_modes=["anonymous"],
    relay_method="datastore_probe",
    credential_connector_ids=[],  # no credential family — purely anonymous
    tool_names=_EXPOSED_DATASTORE_TOOL_NAMES,
    required_ports=(
        # Phase 1a
        6379, 27017, 9200, 2375, 6443, 2379,
        # Phase 1b
        11211, 5601, 10250, 5984,
    ),
    safety_class="anon_datastore",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="triage",
            label="Exposure Triage",
            description=(
                "Confirm whether the exposed datastore accepts unauthenticated "
                "queries, classify the impact (data sensitivity, RCE potential), "
                "and emit a single sized finding. Skip if auth is enforced."
            ),
            prompt_key="exposed_datastore_audit_triage",
            suggested_budget=8,
            cost_hint="low",
        ),
    ],
))
