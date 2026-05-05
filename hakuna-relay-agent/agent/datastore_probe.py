"""Datastore exposure probe executor for the Hakuna relay agent.

Single relay method (`datastore_probe`) covering the Phase 1a + 1b
exposed-datastore audit family:

  Phase 1a:
  - op="redis"    — Redis      (default 6379)
  - op="mongo"    — MongoDB    (default 27017)
  - op="elastic"  — Elasticsearch (default 9200)
  - op="docker"   — Docker Engine API (default 2375)
  - op="k8s"      — Kubernetes API   (default 6443)
  - op="etcd"     — etcd       (default 2379)

  Phase 1b:
  - op="memcached" — Memcached (default 11211)
  - op="kibana"    — Kibana    (default 5601)
  - op="kubelet"   — Kubelet   (default 10250)
  - op="couchdb"   — CouchDB   (default 5984)

Dispatched via `method=datastore_probe` from the backend Exposed-Datastore
Audit agent's tool palette.

## Design notes
- All probes are **anonymous** by spec — the audit's purpose is to detect
  datastores listening without auth. No credentials are accepted.
- Every op is a single connect-and-read of metadata-only endpoints. No
  iteration, no data reads, no writes. The handler enforces this by
  exposing only the read paths to begin with — there's no `op` for
  `KEYS`, `find()`, `/_search`, `/exec`, etc.
- Each probe wraps its synchronous client in `asyncio.to_thread` so the
  relay's event loop stays responsive.
- Per-op timeout is enforced at the handler level (default 8s, capped at
  whatever ``timeout_s`` the backend supplies). Connection failures
  return a structured `_errors` field rather than raising — the agent
  reasons over the error string.
- Heavy clients (`redis`, `pymongo`) are imported lazily inside the
  thread function so a missing optional dependency only fails the
  specific op, not the whole agent.

## Result shape (per op)
Each op returns a dict whose top-level keys describe what an
unauthenticated caller could see. The decisive field for the agent is
named clearly:
  - redis/mongo/elastic/etcd → ``auth_required: bool`` /
                                ``auth_enabled: bool``
  - docker → ``reachable: bool`` (Docker on TCP without TLS is always
              critical; reachability *is* the finding)
  - k8s → ``anon_namespaces: bool`` (anonymous-auth=true at cluster level)
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 8


class DatastoreProbeError(Exception):
    """Any datastore-probe failure surfaced back to the backend."""


@register_method("datastore_probe")
async def datastore_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch one datastore probe based on ``params.op``.

    The relay-side allowlist of legal ops is the keys of ``_OP_HANDLERS``
    below — anything else is rejected. This is the second wall behind the
    backend tool palette: even a buggy / prompt-injected agent can't ask
    the relay to do something this handler hasn't explicitly allowed.
    """
    target = (transport_config or {}).get("target")
    if not target:
        raise DatastoreProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise DatastoreProbeError(
            f"unknown datastore probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 2,  # small grace over the probe's internal timeout
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── Redis ────────────────────────────────────────────────────────────


def _probe_redis(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Connect to Redis with no auth and call PING + INFO server.

    A successful PING (+PONG) without sending AUTH means the instance is
    unauthenticated. INFO gives version/role/os for impact triage.
    """
    try:
        import redis  # type: ignore
    except ImportError:
        return {"_errors": {"redis": "redis client library not installed on relay"}}

    port = port or 6379
    out: dict[str, Any] = {"auth_required": None}
    try:
        client = redis.Redis(
            host=target, port=port,
            socket_connect_timeout=timeout_s,
            socket_timeout=timeout_s,
        )
        try:
            pong = client.ping()
            out["auth_required"] = not bool(pong)
        except redis.exceptions.AuthenticationError:
            out["auth_required"] = True
            return out
        except redis.exceptions.ResponseError as e:
            # NOAUTH error variant — Redis answered but requires AUTH
            if "NOAUTH" in str(e).upper() or "AUTHENTICATION" in str(e).upper():
                out["auth_required"] = True
                return out
            return {"_errors": {"redis": f"unexpected response: {e}"}}

        # Auth not required — gather server info for the finding evidence
        try:
            info = client.info(section="server") or {}
            out["version"] = info.get("redis_version")
            out["mode"] = info.get("redis_mode")
            out["os"] = info.get("os")
            out["arch_bits"] = info.get("arch_bits")
            out["role"] = (client.info(section="replication") or {}).get("role")
        except Exception as e:
            out["_errors"] = {"info": f"info failed: {e}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"redis": f"connect failed: {type(e).__name__}: {e}"}}
    return out


# ── MongoDB ──────────────────────────────────────────────────────────


def _probe_mongo(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Connect to Mongo with no auth and call isMaster + listDatabases.

    listDatabases is an admin command; if it returns the database list
    without auth, the deployment is unauthenticated and exposing every
    database name. We do NOT call ``find()`` on any collection.
    """
    try:
        from pymongo import MongoClient  # type: ignore
        from pymongo.errors import OperationFailure, PyMongoError  # type: ignore
    except ImportError:
        return {"_errors": {"mongo": "pymongo not installed on relay"}}

    port = port or 27017
    out: dict[str, Any] = {"auth_required": None}
    try:
        client = MongoClient(
            host=target, port=port,
            serverSelectionTimeoutMS=timeout_s * 1000,
            connectTimeoutMS=timeout_s * 1000,
            socketTimeoutMS=timeout_s * 1000,
            directConnection=True,
        )
        # isMaster (or hello) always works anonymously and reveals version
        try:
            hello = client.admin.command("isMaster")
            out["version"] = hello.get("version") or hello.get("maxWireVersion")
        except PyMongoError as e:
            return {"_errors": {"mongo": f"isMaster failed: {e}"}}

        try:
            dbs = client.admin.command("listDatabases")
            out["auth_required"] = False
            out["databases"] = [
                {"name": d.get("name"), "size_on_disk": d.get("sizeOnDisk")}
                for d in (dbs.get("databases") or [])
            ][:50]  # cap
        except OperationFailure as e:
            # Auth required → we get an Unauthorized failure
            if "auth" in str(e).lower() or e.code in (13, 18):
                out["auth_required"] = True
            else:
                out["_errors"] = {"listDatabases": str(e)}
        except PyMongoError as e:
            out["_errors"] = {"listDatabases": str(e)}
    except Exception as e:
        return {"_errors": {"mongo": f"connect failed: {type(e).__name__}: {e}"}}
    return out


# ── Elasticsearch ────────────────────────────────────────────────────


def _probe_elastic(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Hit GET / + GET /_cat/indices over plain HTTP and HTTPS.

    Tries plain HTTP first since exposed Elastic is overwhelmingly
    plain-HTTP. Falls back to HTTPS with verify=False (we're auditing
    posture, not asserting cert chain). Index names alone are often
    sensitive enough to be the finding.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"elastic": "httpx not installed on relay"}}

    port = port or 9200
    out: dict[str, Any] = {"auth_required": None}
    schemes = ["http", "https"]
    last_err: str | None = None
    for scheme in schemes:
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                root = client.get(f"{base}/")
                if root.status_code == 401:
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                if root.status_code != 200:
                    last_err = f"{scheme} GET / -> HTTP {root.status_code}"
                    continue
                try:
                    info = root.json()
                except Exception:
                    last_err = f"{scheme} GET / non-json"
                    continue
                out["scheme"] = scheme
                out["version"] = ((info.get("version") or {}).get("number"))
                out["cluster_name"] = info.get("cluster_name")

                indices = client.get(f"{base}/_cat/indices?format=json&bytes=b")
                if indices.status_code == 401:
                    out["auth_required"] = True
                    return out
                if indices.status_code == 200:
                    try:
                        rows = indices.json() or []
                    except Exception:
                        rows = []
                    out["auth_required"] = False
                    out["indices"] = [
                        {
                            "name": r.get("index"),
                            "docs_count": r.get("docs.count"),
                            "store_size_bytes": r.get("store.size"),
                        }
                        for r in rows
                    ][:100]
                else:
                    out["auth_required"] = None
                    out["_errors"] = {"indices": f"HTTP {indices.status_code}"}
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"elastic": last_err or "unreachable"}}


# ── Docker Engine API ────────────────────────────────────────────────


def _probe_docker(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /version + /info on the Docker Engine API.

    Reachability without TLS is itself the finding (full host RCE via
    container escape). We never touch /containers/* or /exec.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"docker": "httpx not installed on relay"}}

    port = port or 2375
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"reachable": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            ver = client.get(f"{base}/version")
            if ver.status_code != 200:
                return {"_errors": {"docker": f"GET /version HTTP {ver.status_code}"}}
            v = ver.json() or {}
            out["reachable"] = True
            out["version"] = v.get("Version")
            out["api_version"] = v.get("ApiVersion")
            out["kernel_version"] = v.get("KernelVersion")
            out["os"] = v.get("Os")
            out["arch"] = v.get("Arch")

            info = client.get(f"{base}/info")
            if info.status_code == 200:
                i = info.json() or {}
                out["total_containers"] = i.get("Containers")
                out["running_containers"] = i.get("ContainersRunning")
                out["total_images"] = i.get("Images")
                out["security_options"] = i.get("SecurityOptions") or []
                out["server_version"] = i.get("ServerVersion")
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"docker": f"{type(e).__name__}: {e}"}}
    return out


# ── Kubernetes API ───────────────────────────────────────────────────


def _probe_k8s(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /version + GET /api/v1/namespaces (anonymously) on the k8s API.

    /version is anonymous-readable on every cluster — it just confirms
    we're talking to k8s and reports the git version. /api/v1/namespaces
    returning 200 anonymously means cluster-level anonymous-auth is on
    (a critical misconfiguration).
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"k8s": "httpx not installed on relay"}}

    port = port or 6443
    base = f"https://{target}:{port}"
    out: dict[str, Any] = {"anon_namespaces": False}
    try:
        with httpx.Client(timeout=timeout_s, verify=False) as client:
            ver = client.get(f"{base}/version")
            if ver.status_code != 200:
                return {"_errors": {"k8s": f"GET /version HTTP {ver.status_code}"}}
            try:
                v = ver.json()
            except Exception:
                return {"_errors": {"k8s": "GET /version non-json — probably not k8s"}}
            out["version"] = v.get("gitVersion")
            out["git_commit"] = v.get("gitCommit")
            out["platform"] = v.get("platform")

            ns = client.get(f"{base}/api/v1/namespaces")
            if ns.status_code == 200:
                try:
                    body = ns.json() or {}
                    items = body.get("items") or []
                    out["anon_namespaces"] = True
                    out["namespaces"] = [
                        (i.get("metadata") or {}).get("name") for i in items
                    ][:50]
                except Exception:
                    out["anon_namespaces"] = False
            elif ns.status_code in (401, 403):
                out["anon_namespaces"] = False
            else:
                out["_errors"] = {"namespaces": f"HTTP {ns.status_code}"}
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"k8s": f"{type(e).__name__}: {e}"}}
    return out


# ── etcd ─────────────────────────────────────────────────────────────


def _probe_etcd(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /version + POST /v3/auth/status on the etcd v3 gRPC-gateway.

    /version is always public and reports etcd + cluster version. The
    auth/status endpoint reports whether RBAC is enabled. We never read
    keyspace.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"etcd": "httpx not installed on relay"}}

    port = port or 2379
    out: dict[str, Any] = {"auth_enabled": None}
    schemes = ["http", "https"]
    last_err: str | None = None
    for scheme in schemes:
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                ver = client.get(f"{base}/version")
                if ver.status_code != 200:
                    last_err = f"{scheme} GET /version HTTP {ver.status_code}"
                    continue
                try:
                    v = ver.json()
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                out["scheme"] = scheme
                out["version"] = v.get("etcdserver")
                out["cluster_version"] = v.get("etcdcluster")

                # POST {} on v3 auth/status — works as the v3 grpc-gateway shape.
                # An "auth disabled" cluster returns {"enabled": false} or similar.
                status = client.post(f"{base}/v3/auth/status", json={})
                if status.status_code == 200:
                    try:
                        body = status.json() or {}
                        out["auth_enabled"] = bool(body.get("enabled"))
                    except Exception:
                        out["auth_enabled"] = None
                elif status.status_code in (401, 403):
                    out["auth_enabled"] = True
                else:
                    out["_errors"] = {"auth_status": f"HTTP {status.status_code}"}
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"etcd": last_err or "unreachable"}}


# ── Memcached ────────────────────────────────────────────────────────


def _probe_memcached(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Speak the Memcached text protocol over a plain TCP socket.

    Memcached has no auth in the wire protocol (SASL is rare in practice),
    so reachability *is* the finding. We send `version\\r\\n` then
    `stats\\r\\n` and parse the lines until END. No iteration, no writes.
    Stdlib socket only — no client library needed.
    """
    port = port or 11211
    out: dict[str, Any] = {"reachable": False}
    try:
        sock = socket.create_connection((target, port), timeout=timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"memcached": f"connect failed: {type(e).__name__}: {e}"}}

    try:
        sock.settimeout(timeout_s)
        # `version\r\n` returns one line: `VERSION 1.6.18\r\n`
        sock.sendall(b"version\r\n")
        version_line = _read_until(sock, b"\r\n", max_bytes=128)
        if not version_line.startswith(b"VERSION "):
            return {"_errors": {"memcached": f"unexpected response: {version_line!r}"}}
        out["reachable"] = True
        out["version"] = version_line[len(b"VERSION "):].strip().decode("ascii", "replace")

        # `stats\r\n` returns many `STAT key value\r\n` lines terminated by `END\r\n`.
        sock.sendall(b"stats\r\n")
        body = _read_until(sock, b"END\r\n", max_bytes=32 * 1024)
        stats = _parse_memcached_stats(body)
        # Only forward a small whitelist — never the full stats dump.
        for key, dest in (
            ("uptime", "uptime_s"),
            ("curr_items", "curr_items"),
            ("total_items", "total_items"),
            ("bytes", "bytes_used"),
            ("limit_maxbytes", "max_bytes"),
            ("curr_connections", "curr_connections"),
        ):
            if key in stats:
                try:
                    out[dest] = int(stats[key])
                except (TypeError, ValueError):
                    out[dest] = stats[key]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _read_until(sock: socket.socket, terminator: bytes, max_bytes: int) -> bytes:
    """Read from sock until `terminator` appears or `max_bytes` reached.

    Bounded so a misbehaving / malicious server can't make us read forever.
    """
    buf = bytearray()
    while terminator not in buf and len(buf) < max_bytes:
        chunk = sock.recv(min(4096, max_bytes - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _parse_memcached_stats(body: bytes) -> dict[str, str]:
    """Parse `STAT key value\\r\\n` lines into a dict."""
    out: dict[str, str] = {}
    for line in body.splitlines():
        if not line.startswith(b"STAT "):
            continue
        parts = line.split(b" ", 2)
        if len(parts) == 3:
            key = parts[1].decode("ascii", "replace")
            value = parts[2].decode("ascii", "replace")
            out[key] = value
    return out


# ── Kibana ───────────────────────────────────────────────────────────


def _probe_kibana(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/status on Kibana over HTTP then HTTPS.

    A 200 with a JSON status body means the UI is anonymous-readable, which
    means the dashboards (and any data they show) are too. 401 = secured.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"kibana": "httpx not installed on relay"}}

    port = port or 5601
    out: dict[str, Any] = {"auth_required": None}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                resp = client.get(f"{base}/api/status")
                if resp.status_code == 401:
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                if resp.status_code != 200:
                    last_err = f"{scheme} GET /api/status -> HTTP {resp.status_code}"
                    continue
                try:
                    body = resp.json()
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                out["auth_required"] = False
                out["scheme"] = scheme
                ver = body.get("version") or {}
                out["version"] = ver.get("number")
                out["build_hash"] = ver.get("build_hash")
                out["build_number"] = ver.get("build_number")
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"kibana": last_err or "unreachable"}}


# ── kubelet ──────────────────────────────────────────────────────────


def _probe_kubelet(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /pods on the kubelet read-only port (HTTPS) without auth.

    A 200 with a pod list = anonymous-auth enabled = full pod exec/log on
    every container on that node. 401/403 = correctly secured. We never
    call /exec, /run, or /logs.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"kubelet": "httpx not installed on relay"}}

    port = port or 10250
    base = f"https://{target}:{port}"
    out: dict[str, Any] = {"anon_pods": False}
    try:
        with httpx.Client(timeout=timeout_s, verify=False) as client:
            resp = client.get(f"{base}/pods")
            if resp.status_code == 200:
                try:
                    body = resp.json() or {}
                except Exception:
                    return {"_errors": {"kubelet": "GET /pods non-json — probably not kubelet"}}
                items = body.get("items") or []
                out["anon_pods"] = True
                out["pod_count"] = len(items)
                # Surface namespaces only — not pod names (to stay below the
                # "no enumeration" bar in spirit; the agent has enough to
                # emit a critical finding from the namespace list alone).
                ns = sorted({
                    (i.get("metadata") or {}).get("namespace")
                    for i in items
                    if (i.get("metadata") or {}).get("namespace")
                })
                out["namespaces"] = ns[:20]
            elif resp.status_code in (401, 403):
                out["anon_pods"] = False
            else:
                out["_errors"] = {"pods": f"HTTP {resp.status_code}"}
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"kubelet": f"{type(e).__name__}: {e}"}}
    return out


# ── CouchDB ──────────────────────────────────────────────────────────


def _probe_couchdb(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET / + GET /_all_dbs on CouchDB.

    Pre-3.0 CouchDB shipped with no admin (the 'admin party' mode) and
    many deployments still run that way. /_all_dbs returning a database
    list = unauthenticated. We never read documents.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"couchdb": "httpx not installed on relay"}}

    port = port or 5984
    out: dict[str, Any] = {"auth_required": None}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                root = client.get(f"{base}/")
                if root.status_code == 401:
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                if root.status_code != 200:
                    last_err = f"{scheme} GET / -> HTTP {root.status_code}"
                    continue
                try:
                    info = root.json()
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                out["scheme"] = scheme
                out["version"] = info.get("version")
                out["vendor"] = (info.get("vendor") or {}).get("name")

                dbs = client.get(f"{base}/_all_dbs")
                if dbs.status_code == 401:
                    out["auth_required"] = True
                    return out
                if dbs.status_code == 200:
                    try:
                        names = dbs.json() or []
                    except Exception:
                        names = []
                    out["auth_required"] = False
                    # Cap — real CouchDB clusters can have thousands of dbs;
                    # the agent only needs a representative sample to size
                    # the finding.
                    out["databases"] = list(names)[:100]
                else:
                    out["_errors"] = {"_all_dbs": f"HTTP {dbs.status_code}"}
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"couchdb": last_err or "unreachable"}}


# ── Relay-side allowlist ─────────────────────────────────────────────
#
# The set of legal ops is exactly the keys of this dict. Anything else
# raises DatastoreProbeError before any network code runs — defense in
# depth behind the backend tool palette.
_OP_HANDLERS: dict[str, Any] = {
    # Phase 1a
    "redis": _probe_redis,
    "mongo": _probe_mongo,
    "elastic": _probe_elastic,
    "docker": _probe_docker,
    "k8s": _probe_k8s,
    "etcd": _probe_etcd,
    # Phase 1b
    "memcached": _probe_memcached,
    "kibana": _probe_kibana,
    "kubelet": _probe_kubelet,
    "couchdb": _probe_couchdb,
}
