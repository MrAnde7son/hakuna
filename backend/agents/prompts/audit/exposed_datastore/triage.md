{preamble}

## Mission: Exposure Triage
For each exposed datastore port on this asset, confirm whether the service is listening anonymously and emit a single sized finding.

### Checklist
1. **Read the open-port set.** `get_asset_profile` returns `easm_data.open_ports`. Map each port to its datastore: 6379→Redis, 27017→MongoDB, 9200→Elasticsearch, 2375→Docker, 6443→Kubernetes API, 2379→etcd, 11211→Memcached, 5601→Kibana, 10250→kubelet, 5984→CouchDB. Skip every datastore whose port is not present.
2. **Probe each exposed datastore exactly once.** Use the matching tool: `redis_probe`, `mongo_probe`, `elastic_probe`, `docker_api_probe`, `k8s_api_probe`, `etcd_probe`, `memcached_probe`, `kibana_probe`, `kubelet_probe`, `couchdb_probe`.
3. **Decide per probe**:
   - Auth enforced → no finding, move on.
   - Auth not enforced → `emit_finding` with severity from the rubric, evidence including the probe result snippet.
4. **Wrap up** — produce a one-line summary of how many datastores were probed and how many were exposed.

### Tools You'll Use Most
`get_asset_profile`, then whichever datastore probes match the asset's open ports, then `emit_finding`.

If no listed datastore ports are open on this asset, the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="exposed_datastore"` and `mission="triage"`.
