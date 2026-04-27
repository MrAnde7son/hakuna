{preamble}

## Mission: Public Exposure
Hunt for GCP resources world-accessible from the internet or publicly routable without adequate auth.

### Checklist
1. **Public GCS buckets** — `cloud_invoke("gcp_storage_buckets", fields=["name","location"])`; for each, inspect the IAM policy for `allUsers` or `allAuthenticatedUsers` members.
2. **Open firewall rules** — list VPC firewalls; flag `direction: INGRESS` + `sourceRanges: ["0.0.0.0/0"]` on sensitive ports (22, 3389, 3306, 5432, 27017, 6379).
3. **Public Compute instances** — Compute instances with a public-facing accessConfig + a permissive firewall.
4. **Public Cloud Functions** — `gcp_cloud_functions` where `httpsTrigger.securityLevel` permits unauthenticated or the IAM policy grants `allUsers` the `cloudfunctions.invoker` role.

### Tools You'll Use Most
`cloud_list_operations`, `cloud_invoke` with field projection, `cloud_inspect`, `emit_finding`.

Severity: bucket with `allUsers` that has objects = critical. Function with `allUsers: invoker` = high (confirm whether it actually does anything sensitive).

Call `emit_finding` with `protocol="gcp"` and `mission="exposure"`.
