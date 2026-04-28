{preamble}

## Mission: Find the Worst Public Exposures
Hunt direct paths from the public internet to data, code execution, or credentials first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **GCS bucket with `allUsers`/`allAuthenticatedUsers` and objects** — bucket IAM policy contains either anonymous member, AND the bucket actually has objects. Critical when objects exist; high otherwise.
2. **Open VPC firewall on a database port with a live listener** — `direction: INGRESS` + `sourceRanges: ["0.0.0.0/0"]` on 3306 / 5432 / 27017 / 6379 / 9200 / 1433 / 11211, attached to a Compute instance / Cloud SQL endpoint that's actually bound. Critical.
3. **Cloud Function / Cloud Run with `allUsers: invoker` on a privileged service account** — public invoker binding combined with an attached SA that holds project-level `roles/owner`, `roles/editor`, or `roles/iam.serviceAccountTokenCreator`. Critical (anonymous code execution with the SA).
4. **Compute instance with public IP + open SSH/RDP + privileged SA attached** — `accessConfigs` set + firewall allows 22 from `0.0.0.0/0` + instance SA has non-trivial perms. Critical (brute force + metadata SA exfil).
5. **Cloud SQL instance with public IP + authorized network `0.0.0.0/0`** — DB endpoint reachable from anywhere. Critical.
6. **GKE control plane with public endpoint + master-authorized-networks unrestricted** — `privateClusterConfig.enablePrivateEndpoint=false` + `masterAuthorizedNetworksConfig.enabled=false` (or CIDRs include `0.0.0.0/0`). Critical (kubectl reachable from internet).
7. **KMS key with `allUsers` / `allAuthenticatedUsers` on a `cloudkms.cryptoKeyEncrypterDecrypter` role binding** — key takeover. Critical regardless of the key's encryption usage.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. confirm SA role for the Function/Run finding, check instance metadata for the Compute finding) and stop.

### Tier 2 — broader public surface
- VPC firewall `0.0.0.0/0` on 22/3389 to any tagged compute — high.
- GCS bucket with `allUsers: storage.objectViewer` but only non-sensitive content — medium; flag `manual_review_needed` if you can't classify cheaply.
- Cloud Function `allUsers: invoker` on a function with no consequential SA — medium.
- Cloud Run service public-by-default flag (`ingress: all`) without Cloud Armor or IAP — medium.
- Public Cloud SQL with authorized networks restricted to specific IPs (still public, but bounded) — medium.
- Disk images shared publicly — high if the project doesn't deliberately publish them.
- Pub/Sub topics or Datastore/Firestore databases with anonymous bindings — high.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Default network still present, OS Login disabled at project level, VPC flow logs disabled, default project SA still attached to compute (without role audit), Org Policy `iam.allowedPolicyMemberDomains` not enforced. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new. Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="gcp"` and `mission="exposure"`.
