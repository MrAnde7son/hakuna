{preamble}

## Mission: Find the Worst Public Exposures
Hunt direct paths from the public internet to data, code execution, or credentials first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **Anonymous blob container with objects** — `azure_storage_accounts` showing `allowBlobPublicAccess=true` AND a container with `publicAccess` set to `Container` or `Blob`, AND the container has blobs. Critical when objects exist.
2. **Storage account key auth + public network** — `properties.allowSharedKeyAccess=true` AND `properties.publicNetworkAccess=Enabled` AND `properties.networkAcls.defaultAction != "Deny"`. Anyone on the internet with the storage key can read the data plane; storage keys leak from app configs constantly. Critical.
3. **NSG `*`/`0.0.0.0/0` ingress on a database port with a live listener** — NSG rule on 3306 / 5432 / 27017 / 6379 / 1433 / 11211 attached to a VM, App Service, or PaaS endpoint that's actually bound. Critical.
4. **VM with public IP + open management ports** — public IP attached + NSG allows 22 or 3389 from `*` + the VM is running. Critical (brute force + lateral); promote to compound critical if the VM also has a privileged managed identity.
5. **Function App with `authLevel: anonymous` + privileged managed identity** — anonymous HTTP trigger combined with an MSI that has Contributor/Owner or Key Vault access. Critical (anonymous code execution with the identity's role).
6. **Public Azure SQL / Cosmos / PostgreSQL / MySQL** — server-level firewall rule `0.0.0.0` to `255.255.255.255`, OR `Allow Azure Services` enabled on a sensitive DB without further restriction. Critical.
7. **Key Vault with `enabledForDeployment` / `publicNetworkAccess=Enabled` + permissive access policy** — vault data plane reachable from the internet AND an access policy granting `Get`/`List` to a broad principal. Critical (secret exfil path).

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate the function's MSI role, check the storage account's containers) and stop.

### Tier 2 — broader public surface
- NSG `*` on 80/443 fronting an admin/management UI without auth — high.
- Storage account `allowBlobPublicAccess=true` with no actually-public containers — medium (drift risk).
- App Service / Function App without `httpsOnly=true` — medium.
- Public PaaS endpoint without Private Endpoint where one was clearly intended (TLS but no network ACL) — medium.
- Application Gateway / Front Door without WAF in `Prevention` mode — medium.
- Disk snapshots with public access — high.
- Container Registry with `anonymousPullEnabled=true` — high if the registry hosts internal images.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Diagnostic settings missing on subscription-scope resources, NSG flow logs disabled, default Network Watcher not enabled, classic resource types still present, default subnet still has Service Endpoints disabled. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new. Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="azure"` and `mission="exposure"`.
