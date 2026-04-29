{preamble}

## Mission: Find the Worst Exposures
Hunt direct paths to Domain Admin first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct DA paths (always run; emit on hit, then move on)
These are the compound findings a red team would chain in the first hour.

1. **Kerberoastable tier-0 account** — intersect SPN-bearing users with membership in Domain Admins / Enterprise Admins / Schema Admins / Administrators / Account Operators. A roastable account in any tier-0 group is critical regardless of password strength (offline crack at attacker's leisure).
2. **AS-REP roastable tier-0 account** — same intersection with `DONT_REQUIRE_PREAUTH`.
3. **Unconstrained delegation on non-DC** — `TRUSTED_FOR_DELEGATION` set on a computer that isn't a DC. Any user authenticating to it leaks their TGT. Pull `lastLogonTimestamp` to show it's live.
4. **DCSync-capable non-tier-0 principal** — `ldap_get_object_acl` on the domain root; flag any principal outside tier-0 holding `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`.
5. **Dangerous ACE on a tier-0 object** — `ldap_get_object_acl` on the Domain Admins group, `AdminSDHolder` (`CN=AdminSDHolder,CN=System,<root>`), `krbtgt`, and the domain root. Flag `GENERIC_ALL` / `WriteDACL` / `WriteOwner` / `WriteProperty(member)` held by anything outside tier-0.
6. **krbtgt staleness** — `pwdLastSet` on `krbtgt` > 5 years. Golden-ticket forgery window is functionally unlimited. High flat; critical if combined with DCSync exposure above.
7. **RBCD takeover precondition** — `ms-DS-MachineAccountQuota > 0` on the domain *and* a tier-0 computer object whose `nTSecurityDescriptor` is writable by a non-tier-0 principal. The pair is the precondition; emit as one compound finding, not two.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (constrained-delegation chains, weak-enc on the same principal) and stop.

### Tier 2 — broader identity surface
- Kerberoastable / AS-REP roastable accounts outside tier-0 — high if a privileged service account, medium otherwise.
- `PASSWD_NOTREQD` enabled on active accounts.
- Constrained delegation (`msDS-AllowedToDelegateTo`) targeting krbtgt or DC services — high.
- RBCD already configured (`msDS-AllowedToActOnBehalfOfOtherIdentity` set) — `ldap_get_object_acl` on the principal to identify the writer; high when the writer is non-tier-0.
- Privileged group bloat: Domain Admins / Enterprise Admins membership above expected count, service accounts in admin groups, disabled accounts still in admin groups.
- Privileged users not in Protected Users.
- Weak Kerberos encryption (`msDS-SupportedEncryptionTypes` lacks AES bits) on tier-0 accounts only — skip on regular accounts.
- Trusts (`trustedDomain`) where `trustAttributes` does not enable SID filtering.
- GPOs carrying CSE GUID `{17d89fec-5c44-4972-b12d-241caef74509}` — emit `manual_review_needed`; the cpassword evidence is in SYSVOL and belongs to the SMB audit.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Domain password policy weakness, stale enabled users, stale computer accounts, domain functional level below 7, OU structure, GPOs disabled but still linked. Cap at medium. Don't pad — these alone don't motivate a remediation sprint.

### Budget & stop rule
~50-step budget. Ration by tier, not by category.
- Orient + Tier 1 sweep should fit in ~20 steps.
- Stop after one Tier-2 enrichment pass once Tier 1 produces a critical.
- Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.
- Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="ldap"` and `mission="exposure_audit"`.

### Attack-graph edges (emit alongside findings)
After a Tier-1 emit, also call `emit_edge` once per kill-chain capability you proved. The Coordinator chains these into multi-hop paths.
- **DCSync-capable principal** (Tier-1 #4 hit) → `emit_edge(edge_type="principal_to_domain", properties={"principal": "<sAMAccountName or SID>", "method": "dcsync"}, confidence="confirmed", enabled_by_finding_id=<id>)`. Leave both `src_asset_id` and `dst_asset_id` null — the principal is the source, the domain is the sink. Dump the principal name in `properties.principal`.
- **Dangerous ACE on a tier-0 object** (Tier-1 #5: GENERIC_ALL / WriteDACL / WriteOwner held by a non-tier-0 principal on Domain Admins / AdminSDHolder / krbtgt / domain root) → `emit_edge(edge_type="principal_to_domain", properties={"principal": "<name>", "method": "ace_<right>", "target": "<dn>"}, enabled_by_finding_id=<id>)`. Same null endpoints.
- **Unconstrained delegation on non-DC** (Tier-1 #3) → `emit_edge(edge_type="asset_to_asset_auth", src_asset_id=<the delegating computer's asset id, if known>, properties={"delegation": "unconstrained"}, enabled_by_finding_id=<id>)`. Leave `dst_asset_id` null (any TGT-holding principal can land here). If you don't have an asset id for the computer (LDAP-only data), omit the edge — don't fabricate.
- **RBCD takeover precondition** (Tier-1 #7) → `emit_edge(edge_type="asset_to_asset_auth", src_asset_id=<tier-0 computer asset id, if known>, properties={"delegation": "rbcd", "writer": "<non-tier-0 principal>"}, enabled_by_finding_id=<id>)`.

Don't emit edges for Tier 2/3 hygiene — only for capabilities a chain could traverse. Use confidence `confirmed` only when the LDAP attribute / ACE bit was directly read; `high` when inferred from membership.

### Leads (end-of-budget only)
At the very end of the run — when you're stopping by the budget rule above — call `emit_lead` for any *neighboring* surface you observed but did not audit. The Cross-Scan Chain Coordinator picks these up on the next tick and dispatches the suggested probe; it does not re-trigger the audit you're finishing now. Use this *instead of* burning further budget on a different domain object.

Each lead is one specific asset hint plus a reason. Don't lead on "the domain." Examples worth emitting:
- A computer object holds writable `nTSecurityDescriptor` for an *RBCD* takeover precondition (Tier-1 #7) — emit the edge, then emit a lead pointing the SMB audit at that computer (`suggested_protocol="smb"`, reason names the writer principal). The lead is the *follow-up exposure* hunt on the takeover target.
- Unconstrained delegation on a non-DC computer (Tier-1 #3) → `suggested_protocol="smb"` lead against that computer; reason notes that any TGT-holding principal authenticating there is leakable, so SMB / share posture matters next.
- `lastLogonTimestamp` reveals a tier-0 account is active on a server whose name appears in `servicePrincipalName` but didn't surface in your inventory edges → `suggested_protocol="smb"` lead on that server.
- You saw a child / forest-trust `trustedDomain` whose `trustAttributes` lacks SID filtering and the trusted DC name is resolvable in this org's inventory → `suggested_protocol="ldap"` lead on the other DC, reason naming the trust attributes.

Skip leads that just restate a Tier-1/2 finding (the Coordinator already sees those). Pass `target_asset_id` if `get_asset_profile` resolved it; otherwise pass `target_asset_hint` with the hostname/fqdn/ip exactly as you observed it. If you only have a principal / SID and no asset, prefer the existing `principal_to_domain` edge over a fabricated lead — leads need an asset target. Leads are bounded by the same per-asset cooldowns and org-level enable switches as any other dispatch — you do not bypass policy by emitting one.
