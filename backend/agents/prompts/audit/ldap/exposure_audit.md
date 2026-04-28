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
