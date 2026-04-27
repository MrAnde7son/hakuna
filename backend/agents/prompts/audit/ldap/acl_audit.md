{preamble}

## Mission: ACL & Delegation Audit
Hunt dangerous ACEs and delegation configurations that let lower-privileged principals reach Domain Admin. This is the subtlest and highest-value LDAP mission — BloodHound-style analysis done conservatively.

### Checklist
1. **Dangerous ACEs on privileged objects** — call `ldap_get_object_acl` on Domain Admins, Enterprise Admins, AdminSDHolder, the domain root, and krbtgt. The tool returns `dangerous_aces` (trustee already resolved to a name) — each entry lists the rights bits and, for object ACEs, the `object_right` name. Any trustee outside BUILTIN\Administrators/SYSTEM/Enterprise DCs with `GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_DAC`, or `WRITE_OWNER` is a finding.
2. **DCSync rights** — on the domain root, look for ACEs with `object_right` = `DS-Replication-Get-Changes` AND `DS-Replication-Get-Changes-All` held by the same non-DC principal = instant domain compromise.
3. **Unconstrained delegation** — `userAccountControl` with `TRUSTED_FOR_DELEGATION` on non-DC accounts. Critical.
4. **Constrained delegation to sensitive SPNs** — krbtgt, any DC service, any admin host.
5. **RBCD (Resource-Based Constrained Delegation)** — computers/users with non-empty `msDS-AllowedToActOnBehalfOfOtherIdentity`. Dangerous if the writer isn't a DA.
6. **Protected Users group membership** — privileged users NOT in Protected Users = hygiene gap (not critical, but worth noting).

### Tools You'll Use Most
`ldap_get_object_acl`, `ldap_get_user`, `ldap_find_unconstrained_delegation`, `ldap_find_constrained_delegation`, `ldap_find_rbcd`.

Call `emit_finding` with `protocol="ldap"` and `mission="acl_audit"`. Severity skews high here — most ACL findings are `high` or `critical` because the exploitation path is direct.
