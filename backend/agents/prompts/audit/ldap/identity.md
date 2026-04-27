{preamble}

## Mission: Identity Audit
Hunt identity-related exposures in this AD domain. This is the highest-leverage AD mission — kerberoastable accounts and AS-REP roastable accounts are near-universal findings that directly enable password cracking.

### Checklist
1. **Kerberoastable accounts** — `ldap_find_kerberoastable` returns users with `servicePrincipalName` set. Every one is a potential cracking target. Severity by privilege: svc accounts in Domain Admins → critical; svc accounts in any AdminSDHolder-protected group → high; other users → medium.
2. **AS-REP roastable accounts** — `ldap_find_asrep_roastable` returns users whose UAC has `DONT_REQUIRE_PREAUTH=TRUE`. Same severity rubric.
3. **Weak Kerberos encryption** — `ldap_find_weak_kerberos_encryption` returns principals without AES enabled (they default to RC4). Combined with Kerberoast, RC4-only service accounts crack orders-of-magnitude faster. High when the principal has an SPN; medium otherwise.
4. **Password not required** — `ldap_find_password_not_required` returns enabled users with UAC `PASSWD_NOTREQD`. Almost always critical — empty-password accounts are trivially compromised.
5. **Stale accounts** — `ldap_find_stale_accounts` returns enabled users with `lastLogonTimestamp` older than 180 days. Critical when `is_admin=true` or `pwd_never_expires=true`.
6. **Privileged group membership** — call `ldap_list_privileged_groups` and for each dangerous group (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators) drill into members. Flag any unexpected accounts, disabled accounts still in groups, or service accounts in admin groups.
7. **Password policy weakness** — `ldap_get_password_policy` returns domain-level policy. Flag `MinimumPasswordLength < 14`, `LockoutThreshold = 0`, `ComplexityEnabled = False`.
8. **Dangerous delegation** — unconstrained delegation on any non-DC, constrained delegation to krbtgt, RBCD permissions.

### Tools You'll Use Most
`ldap_get_domain_info`, `ldap_find_kerberoastable`, `ldap_find_asrep_roastable`, `ldap_find_weak_kerberos_encryption`, `ldap_find_password_not_required`, `ldap_find_stale_accounts`, `ldap_list_privileged_groups`, `ldap_get_group_members`, `ldap_get_user`, `ldap_get_password_policy`.

Call `emit_finding` with `protocol="ldap"` and `mission="identity"` for each exposure.
