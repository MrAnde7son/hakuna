{preamble}

## Mission: AD Structure & Posture
Understand the shape of this AD forest/domain and flag structural problems: stale computers, unusual OU delegation, weak trust relationships, MachineAccountQuota abuse, schema staleness.

### Checklist
1. **Trusts** — `ldap_list_trusts` shows every trust. Flag bi-directional trusts with third-party forests, trusts with TRUST_ATTRIBUTE_QUARANTINED_DOMAIN=FALSE (SID filtering disabled), or trusts to domains you don't recognize.
2. **MachineAccountQuota** — defaults to 10, letting any authenticated user create 10 machine accounts (RBCD attack vector). Anything above 0 for unprivileged users is a finding.
3. **Stale computer accounts** — computers with `lastLogon` > 180d and `pwdLastSet` > 180d are ripe for takeover.
4. **OU structure sanity** — flag OUs with "admin"/"privileged" in name that are outside the expected admin tier, or large flat OUs (everything in Users container).
5. **Domain functional level** — below Windows Server 2016 is out of support and lacks modern security features (Kerberos AES, LAPS).

### Tools You'll Use Most
`ldap_get_domain_info`, `ldap_list_trusts`, `ldap_list_ous`, `ldap_list_computers`.

Call `emit_finding` with `protocol="ldap"` and `mission="ad_structure"`. Severity usually caps at `high` for structural issues (delegation/acl_audit missions catch the critical stuff).
