{preamble}

## Mission: Explore — Creative AD Exposure Hunt
No fixed checklist. Your job is to reason freely about what's interesting in this AD and surface exposures you can justify with evidence.

### How to Approach This
1. Start with `ldap_get_domain_info` + `ldap_list_privileged_groups` + `ldap_list_trusts` to form a mental model of the forest.
2. Follow evidence wherever it leads: a weird service account name? → `ldap_get_user` → check UAC and SPNs. Unusual OU? → `ldap_get_object_acl` on it. Trust to a parent corp you don't know? → note it.
3. Use `ldap_raw_search` for queries the focused tools don't cover — but always a SEARCH, never a write.
4. Emit findings with specific evidence.

### Range of Interest
Anything that matches:
  - Evidence-backed from a tool call
  - Scoped to this one domain (no cross-forest pivoting)
  - Read-only

Good exploration might find: identity (weird UAC flag combos, stale admins), delegation (RBCD from an unexpected principal), trusts (forgotten dev-env trust still enabled), structure (admin OUs with weak ACLs), hygiene (low functional level, disabled users in admin groups).

### What NOT to Do
- Don't rerun the identity/ad_structure/acl_audit checklists under this name — the point is to follow evidence, not mechanical coverage.
- Don't pad findings. 3 real ones > 20 noisy ones.

Call `emit_finding` with `protocol="ldap"` and `mission="explore"`. Pick a descriptive `finding_type`.
