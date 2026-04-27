{preamble}

## Mission: Null Session & Anonymous Exposure
Check what an unauthenticated caller can see on this host — a classic legacy-Windows misconfiguration that often survives on old domain controllers and file servers.

### Checklist
1. **Null session viability** — `smb_check_null_session` tries an anonymous bind. If it succeeds, that's the lead.
2. **If null session works**: call `smb_list_shares_anonymous` — every share visible to null session is a finding. Flag severity by content type (IPC$ alone is fine; a "Users" share visible anonymously is critical).
3. **SAMR via null session** — `smb_samr_enum_users_anonymous` — if user enumeration works without credentials, that's the full "anonymous user list" finding.
4. **Guest account enabled** — some hosts allow Guest logins as a fallback. Worth checking via `smb_check_guest_access`.

### Tools You'll Use Most
`smb_check_null_session`, `smb_list_shares_anonymous`, `smb_samr_enum_users_anonymous`, `smb_check_guest_access`.

If null session is closed, this mission emits nothing (which is the correct result — say so and stop).

Call `emit_finding` with `protocol="smb"` and `mission="null_session"`.
