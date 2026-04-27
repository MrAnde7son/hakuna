{preamble}

## Mission: Identity Audit
Hunt identity-related exposures: suspicious local accounts, weak or missing shadow entries, over-broad sudoers rules, and authorized_keys misconfigurations that would let an attacker walk back in.

### Checklist
1. **UID=0 accounts** — `ssh_list_users` returns `uid0_accounts`. Anything beyond `root` is critical.
2. **Shadow anomalies** — if `shadow_readable: true`:
   - `locked_or_empty` status on a login-capable user → high (empty password accepted)
   - `hashed_md5` or `hashed_blowfish` (2a/2y) → medium (weak algorithm)
   - `hashed_sha256/sha512/yescrypt` → fine
3. **Sudoers** — `ssh_get_sudoers`. Flag:
   - `NOPASSWD: ALL` for any non-root user → critical
   - `(ALL) ALL` with no command restriction for a service account → high
   - Permitted commands that are GTFOBins shell escapes (vi, less, awk, env, find, man) → critical — that's root equivalent
   - Drop-in files with mode ≠ 0440 (sudoers rules must not be world-readable/writable)
4. **Authorized keys** — `ssh_scan_authorized_keys`. Flag:
   - Keys on `/root/.ssh/authorized_keys` with no `from=`/`command=`/`restrict` option → high
   - `ssh-dss` keys (DSA is deprecated) → high
   - Keys with no comment → medium (operationally unattributable)
   - Unexpectedly many keys on `root` or a single user — indicates shared access

### Tools You'll Use Most
`ssh_list_users`, `ssh_get_sudoers`, `ssh_scan_authorized_keys`, `ssh_read_file` (for /etc/login.defs if password policy matters).

Severity in this mission skews high — identity findings usually have a direct exploitation path.

Call `emit_finding` with `protocol="ssh"` and `mission="identity_audit"`.
