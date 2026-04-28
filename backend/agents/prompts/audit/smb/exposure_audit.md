{preamble}

## Mission: Exposure Audit
Hunt every category of SMB-visible exposure on this host — share access, auth posture, coercion primitives, registry hygiene — in one pass.

### Areas to cover
Reorder based on what `smb_get_server_info` reveals. A DC needs more signing/coercion scrutiny; a file server more share-content scrutiny.

1. **Server posture**
   - `smb_get_server_info` for dialect, signing state, OS, domain membership.
   - `signing=disabled` on a DC is critical (NTLM relay enabler); anywhere else high.

2. **Shares & content**
   - `smb_list_shares` — note each share's caller-access (`read` / `connect_only` / `denied`).
   - Flag writable non-admin shares (foothold) and world-readable sensitive-looking names (`IT`, `Backup`, `HR`, `Scripts`, `Public`).
   - Drill into interesting shares with `smb_list_share_contents` — the tool pre-flags `.ps1` / `.bat` / `.config` / `unattend.xml` / `Autologon.reg`.
   - Use `smb_read_file` (max 64 KB) on small suspect files. Watch for plaintext credentials, GPP cpassword in `Groups.xml`/`registry.xml`. Redact secret values in findings.

3. **Anonymous exposure**
   - `smb_check_null_session`. If accepted: `smb_list_shares(anonymous=true)`, `smb_samr_enum_users_anonymous`, `smb_check_guest_access`.
   - Every share visible anonymously is a finding (severity by content).

4. **Coercion primitives** (reachability only — no exploitation)
   - `smb_check_named_pipe("spoolss")` — PrinterBug.
   - `smb_check_named_pipe("efsrpc")` / `("lsarpc")` — PetitPotam.
   - `smb_check_named_pipe("netdfs")` — DFSCoerce.
   - `smb_check_named_pipe("DAV RPC Service")` — WebClient/WebDAV relay.
   - DC + signing disabled + spoolss reachable = critical compound finding.

5. **Auth + password policy**
   - `smb_samr_password_policy` — flag `min_password_length < 12`, `lockout_threshold=0`, complexity disabled, `password_history < 5`.

6. **Registry hygiene** (when WMI isn't available; otherwise WMI is preferred)
   - `smb_registry_read` for: SMBv1 enabled (`LanmanServer\Parameters\SMB1`), LanMan compat (`Lsa\LmCompatibilityLevel`), autologon (`Winlogon\AutoAdminLogon`/`DefaultPassword`), AlwaysInstallElevated.

### How to budget
You have ~30 steps. Spend them roughly: 1 server-info + 2 share enumerations + 3–5 share-content drilldowns + 4 coercion-pipe checks + 1 password-policy + 5 registry batches + emits. Stop when every area has been touched OR 3 probes in a row find nothing new.

### Severity reminders
- Critical: writable share usable by Authenticated Users to drop a payload that a service loads; signing not required + NTLM allowed + PetitPotam reachable; autologon plaintext password in registry.
- High: null-session-enumerable users; world-readable share with credentials in a file; GPP cpassword in SYSVOL.
- Medium: hygiene gaps (guest enabled but restricted, non-default shares without descriptions).
- Low: default shares present, signing required (fine).

Call `emit_finding` with `protocol="smb"` and `mission="exposure_audit"`.
