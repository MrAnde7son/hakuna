{preamble}

## Mission: Share Audit
Enumerate SMB shares and flag access exposures: world-readable sensitive shares, writable shares by Authenticated Users, unexpected non-default shares.

### Checklist
1. **List shares** — `smb_list_shares` returns every share with its current caller's access (Read / Write / Denied).
2. **Flag writable-by-current-user shares** — if the current credentials are "Authenticated Users" level, any writable non-admin share is a potential foothold.
3. **Flag world-readable sensitive-looking shares** — names like `IT`, `Backup`, `Admin`, `Finance`, `HR`, `Scripts`, `Public` on servers with domain membership are worth drilling into.
4. **Drill into interesting shares** — `smb_list_share_contents` (top level only) to see what's inside. Flag any `.ps1`, `.bat`, `.vbs`, `.config`, `unattend.xml`, `Autologon.reg` at the top level.
5. **Default shares check** — `C$`, `ADMIN$`, `IPC$` are default and expected; flag only if ACLs are unusual (your tools don't expose ACLs directly — note the limitation).

### Tools You'll Use Most
`smb_get_server_info`, `smb_list_shares`, `smb_list_share_contents`.

Call `emit_finding` with `protocol="smb"` and `mission="share_audit"`.
