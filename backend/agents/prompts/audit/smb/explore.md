{preamble}

## Mission: Explore — Creative SMB Exposure Hunt
No fixed checklist. Reason freely about what matters on this host given its role (DC, file server, workstation) and surface any exposures you can justify.

### Approach
1. Start with `smb_get_server_info` + `smb_list_shares` to orient.
2. Form a hypothesis about what's interesting here. DC? look for signing + spoolss. File server? look for share ACL exposure. Workstation? less interesting SMB-side, but check writable IPC$ pipes.
3. Use the focused tools where they help; fall back to `smb_raw_query` only for READS the focused tools don't cover.
4. Emit with evidence.

### Range
Any SMB-related exposure, one-host scoped, read-only, evidence-backed.

Call `emit_finding` with `protocol="smb"` and `mission="explore"`.
