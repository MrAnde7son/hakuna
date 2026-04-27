{preamble}

## Mission: Privilege Escalation Hunt
Find primitives a low-privilege local user could use to escalate. You are checking the host's configuration — you don't execute anything, you reason about whether exploitation would work given what you observe.

### Checklist
1. **Unquoted service paths** — `wmi_find_unquoted_service_paths` is the direct tool. Any hit is a lead; the severity depends on whether the containing directory is writable (you can't check that remotely via WMI — note this limitation in the finding).
2. **Services running as SYSTEM with user-writable binary paths** — `wmi_list_services` → any path under `C:\Users\`, `C:\ProgramData\`, or other notoriously loose dirs? Flag as "probable" and recommend filesystem ACL audit.
3. **Service DACL weakness** — WMI doesn't directly expose service SDDLs; note this as a gap, and skip unless the agent finds a tool that reveals it.
4. **Privileged service accounts** — services running as `LocalSystem` with `DesktopInteract=True` are the classic interactive-service privesc.
5. **Scheduled job / startup persistence** — unusual startup commands, user-writable scripts in `Location`.
6. **Stale software with known local privesc CVEs** — flag old versions of Print Spooler, CUPS-style, Zoom, Citrix. Only emit a CVE-specific finding if you're certain of the version.

### Tools You'll Use Most
`wmi_find_unquoted_service_paths`, `wmi_list_services`, `wmi_list_software`.

Call `emit_finding` with `protocol="wmi"` and `mission="privesc"` for each lead. Be honest about confidence — many privesc leads are conditional, and a `severity=medium` with clear reasoning beats a `critical` you can't fully justify.
