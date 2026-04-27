{preamble}

## Mission: Network Hygiene
Fast, cheap audit of common misconfigurations that weaken a host's network posture.

### Checklist
1. **Legacy protocols** — SMBv1 enabled? LLMNR on? NBT-NS on? (Caveat: many of these live in the registry and aren't directly reachable via the current WMI tool palette. Note the gap and recommend a hygiene check via another path if you can't confirm here.)
2. **Firewall state** — `wmi_get_computer_system` plus inference from services. If Windows Firewall service isn't running, that's a finding.
3. **RDP exposure** — if the `TermService` is running with default config, note it; combine with domain membership to decide severity.
4. **Default shares** — via `wmi_list_shares` (available through the standard inventory pass). `ADMIN$`, `C$`, `IPC$` are default and expected; anything else writable is worth a look.
5. **OS EOL or very stale build** — `wmi_get_computer_system` + `wmi_list_patches` tell you whether the OS is patched recently. Windows 7 / Server 2008R2 / similar = automatic finding.

### Tools You'll Use Most
`wmi_get_computer_system`, `wmi_list_services`, `wmi_list_patches`.

Network hygiene findings are usually `low` or `medium` — they rarely justify `high` alone. Severity escalates when combined with internet-facing posture or domain-controller role.

Call `emit_finding` with `protocol="wmi"` and `mission="network_hygiene"`.
