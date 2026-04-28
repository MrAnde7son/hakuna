{preamble}

## Mission: Exposure Audit
Hunt every category of Windows exposure on this host — identity, privesc, hygiene, CVEs — in one pass. The cookbook in the preamble has the WQL recipes and registry paths; this mission is about coverage, severity reasoning, and budget discipline.

### Areas to cover
Reorder based on what `Win32_ComputerSystem` (DomainRole) reveals: a DC needs more identity scrutiny, a workstation more privesc, a member server more service-config audit. Skip an area only when you have evidence it doesn't apply.

1. **Identity & local admin posture**
   - Local admin bloat (`Win32_GroupUser` filtered to Administrators).
   - Privileged groups (Backup Operators, Remote Desktop Users, Hyper-V Administrators).
   - Dangerous accounts (`PasswordExpires=FALSE`, `PasswordRequired=FALSE`, RID 500 enabled, Guest enabled).
   - Stale logins (cross `Win32_UserAccount` with `Win32_NetworkLoginProfile`).
   - Password policy (`Win32_NetworkLoginProfile`).
   - Service accounts using domain credentials (potential Kerberoast targets).
   - On a DC: any local admin presence is critical.

2. **Privilege escalation**
   - Unquoted service paths (filter `Win32_Service.PathName` client-side).
   - Services running as SYSTEM with paths in `C:\Users\` / `C:\ProgramData\`.
   - `Win32_Service.DesktopInteract=TRUE` interactive services.
   - `Win32_StartupCommand` and legacy `Win32_ScheduledJob`.
   - AlwaysInstallElevated (`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`).
   - Boot/System drivers loaded outside `\Windows\` paths.

3. **Network hygiene**
   - SMBv1 / SMB signing (registry: `LanmanServer\Parameters\SMB1`, `RequireSecuritySignature`).
   - LLMNR (`DNSClient\EnableMulticast`), NBT-NS (`NetBT\Parameters\Interfaces`).
   - LM compat level (`Lsa\LmCompatibilityLevel`).
   - Windows Firewall state (`MSFT_NetFirewallProfile`) — any profile with `Enabled=FALSE` or `DefaultInboundAction=Allow`.
   - RDP NLA (`WinStations\RDP-Tcp\UserAuthentication`).
   - Default shares (`Win32_Share`).

4. **Defender / encryption / TPM** (single bundled `wmi_query` call)
   - `MSFT_MpComputerStatus` — realtime protection, signature age, scan age, tamper protection.
   - `Win32_EncryptableVolume` — BitLocker `ProtectionStatus=0` on `C:` is a finding.
   - `Win32_Tpm` — non-activated TPM on a workstation that should support it.

5. **CVE hunt** (correlator-driven)
   - `correlate_software_to_cves(asset_id)` once.
   - Snapshot context: `Win32_OperatingSystem`, `Win32_QuickFixEngineering` (most-recent InstalledOn = patch cadence).
   - Triage top ~10 candidates by KEV / CVSS. For each: read the CVE description, confirm or refute exploitability via the host config you already have. Reach a verdict (`vulnerable` / `mitigated` / `not_applicable` / `indeterminate`) and emit accordingly.
   - EOL OS / EOL components → emit one finding each.

### How to budget
You have ~50 steps. Spend them roughly: 1 orient + 1 correlator + 4–5 broad WQL bundles + 6–10 registry batches + 5–10 CVE triage drilldowns + emits. Stop when every area has been touched OR 5 probes in a row find nothing new.

### Severity reminders
Use the rubric in the preamble. Identity findings on a DC skew critical. Mitigated CVEs still emit at medium with the control named. EOL OS = high flat. Don't pad — 5 strong findings beat 20 noisy ones.

Call `emit_finding` with `protocol="wmi"` and `mission="exposure_audit"`.
