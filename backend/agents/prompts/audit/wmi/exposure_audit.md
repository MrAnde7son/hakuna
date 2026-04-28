{preamble}

## Mission: Find the Worst Exposures
Hunt direct paths to SYSTEM or domain compromise first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

Orient with `Win32_ComputerSystem` (`DomainRole`): a DC tilts toward identity-class kill-chains, a workstation toward privesc, a member server toward service-config audit. Skip a tier-1 probe only when DomainRole evidence proves it doesn't apply.

### Tier 1 — direct SYSTEM / DA paths (always run; emit on hit, then move on)
1. **EOL OS reachable** — `Win32_OperatingSystem.Caption` + `Version`. Server 2008/2008R2/2012/2012R2, Windows 7/8/8.1, Windows 10 builds before 19044 — flat critical when the host has any non-loopback service exposed.
2. **AlwaysInstallElevated = 1** — both `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` and the HKCU twin. When both are `1`, any user-context MSI runs as SYSTEM. Critical instant privesc.
3. **Unquoted service path with writable intermediate** — filter `Win32_Service` for `PathName` containing spaces and not enclosed in quotes, where `StartName` is a SYSTEM-class account, then check that an intermediate directory is writable by `Authenticated Users` or `Users`. Critical (the path-resolution fork is the privesc).
4. **SeImpersonate-class service writable on disk** — `Win32_Service` running as `LocalSystem` / `NetworkService` / `LocalService` whose binary path or working directory is writable by non-admins. Potato-class chain to SYSTEM. Critical.
5. **Local Administrators bloat with non-tier-0 principals** — `Win32_GroupUser` filtered to the local Administrators group. Domain Users, "Authenticated Users", a generic helpdesk group, or unexpected user accounts = critical on any DC; high to critical elsewhere depending on the asset.
6. **Defender realtime protection off OR signature age > 30 days** — `MSFT_MpComputerStatus`. `RealTimeProtectionEnabled=FALSE`, `AntispywareSignatureAge > 30`, or `IsTamperProtected=FALSE` on a DC, server, or internet-facing box. Critical (active malware can persist undetected).
7. **KEV-listed unpatched CVE on an exposed service** — run `correlate_software_to_cves(asset_id)` once; cross-reference `Win32_QuickFixEngineering` for missing patches. PrintNightmare, EternalBlue, ZeroLogon, ProxyShell, ProxyNotShell, and other KEV-listed CVEs that match the host's installed software/version → flat critical when the affected service is bound to a non-loopback interface.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass on the same surface (e.g. firewall state for the CVE finding, share enumeration for the SeImpersonate finding) and stop.

### Tier 2 — broader hardening surface
- BitLocker `ProtectionStatus=0` on `C:` for a portable / laptop class device.
- SMBv1 enabled (`LanmanServer\Parameters\SMB1`).
- SMB signing not required (`RequireSecuritySignature=0`).
- `LmCompatibilityLevel < 5`.
- LLMNR enabled (`DNSClient\EnableMulticast=1`); NBT-NS enabled on any interface.
- Windows Firewall profile with `Enabled=FALSE` or `DefaultInboundAction=Allow`.
- RDP NLA disabled (`WinStations\RDP-Tcp\UserAuthentication=0`).
- Service accounts running as domain users with SPNs (Kerberoast bait).
- Dangerous accounts: `Guest` enabled, RID-500 Administrator enabled with `PasswordExpires=FALSE`, `PasswordRequired=FALSE` on any active account.
- Password policy: `MinPasswordLength < 12`, `LockoutThreshold = 0`, complexity disabled.
- `Win32_StartupCommand` / scheduled tasks running SYSTEM from non-standard paths.
- Boot/system drivers (`Win32_SystemDriver`) with image paths outside `\Windows\` or `\Program Files\`.
- Privileged-group bloat: Backup Operators, Hyper-V Administrators, Remote Desktop Users with unexpected members.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Stale logins (`Win32_NetworkLoginProfile.LastLogon` > 90d on enabled accounts), default shares present, Win32_Tpm not activated on a workstation that supports it, patch cadence (most-recent `Win32_QuickFixEngineering.InstalledOn` > 60 days), `DesktopInteract=TRUE` on services without further evidence. Cap at medium. Don't pad.

### CVE triage discipline
For each top-10 CVE candidate from the correlator, reach a verdict before emitting:
- `vulnerable` — version matches, service is reachable on a non-loopback interface, no compensating control evident.
- `mitigated` — version matches but a documented mitigation is in place (firewall rule, disabled feature, KB on a related component). Emit at one severity below "vulnerable" with the control named.
- `not_applicable` — version doesn't match, or the affected component isn't installed.
- `indeterminate` — config evidence is missing. Emit `manual_review_needed`, don't pad as "vulnerable".

### Budget & stop rule
~50-step budget. Ration by tier, not by category.
- Orient + Tier 1 sweep should fit in ~25 steps (CVE correlator alone burns a few).
- Stop after one Tier-2 enrichment pass once Tier 1 produces a critical.
- Stop if Tier 1 and Tier 2 are clean and you're 5 probes into Tier 3 with nothing new.
- Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="wmi"` and `mission="exposure_audit"`.
