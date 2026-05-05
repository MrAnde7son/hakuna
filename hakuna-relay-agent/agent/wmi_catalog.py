"""WQL query catalog for credentialed Windows inventory collection.

Each profile name maps to either:
  - A plain WQL string (executed via IWbemServices.ExecQuery), or
  - The sentinel string "stdregprov:<path-key>" which tells wmi_query.py to
    walk the Uninstall subkeys under the matching HKLM path via StdRegProv.

The profile names here are the contract between the backend's
services.wmi_scanner (which ships them in the task envelope's `params.profiles`)
and services.wmi_result_mapper (which dispatches each profile's rows to the
right Inventory* table). Keep them stable.
"""

# WQL profiles. Each entry is either:
#   - A plain WQL string → executed in root\cimv2 (the default namespace), or
#   - A (namespace, query) tuple → executed in the given namespace instead.
# The executor in wmi_query.py reads the tuple form and opens the target
# namespace lazily. Cross-namespace profiles let the agent reach security-
# specific providers (MSFT_MpComputerStatus, Win32_EncryptableVolume,
# MSFT_NetFirewallProfile, etc.) that aren't in the default cimv2 namespace.
WQL_PROFILES: dict[str, str | tuple[str, str]] = {
    "software_product": (
        "SELECT Name, Version, Vendor, InstallDate FROM Win32_Product"
    ),
    "services": (
        "SELECT Name, DisplayName, State, StartMode, StartName, PathName "
        "FROM Win32_Service"
    ),
    "patches": (
        "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"
    ),
    "shares": (
        "SELECT Name, Path, Description, Type FROM Win32_Share"
    ),
    "local_users": (
        # LocalAccount = TRUE filters out domain accounts on domain-joined hosts
        "SELECT Name, SID, Disabled, Lockout, PasswordExpires, PasswordRequired, "
        "Description, FullName FROM Win32_UserAccount WHERE LocalAccount = TRUE"
    ),
    "local_groups": (
        "SELECT Name, SID, Description FROM Win32_Group WHERE LocalAccount = TRUE"
    ),
    "group_membership": (
        # Win32_GroupUser is an association class: GroupComponent → PartComponent.
        # The ref strings come back as e.g. 'Win32_Group.Domain="FOO",Name="Users"'
        # and we parse them in wmi_query._parse_ref.
        "SELECT GroupComponent, PartComponent FROM Win32_GroupUser"
    ),
    "os_info": (
        # Used to populate Asset.os downstream — cheap and always useful.
        "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate "
        "FROM Win32_OperatingSystem"
    ),

    # ── Audit-oriented probes (added for WMI Audit ReAct agent) ──
    #
    # These don't populate Inventory* tables directly — the WMI audit agent
    # uses them to reason about exposures (weak password policy, writable
    # service perms, unquoted service paths, etc.) and then emits findings.

    "password_policy": (
        # Win32_AccountPolicy lives in root\cimv2\Security\MicrosoftTpm on some
        # SKUs; most commonly available via `net accounts` semantics through
        # Win32_NetworkLoginProfile. We read the common policy fields from
        # Win32_NetworkLoginProfile joined with Win32_OperatingSystem context.
        # Note: the richer Win32_AccountPolicy is deprecated; this is the best
        # read-only view of effective policy on modern Windows.
        "SELECT MinimumPasswordLength, PasswordHistorySize, MaximumPasswordAge, "
        "MinimumPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow "
        "FROM Win32_NetworkLoginProfile"
    ),

    "services_with_paths": (
        # Same as "services" but always includes PathName — used by the agent
        # to check unquoted-path privesc. Kept distinct so the default inventory
        # profile can stay lean.
        "SELECT Name, DisplayName, State, StartMode, StartName, PathName, "
        "ServiceType, DesktopInteract FROM Win32_Service"
    ),

    "logged_on_users": (
        "SELECT Name, Domain, LogonType FROM Win32_LoggedOnUser"
    ),

    "scheduled_tasks": (
        # Win32_ScheduledJob is legacy (at.exe jobs) but still reveals
        # persistence mechanisms. Modern scheduled tasks live in
        # root\Microsoft\Windows\TaskScheduler (separate namespace — fetched
        # by a dedicated audit tool when the agent asks).
        "SELECT Caption, Command, Owner, Status, JobId, Elapsed "
        "FROM Win32_ScheduledJob"
    ),

    "network_adapters": (
        "SELECT Name, MACAddress, IPEnabled, IPAddress, DefaultIPGateway, "
        "DNSServerSearchOrder, DHCPEnabled FROM Win32_NetworkAdapterConfiguration "
        "WHERE IPEnabled = TRUE"
    ),

    "firewall_profiles": (
        # MS_409 / StandardProfile via root\StandardCimv2 is the modern path;
        # this returns the legacy view which still reports enabled state.
        "SELECT Name, Description FROM __NAMESPACE"
    ),

    "startup_commands": (
        # Registry Run keys + common persistence locations as seen by WMI.
        "SELECT Caption, Command, Location, User, UserSID "
        "FROM Win32_StartupCommand"
    ),

    "installed_hotfix_detail": (
        # Richer than `patches` — includes InstalledBy / InstalledOn for
        # reasoning about patch cadence and stale systems.
        "SELECT HotFixID, Description, InstalledBy, InstalledOn, FixComments "
        "FROM Win32_QuickFixEngineering"
    ),

    "computer_system": (
        # Domain membership, last boot, manufacturer — context the agent uses
        # to decide if this is a DC, workstation, or server.
        "SELECT Name, Domain, DomainRole, Manufacturer, Model, "
        "PartOfDomain, TotalPhysicalMemory FROM Win32_ComputerSystem"
    ),

    # ── Cross-namespace profiles (security providers) ────────────────────
    #
    # These live outside root\cimv2. The executor opens a fresh IWbemServices
    # against the named namespace for these. Per-profile error isolation
    # still applies — missing providers (e.g., MSFT_NetFirewallProfile on
    # pre-Win8 hosts) yield a _errors entry rather than failing the batch.

    "defender_status": (
        r"root\Microsoft\Windows\Defender",
        "SELECT AMEngineVersion, AntivirusEnabled, AntispywareEnabled, "
        "BehaviorMonitorEnabled, NISEnabled, OnAccessProtectionEnabled, "
        "RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, "
        "QuickScanAge, FullScanAge, TamperProtectionSource, "
        "IsTamperProtected FROM MSFT_MpComputerStatus",
    ),

    "firewall_profile": (
        r"root\StandardCimv2",
        # Enabled: 1=true/0=false. DefaultInboundAction: 2=Block 4=Allow.
        # Modern API; preferred over the legacy HNetCfg/FwPolicy2 COM object.
        "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction, "
        "LogAllowed, LogBlocked, LogIgnored, LogFileName, LogMaxSizeKilobytes, "
        "AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, "
        "AllowUserApps, AllowUserPorts, NotifyOnListen "
        "FROM MSFT_NetFirewallProfile",
    ),

    "bitlocker_volumes": (
        r"root\cimv2\Security\MicrosoftVolumeEncryption",
        # ProtectionStatus: 0=unprotected 1=protected 2=unknown.
        # EncryptionMethod: 0=none, 1=AES128_diffuser, 2=AES256_diffuser,
        # 3=AES128, 4=AES256, 6=XTS_AES128, 7=XTS_AES256.
        "SELECT DeviceID, DriveLetter, PersistentVolumeID, ProtectionStatus, "
        "EncryptionMethod, ConversionStatus, VolumeType, LockStatus "
        "FROM Win32_EncryptableVolume",
    ),

    "tpm_info": (
        r"root\cimv2\Security\MicrosoftTpm",
        "SELECT IsActivated_InitialValue, IsEnabled_InitialValue, "
        "IsOwned_InitialValue, ManufacturerId, ManufacturerVersion, "
        "SpecVersion, PhysicalPresenceVersionInfo "
        "FROM Win32_Tpm",
    ),

    # ── Root\cimv2 additions (no namespace change) ───────────────────────

    "system_drivers": (
        # Kernel driver inventory + signing state. StartMode of Boot/System
        # + unsigned is a classic rootkit / legacy-driver indicator.
        "SELECT Name, DisplayName, State, StartMode, PathName, ServiceType "
        "FROM Win32_SystemDriver"
    ),

    "shares_detailed": (
        # Same as `shares` but with AllowMaximum for connection caps — some
        # checks flag shares with unlimited connections as risky.
        "SELECT Name, Path, Description, Type, AllowMaximum "
        "FROM Win32_Share"
    ),
}


# StdRegProv profiles — the handler in wmi_query.py walks the Uninstall subkeys
# and reads DisplayName / DisplayVersion / Publisher / InstallDate.
# Both HKLM paths are covered so 32-bit apps on 64-bit Windows are captured.
STDREGPROV_UNINSTALL_PATHS: list[str] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]


# Fields we pull from each Uninstall subkey. Missing values return empty strings.
UNINSTALL_VALUES: list[str] = ["DisplayName", "DisplayVersion", "Publisher", "InstallDate"]


# Default profiles executed when the backend doesn't specify a subset —
# aligns with v1 scope in /Users/itamar/.claude/plans/wild-finding-sedgewick.md.
DEFAULT_PROFILES: list[str] = [
    "os_info",
    "software_uninstall",  # primary software source (StdRegProv registry walk)
    "software_product",    # secondary, MSI-only — catches what Uninstall misses
    "services",
    "patches",
    "shares",
    "local_users",
    "local_groups",
    "group_membership",
]


def known_profile(name: str) -> bool:
    return name in WQL_PROFILES or name == "software_uninstall"


# Audit-only profiles — not included in DEFAULT_PROFILES (so inventory-style
# sweeps stay lean), but callable via the WMI audit agent's tool palette.
AUDIT_PROFILES: list[str] = [
    "password_policy",
    "services_with_paths",
    "logged_on_users",
    "scheduled_tasks",
    "network_adapters",
    "startup_commands",
    "installed_hotfix_detail",
    "computer_system",
]
