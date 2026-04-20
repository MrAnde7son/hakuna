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

# WQL strings — executed directly via IWbemServices.ExecQuery in root\cimv2.
WQL_PROFILES: dict[str, str] = {
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
