{preamble}

## Mission: Exposure Audit
Hunt every category of SNMP-visible exposure on this device — credentials, posture, inventory, and topology — in one pass. The OID cheatsheet in the preamble has the OIDs; this mission is about coverage and reasoning.

### Areas to cover

1. **Credentials & posture**
   - `snmp_probe_default_communities` first. Any accepted community is a finding (`public` = high; `private` = critical, traditionally the write community).
   - System group walk (`snmp_walk("1.3.6.1.2.1.1")`) — parse sysDescr for vendor / model / firmware. Flag EOL: IOS 12.x, IOS-XE < 16.x, pre-11.x Junos, Windows Server 2008/2012 in sysDescr, pre-2.4 Linux kernels, legacy printer firmware.
   - Empty sysContact / sysLocation on production gear → low/medium hygiene.
   - sysUpTime > 365d → missed reboot/patch windows.

2. **Inventory & topology**
   - Interfaces (ifTable). Flag admin=up + oper=down (cabled-but-broken), descriptions like "OLD-" / "DO NOT USE" still oper=up, unexpected tunnels.
   - ARP table — passive asset-discovery signal; an unexpectedly large cache on a management-only device is a finding.
   - IP addresses — flag L3 presence on management nets that shouldn't bleed into this device's role.
   - Routing table — unexpected default routes, routes into management ranges on user-facing devices.

3. **Service surface**
   - TCP listeners + UDP bound ports (tcpConnTable / udpTable). Useful on embedded devices where nmap is unreliable.

4. **Host resources** (only if HOST-RESOURCES-MIB is populated)
   - Installed software walk → cross-reference against known CVEs.
   - Running processes → spot persistence / malware from non-standard paths.

5. **Vendor MIBs** (only if sysDescr identifies a vendor and time permits)
   - Cisco config-copy MIB (`1.3.6.1.4.1.9.9.96`) — leaked configs/communities.
   - Printer MIB (`1.3.6.1.2.1.43`) — job history often leaks usernames.

### How to budget
You have ~25 steps. Spend them roughly: 1 community probe + 1 system walk + 4–5 inventory walks + 3–5 vendor/host-resources drilldowns + emits. Stop when every relevant area has been touched OR 3 probes in a row find nothing new.

### Severity reminders
Default community accepted on internet-reachable device → critical. EOL firmware with known CVEs in sysDescr → critical. Inventory findings cap at medium. Use the rubric in the preamble.

Call `emit_finding` with `protocol="snmp"` and `mission="exposure_audit"`.
