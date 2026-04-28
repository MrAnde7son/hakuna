{preamble}

## Mission: Find the Worst Exposures
Hunt direct paths to device control, config exfil, or pivot first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **Write community accepted** — `snmp_probe_default_communities` reveals `private` (or any other write community) is accepted. Full device control via SET; on Cisco gear this means config rewrite. Critical.
2. **Read community accepted on internet-reachable device** — `public` or any default community accepted AND the host's reachability profile is internet-facing. Full inventory + topology + often config exfil. Critical (high if the host is internal-only).
3. **Cisco config-copy MIB writable** — when a write community is accepted, probe `1.3.6.1.4.1.9.9.96` (CISCO-CONFIG-COPY-MIB). One SET copies running-config to attacker TFTP. Critical compound (community + write OID); emit as one finding citing both halves.
4. **EOL firmware in sysDescr with KEV-listed CVE** — system walk surfaces vendor + version. Cisco IOS 12.x, IOS-XE < 16.x, pre-11.x Junos, Windows Server 2008/2012, pre-2.4 Linux kernel, legacy printer firmware — cross-reference against KEV catalog. Flat critical when reachable on a non-management interface.
5. **Routing/ARP discloses pivot path into protected segment** — routing table entry into a management or restricted CIDR from a user-accessible device, or ARP cache showing protected hosts on this device. Critical when the device itself is reachable from a less-trusted zone.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (HOST-RESOURCES software for CVE confirmation, interface table for the pivot finding) and stop.

### Tier 2 — broader exposure surface
- Installed software walk (HOST-RESOURCES-MIB) revealing software with known CVEs, cross-referenced via the correlator if available.
- Running processes from non-standard paths (persistence / malware indicator).
- `sysUpTime > 365d` on an EOL-prone device (missed reboot/patch windows).
- Interfaces with admin=up + descriptions like `OLD-` / `DO NOT USE` / `TEMP` still oper=up — operational risk.
- Unexpected tunnel or VPN interfaces, especially on edge devices.
- TCP/UDP listener disclosure surfacing services that nmap couldn't see (embedded gear).
- Printer MIB job history leaking usernames or document titles (`1.3.6.1.2.1.43`).
- L3 presence on a management network from a device whose role shouldn't bridge zones.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Empty `sysContact` / `sysLocation`, cabled-but-broken interfaces (admin=up + oper=down) without other context, generic process snapshots, default community detected but bound to loopback only. Cap at medium.

### Budget & stop rule
~25-step budget. Ration by tier, not by category.
- Community probe + system walk + Tier 1 sweep should fit in ~10 steps.
- Stop after one Tier-2 enrichment pass once Tier 1 produces a critical.
- Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.
- Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="snmp"` and `mission="exposure_audit"`.
