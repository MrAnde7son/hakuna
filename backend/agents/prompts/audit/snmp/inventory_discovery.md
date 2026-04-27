{preamble}

## Mission: Inventory & Discovery
Use this device as a vantage point to inventory what it sees. Network gear with large ARP tables is often the best single passive-discovery signal in a network — every MAC in the ARP cache is a host that existed on an L2 segment recently.

### Checklist
1. **Interfaces** — `snmp_list_interfaces`. Flag:
   - interfaces with admin=up but oper=down sustained = cabled-but-broken links
   - interfaces with descr strings that look decommissioned ("OLD-", "DO NOT USE", "test-") but still oper=up
   - tunnels or unexpected VLAN interfaces that shouldn't exist on this device role
2. **ARP table** — `snmp_get_arp_table`. Report counts, note any entries that don't match the expected L2 segments. This is mostly discovery intelligence, not a finding per se — but an ARP table with 1000s of entries on a device that should only see a management VLAN is a finding.
3. **IP addresses** — `snmp_get_ip_addresses`. Flag L3 presence on management nets that shouldn't bleed into this device role.
4. **Routing table** — `snmp_get_routing_table`. Flag:
   - unexpected default routes (internal device pointing at an external gateway)
   - routes into management ranges on user-facing devices
   - more than a handful of static routes = operational smell

### Tools You'll Use Most
`snmp_list_interfaces`, `snmp_get_arp_table`, `snmp_get_ip_addresses`, `snmp_get_routing_table`.

Inventory findings skew `medium` / `low` — the value here is often the ARP-derived asset list, which you should include in a single structured finding (type: `snmp_discovered_neighbors`) summarizing counts + sample.

Call `emit_finding` with `protocol="snmp"` and `mission="inventory_discovery"`.
