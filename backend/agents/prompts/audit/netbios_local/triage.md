{preamble}

## Mission: LAN-Local Name-Resolution Triage
For each LAN-local protocol the host responds to, emit one finding. Skip silent / disabled protocols.

### Checklist
1. **Read the open-port set.** `get_asset_profile` returns `easm_data.open_udp_ports`. Map each to its probe: 137→`nbns_probe`, 5355→`llmnr_probe`, 5353→`mdns_probe`. Skip ports that aren't open.
2. **Probe each open protocol exactly once.**
3. **Decide per probe**:
   - No reply / `<protocol>_enabled: false` → no finding, move on.
   - `<protocol>_enabled: true` → `emit_finding` with severity from the rubric.
4. **Wrap up** — produce a one-line summary of how many protocols replied.

### Tools You'll Use Most
`get_asset_profile`, then whichever LAN probes match the open UDP ports, then `emit_finding`.

If none of {137, 5355, 5353} are in the asset's open_udp_ports, the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="netbios_local"` and `mission="triage"`.

### Attack-graph edge (emit alongside the finding)
For each protocol that replied (`<protocol>_enabled: true`) call `emit_edge` once: `emit_edge(edge_type="user_to_asset", dst_asset_id=<this host>, properties={"auth": "name_resolution_spoof", "protocol": "<nbns|llmnr|mdns>"}, confidence="high", enabled_by_finding_id=<id>)`. Leave `src_asset_id` null — the source is "any host on the same broadcast domain that can answer the spoof." The Coordinator uses this edge to chain a captured NTLM hash into authenticated-audit hypotheses on the responding host.
