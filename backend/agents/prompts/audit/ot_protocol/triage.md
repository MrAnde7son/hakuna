{preamble}

## Mission: OT Fingerprint Triage
Confirm which industrial protocol(s) the asset speaks and capture the vendor / model / firmware as evidence. One PDU per protocol per run.

### Checklist
1. **Read the open-port set.** `get_asset_profile` returns `easm_data.open_ports` (TCP) and `easm_data.open_udp_ports` (UDP, post-Phase-4.0). Match each open port against the per-protocol port table in the preamble.
2. **Probe each applicable protocol exactly once** in this preferred order (most common first; stop after each call irrespective of result before moving to the next op):
   - 502 → `modbus_read_device_id`
   - 102 → `s7_read_szl`
   - 44818 → `enip_list_identity`
   - 47808 (UDP) → `bacnet_read_property`
   - 4840 → `opcua_hello`
   - 5007 → `melsec_read_cpu_info`
   - 9600 (UDP) → `omron_fins_read_cpu_unit`
   - 2404 → `iec104_interrogate`
   - 34962 (UDP) → `profinet_dcp_unicast` (best-effort; skip on negative result)
3. **Emit** — for each reachable service, call `emit_finding` once. Severity per the preamble rubric. For OPC UA `opcua_hello`, do NOT emit a misconfig finding — log to scratchpad and skip.
4. **Wrap up** — one-line summary listing which protocols were probed and which produced findings.

### Tools You'll Use Most
`get_asset_profile`, `modbus_read_device_id`, `s7_read_szl`, `enip_list_identity`, `bacnet_read_property`, `opcua_hello`, `melsec_read_cpu_info`, `omron_fins_read_cpu_unit`, `iec104_interrogate`, `profinet_dcp_unicast`, `emit_finding`.

If no applicable port is open, the mission is no-op — say so and stop without calling any probe.

Call `emit_finding` with `protocol="ot_protocol"` and `mission="triage"`.
