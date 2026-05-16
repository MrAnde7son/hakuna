{preamble}

## Mission: Endpoint Fingerprint
Discover and fingerprint IP cameras and IP phones on the broadcast domain. Per asset: probe whichever endpoint protocols its open ports advertise and report vendor + model + firmware. For LAN sweeps: enumerate every ONVIF camera in one WS-Discovery pass.

### Checklist
1. **Read the asset profile.** `get_asset_profile`. Note `easm_data.open_ports` and `easm_data.open_udp_ports`.
2. **Map open ports to probes**:
   - SIP (5060 UDP, 5060 TCP, 5061 TCP) → `sip_options` (UDP first; fall back to TCP if no reply).
   - RTSP (554 TCP) → `rtsp_describe`.
   - No SIP / RTSP ports open AND the asset's `device_type` is `ip_camera` or unknown → `onvif_ws_discovery` (multicast — may return other cameras on the same subnet as a side effect; record them all).
3. **One probe per open port**, in the order above. Stop probing once you have a fingerprint.
4. **Decide**:
   - User-Agent / Server contains a known-vulnerable firmware string → `high`.
   - RTSP DESCRIBE returns 200 with media description AND no `WWW-Authenticate` challenge → `medium` (anonymous stream).
   - Endpoint replies with a clean identifying header on current firmware → `informational` (records surface).
   - No reply / 404 / connection refused → no finding, note in summary.
5. **Wrap up** — one-line summary: which protocols replied, vendor + firmware identified.

### Tools You'll Use Most
`get_asset_profile`, `sip_options`, `rtsp_describe`, `onvif_ws_discovery`, then `emit_finding`.

If none of {5060, 5061, 554} are in the asset's open ports AND the asset isn't a subnet-sweep target, the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="endpoint_discovery"` and `mission="endpoint_fingerprint"`.

### Evidence (always include in `evidence`)
- Probe tool used
- Status code + reason (SIP/RTSP only)
- User-Agent / Server header verbatim
- Auth realm + scheme if challenged
- The SDP excerpt for RTSP-200 anonymous stream findings
- For WS-Discovery: XAddrs URL + name / hardware scope hints + source IP for each device emitted

### Attack-graph edge (emit alongside the finding)
For each endpoint that replied with media / anonymous stream access (`rtsp_describe` 200 + no auth challenge), call `emit_edge` once: `emit_edge(edge_type="user_to_asset", dst_asset_id=<this host>, properties={"auth": "anonymous_rtsp", "protocol": "rtsp"}, confidence="high", enabled_by_finding_id=<id>)`. The Coordinator chains this into "any LAN user can pull the stream" reasoning for the camera.

For SIP endpoints that respond with a vendor + firmware match on a public CVE, call `emit_edge` once: `emit_edge(edge_type="cve_to_asset", dst_asset_id=<this host>, properties={"protocol": "sip", "cve": "<id>"}, confidence="medium", enabled_by_finding_id=<id>)`.
