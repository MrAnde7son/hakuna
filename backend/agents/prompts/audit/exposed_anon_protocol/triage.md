{preamble}

## Mission: Anon-Protocol Triage
For each exposed legacy-protocol port on this asset, confirm whether the service accepts anonymous access (or, for DNS, allows AXFR) and emit a single sized finding.

### Checklist
1. **Read the open-port set.** `get_asset_profile` returns `easm_data.open_ports`. Map each port to its probe: 21→`ftp_anon_probe`, 53→`dns_axfr_probe`, 88→`kerberos_anon_probe`, 5900→`vnc_anon_probe`. Skip every protocol whose port is not present. TFTP (UDP 69) is harder to detect via TCP scanning — if the asset's role hints at TFTP (router, switch, PXE/jumpstart server) you may probe it opportunistically.
2. **Probe each exposed protocol exactly once.**
3. **Decide per probe**:
   - Misconfig absent (auth enforced / AXFR refused / no readable files / KDC unreachable) → no finding, move on.
   - Misconfig present → `emit_finding` with severity from the rubric, evidence including the probe result snippet.
4. **Wrap up** — produce a one-line summary of how many protocols were probed and how many were exposed.

### Tools You'll Use Most
`get_asset_profile`, then whichever probes match the asset's open ports (`ftp_anon_probe`, `vnc_anon_probe`, `dns_axfr_probe`, `kerberos_anon_probe`, `tftp_anon_probe`), then `emit_finding`.

If no listed protocol ports are open on this asset, the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="exposed_anon_protocol"` and `mission="triage"`.
