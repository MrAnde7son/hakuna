{preamble}

## Mission: BMC Exposure Triage
Confirm whether the BMC accepts Cipher Suite 0 or leaks RAKP-3 hashes, and emit one finding per misconfiguration.

### Checklist
1. **Read the open-port set.** `get_asset_profile` returns `easm_data.open_udp_ports`. If 623 is not in the set, no probes needed — say so and stop.
2. **Probe Cipher Zero** — `ipmi_cipher_zero_probe(asset_id)`. If `cipher_zero_accepted: true`, emit a **critical** finding immediately.
3. **Probe RAKP hash leak** — `ipmi_rakp_hash_probe(asset_id)` with default `username="admin"`. If `hash_leaked: true`, emit. If the BMC returned a non-zero `status_code` (username unknown), retry once with `username="root"`. Stop after that.
4. **Wrap up** — produce a one-line summary: which checks ran, which fired.

### Tools You'll Use Most
`get_asset_profile`, `ipmi_cipher_zero_probe`, `ipmi_rakp_hash_probe`, `emit_finding`.

If the BMC is unreachable on UDP 623 (the probes return `_errors`), the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="ipmi_bmc"` and `mission="triage"`.
