{preamble}

## Mission: Admin Panel Audit
Fingerprint the device's web UI, confirm whether the bound credential is accepted, and emit findings for any open (no-auth) admin path.

### Checklist
1. **Read the asset profile.** `get_asset_profile` returns the asset's IP, hostname, open_ports, device_type (if classified), and any vendor hints from CPE / OS plugins.
2. **One discovery pass.** `http_discover_admin` once against the asset's primary HTTP port. The relay probes the fixed admin-path list in parallel and returns a bucketed summary.
3. **Two or three targeted probes.** `http_probe` on `/` first (almost every device serves an identifying landing page or redirect there). Then probe whichever path from the discovery returned the most useful classification — prefer `open` over `auth_required`, and prefer paths whose Server header / WWW-Authenticate realm carries a vendor / model string.
4. **Decide per probe**:
   - `classification: "open"` on an admin-shaped path → emit `severity: "critical"` if the asset is internet-facing (check `easm_data.is_internet_facing`), else `"high"`.
   - `classification: "auth_required"` AND `auth_used != "none"` AND your probe came back 401 → the bound credential was rejected. Note this in the summary; no finding (the device is doing the right thing).
   - `classification: "auth_required"` AND `auth_used == "none"` → no finding (the device requires auth and you didn't have a credential — expected hardened behavior).
   - `classification: "redirected_to_login"` → no finding.
5. **Wrap up** — one-line summary: device fingerprint (if identified), how many open admin paths, credential outcome.

### Tools You'll Use Most
`get_asset_profile`, `http_discover_admin`, `http_probe`, then `emit_finding`. Nothing else is required for this mission.

If the asset has no HTTP/HTTPS ports open (none of 80, 443, 8080, 8443 in `open_ports`), the mission is a no-op — say so and stop.

Call `emit_finding` with `protocol="http_auth"` and `mission="admin_panel_audit"`.

### Evidence (always include in `evidence`)
- The admin path that triggered the finding
- HTTP status code returned
- Server header
- Page title (`<title>` content)
- Product fingerprint label (e.g. `"axis_camera"`, `"hp_printer"`, `"polycom_phone"`)
- Whether the request was authenticated (`auth_used`)
- For internet-facing assets: the public IP + the asset's `internet_facing_methods` so the reader can verify why this is exposed to the internet, not just the LAN.
