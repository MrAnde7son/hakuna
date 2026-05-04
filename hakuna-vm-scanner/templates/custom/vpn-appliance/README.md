# Curated VPN / Remote-Access Appliance Templates

Detection-only Nuclei templates targeting internet-facing VPN gateways and
remote-access portals. Every template in this directory is **non-exploitive**:
it confirms vendor + product, extracts a version where possible, and reports
presence of a vulnerable build by version-range matching. None of them send
exploit payloads.

This is intentional. Hakuna's job in Pipeline A is to *find* exposed
appliances and prioritize them; confirming exploitability against customer
infrastructure is a pentest activity that lives outside the scanner.

## Family routing

Every template tags `vpn-appliance` so
`backend/services/vm_scanner._classify_nuclei_plugin_family` lands the
finding in the `"VPN Appliance"` plugin family, which carries a 1.5x weight
in the prioritizer (see `PLUGIN_FAMILY_WEIGHTS`). When combined with
internet-facing reachability and CISA KEV membership, these findings outrank
nearly everything else in the queue — which matches the operational reality
that a publicly-reachable Ivanti or Fortinet box on a vulnerable build is the
single highest-impact finding most environments produce.

## Coverage

| Template                                  | Vendor       | CVE              | KEV |
|-------------------------------------------|--------------|------------------|-----|
| vpn-appliance-detect.yaml                 | (any)        | —                | —   |
| ivanti-cs-cve-2024-21887.yaml             | Ivanti       | CVE-2024-21887   | yes |
| ivanti-cs-cve-2023-46805.yaml             | Ivanti       | CVE-2023-46805   | yes |
| fortios-sslvpn-cve-2024-21762.yaml        | Fortinet     | CVE-2024-21762   | yes |
| fortios-cve-2024-55591.yaml               | Fortinet     | CVE-2024-55591   | yes |
| fortios-cve-2022-42475.yaml               | Fortinet     | CVE-2022-42475   | yes |
| citrix-netscaler-cve-2023-4966.yaml       | Citrix       | CVE-2023-4966    | yes |
| citrix-netscaler-cve-2023-3519.yaml       | Citrix       | CVE-2023-3519    | yes |
| panos-globalprotect-cve-2024-3400.yaml    | Palo Alto    | CVE-2024-3400    | yes |
| sonicwall-sma-cve-2024-40766.yaml         | SonicWall    | CVE-2024-40766   | yes |
| cisco-asa-cve-2023-20269.yaml             | Cisco        | CVE-2023-20269   | yes |

## Adding a new template

1. Place the YAML in this directory.
2. Tag it `vpn-appliance` plus the vendor name.
3. Set `info.metadata.kev: true` if the CVE is on the CISA Known Exploited
   Vulnerabilities catalog — the prioritizer reads that signal.
4. Detection should be passive: a GET to a fingerprint path + version regex.
   Do not POST exploit payloads.
