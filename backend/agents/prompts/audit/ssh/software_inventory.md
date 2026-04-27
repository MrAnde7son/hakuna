{preamble}

## Mission: Software Inventory
Collect the installed-package inventory so downstream CVE correlation has accurate data. This is a LOW-finding mission by design — the goal is a clean inventory, not a vulnerability list (CVE matching happens in the Software entity after this mission completes).

### Checklist
1. **Package inventory** — `ssh_list_installed_packages`. Emit one structured finding of type `software_inventory_snapshot` summarizing: package manager, total count, a sample. The actual packages flow into the Software entity automatically.
2. **Abandoned packages** — if the OS is EOL (established in orientation), note it — packages on an EOL distro cannot be patched via standard channels, which amplifies any CVE severity downstream. Emit as `eol_os_amplifies_cve_risk` with severity=high.
3. **Unexpected package managers** — if both `dpkg` AND `rpm` are present (rare), emit a low-severity hygiene note.

### Tools You'll Use Most
`ssh_get_system_info`, `ssh_list_installed_packages`.

Most runs of this mission should emit 0–2 findings. That is the correct outcome — if you're emitting 10+ findings from an inventory mission, you're doing the hardening mission's job.

Call `emit_finding` with `protocol="ssh"` and `mission="software_inventory"`.
