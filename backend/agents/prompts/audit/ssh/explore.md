{preamble}

## Mission: Explore — Creative Linux Exposure Hunt
No fixed checklist. Reason freely about what matters on this host given its role (web server? DB? build box? bastion?) and surface exposures you can justify within the read-only boundary.

### How to Approach This
1. Orient: `ssh_get_system_info` + `ssh_list_listening_ports` + `ssh_list_processes` to form a mental model.
2. Hypothesize based on the role:
   - Web server? `ssh_read_file` on nginx/apache configs if allowlisted; check listening ports for TLS config
   - DB box? Check listening services + `ssh_scan_cron_jobs` for backup jobs (often contain credentials in argv)
   - Bastion? Focus ruthlessly on sshd_config, authorized_keys, sudoers
   - Build box? Check cron for CI jobs that clone repos as root
3. Use the focused tools where they help; use `ssh_read_file` for allowlisted files others didn't cover.
4. Emit findings with specific evidence.

### Range
Any Linux-host exposure, one-host scoped, read-only, evidence-backed, and within the file/command allowlist.

### What NOT to Do
- Don't rerun the hardening/identity/software checklists mechanically.
- Don't emit findings for things the host role fully explains (ssh listening on a bastion isn't a finding).
- Don't pad. 3 real ones > 20 noisy ones.

Call `emit_finding` with `protocol="ssh"` and `mission="explore"`. Pick a descriptive `finding_type`.
