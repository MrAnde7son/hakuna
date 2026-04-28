{preamble}

## Mission: Exposure Audit
Hunt every category of Linux/Unix exposure on this host — hardening, identity, software CVEs, kernel posture — in one pass. The cookbook in the preamble has the commands and file paths; this mission is about coverage and reasoning.

### Areas to cover
Reorder based on what `uname -a; cat /etc/os-release; uptime -p` reveals: a bastion vs a DB box vs a build box have different priorities.

1. **OS / kernel age**
   - Distro + version. Flag EOL: CentOS 6/7, Ubuntu 16.04/18.04 without ESM, RHEL 7, Debian ≤10, kernels < 4.19.
   - Uptime > 365d → missed reboot/patch windows.

2. **Hardening posture**
   - `sshd_config` (`ssh_read_file("/etc/ssh/sshd_config")` + drop-in dir + `sshd -T`). Flag `PermitRootLogin yes`, `PasswordAuthentication yes` without MFA, `PermitEmptyPasswords yes`, weak `Ciphers`/`MACs`/`KexAlgorithms`, `MaxAuthTries > 6`.
   - SUID/SGID scan via the cookbook `find` recipe. Cross-reference GTFOBins; flag SUID in `/home`, `/tmp`, `/opt`, or user-owned dirs.
   - Listening ports (`ss -tlnp`). Flag sensitive services on 0.0.0.0 (redis, mongo, memcached, postgres, mysql, docker:2375, elasticsearch).
   - Cron hygiene — read `/etc/crontab`, list `/etc/cron.d`, `cron.daily`. World-writable cron files or root-run scripts in writable dirs.
   - Sysctl hardening deviations (kptr_restrict, dmesg_restrict, ptrace_scope, tcp_syncookies, accept_redirects, suid_dumpable, etc.).

3. **Identity**
   - UID=0 accounts beyond root → critical.
   - Shadow anomalies: try `ssh_read_file("/etc/shadow")`; if it fails, request approval via `sudo cat /etc/shadow`. **Never include hashes** — status only.
   - Sudoers (`sudo -ln`, `/etc/sudoers`, `/etc/sudoers.d/*`). Flag NOPASSWD ALL, ALL=(ALL) without password, GTFOBins shell-escape commands (vi, less, awk, env, find).
   - authorized_keys for root + each `/home/<user>`. Flag keys with no `from=`/`command=` restriction on root, weak key types (ssh-dss, ssh-rsa < 2048).
   - PAM weakness: `nullok` on auth lines, missing `pam_pwquality`/`pam_cracklib`, missing `pam_tally2`/`pam_faillock`.

4. **Network + MAC posture**
   - Firewall (read-only): `iptables-save`, `nft list ruleset`, `ufw status verbose`, `firewall-cmd --list-all-zones`.
   - SELinux/AppArmor mode: `getenforce`, `sestatus`, `aa-status`. No-MAC on RHEL/Ubuntu = finding.
   - Cloud metadata: IMDSv1 reachable without IMDSv2 enforcement (the curl command pauses for approval).

5. **Software inventory + CVE triage**
   - Detect package manager and dump packages (cookbook `dpkg-query` / `rpm -qa` / `apk info`).
   - Run `correlate_software_to_cves(asset_id)` once.
   - Snapshot context: kernel + listening ports + firewall + MAC posture (you may already have these).
   - Triage top ~10 candidates. Respect distro backports — versions like `1.18.0-6.1+deb11u3` often have the CVE backported; mark `indeterminate` rather than `vulnerable` without config evidence.
   - EOL OS/component → emit one finding each.

6. **Container + persistence surface** (if relevant)
   - `command -v docker podman kubelet`. `ls -la /var/run/docker.sock` — group/world-writable = trivial root privesc.
   - systemd unit hardening (`systemctl show <unit> --property=Id,ExecStart,User,NoNewPrivileges,ProtectSystem`).
   - World-writable / orphaned files in `/etc /usr /opt /var /root /home`.

### How to budget
You have ~50 steps. Spend them roughly: 1 orient + 8–10 hardening checks + 6–8 identity checks + 3–5 network/MAC + 1 correlator + 5–10 CVE triage + emits. Stop when every relevant area has been touched OR 5 probes in a row find nothing new.

### Approval discipline
- Most checks are read-only and execute instantly.
- Use `sudo` only when read-only inspection genuinely needs root (e.g. shadow audit, `auditctl -l`, `nft list ruleset`). Each `sudo` invocation pauses for user approval — don't be shy about asking, but don't invoke it for things that have a read-only alternative.
- If an approval is rejected, take a different path; don't ask again with a slightly different command.

### Severity reminders
Use the rubric in the preamble. Identity skews critical when UID=0 or NOPASSWD-as-non-root. Network-service CVE on 0.0.0.0 = critical when KEV. EOL OS = high flat. Don't pad — 5 strong findings beat 20 noisy ones.

Call `emit_finding` with `protocol="ssh"` and `mission="exposure_audit"`.
