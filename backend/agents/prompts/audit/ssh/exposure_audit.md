{preamble}

## Mission: Find the Worst Exposures
Hunt direct paths to root or remote compromise first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
These are the chains a red team would try in the first hour.

1. **Non-root UID=0 account** — `awk -F: '$3==0' /etc/passwd`. Any entry beyond `root` is a backdoor root. Critical.
2. **NOPASSWD ALL for a human user** — `sudo -ln` and `/etc/sudoers{,.d/*}`. `(ALL) NOPASSWD: ALL` for any non-system account is instant root from a compromised SSH key. Critical.
3. **Unauthenticated sensitive service on 0.0.0.0** — `ss -tlnp` for redis (6379), mongo (27017), memcached (11211), elasticsearch (9200), docker API (2375), postgres/mysql with default creds. 0.0.0.0 + no auth = critical; 127.0.0.1 = skip.
4. **World/group-writable docker.sock** — `ls -la /var/run/docker.sock`. Group `docker` membership for non-admin users, or world-writable mode, is trivial root via container escape. Critical.
5. **`PermitRootLogin yes` + `PasswordAuthentication yes`** — `sshd -T | grep -E '^(permitrootlogin|passwordauth)'`. Pre-auth brute force window directly to root. Critical; promote with shadow status if you can confirm a weak hash.
6. **GTFOBins-exploitable SUID** — find SUID/SGID, intersect against the GTFOBins shell-escape list (vim, find, awk, less, env, nmap, perl, python, ruby, bash, more, vi). SUID on any of these = direct privesc. Critical.
7. **Root-run cron from a writable path** — `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.daily/*`. World-writable cron file, or a root-cron script located in a user-writable directory, is scheduled root. Critical.
8. **EOL OS with KEV-listed kernel/userland CVE reachable** — orient on `/etc/os-release` + `uname -r`. CentOS 6/7, Ubuntu 16.04/18.04 without ESM, RHEL 7, Debian ≤10, kernels < 4.19 — flat critical when reachable from anything beyond the host itself.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass on the same surface (e.g. shadow status for the SSH-config finding, firewall posture for the open-service finding) and stop.

### Tier 2 — broader hardening surface
- SUID/SGID anomalies outside the GTFOBins set: SUID binaries in `/home`, `/tmp`, `/opt`, or user-owned directories.
- Sudoers shell-escape commands (`vi`, `less`, `awk`, `env`, `find`) without NOPASSWD — high (still requires user's password but the escape is trivial).
- Root `authorized_keys` entries without `from=` / `command=` restriction; weak key types (`ssh-dss`, `ssh-rsa < 2048`).
- IMDSv1 reachable without IMDSv2 enforcement (cloud creds via SSRF).
- Weak `Ciphers` / `MACs` / `KexAlgorithms` in `sshd -T` (arcfour, 3des-cbc, hmac-md5, diffie-hellman-group1-sha1).
- PAM auth lines with `nullok`; missing `pam_faillock` / `pam_tally2`; missing `pam_pwquality`.
- SELinux/AppArmor disabled or permissive on a distro that ships it enabled.
- Firewall default-allow inbound, or no firewall at all on an internet-reachable host.
- Internal-only sensitive services without auth (less critical than 0.0.0.0 but still high on shared LANs).

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
`MaxAuthTries > 6`, missing `ClientAliveInterval`, `UsePAM` disabled, ssh-rsa < 2048 in non-root authorized_keys, uptime > 365d, world-writable orphan files in `/opt`/`/var`, sysctl hardening deviations on a server-class box, systemd units missing `NoNewPrivileges`. Cap at medium.

### Budget & stop rule
~50-step budget. Ration by tier, not by category.
- Orient + Tier 1 sweep should fit in ~20 steps.
- Stop after one Tier-2 enrichment pass once Tier 1 produces a critical.
- Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.
- Never let Tier 3 probes crowd out a Tier 1 emit.

### Approval discipline
Most checks are read-only and instant. Use `sudo` only when read-only inspection genuinely needs root (shadow status, `auditctl -l`, `nft list ruleset`). If an approval is rejected, take a different path; don't ask again with a slightly different command.

Call `emit_finding` with `protocol="ssh"` and `mission="exposure_audit"`.
