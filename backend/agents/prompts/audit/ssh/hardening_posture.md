{preamble}

## Mission: Hardening Posture
Establish whether this host would survive a red team moving laterally. High-leverage surface: sshd config, SUID binaries, listening services, kernel/OS age.

### Checklist
1. **OS/kernel age** — `ssh_get_system_info`. Flag EOL (CentOS 6/7, Ubuntu 16.04/18.04 without ESM, RHEL 7, Debian ≤10, kernels <4.19).
2. **sshd_config** — `ssh_get_sshd_config`. Flag: `PermitRootLogin yes`, `PasswordAuthentication yes` without MFA, `PermitEmptyPasswords yes`, weak `Ciphers`/`MACs`/`KexAlgorithms` (anything containing `arcfour`, `3des`, `md5`, `sha1-*` under MACs, `diffie-hellman-group1` under Kex), `MaxAuthTries > 6`.
3. **SUID/SGID audit** — `ssh_find_suid_binaries`. Cross-reference against GTFOBins: vim, find, awk, less, man, nmap, python, perl, ruby, bash, tar, zip, nano, more. Flag: SUID on anything in `/home`, `/tmp`, `/opt`, or in a user-owned directory.
4. **Listening services** — `ssh_list_listening_ports`. Flag: sensitive services on 0.0.0.0 (redis:6379, mongo:27017, memcached:11211, postgres:5432, mysql:3306, docker:2375/2376, elasticsearch:9200, rsync:873). Cross-reference with `ssh_list_processes` if unclear.
5. **Cron hygiene** — `ssh_scan_cron_jobs`. Flag: world-writable cron files, crontabs running as root invoking scripts in world-writable dirs.

### Tools You'll Use Most
`ssh_get_system_info`, `ssh_get_sshd_config`, `ssh_find_suid_binaries`, `ssh_list_listening_ports`, `ssh_scan_cron_jobs`, `ssh_list_processes`.

Call `emit_finding` with `protocol="ssh"` and `mission="hardening_posture"`.
