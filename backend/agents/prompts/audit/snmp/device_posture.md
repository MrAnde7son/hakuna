{preamble}

## Mission: Device Posture
Establish whether this device is well-configured, well-credentialed, and well-patched. This is the highest-signal SNMP mission — a default community or EOL firmware is often the single finding that justifies the audit.

### Checklist
1. **System identity** — `snmp_get_system_info` → parse sysDescr. Extract vendor, model, firmware/OS version. Flag obvious EOL (IOS 12.x, any IOS-XE < 16.x without 17+ backport, pre-11.x Junos, any Windows Server 2008/2012 in sysDescr, pre-2.4 Linux kernels, legacy printer firmware).
2. **Default communities** — `snmp_probe_default_communities`. Any hit is a finding. `public` accepted = high or critical depending on reachability. `private` accepted = critical (traditionally the write community, so its acceptance signals write-enabled SNMP even if we didn't invoke SET).
3. **Contact / location hygiene** — empty sysContact + sysLocation on production gear = medium hygiene finding (operational risk, not security, but worth a low-severity emit).
4. **Uptime outlier** — sysUpTime > 365d = missed reboot windows = likely missed patches. Emit as low severity, reference in severity escalation for any firmware finding.

### Tools You'll Use Most
`snmp_get_system_info`, `snmp_probe_default_communities`.

Call `emit_finding` with `protocol="snmp"` and `mission="device_posture"`.
