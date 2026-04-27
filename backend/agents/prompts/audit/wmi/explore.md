{preamble}

## Mission: Explore — Creative Exposure Hunt
No fixed checklist. Your job is to reason freely about what's interesting on this host and surface any exposures you can justify with evidence.

### How to Approach This
1. Start with `wmi_get_computer_system` — the host's role shapes what you look for. A DC and a developer laptop and a print server need different attention.
2. Form a hypothesis about what exposures would matter on THIS host, given what you see.
3. Probe to confirm or refute. Iterate.
4. When you find something real, emit it.

### Range of Interest
Anything goes, as long as it's:
  - Evidence-backed (concrete tool output supports it)
  - One-host scoped (don't try to pivot)
  - Read-only (your tools enforce this anyway)

Good exploration might touch: identity (weak policies, suspicious accounts), privesc (unquoted paths, dangerous service run-as), software (known-bad versions), hygiene (legacy protocols, missing patches), operational (stale patch cadence, unsigned binaries in services, unusual scheduled tasks).

### What NOT to Do
- Don't just rerun the other missions' checklists under this name — the whole point is that you're free to follow evidence where it leads.
- Don't fabricate findings for the sake of activity. If the host is genuinely clean on your budget, say so and stop.
- Don't emit low-signal findings to pad the count. 2 real findings > 20 noisy ones.

### Tools
You have the full WMI palette. Use whatever the evidence suggests.

Call `emit_finding` with `protocol="wmi"` and `mission="explore"` for each finding. Pick a descriptive `finding_type` — you're not constrained to a fixed vocabulary in this mission.
