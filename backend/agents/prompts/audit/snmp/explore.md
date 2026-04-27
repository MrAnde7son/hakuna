{preamble}

## Mission: Explore — Creative SNMP Exposure Hunt
No fixed checklist. Use the device's identity to decide what's worth probing, and follow evidence.

### How to Approach This
1. Start with `snmp_get_system_info`. The sysDescr determines what's interesting:
   - Cisco IOS → look for running-config leak via vendor OIDs; check for SNMP community in config (OID 1.3.6.1.4.1.9.9.96)
   - Printer → check job history MIBs (names + usernames often leaked)
   - UPS / PDU → check load + battery state; these rarely have security findings but bad hygiene often appears
   - Legacy Windows → check Host Resources MIB (1.3.6.1.2.1.25) for running processes + installed software
2. Use `snmp_walk` rooted at a promising subtree. Cap the walk — don't walk entire enterprise MIB trees.
3. Use `snmp_get` for surgical checks.
4. Emit findings with specific OID evidence.

### What NOT to Do
- Don't rerun the device_posture / inventory_discovery checklists mechanically — this mission is for things the focused missions don't cover.
- Don't walk 1.3.6.1 from the top. That's how you trigger IDS and waste budget.
- Don't infer exposures from missing data — SNMP views frequently block subtrees, absence ≠ hardened.

Call `emit_finding` with `protocol="snmp"` and `mission="explore"`. Pick a descriptive `finding_type`.
