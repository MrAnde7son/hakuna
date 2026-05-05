# Finding Category Refactor — Plan

**Goal:** Decouple prioritization, owner routing, and attack-surface scoring from Nessus's plugin/family taxonomy. Re-key everything on a normalized `category` populated from CWE + scanner-specific signals. Hakuna ships only with the native scanners (Nuclei VM scanner, protocol audit agents, cloud audit agents, EASM) and still delivers full competitive value.

**Why:** `OWNER_MAP`, `PLUGIN_FAMILY_WEIGHTS`, and `ATTACK_SURFACE_PLUGIN_IDS` in [backend/services/prioritizer.py](backend/services/prioritizer.py) are keyed on Nessus families and Nessus plugin IDs. Without Nessus data they fall back to neutral defaults, losing owner suggestions, family weighting, and attack-surface signal. CWE is now populated across every scanner ([recent commit 7e3c9c8](backend/models/models.py)) — that's the join key.

---

## Native scanner sources to support

| Source | `source_type` | Family/category signal today |
|--------|--------------|------------------------------|
| Nuclei VM scanner | `vm_scanner` | `_classify_nuclei_plugin_family()` → "CVE"/"DefaultLogin"/"Misconfiguration"/"Exposure"/"Takeover"/"TLS" + `custom_fields["nuclei_tags"]` |
| Protocol audit agents (WMI, LDAP, SMB, Kerberos, WinRM, SNMP, SSH) | `{proto}_audit` | `_PROTOCOL_PLUGIN_FAMILIES` in [emit_finding.py:44-55](backend/agents/tools/emit_finding.py#L44-L55) → "Audit: Windows", "Audit: Active Directory", etc. |
| Cloud audit agents (AWS/Azure/GCP) | `{cloud}_audit` | "Audit: Cloud (AWS)", "Audit: Cloud (Azure)", "Audit: Cloud (GCP)" |
| EASM | `easm` | `plugin_id` prefix `EASM-TLS-*`, `EASM-PORT-*`, `EASM-TECH-*`, `EASM-EXPOSED-DB-*`, `EASM-CVE-*`, `EASM-DNS-*` |
| Integration Builder (third-party imports) | user-defined | User-mapped `plugin_family` |
| Nessus (legacy / customer imports) | `nessus` | Native plugin_family taxonomy |

---

## Step 1 — `backend/services/finding_category.py`

Single source of truth. Exports:

- `CATEGORIES: tuple[str, ...]` — closed enum
- `CATEGORY_WEIGHTS: dict[str, float]` — replaces `PLUGIN_FAMILY_WEIGHTS`
- `CATEGORY_OWNERS: dict[str, str]` — replaces `OWNER_MAP`, values are `core.ownership_teams.OWNERSHIP_ROLES`
- `classify_category(finding: dict) -> str`

### Categories (14, each maps to one owner)

| Category | Weight | Owner |
|----------|-------:|-------|
| `compromise` | 1.5 | SOC |
| `web-app` | 1.3 | AppSec |
| `iam` | 1.3 | IAM |
| `crypto` | 1.2 | AppSec |
| `database` | 1.2 | DBA |
| `os-patch` | 1.2 | IT |
| `cloud-misconfig` | 1.1 | SecOps |
| `network-device` | 1.1 | Networking |
| `tls` | 1.0 | Networking |
| `endpoint` | 1.0 | IT |
| `dos` | 1.0 | SecOps |
| `compliance` | 0.9 | GRC |
| `attack-surface` | 0.7 | SecOps |
| `other` | 1.0 | SecOps |

### Classifier precedence (first hit wins)

1. **Explicit override** — `finding["category"]` set by emitter (agents/integrations can pin)
2. **CWE → category** — most reliable cross-scanner signal
3. **Source-specific quick path:**
   - Nuclei: `plugin_family` + `custom_fields["nuclei_tags"]`
   - EASM: `plugin_id` prefix
   - Protocol/cloud audit: `plugin_family` from `_PROTOCOL_PLUGIN_FAMILIES`
4. **Nessus `plugin_family`** — port existing `OWNER_MAP` / `PLUGIN_FAMILY_WEIGHTS` knowledge
5. **`plugin_name` keyword fallback** — TLS/SSH/SMB/RDP/etc.
6. Default `other`

### CWE → category map (key entries)

| CWE | Category | Notes |
|-----|----------|-------|
| CWE-79, CWE-89, CWE-78, CWE-77, CWE-94, CWE-22, CWE-918, CWE-352, CWE-611, CWE-502, CWE-434, CWE-601 | `web-app` | Web/API exploitation classes |
| CWE-287, CWE-306, CWE-862, CWE-863, CWE-269 | `iam` | Auth/authz failures |
| CWE-798, CWE-330, CWE-327, CWE-319 | `crypto` | Hardcoded secrets, weak crypto, plaintext |
| CWE-119, CWE-787, CWE-416, CWE-125 | `os-patch` | Memory safety — vendor patch territory |
| CWE-200, CWE-209 | `attack-surface` | Information disclosure |
| CWE-400, CWE-770 | `dos` | Resource exhaustion |

### Nessus family → category map (representative)

| Nessus family | Category |
|---------------|----------|
| `Windows`, `Windows : Microsoft Bulletins`, `*Local Security Checks`, `Patch Management`, `MacOS X Local Security Checks` | `os-patch` |
| `Windows : User management`, `Credentials`, `Default Unix Accounts` | `iam` |
| `Gain a shell remotely`, `Backdoors`, `Malware` | `compromise` |
| `CGI abuses`, `CGI abuses : XSS`, `Web Servers` | `web-app` |
| `Databases` | `database` |
| `Firewalls`, `CISCO`, `Junos*`, `Palo Alto*` | `network-device` |
| `Policy Compliance` | `compliance` |
| `Service detection`, `Settings`, `General`, `Misc.`, `Port scanners` | `attack-surface` |
| `Denial of Service` | `dos` |

### EASM prefix → category

| Prefix | Category |
|--------|----------|
| `EASM-TLS-*` | `tls` |
| `EASM-PORT-*`, `EASM-TECH-*`, `EASM-DNS-*` | `attack-surface` |
| `EASM-EXPOSED-DB-*` | `database` |
| `EASM-COOKIE-*`, `EASM-HEADER-*` | `web-app` |
| `EASM-CVE-*` | CWE-driven, fallback `web-app` |

### Protocol audit family → category

| Family | Category |
|--------|----------|
| `Audit: Windows` (WMI), `Audit: SMB`, `Audit: WinRM`, `Audit: SSH` | `endpoint` |
| `Audit: Active Directory` (LDAP), `Audit: Kerberos` | `iam` |
| `Audit: SNMP` | `network-device` |
| `Audit: Cloud (AWS/Azure/GCP)` | `cloud-misconfig` |

### Nuclei taxonomy → category

| Nuclei family | Category |
|---------------|----------|
| `DefaultLogin` | `iam` |
| `Exposure` | `attack-surface` |
| `Takeover` | `web-app` |
| `TLS` | `tls` |
| `CVE` | CWE-driven; memory-safety CWE → `os-patch`, web CWE → `web-app`, fallback `other` |
| `Misconfiguration` | tag-driven; default `other` |

---

## Step 2 — Persist `category` on Finding

- Add `category = Column(String, index=True, nullable=True)` to `Finding` near the prioritization fields ([models.py:583](backend/models/models.py#L583) area).
- Populate in `post_ingest.py` alongside `priority_score` so reclassification happens on every recompute.
- Migration `backend/migrations/049_add_finding_category.py` — adds the column, backfills existing rows by running the classifier in batches.

---

## Step 3 — Rewire `prioritizer.py`

- Replace `family_weight = PLUGIN_FAMILY_WEIGHTS.get(family, 1.0)` with `CATEGORY_WEIGHTS.get(category, 1.0)`
- Replace `owner = OWNER_MAP.get(family, "SecOps")` with `CATEGORY_OWNERS.get(category, "SecOps")`
- **Drop `ATTACK_SURFACE_PLUGIN_IDS`.** Replace with:
  ```python
  if category == "attack-surface" and severity == 0:
      family_bonus = max(family_bonus, 0.2)
  ```
- Keep `PATCH_FAMILIES` / `COMPLEX_FAMILIES` for effort logic, but add category-based triggers:
  - `category == "os-patch"` → patch effort path
  - `category in {"compromise", "iam", "network-device"}` → complex effort path

---

## Step 4 — Tests

`backend/tests/test_finding_category.py` — table-driven coverage:

- Nessus Windows KB → `os-patch` / IT
- Nessus Default Unix Accounts → `iam` / IAM
- Nuclei CVE template (web CWE) → `web-app` / AppSec
- Nuclei CVE template (memory-safety CWE) → `os-patch` / IT
- Nuclei DefaultLogin → `iam` / IAM
- EASM TLS → `tls` / Networking
- EASM PORT → `attack-surface` / SecOps
- WMI audit → `endpoint` / IT
- LDAP audit → `iam` / IAM
- AWS audit → `cloud-misconfig` / SecOps
- Integration-builder finding with explicit `category` override → respected
- No CWE / no family / unknown plugin → `other` / SecOps

---

## Out of scope for this pass

- UI surfacing of `category` (filter, group-by, finding detail badge) — follow-up PR
- `rule_engine` operand exposure for `category` — easy add, separate PR
- Inventory extractor / credential exposure plugin-ID dispatch refactor — different concern
- Re-tuning `_DEFAULT_FINDING_WEIGHTS` weights now that `family` channel comes from a more reliable source

---

## Risks / tradeoffs

- **Single point of failure.** Classifier becomes a quiet authority — owner routing, score weights, and effort all key off it. Bad classification breaks three things at once. Mitigation: test table per scanner source + explicit emitter override path.
- **Migration backfill cost.** Single UPDATE pass per row in `049_*.py`; large tenants will need batched processing.
- **Lost Nessus granularity.** Some Nessus families (e.g. `Windows : User management`) collapse into the same category as broader ones. Acceptable since prioritization signal still differentiates via CWE/CVE/KEV/EPSS.

---

## Suggested execution order

1. Step 1 — module + classifier + tests (no DB change). Review the taxonomy here.
2. Step 3 — rewire `prioritizer.py` to read from `finding.get("category")` (computed inline if column not yet present). Run existing prioritizer tests.
3. Step 2 — add column + migration + populate in `post_ingest.py`.
4. Step 4 — full test suite green.
