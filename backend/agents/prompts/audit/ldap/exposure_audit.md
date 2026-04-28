{preamble}

## Mission: Exposure Audit
Hunt every category of AD exposure on this domain — identity, structure, delegation, and ACLs — in one pass. The cookbook in the preamble has the LDAP filters; this mission is about *coverage and severity reasoning*, not memorizing recipes.

### Areas to cover
Reorder based on what RootDSE + the orient queries reveal. Skip an area only when you have evidence it doesn't apply.

1. **Identity exposure**
   - Kerberoastable accounts (`servicePrincipalName` set on users).
   - AS-REP roastable accounts (`DONT_REQUIRE_PREAUTH`).
   - Weak Kerberos encryption (`msDS-SupportedEncryptionTypes` lacks AES bits).
   - `PASSWD_NOTREQD` on enabled accounts.
   - Stale enabled accounts (last logon > 180d).

2. **Privileged group bloat**
   - Members of Domain Admins / Enterprise Admins / Schema Admins / Account Operators / Backup Operators / Server Operators / DnsAdmins.
   - Disabled accounts still in admin groups; service accounts in admin groups.
   - Privileged users *not* in Protected Users.

3. **Password & policy posture**
   - Domain password policy (`minPwdLength`, `lockoutThreshold`, `pwdProperties` complexity).
   - `ms-DS-MachineAccountQuota` > 0 for unprivileged users.

4. **Structure & trust**
   - `trustedDomain` objects — direction, type, whether `trustAttributes` enables SID filtering.
   - Stale computer accounts (`lastLogonTimestamp` / `pwdLastSet` > 180d).
   - Domain functional level below 7 (Windows Server 2016).

5. **Delegation & ACLs**
   - Unconstrained delegation (`TRUSTED_FOR_DELEGATION`) on non-DCs.
   - Constrained delegation (`msDS-AllowedToDelegateTo`) targeting krbtgt or DC services.
   - RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) — call `ldap_get_object_acl` on the principal to identify the writer.
   - Dangerous ACEs (`GENERIC_ALL` / `WriteDACL` / `WriteOwner` / `DS-Replication-Get-Changes(-All)`) on Domain Admins, AdminSDHolder, krbtgt, the domain root.

6. **Group Policy hygiene** (optional — skip if budget is tight)
   - GPOs with the GPP CSE GUID `{17d89fec-5c44-4972-b12d-241caef74509}` — possible legacy cpassword in SYSVOL.
   - GPOs disabled but still linked.

### How to budget
You have ~50 steps. Spend them roughly: 5 orient + 25 broad searches across the areas + 15 ACL/delegation drilldowns + 5 finding emits. Stop when every area above has been touched, OR when 5 probes in a row find nothing new.

### Severity reminders
Identity findings skew critical when they hit Domain Admins. ACL findings skew critical when the path is direct (DCSync, GenericAll on a DA). Structure findings cap at high. Use the rubric in the preamble.

Call `emit_finding` with `protocol="ldap"` and `mission="exposure_audit"`.
