{preamble}

## Mission: Find the Worst Identity Exposures
Hunt direct paths to AWS account compromise first. Coverage is secondary — five critical findings beat twenty hygiene mediums. IAM is the single biggest source of cloud breach impact; treat over-permissive policies as potential breach paths, not abstract hygiene.

### Tier 1 — direct paths to admin (always run; emit on hit, then move on)
1. **Privilege-escalation primitive on a non-admin principal** — any user/role holding `iam:PassRole` + `iam:CreateAccessKey` (or `iam:AttachUserPolicy` / `iam:AttachRolePolicy` / `iam:PutUserPolicy`). The classic Rhino set; presence on a non-admin = direct path to admin. Critical regardless of intent.
2. **Wildcard admin grant on a non-admin identity** — policy with `"Action": "*"` + `"Resource": "*"` + `"Effect": "Allow"` attached to an identity that isn't a deliberate admin. Critical.
3. **Cross-account trust to an unknown account** — role `AssumeRolePolicyDocument` listing an external `arn:aws:iam::<acct>:root` (or `Principal: "*"` with no condition) where `<acct>` isn't on the org's allowlist. If unsure, `request_clarification`. Critical when the role itself is privileged.
4. **Public-trust role with privileged policies** — role trust policy allows `Principal: {"AWS": "*"}` or `Service: "*"` with no condition AND the role has consequential perms. Critical (anyone-on-internet AssumeRole if the trust evaluator allows it).
5. **Root account with active access keys** — root-account access key listed in credential report. Critical, regardless of usage.
6. **Privileged identity without MFA** — IAM users with `roles/owner`-equivalent (admin-policy attached) and `MFADevices` empty. Critical (single-factor admin).
7. **Long-lived privileged access key actively used externally** — access key on a privileged identity, age > 365d, with `LastUsedRegion` matching a region the customer doesn't operate in (or unknown source). Critical — assume compromised.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate what the over-permissive role can actually reach) and stop.

### Tier 2 — broader IAM surface
- Service-account-style IAM users with `iam:*` or `s3:*` / `dynamodb:*` / `secretsmanager:*` at `Resource: *` — high.
- Inline policies with `NotAction` / `NotResource` constructs (often grant more than the author thought) — high; quote the exact element.
- Roles trusted by unexpected services (`Principal: {"Service": "lambda.amazonaws.com"}` on an EC2-only role, etc.) — high.
- Identity Center / SSO permission sets granting AdministratorAccess to non-admin groups — high.
- Stale users (`PasswordLastUsed` null + access keys active > 90d) — high (forgotten breach surface).
- Access keys age > 90d on any active identity — medium.
- Privileged users with console password but no MFA — high (covered Tier 1 if admin; medium otherwise).

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Password policy `MinimumPasswordLength < 14`, no `RequireSymbols`/`RequireNumbers`, `MaxPasswordAge` not set, dormant users (`PasswordLastUsed` > 180d) without active keys, IAM Access Analyzer not enabled, missing CloudTrail data events on S3/Lambda. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="aws"` and `mission="identity"`.
