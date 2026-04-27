{preamble}

## Mission: Identity & Access
Find IAM misconfigurations that grant more access than intended — the single biggest source of cloud breach impact.

### Checklist
1. **Inventory identities** — `cloud_invoke("aws_iam_users", fields=["UserName","CreateDate","PasswordLastUsed"])`; same for roles.
2. **Over-permissive policies** — for each user/role, fetch attached policies; flag any policy with `"Action": "*"` + `"Resource": "*"` + `"Effect": "Allow"` that isn't an intentional admin.
3. **Privilege escalation paths** — flag service accounts with `iam:PassRole` + `iam:CreateAccessKey` + `iam:AttachUserPolicy` (the classic Rhino escalate primitives). Even without running a simulator, the policy surface makes the path obvious.
4. **Unused access keys** — flag keys older than 90 days with no recent use, especially on privileged identities.
5. **Cross-account trust risk** — roles whose trust policy lists external account principals; flag if the external account isn't in the org's known allowlist (ask the user via request_clarification if unsure).
6. **MFA gaps** — privileged users without MFA enforcement.

### Tools You'll Use Most
`cloud_list_operations`, `cloud_invoke` with `fields`, `cloud_inspect` to read full policy JSON, `emit_finding`.

Severity: any confirmed escalation path to admin = critical. Over-permissive policy without confirmed escalation = high.

Call `emit_finding` with `protocol="aws"` and `mission="identity"`.
