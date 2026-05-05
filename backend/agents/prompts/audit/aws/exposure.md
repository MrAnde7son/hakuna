{preamble}

## Mission: Find the Worst Public Exposures
Hunt direct paths from the public internet to data, code execution, or credentials first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Probe by tier, not by category.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **S3 bucket with anonymous data exposure** — public ACL or bucket policy with `Principal: *`, AND the bucket actually has objects. List a handful of keys to confirm. Critical when objects exist; medium when the bucket is empty.
2. **SG `0.0.0.0/0` on a database port with a live listener** — SG ingress on 3306 / 5432 / 27017 / 6379 / 9200 / 1433 / 11211, attached to an instance/RDS that's actually bound to that port. Compound finding (rule + binding + public IP). Critical.
3. **Lambda function URL `AuthType: NONE` on a function with privileged role** — anonymous URL combined with an IAM role that grants real access (`s3:*`, `dynamodb:*`, `secretsmanager:GetSecretValue`, anything-`*` on resource-`*`). Critical (anonymous code execution with the function's role).
4. **EC2 with public IP + IMDSv1 not enforced + privileged instance role** — `MetadataOptions.HttpTokens != required` AND attached IAM role has non-trivial perms. SSRF → IAM credential exfil. Critical.
5. **RDS / Aurora `PubliclyAccessible=true` + permissive SG** — DB endpoint reachable from the internet on its native port. Critical.
6. **KMS key policy with `Principal: *` or external account** — key takeover / cross-account decrypt. Critical regardless of the key's encryption usage.
7. **API Gateway / ALB unauthenticated route fronting a management or admin path** — confirm via route inspection (no authorizer, no Cognito, no WAF rule) and a path that hints at admin (`/admin`, `/api/internal`, `/_dashboard`). Critical to high based on what the route does.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. confirm IAM blast radius for the Lambda/EC2 finding) and stop.

### Tier 2 — broader public surface
- SG `0.0.0.0/0` on 22 / 3389 to any compute — high (brute-force surface, assume eventual compromise without MFA).
- Bucket with `public-read` ACL but only non-sensitive content (logos, web assets) — medium; flag as `manual_review_needed` if you can't classify the content cheaply.
- Missing S3 public-access-block at the bucket OR account level when no actual public ACLs exist today — medium (drift risk, not active exposure).
- Lambda function URL `AuthType: NONE` on a function with read-only / no IAM role of consequence — medium.
- CloudFront distribution without a WAF in front of API/admin origins — medium.
- Public ALB without WAF managed-rule sets — medium.
- Snapshots (EBS / RDS) shared with `all` or unknown account IDs — high.
- AMIs marked public — high if the customer doesn't deliberately publish AMIs.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
S3 default-encryption missing on a bucket already protected by IAM, VPC flow logs disabled, single-region CloudTrail, default VPC still present, IAM Access Analyzer not enabled. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new. Never let Tier 3 probes crowd out a Tier 1 emit.

Call `emit_finding` with `protocol="aws"` and `mission="exposure"`.
