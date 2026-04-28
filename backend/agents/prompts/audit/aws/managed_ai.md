{preamble}

## Mission: Find the Worst Managed-AI Exposures (Bedrock + SageMaker)
Hunt direct paths to model invocation by external principals or unaudited inference first. Coverage is secondary — five critical findings beat twenty hygiene mediums. The risk vocabulary here is *who can invoke* and *who can read the audit trail*, not generic compute/storage.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **Bedrock role with public trust + `bedrock:InvokeModel`** — IAM role whose trust policy allows `Principal: {"AWS": "*"}` (or external/unknown account) AND has `bedrock:InvokeModel` in an attached policy. Anyone can assume → invoke models. Critical.
2. **SageMaker endpoint with no VPC config + wildcard invoker** — endpoint config `VpcConfig` absent AND any IAM principal holds `sagemaker:InvokeEndpoint` on `Resource: "*"` with public-trust assumption path. Critical (anonymous-to-internal inference).
3. **`bedrock:*` granted broadly to a non-admin** — wildcard Bedrock action on a service or workload role that doesn't deliberately operate the AI surface. Critical when the role's trust is also broad; high otherwise.
4. **Model invocation logging absent** — `aws_bedrock_invocation_logging` returns null/empty for a region where Bedrock is in active use (foundation models listed, guardrails configured, or recent invocation activity inferred). Inference traffic is unauditable — no detection of prompt injection, data exfil via prompts, or model misuse. High flat; critical when combined with public-trust above.
5. **Bedrock guardrails absent on a populated account** — `aws_bedrock_foundation_models` returns a populated list but `aws_bedrock_guardrails` is empty. No content filtering or PII redaction. High in regulated subscriptions, medium otherwise.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (resolve the role's actual trust principals, sample one endpoint config) and stop.

### Tier 2 — broader managed-AI surface
- `bedrock:InvokeModel` with `Resource: "*"` on a service role with non-public trust — high.
- SageMaker endpoint without VPC config attached to a model that processes sensitive data (training data labels imply PII/PHI) — high.
- `sagemaker:CreateEndpoint` / `CreatePresignedNotebookInstanceUrl` granted to non-admin principals — high (chain to model substitution / notebook escape).
- SageMaker notebook instance with `DirectInternetAccess=Enabled` and IAM role with broad data perms — high.
- Cross-account model imports without explicit allowlist — high.
- KMS-key policy on Bedrock/SageMaker resources missing the service principal restriction (`kms:ViaService`) — medium.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Bedrock guardrails configured but in `report` mode rather than `block`, SageMaker training jobs without intra-job network isolation, deprecated model versions still pinned in production deployments, missing tag taxonomy on AI resources. Cap at medium.

### Skip rules
- If Bedrock isn't enabled (foundation-models list returns empty AND no invocation logging configured), skip the entire Bedrock checklist.
- If SageMaker has zero endpoints, skip the endpoint checklist.
- Don't enumerate every model version — the signal is in IAM and endpoint config, not the model registry.

### Compliance evidence
Findings auto-tag with `nist_ai_rmf` and `iso_42001`. In `evidence`, always include resource ARN, the exact policy element (quote `Action`/`Resource`/`Principal`), and region (Bedrock/SageMaker are regional — a finding in us-east-1 says nothing about eu-west-1).

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="aws"` and `mission="managed_ai"`.
