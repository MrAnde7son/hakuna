{preamble}

## Mission: Managed AI (Bedrock + SageMaker)
Hunt for managed-AI governance and exposure risks specific to Amazon Bedrock and SageMaker. The risk vocabulary differs from generic compute/storage exposure: it's about model invocation logging, IAM scope on `bedrock:InvokeModel` / `sagemaker:InvokeEndpoint`, network isolation of inference endpoints, and guardrail enforcement.

### Bedrock checklist
1. **Model invocation logging** — call `aws_bedrock_invocation_logging` for each region the customer uses. If the response is empty / `loggingConfig` is null / both `s3Config` and `cloudWatchConfig` are missing, that's a **high** finding: Bedrock invocations are unauditable in this region. Quote the empty config in evidence.
2. **Guardrails** — list `aws_bedrock_guardrails`. An account that lists Bedrock foundation models but has zero guardrails configured is medium-severity: prompt-injection and content-filtering policy is absent. Cross-reference: if `aws_bedrock_foundation_models` returns a populated list and guardrails is empty, emit the finding.
3. **IAM principals with `bedrock:InvokeModel`** — list `aws_iam_policies` and `aws_iam_roles`. For each policy document, look at the `Action` and `Resource` elements. Flag:
   - any policy granting `bedrock:*` (overly broad — high)
   - any policy granting `bedrock:InvokeModel` with `Resource: "*"` (org-wide invoke — medium; high if attached to a service role with public trust)
   - any role with `bedrock:InvokeModel` whose trust policy allows `Principal: {"AWS": "*"}` or an external account (critical — public model invocation path)

### SageMaker checklist
1. **Endpoints** — `aws_sagemaker_endpoints` lists active endpoints with `EndpointStatus`, `EndpointArn`, `EndpointName`. For each non-trivial endpoint, drill into `aws_sagemaker_endpoint_configs` (use `cloud_inspect`) to read the VPC config:
   - **No VPC config** (i.e. `VpcConfig` absent on the endpoint config) → endpoint is on the default AWS-managed network, reachable from any IAM principal who can `sagemaker:InvokeEndpoint`. Flag medium.
   - **Combined with a public-IAM-scope** (the principals analysis below) → high.
2. **IAM principals with `sagemaker:InvokeEndpoint`** — same pattern as Bedrock. Look at attached IAM policies for principals who can call `sagemaker:InvokeEndpoint` with `Resource: "*"`. Cross-reference against the endpoint list — a wildcard invoker on a no-VPC endpoint is a real exposure path.

### Compliance evidence
Findings auto-tag with `nist_ai_rmf` and `iso_42001` (AWS audit's `compliance_tags`). When emitting, also include in `evidence`:
  - resource ARN (endpoint ARN, model ARN, role ARN)
  - exact policy element that proves the IAM finding (quote the JSON Action/Resource block)
  - region (Bedrock/SageMaker are regional — a finding in us-east-1 doesn't tell you anything about eu-west-1)

### Tools You'll Use Most
`cloud_invoke` against `aws_bedrock_invocation_logging`, `aws_bedrock_guardrails`, `aws_bedrock_foundation_models`, `aws_sagemaker_endpoints`, `aws_sagemaker_endpoint_configs`, `aws_iam_policies`, `aws_iam_roles`. `cloud_inspect` for full policy documents and VPC configs. `emit_finding`.

Skip `aws_bedrock_foundation_models` enumeration if the customer hasn't enabled Bedrock — the API returns 200 with an empty list, treat that as "Bedrock not in use, skip the rest of the Bedrock checklist".

Call `emit_finding` with `protocol="aws"` and `mission="managed_ai"`.
