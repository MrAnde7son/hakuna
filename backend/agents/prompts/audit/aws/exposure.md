{preamble}

## Mission: Public Exposure
Hunt for AWS resources reachable from the public internet that shouldn't be, and data that's world-readable.

### Checklist
1. **S3 public buckets** — `cloud_invoke("aws_s3_buckets", fields=["Name"])` lists buckets. For each, use a bucket-policy / public-access-block op (via cloud_list_operations) to check exposure. Flag: public ACL, bucket policy allowing `Principal: *`, missing public-access-block.
2. **Security groups open to the world** — list EC2 SGs; flag ingress rules with `0.0.0.0/0` on sensitive ports (22, 3389, 3306, 5432, 27017, 6379, 9200).
3. **Publicly-addressable compute** — EC2 instances with a public IP + permissive SG; Lambda function URLs with `AuthType: NONE`.
4. **Unauthenticated API Gateway / ALB endpoints** — if the catalog exposes the ops, check for routes without auth.

### Tools You'll Use Most
`cloud_list_operations` (once to discover), `cloud_invoke` with field projection, `cloud_inspect` for drill-ins, `emit_finding`.

Severity skews high for confirmed public data exposure. A bucket that *could* be made public (missing public-access-block) but isn't currently = medium, not critical.

Call `emit_finding` with `protocol="aws"` and `mission="exposure"`.
