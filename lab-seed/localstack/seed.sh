#!/usr/bin/env bash
# LocalStack init hook — runs once when the service is "ready".
# Mounted into /etc/localstack/init/ready.d/seed.sh
#
# Creates a publicly-listable S3 bucket (`corp-backups`) and uploads what
# looks like a leaked SSH private key + a config file. The audit should
# detect:
#   - bucket-level public-read ACL
#   - sensitive object names (id_rsa, *.pem)
#   - cleartext key material in object body
#
# Also creates an IAM user with overly-permissive inline policy, plus a
# Lambda function whose code references the AWS keys — to feed the cloud
# audit's identity + managed_ai prompts.

set -euo pipefail

awslocal s3 mb s3://corp-backups || true
awslocal s3 mb s3://corp-logs    || true

TMPDIR=$(mktemp -d)

cat >"$TMPDIR/lab_id_rsa" <<'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBPTacXk6Z2vbe2pAFlnxr6hoTeRJYQRLBGFB7Tlz9bFwAAAJB+FAKofhQC
qAAAAAtzc2gtZWQyNTUxOQAAACBPTacXk6Z2vbe2pAFlnxr6hoTeRJYQRLBGFB7Tlz9bFw
AAAEDr0bZkqYZRrPi5zU/ZVjOg8xDU0r6t9IGHi+MeJK5J/k9NpxeTpna9t7akAWWfGvqG
hN5ElhBEsEYUHtOXP1sXAAAAEmxhYi10ZXN0LWtleS1maWxlcgECAw==
-----END OPENSSH PRIVATE KEY-----
KEY

cat >"$TMPDIR/lab_id_rsa.pub" <<'PUB'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE9NpxeTpna9t7akAWWfGvqGhN5ElhBEsEYUHtOXP1sX lab@hakuna-lab-test-key
PUB

cat >"$TMPDIR/backup-config.ini" <<'CFG'
[backup]
ssh_host = ssh
ssh_port = 2222
ssh_user = lab
ssh_key  = s3://corp-backups/ssh/lab_id_rsa
mysql_host = mysql
mysql_user = root
mysql_pass = Summer2024!
CFG

awslocal s3 cp "$TMPDIR/lab_id_rsa"        s3://corp-backups/ssh/lab_id_rsa
awslocal s3 cp "$TMPDIR/lab_id_rsa.pub"    s3://corp-backups/ssh/lab_id_rsa.pub
awslocal s3 cp "$TMPDIR/backup-config.ini" s3://corp-backups/config/backup-config.ini

# Public-read ACL — the headline misconfig.
awslocal s3api put-bucket-acl --bucket corp-backups --acl public-read || true
awslocal s3api put-public-access-block \
  --bucket corp-backups \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false \
  || true

# IAM: an admin-equivalent user with an inline wildcard policy.
awslocal iam create-user --user-name backup-bot || true
awslocal iam create-access-key --user-name backup-bot || true
awslocal iam put-user-policy \
  --user-name backup-bot \
  --policy-name AdminEverywhere \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect":"Allow","Action":"*","Resource":"*"}]
  }' || true

# Lambda: a function whose env contains the backup creds (info-disclosure).
cat >"$TMPDIR/handler.py" <<'PY'
def handler(event, context):
    return {"statusCode": 200, "body": "lab"}
PY
( cd "$TMPDIR" && zip -q handler.zip handler.py )

awslocal lambda create-function \
  --function-name corp-backup-runner \
  --runtime python3.11 \
  --role arn:aws:iam::000000000000:role/lambda-exec \
  --handler handler.handler \
  --zip-file "fileb://$TMPDIR/handler.zip" \
  --environment "Variables={AWS_ACCESS_KEY_ID=test,AWS_SECRET_ACCESS_KEY=test,SSH_KEY_S3=s3://corp-backups/ssh/lab_id_rsa,DB_PASSWORD=Summer2024!}" \
  || true

echo "lab seed: localstack populated (s3://corp-backups, iam user backup-bot, lambda corp-backup-runner)"
