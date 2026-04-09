"""End-to-end tests for AWS CNAPP connectors.

Simulates a full ingest pipeline using realistic AWS XML responses:
  raw XML → _parse_response → records_path resolution → field_mapper.map_record
This catches schema mismatches between connector field maps and the actual
shape produced by xmltodict, which is what we'd hit at runtime.
"""

import json
from pathlib import Path

import httpx
import pytest

from services.transports.api_transport import _parse_response, _resolve_dot_path
from services.field_mapper import map_record

CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"


def _load_connector(cid: str) -> dict:
    return json.loads((CONNECTORS_DIR / f"{cid}.json").read_text())


def _xml_response(body: str) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        headers={"content-type": "text/xml"},
        content=body.encode("utf-8"),
    )


def _run_connector_pipeline(connector_id: str, xml_body: str) -> list[dict]:
    """Pipe an XML response through parse → records_path → field_mapper.

    Returns the list of mapped records.
    """
    connector = _load_connector(connector_id)
    parsed = _parse_response(_xml_response(xml_body))
    records = _resolve_dot_path(parsed, connector["records_path"])
    if records is None:
        return []
    if not isinstance(records, list):
        records = [records]

    mapped_records = []
    for raw in records:
        result = map_record(raw, connector["default_field_map"])
        mapped_records.append(result["mapped"])
    return mapped_records


# ───────────────────────── EC2 ─────────────────────────

EC2_DESCRIBE_INSTANCES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>req-1</requestId>
  <reservationSet>
    <item>
      <reservationId>r-aaa</reservationId>
      <ownerId>111122223333</ownerId>
      <groupSet/>
      <instancesSet>
        <item>
          <instanceId>i-0abc1234567890def</instanceId>
          <imageId>ami-0123456789abcdef0</imageId>
          <instanceState>
            <code>16</code>
            <name>running</name>
          </instanceState>
          <privateDnsName>ip-10-0-0-5.ec2.internal</privateDnsName>
          <dnsName>ec2-203-0-113-10.compute-1.amazonaws.com</dnsName>
          <instanceType>t3.micro</instanceType>
          <launchTime>2024-06-15T10:30:00.000Z</launchTime>
          <placement>
            <availabilityZone>us-east-1a</availabilityZone>
            <tenancy>default</tenancy>
          </placement>
          <subnetId>subnet-abc123</subnetId>
          <vpcId>vpc-def456</vpcId>
          <privateIpAddress>10.0.0.5</privateIpAddress>
          <ipAddress>203.0.113.10</ipAddress>
          <iamInstanceProfile>
            <arn>arn:aws:iam::111122223333:instance-profile/web-tier</arn>
            <id>AIPATEST</id>
          </iamInstanceProfile>
          <groupSet>
            <item>
              <groupId>sg-0abc</groupId>
              <groupName>web-sg</groupName>
            </item>
            <item>
              <groupId>sg-0def</groupId>
              <groupName>monitoring-sg</groupName>
            </item>
          </groupSet>
          <tagSet>
            <item>
              <key>Environment</key>
              <value>production</value>
            </item>
            <item>
              <key>Name</key>
              <value>web-01</value>
            </item>
          </tagSet>
        </item>
        <item>
          <instanceId>i-1aaaaaaaaaaaaaaaa</instanceId>
          <imageId>ami-0123456789abcdef0</imageId>
          <instanceState><name>stopped</name></instanceState>
          <instanceType>t3.large</instanceType>
          <launchTime>2024-05-01T08:00:00.000Z</launchTime>
          <placement>
            <availabilityZone>us-east-1b</availabilityZone>
          </placement>
          <subnetId>subnet-xyz789</subnetId>
          <vpcId>vpc-def456</vpcId>
          <privateIpAddress>10.0.1.20</privateIpAddress>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>"""


class TestEc2ConnectorPipeline:
    def test_records_path_flattens_reservations_to_instances(self):
        connector = _load_connector("aws_ec2_instances")
        parsed = _parse_response(_xml_response(EC2_DESCRIBE_INSTANCES_XML))
        records = _resolve_dot_path(parsed, connector["records_path"])
        assert isinstance(records, list)
        assert len(records) == 2

    def test_maps_running_instance(self):
        records = _run_connector_pipeline("aws_ec2_instances", EC2_DESCRIBE_INSTANCES_XML)
        assert len(records) == 2

        running = records[0]
        assert running["source_id"] == "i-0abc1234567890def"
        assert running["hostname"] == "i-0abc1234567890def"
        assert running["fqdn"] == "ip-10-0-0-5.ec2.internal"
        assert running["ip_address"] == "203.0.113.10"
        assert running["asset_type"] == "cloud_instance"
        assert running["is_internet_facing"] is True
        assert running["tags"] == ["running"]

        identity = running["asset_identity"]
        assert identity["cloud_provider"] == "aws"
        assert identity["instance_id"] == "i-0abc1234567890def"
        assert identity["region"] == "us-east-1"
        assert identity["availability_zone"] == "us-east-1a"

        attrs = running["asset_attributes"]
        assert attrs["resource_type"] == "ec2_instance"
        assert attrs["instance_type"] == "t3.micro"
        assert attrs["state"] == "running"
        assert attrs["vpc_id"] == "vpc-def456"
        assert attrs["subnet_id"] == "subnet-abc123"
        assert attrs["iam_instance_profile_arn"].endswith(":instance-profile/web-tier")
        assert sorted(attrs["security_groups"]) == ["sg-0abc", "sg-0def"]
        assert attrs["tags"] == {"Environment": "production", "Name": "web-01"}

    def test_maps_stopped_instance_without_public_ip(self):
        records = _run_connector_pipeline("aws_ec2_instances", EC2_DESCRIBE_INSTANCES_XML)
        stopped = records[1]
        assert stopped["source_id"] == "i-1aaaaaaaaaaaaaaaa"
        assert stopped["is_internet_facing"] is False
        assert stopped["asset_attributes"]["state"] == "stopped"
        # No tagSet → empty dict
        assert stopped["asset_attributes"]["tags"] == {}
        assert stopped["asset_attributes"]["security_groups"] == []


# ───────────────────────── IAM Users ─────────────────────────

IAM_LIST_USERS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult>
    <IsTruncated>false</IsTruncated>
    <Users>
      <member>
        <Path>/</Path>
        <UserName>alice</UserName>
        <UserId>AIDAALICE0000000000</UserId>
        <Arn>arn:aws:iam::111122223333:user/alice</Arn>
        <CreateDate>2024-01-15T12:00:00Z</CreateDate>
        <PasswordLastUsed>2026-04-01T09:30:00Z</PasswordLastUsed>
      </member>
      <member>
        <Path>/engineering/</Path>
        <UserName>bob</UserName>
        <UserId>AIDABOB000000000000</UserId>
        <Arn>arn:aws:iam::111122223333:user/engineering/bob</Arn>
        <CreateDate>2024-02-20T08:30:00Z</CreateDate>
      </member>
    </Users>
  </ListUsersResult>
  <ResponseMetadata>
    <RequestId>req-2</RequestId>
  </ResponseMetadata>
</ListUsersResponse>"""


class TestIamUsersConnectorPipeline:
    def test_records_path_resolves_member_list(self):
        connector = _load_connector("aws_iam_users")
        parsed = _parse_response(_xml_response(IAM_LIST_USERS_XML))
        records = _resolve_dot_path(parsed, connector["records_path"])
        assert isinstance(records, list)
        assert len(records) == 2

    def test_maps_user_with_console_access(self):
        records = _run_connector_pipeline("aws_iam_users", IAM_LIST_USERS_XML)
        alice = records[0]
        assert alice["source_id"] == "AIDAALICE0000000000"
        assert alice["hostname"] == "alice"
        assert alice["fqdn"] == "arn:aws:iam::111122223333:user/alice"
        assert alice["asset_type"] == "identity"
        assert alice["first_seen"] is not None
        assert alice["last_seen"] is not None  # PasswordLastUsed populated

        identity = alice["asset_identity"]
        assert identity["cloud_provider"] == "aws"
        assert identity["identity_type"] == "iam_user"
        assert identity["username"] == "alice"
        assert identity["account_id"] == "111122223333"

        attrs = alice["asset_attributes"]
        assert attrs["identity_subtype"] == "human"
        assert attrs["resource_type"] == "iam_user"
        assert attrs["has_console_access"] is True

    def test_maps_user_without_console_access(self):
        records = _run_connector_pipeline("aws_iam_users", IAM_LIST_USERS_XML)
        bob = records[1]
        assert bob["source_id"] == "AIDABOB000000000000"
        assert bob["asset_attributes"]["has_console_access"] is False
        assert bob["asset_attributes"]["path"] == "/engineering/"


# ───────────────────────── IAM Roles ─────────────────────────

IAM_LIST_ROLES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListRolesResult>
    <IsTruncated>false</IsTruncated>
    <Roles>
      <member>
        <Path>/service-role/</Path>
        <RoleName>lambda-execution-role</RoleName>
        <RoleId>AROALAMBDA000000000</RoleId>
        <Arn>arn:aws:iam::111122223333:role/service-role/lambda-execution-role</Arn>
        <CreateDate>2024-03-10T15:00:00Z</CreateDate>
        <MaxSessionDuration>3600</MaxSessionDuration>
        <RoleLastUsed>
          <LastUsedDate>2026-04-07T12:00:00Z</LastUsedDate>
          <Region>us-east-1</Region>
        </RoleLastUsed>
      </member>
    </Roles>
  </ListRolesResult>
</ListRolesResponse>"""


class TestIamRolesConnectorPipeline:
    def test_maps_role_with_last_used(self):
        records = _run_connector_pipeline("aws_iam_roles", IAM_LIST_ROLES_XML)
        assert len(records) == 1
        role = records[0]
        assert role["source_id"] == "AROALAMBDA000000000"
        assert role["hostname"] == "lambda-execution-role"
        assert role["asset_type"] == "identity"

        identity = role["asset_identity"]
        assert identity["identity_type"] == "iam_role"
        assert identity["account_id"] == "111122223333"
        assert identity["arn"].endswith(":role/service-role/lambda-execution-role")

        attrs = role["asset_attributes"]
        assert attrs["identity_subtype"] == "machine_identity"
        assert attrs["resource_type"] == "iam_role"
        assert attrs["max_session_duration"] == "3600"
        assert attrs["last_used_region"] == "us-east-1"


# ───────────────────────── S3 ─────────────────────────

S3_LIST_BUCKETS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>abc1234567890def</ID>
    <DisplayName>account-owner</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>company-data-prod</Name>
      <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
    <Bucket>
      <Name>company-logs</Name>
      <CreationDate>2024-06-15T12:30:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>"""


class TestS3BucketsConnectorPipeline:
    def test_maps_buckets(self):
        records = _run_connector_pipeline("aws_s3_buckets", S3_LIST_BUCKETS_XML)
        assert len(records) == 2
        assert {r["source_id"] for r in records} == {"company-data-prod", "company-logs"}

        prod = next(r for r in records if r["source_id"] == "company-data-prod")
        assert prod["hostname"] == "company-data-prod"
        assert prod["fqdn"] == "company-data-prod.s3.amazonaws.com"
        assert prod["asset_type"] == "cloud_instance"

        identity = prod["asset_identity"]
        assert identity["cloud_provider"] == "aws"
        assert identity["service"] == "s3"
        assert identity["arn"] == "arn:aws:s3:::company-data-prod"
        assert identity["bucket_name"] == "company-data-prod"

        attrs = prod["asset_attributes"]
        assert attrs["resource_type"] == "s3_bucket"
        assert attrs["service"] == "s3"

        # easm_data nested target
        assert prod["easm_data"]["aws_s3"]["bucket_url"] == "https://company-data-prod.s3.amazonaws.com"


# ───────────────────────── Lambda (JSON, not XML) ─────────────────────────

LAMBDA_LIST_FUNCTIONS_JSON = json.dumps({
    "Functions": [
        {
            "FunctionName": "process-orders",
            "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:process-orders",
            "Runtime": "python3.11",
            "Role": "arn:aws:iam::111122223333:role/lambda-execution-role",
            "Handler": "main.handler",
            "CodeSize": 12345,
            "MemorySize": 256,
            "Timeout": 30,
            "LastModified": "2024-08-01T10:00:00.000+0000",
            "Version": "$LATEST",
            "Architectures": ["x86_64"],
            "PackageType": "Zip",
            "State": "Active",
            "Environment": {"Variables": {"DB_URL": "postgres://...", "API_KEY": "secret"}},
            "VpcConfig": {"VpcId": "vpc-def456"},
            "KMSKeyArn": "",
        }
    ]
})


# ───────────────────────── IAM Policies (entitlements) ─────────────────────────

IAM_LIST_POLICIES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListPoliciesResult>
    <IsTruncated>false</IsTruncated>
    <Policies>
      <member>
        <PolicyName>S3ReadOnlyForBI</PolicyName>
        <PolicyId>ANPA111111111111111</PolicyId>
        <Arn>arn:aws:iam::111122223333:policy/S3ReadOnlyForBI</Arn>
        <Path>/</Path>
        <DefaultVersionId>v3</DefaultVersionId>
        <AttachmentCount>5</AttachmentCount>
        <PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>
        <IsAttachable>true</IsAttachable>
        <Description>Read-only access to data lake S3 buckets for BI tooling</Description>
        <CreateDate>2024-01-15T12:00:00Z</CreateDate>
        <UpdateDate>2024-09-20T16:30:00Z</UpdateDate>
      </member>
    </Policies>
  </ListPoliciesResult>
</ListPoliciesResponse>"""


class TestIamPoliciesConnectorPipeline:
    def test_maps_managed_policy(self):
        records = _run_connector_pipeline("aws_iam_policies", IAM_LIST_POLICIES_XML)
        assert len(records) == 1
        policy = records[0]
        assert policy["source_id"] == "ANPA111111111111111"
        assert policy["hostname"] == "S3ReadOnlyForBI"
        assert policy["asset_type"] == "cloud_entitlement"

        identity = policy["asset_identity"]
        assert identity["cloud_provider"] == "aws"
        assert identity["entitlement_type"] == "iam_policy"
        assert identity["account_id"] == "111122223333"
        assert identity["arn"].endswith(":policy/S3ReadOnlyForBI")

        attrs = policy["asset_attributes"]
        assert attrs["resource_type"] == "iam_policy"
        assert attrs["entitlement_kind"] == "permission_set"
        assert attrs["attachment_count"] == 5
        assert attrs["is_attachable"] is True
        assert attrs["default_version_id"] == "v3"


class TestLambdaConnectorPipeline:
    def test_maps_lambda_function(self):
        connector = _load_connector("aws_lambda_functions")
        resp = httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=LAMBDA_LIST_FUNCTIONS_JSON.encode(),
        )
        parsed = _parse_response(resp)
        records = _resolve_dot_path(parsed, connector["records_path"])
        assert isinstance(records, list) and len(records) == 1

        result = map_record(records[0], connector["default_field_map"])
        fn = result["mapped"]
        assert fn["source_id"] == "arn:aws:lambda:us-east-1:111122223333:function:process-orders"
        assert fn["hostname"] == "process-orders"
        assert fn["asset_type"] == "cloud_instance"

        identity = fn["asset_identity"]
        assert identity["cloud_provider"] == "aws"
        assert identity["service"] == "lambda"
        assert identity["account_id"] == "111122223333"
        assert identity["region"] == "us-east-1"

        attrs = fn["asset_attributes"]
        assert attrs["resource_type"] == "lambda_function"
        assert attrs["runtime"] == "python3.11"
        assert attrs["memory_size"] == 256
        assert attrs["timeout"] == 30
        assert sorted(attrs["environment_variables"]) == ["API_KEY", "DB_URL"]
