"""Tests for XML response parsing in ApiTransport (AWS Query API support)."""

import httpx
import pytest

from services.transports.api_transport import (
    _parse_response,
    _resolve_dot_path,
    _strip_xml_namespaces,
)


def _make_response(body: str, content_type: str = "text/xml") -> httpx.Response:
    """Build a real httpx.Response object so _parse_response can read .text/.headers."""
    return httpx.Response(
        status_code=200,
        headers={"content-type": content_type},
        content=body.encode("utf-8"),
    )


# ───────────────────────── XML parsing ─────────────────────────

class TestXmlParsing:
    def test_parses_aws_ec2_describe_instances(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <reservationId>r-1234</reservationId>
      <ownerId>111122223333</ownerId>
      <instancesSet>
        <item>
          <instanceId>i-aaa</instanceId>
          <instanceType>t3.micro</instanceType>
          <privateIpAddress>10.0.0.5</privateIpAddress>
          <placement>
            <availabilityZone>us-east-1a</availabilityZone>
          </placement>
        </item>
        <item>
          <instanceId>i-bbb</instanceId>
          <instanceType>t3.large</instanceType>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>"""
        parsed = _parse_response(_make_response(body))
        # Default namespace is dropped by _strip_xml_namespaces
        assert "DescribeInstancesResponse" in parsed
        reservations = parsed["DescribeInstancesResponse"]["reservationSet"]["item"]
        assert isinstance(reservations, list)
        assert len(reservations) == 1
        instances = reservations[0]["instancesSet"]["item"]
        assert isinstance(instances, list)
        assert len(instances) == 2
        assert instances[0]["instanceId"] == "i-aaa"
        assert instances[1]["instanceId"] == "i-bbb"

    def test_parses_aws_iam_list_users(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult>
    <Users>
      <member>
        <UserName>alice</UserName>
        <UserId>AIDAALICE</UserId>
        <Arn>arn:aws:iam::111122223333:user/alice</Arn>
        <CreateDate>2024-01-15T12:00:00Z</CreateDate>
        <Path>/</Path>
      </member>
      <member>
        <UserName>bob</UserName>
        <UserId>AIDABOB</UserId>
        <Arn>arn:aws:iam::111122223333:user/bob</Arn>
        <CreateDate>2024-02-20T08:30:00Z</CreateDate>
        <Path>/engineering/</Path>
      </member>
    </Users>
    <IsTruncated>false</IsTruncated>
  </ListUsersResult>
  <ResponseMetadata>
    <RequestId>req-1</RequestId>
  </ResponseMetadata>
</ListUsersResponse>"""
        parsed = _parse_response(_make_response(body))
        users = parsed["ListUsersResponse"]["ListUsersResult"]["Users"]["member"]
        assert isinstance(users, list)
        assert len(users) == 2
        assert users[0]["UserName"] == "alice"
        assert users[1]["UserName"] == "bob"
        assert users[1]["Arn"].endswith(":user/bob")

    def test_single_member_still_a_list(self):
        """force_list ensures one-element collections aren't collapsed to dict."""
        body = """<?xml version="1.0"?>
<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListRolesResult>
    <Roles>
      <member>
        <RoleName>solo-role</RoleName>
        <RoleId>AROASOLO</RoleId>
      </member>
    </Roles>
  </ListRolesResult>
</ListRolesResponse>"""
        parsed = _parse_response(_make_response(body))
        roles = parsed["ListRolesResponse"]["ListRolesResult"]["Roles"]["member"]
        assert isinstance(roles, list)
        assert len(roles) == 1
        assert roles[0]["RoleName"] == "solo-role"

    def test_parses_aws_s3_list_buckets(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>abc</ID></Owner>
  <Buckets>
    <Bucket>
      <Name>my-bucket-1</Name>
      <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
    <Bucket>
      <Name>my-bucket-2</Name>
      <CreationDate>2024-06-15T12:30:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>"""
        parsed = _parse_response(_make_response(body))
        buckets = parsed["ListAllMyBucketsResult"]["Buckets"]["Bucket"]
        assert isinstance(buckets, list)
        assert len(buckets) == 2
        assert {b["Name"] for b in buckets} == {"my-bucket-1", "my-bucket-2"}

    def test_strips_namespace_prefix_from_keys(self):
        # Some AWS responses use prefixed namespaces
        body = """<?xml version="1.0"?>
<ns:Root xmlns:ns="http://example.com/">
  <ns:Child>value</ns:Child>
</ns:Root>"""
        parsed = _parse_response(_make_response(body))
        assert "Root" in parsed
        assert parsed["Root"]["Child"] == "value"

    def test_parses_json_when_content_type_is_json(self):
        body = '{"items": [{"id": 1}, {"id": 2}]}'
        parsed = _parse_response(_make_response(body, content_type="application/json"))
        assert parsed == {"items": [{"id": 1}, {"id": 2}]}

    def test_falls_back_to_xml_when_body_starts_with_angle_bracket(self):
        # No content-type header at all — sniff the body
        body = "<Root><Foo>bar</Foo></Root>"
        resp = httpx.Response(status_code=200, content=body.encode("utf-8"))
        parsed = _parse_response(resp)
        assert parsed == {"Root": {"Foo": "bar"}}

    def test_empty_body_returns_raw_wrapper(self):
        resp = httpx.Response(status_code=200, content=b"", headers={"content-type": "application/json"})
        parsed = _parse_response(resp)
        # Empty JSON .json() raises; we wrap it
        assert isinstance(parsed, dict)


# ───────────────────────── Path resolver ─────────────────────────

class TestResolveDotPath:
    def test_simple_dot_path(self):
        obj = {"a": {"b": {"c": "deep"}}}
        assert _resolve_dot_path(obj, "a.b.c") == "deep"

    def test_returns_none_for_missing(self):
        assert _resolve_dot_path({"a": 1}, "a.b") is None
        assert _resolve_dot_path({"a": 1}, "z") is None

    def test_array_index(self):
        obj = {"items": [{"id": "x"}, {"id": "y"}]}
        assert _resolve_dot_path(obj, "items[0].id") == "x"
        assert _resolve_dot_path(obj, "items[1].id") == "y"

    def test_array_index_out_of_range(self):
        obj = {"items": [{"id": "x"}]}
        assert _resolve_dot_path(obj, "items[5].id") is None

    def test_wildcard_flatten_single_level(self):
        obj = {"reservations": [
            {"instances": [{"id": "a"}, {"id": "b"}]},
            {"instances": [{"id": "c"}]},
        ]}
        result = _resolve_dot_path(obj, "reservations[*].instances[*]")
        assert result == [{"id": "a"}, {"id": "b"}, {"id": "c"}]

    def test_wildcard_flatten_aws_ec2_shape(self):
        # The exact shape produced by xmltodict for EC2 DescribeInstances
        obj = {
            "DescribeInstancesResponse": {
                "reservationSet": {
                    "item": [
                        {
                            "ownerId": "111",
                            "instancesSet": {
                                "item": [
                                    {"instanceId": "i-1", "instanceType": "t3.micro"},
                                    {"instanceId": "i-2", "instanceType": "t3.large"},
                                ]
                            },
                        },
                        {
                            "ownerId": "222",
                            "instancesSet": {
                                "item": [{"instanceId": "i-3", "instanceType": "m5.large"}]
                            },
                        },
                    ]
                }
            }
        }
        result = _resolve_dot_path(
            obj, "DescribeInstancesResponse.reservationSet.item[*].instancesSet.item[*]"
        )
        assert isinstance(result, list)
        assert len(result) == 3
        assert {r["instanceId"] for r in result} == {"i-1", "i-2", "i-3"}

    def test_empty_path_returns_root(self):
        obj = {"a": 1}
        assert _resolve_dot_path(obj, "") == obj
        assert _resolve_dot_path(obj, None) == obj


# ───────────────────────── Namespace stripping ─────────────────────────

class TestStripXmlNamespaces:
    def test_strips_prefixed_keys(self):
        obj = {"ns:Root": {"ns:Child": "value"}}
        cleaned = _strip_xml_namespaces(obj)
        assert cleaned == {"Root": {"Child": "value"}}

    def test_drops_xmlns_attribute_keys(self):
        obj = {"Root": {"@xmlns": "http://example.com/", "Child": "value"}}
        cleaned = _strip_xml_namespaces(obj)
        assert "@xmlns" not in cleaned["Root"]
        assert cleaned["Root"]["Child"] == "value"

    def test_preserves_attribute_prefix(self):
        # @-prefixed attribute keys should not be stripped
        obj = {"Root": {"@id": "5", "Child": "x"}}
        cleaned = _strip_xml_namespaces(obj)
        assert cleaned["Root"]["@id"] == "5"

    def test_handles_lists(self):
        obj = {"ns:Items": [{"ns:Item": "a"}, {"ns:Item": "b"}]}
        cleaned = _strip_xml_namespaces(obj)
        assert cleaned == {"Items": [{"Item": "a"}, {"Item": "b"}]}
