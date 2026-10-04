from copy import deepcopy

import pytest

from app.services.cloud_drift import (SNAPSHOT_VERSION, compare_drift, discover_aws,
                                      snapshot_to_model, validate_snapshot)
from app.services.model_interchange import ModelError

ACCOUNT, REGION = "123456789012", "us-east-1"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-api"


def snapshot():
    return {"schema_version": SNAPSHOT_VERSION, "provider": "aws", "account_id": ACCOUNT, "region": REGION,
        "observed_at": "2026-10-04T12:00:00+00:00", "coverage": {"ec2": {"status": "complete"}},
        "resources": [{"id": ARN, "name": "api", "type": "aws_ec2_instance", "service": "ec2",
                       "properties": {"metadata_HttpTokens": "required"}}]}


def test_drift_changes_are_deterministic_and_missing_fields_remain_unknown():
    before, after = snapshot(), snapshot()
    after["resources"][0]["properties"] = {"public_ip_assigned": True}
    result = compare_drift(before, after)
    assert result == compare_drift(before, after)
    assert result["changes"][0]["status"] == "unknown"
    assert all(f["status"] == "unknown" for f in result["changes"][0]["fields"])
    assert "publicly_accessible" not in str(result)
    after["resources"][0]["properties"]["metadata_HttpTokens"] = "optional"
    assert compare_drift(before, after)["changes"][0]["status"] == "changed"


def test_missing_resource_even_in_complete_snapshot_is_not_verified_deleted():
    before, after = snapshot(), snapshot()
    after["resources"] = []
    result = compare_drift(before, after)
    assert result["changes"] == [{"resource_id": ARN, "status": "not_observed", "collection_status": "complete"}]
    assert "verified_fixed" not in str(result)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(region="eu-west-1"),
    lambda d: d.update(account_id="999999999999"),
    lambda d: d.update(observed_at="invalid"),
    lambda d: d["resources"].append(deepcopy(d["resources"][0])),
    lambda d: d["resources"][0].update(service="s3"),
    lambda d: d["coverage"]["ec2"].update(status="not_requested"),
    lambda d: d.update(observed_at="2026-10-04T12:00:00"),
])
def test_invalid_scope_and_snapshots_are_rejected(mutate):
    value = snapshot()
    mutate(value)
    with pytest.raises(ModelError):
        validate_snapshot(value)


def test_older_observation_rejected():
    before, after = snapshot(), snapshot()
    after["observed_at"] = "2026-10-03T12:00:00Z"
    with pytest.raises(ModelError, match="older"):
        compare_drift(before, after)


def test_snapshot_model_keeps_identity_but_never_invents_flows_or_trust():
    model = snapshot_to_model(snapshot())
    assert model["architecture"]["flows"] == []
    component = model["architecture"]["components"][0]
    assert component["id"] == component["properties"]["arn"] == ARN
    assert component["trust_level"] == "unknown"
    assert component["evidence"][0]["source_sha256"]


def test_model_drift_requires_explicit_scope_and_resource_binding():
    model = snapshot_to_model(snapshot())
    model["architecture"]["components"][0]["properties"]["cloud_expected"] = {"metadata_HttpTokens": "optional"}
    assert compare_drift(model, snapshot())["changes"][0]["status"] == "changed"
    model["architecture"]["metadata"].pop("cloud_scope")
    with pytest.raises(ModelError, match="cloud_scope"):
        compare_drift(model, snapshot())


class FakeSession:
    def __init__(self, pages=None, account=ACCOUNT):
        self.pages = pages or {}
        self.account = account
        self.calls = []

    def client(self, service, **config):
        owner = self
        class Client:
            def get_caller_identity(self):
                owner.calls.append((service, "get_caller_identity", {}))
                return {"Account": owner.account, "Arn": f"arn:aws:iam::{owner.account}:role/read-only"}

            def describe_instances(self, **kwargs):
                owner.calls.append((service, "describe_instances", kwargs))
                result = owner.pages[service].pop(0)
                if isinstance(result, Exception):
                    raise result
                return result

            def list_functions(self, **kwargs):
                owner.calls.append((service, "list_functions", kwargs))
                return owner.pages[service].pop(0)

            def describe_db_instances(self, **kwargs):
                owner.calls.append((service, "describe_db_instances", kwargs))
                return owner.pages[service].pop(0)
        return Client()


def page(identifier="i-api", token=None):
    return {"Reservations": [{"Instances": [{"InstanceId": identifier, "MetadataOptions": {"HttpTokens": "required"}}]}],
            **({"NextToken": token} if token else {})}


def test_discovery_checks_account_before_resource_clients():
    session = FakeSession(account="000000000000")
    with pytest.raises(ModelError, match="does not match"):
        discover_aws(account_id=ACCOUNT, region=REGION, services=["ec2"], session=session)
    assert len(session.calls) == 1


def test_discovery_read_only_paginated_bounded_and_not_public_by_default():
    session = FakeSession({"ec2": [page(token="more"), page("i-worker")]})
    value = discover_aws(account_id=ACCOUNT, region=REGION, services=["ec2"], session=session)
    assert value["coverage"]["ec2"]["status"] == "complete"
    assert len(value["resources"]) == 2
    assert session.calls[-1][2]["NextToken"] == "more"
    assert "public_ip_assigned" not in value["resources"][0]["properties"]
    assert {r[1] for r in session.calls} == {"get_caller_identity", "describe_instances"}


@pytest.mark.parametrize("limits", [{"max_resources": 1}, {"max_requests": 2}])
def test_discovery_limits_return_partial_not_empty_clean_inventory(limits):
    session = FakeSession({"ec2": [page(token="more"), page("i-worker")]})
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["ec2"], session=session, **limits)
    assert result["coverage"]["ec2"]["status"] == "partial"
    assert len(result["resources"]) == 1
    assert len(session.calls) == 2


def test_access_denied_is_unknown_and_error_messages_are_not_leaked():
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDenied"}}
    session = FakeSession({"ec2": [Denied("secret-token-in-message")]})
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["ec2"], session=session)
    assert result["coverage"]["ec2"] == {"status": "partial", "reason": "AccessDenied"}
    assert "secret-token" not in str(result)


def test_lambda_discovery_does_not_retain_environment_or_code_credentials():
    session = FakeSession({"lambda": [{"Functions": [{"FunctionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:api",
        "FunctionName": "api", "Runtime": "python3.12", "Environment": {"Variables": {"secret": "do-not-keep"}},
        "Code": {"Location": "https://signed.invalid/token"}}]}]})
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["lambda"], session=session)
    assert result["resources"][0]["properties"] == {"runtime": "python3.12"}
    assert "do-not-keep" not in str(result)


def test_rds_public_setting_is_not_effective_reachability():
    session = FakeSession({"rds": [{"DBInstances": [{"DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders",
        "DBInstanceIdentifier": "orders", "PubliclyAccessible": True, "StorageEncrypted": False}]}]})
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["rds"], session=session)
    assert result["resources"][0]["properties"] == {"publicly_accessible_setting": True, "encryption_at_rest": False}


@pytest.mark.parametrize("kwargs", [{"region": ""}, {"account_id": "default"}, {"max_resources": 9000},
                                   {"services": ["iam"]}, {"services": ["ec2", "ec2"]}, {"max_requests": 0}])
def test_discovery_invalid_arguments_do_not_touch_cloud(kwargs):
    session = FakeSession()
    params = {"account_id": ACCOUNT, "region": REGION, "services": ["ec2"], "session": session, **kwargs}
    with pytest.raises(ModelError):
        discover_aws(**params)
    assert not session.calls


class S3Session(FakeSession):
    def __init__(self, *, deny_account=False, deny_encryption=False, deny_location=False):
        super().__init__()
        self.deny_account, self.deny_encryption, self.deny_location = deny_account, deny_encryption, deny_location

    def client(self, service, **config):
        if service == "sts":
            return super().client(service, **config)
        owner = self

        class Denied(Exception):
            response = {"Error": {"Code": "AccessDenied"}}

        class S3:
            def record(self, method, args):
                owner.calls.append((service, method, args))

            def list_buckets(self, **kwargs):
                self.record("list_buckets", kwargs)
                if "ContinuationToken" not in kwargs:
                    return {"Buckets": [{"Name": "other-region"}], "ContinuationToken": "next-page"}
                return {"Buckets": [{"Name": "images"}]}

            def get_bucket_location(self, **kwargs):
                self.record("get_bucket_location", kwargs)
                if owner.deny_location:
                    raise Denied("do not leak")
                return {"LocationConstraint": "EU" if kwargs["Bucket"] == "other-region" else None}

            def get_public_access_block(self, **kwargs):
                self.record("get_public_access_block", kwargs)
                if service == "s3control" and owner.deny_account:
                    raise Denied("do not leak")
                return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}

            def get_bucket_policy_status(self, **kwargs):
                self.record("get_bucket_policy_status", kwargs)
                return {"PolicyStatus": {"IsPublic": True}}

            def get_bucket_encryption(self, **kwargs):
                self.record("get_bucket_encryption", kwargs)
                if owner.deny_encryption:
                    raise Denied("do not leak")
                return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
        return S3()


def test_s3_is_owner_checked_region_filtered_and_never_infers_public_access():
    session = S3Session()
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["s3"], session=session)
    assert result["coverage"]["s3"]["status"] == "complete"
    assert len(result["resources"]) == 1
    row = result["resources"][0]
    assert row["id"] == "arn:aws:s3:::images"
    assert row["account_id"] == ACCOUNT and row["region"] == REGION
    assert row["properties"]["account_public_access_block"]["BlockPublicPolicy"] is True
    assert row["properties"]["bucket_policy_status"]["IsPublic"] is True
    assert "public_access" not in row["properties"]
    assert "encryption_at_rest" not in row["properties"]
    for service, operation, kwargs in session.calls:
        if service == "s3" and operation != "list_buckets":
            assert kwargs["ExpectedBucketOwner"] == ACCOUNT
        if operation in {"get_bucket_encryption", "get_bucket_policy_status"}:
            assert kwargs["Bucket"] == "images"
    assert snapshot_to_model(result)["architecture"]["components"][0]["trust_level"] == "unknown"


def test_s3_missing_encryption_or_account_block_is_unknown_not_a_vulnerability():
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["s3"],
                          session=S3Session(deny_account=True, deny_encryption=True))
    assert result["coverage"]["s3"]["status"] == "partial"
    props = result["resources"][0]["properties"]
    assert "default_encryption_configuration" not in props
    assert "account_public_access_block" not in props
    assert "encryption_at_rest" not in props


def test_s3_unknown_location_is_not_assumed_in_scope():
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["s3"], session=S3Session(deny_location=True))
    assert not result["resources"]
    assert result["coverage"]["s3"]["status"] == "partial"


def test_s3_budget_exhaustion_retains_partial_evidence():
    session = S3Session()
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["s3"], session=session, max_requests=6)
    assert len(session.calls) == 6
    assert result["coverage"]["s3"]["status"] == "partial"
    assert result["resources"][0]["properties"] == {"account_public_access_block": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}


def test_s3_arns_require_separate_account_region_bindings():
    result = discover_aws(account_id=ACCOUNT, region=REGION, services=["s3"], session=S3Session())
    result["resources"][0].pop("account_id")
    with pytest.raises(ModelError, match="account/region"):
        validate_snapshot(result)
