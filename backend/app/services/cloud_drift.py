"""Bounded read-only AWS inventory and offline evidence-aware snapshot drift.

This module never changes cloud state, executes IaC, or derives reachability from
inventory alone. Missing fields and incomplete collection remain unknown.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
import time

from .model_interchange import ModelError, bounded, digest, validate_model

SNAPSHOT_VERSION = "aegis-cloud-snapshot/1"
DRIFT_VERSION = "aegis-cloud-drift/1"
SERVICES = {"ec2", "rds", "lambda", "s3"}
TYPES = {"ec2": "aws_ec2_instance", "rds": "aws_rds_instance", "lambda": "aws_lambda_function", "s3": "aws_s3_bucket"}
READ_OPERATIONS = {"sts": "get_caller_identity", "ec2": "describe_instances",
                   "rds": "describe_db_instances", "lambda": "list_functions", "s3": "list_buckets", "s3control": "get_public_access_block"}
READ_ALLOWLIST = {key: {operation} for key, operation in READ_OPERATIONS.items()}
READ_ALLOWLIST["s3"] |= {"get_bucket_location", "get_public_access_block", "get_bucket_policy_status", "get_bucket_encryption"}
MAX_RESOURCES = 2000


def _scope(account_id, region):
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise ModelError("An explicit 12-digit AWS account ID is required")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region):
        raise ModelError("An explicit AWS region is required")


def validate_snapshot(document: dict) -> dict:
    bounded(document)
    if not isinstance(document, dict):
        raise ModelError("Snapshot must be an object")
    if document.get("schema_version") != SNAPSHOT_VERSION or document.get("provider") != "aws":
        raise ModelError("Unsupported cloud snapshot schema or provider")
    value = deepcopy(document)
    _scope(value.get("account_id"), value.get("region"))
    try:
        observed = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise ValueError("timezone required")
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ModelError("Snapshot requires an ISO-8601 observed_at with timezone") from exc
    resources, coverage = value.get("resources"), value.get("coverage")
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES or not isinstance(coverage, dict) or not coverage:
        raise ModelError("Invalid snapshot resources or coverage")
    for service, state in coverage.items():
        if service not in SERVICES or not isinstance(state, dict) or state.get("status") not in {"complete", "partial", "not_requested"}:
            raise ModelError("Invalid collection coverage")
    ids = set()
    for row in resources:
        if not isinstance(row, dict):
            raise ModelError("Resource must be an object")
        arn, service = row.get("id"), row.get("service")
        if service not in SERVICES or not isinstance(arn, str):
            raise ModelError("Unsupported resource identity or service")
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn" or not parts[1].startswith("aws") or parts[2] != service or not parts[5]:
            raise ModelError("Resource ID must be an AWS ARN for its declared service")
        scope_matches = (parts[3:5] == ["", ""] and row.get("account_id") == value["account_id"]
                         and row.get("region") == value["region"]) if service == "s3" else parts[3:5] == [value["region"], value["account_id"]]
        if not scope_matches or arn in ids:
            raise ModelError("Duplicate or cross-account/region resource identity")
        if row.get("type") != TYPES[service] or not isinstance(row.get("properties"), dict):
            raise ModelError("Resource requires a supported type and properties object")
        if service not in coverage or coverage[service]["status"] == "not_requested":
            raise ModelError("Resource contradicts collection coverage")
        ids.add(arn)
    value["resources"].sort(key=lambda r: r["id"])
    return value


def snapshot_to_model(document: dict) -> dict:
    snapshot = validate_snapshot(document)
    source_hash = digest(snapshot)
    if not snapshot["resources"]:
        raise ModelError("No observed resources to model; empty inventory is not an architecture")
    components = [{"id": r["id"], "name": r.get("name") or r["id"], "type": r["type"],
        "trust_level": "unknown", "properties": {**r["properties"], "arn": r["id"], "account_id": snapshot["account_id"],
            "region": snapshot["region"], "provider": "aws", "cloud_observed_at": snapshot["observed_at"]},
        "evidence": [{"source_type": "cloud_snapshot", "source_sha256": source_hash,
            "resource_id": r["id"], "observed_at": snapshot["observed_at"], "verification": "configuration_observation_not_exploit_test"}]}
        for r in snapshot["resources"]]
    return validate_model({"model_id": f"aws:{snapshot['account_id']}:{snapshot['region']}",
        "project_name": "AWS configuration snapshot", "architecture": {"components": components, "flows": [],
            "metadata": {"cloud_scope": {k: snapshot[k] for k in ("provider", "account_id", "region")},
                         "collection_coverage": snapshot["coverage"]}},
        "provenance": {"source_sha256": source_hash, "observed_at": snapshot["observed_at"]},
        "extensions": {"warnings": ["Inventory does not identify application flows, effective permissions, route reachability, or security test outcomes."]}})


def compare_drift(baseline: dict, observed: dict) -> dict:
    """Compare two scoped snapshots or explicit ARN-bound model assertions.

    No fuzzy resource matching: display names are neither unique nor identities.
    Removed-from-inventory is never equivalent to deleted or risk remediated.
    """
    after = validate_snapshot(observed)
    scope = {k: after[k] for k in ("provider", "account_id", "region")}
    warnings = ["Configuration drift is not a vulnerability verdict or proof of effective public access.",
                "Missing resources or fields remain unobserved; collection does not prove deletion or remediation."]
    if baseline.get("schema_version") == SNAPSHOT_VERSION:
        before = validate_snapshot(baseline)
        if any(before[k] != scope[k] for k in scope):
            raise ModelError("Cannot compare snapshots from different account/region scopes")
        if datetime.fromisoformat(after["observed_at"].replace("Z", "+00:00")) < datetime.fromisoformat(before["observed_at"].replace("Z", "+00:00")):
            raise ModelError("Observed snapshot is older than the baseline")
        expected = {r["id"]: r for r in before["resources"]}
        baseline_identity = {"kind": "snapshot", "sha256": digest(before), "observed_at": before["observed_at"]}
    else:
        before = validate_model(baseline)
        declared_scope = (before["architecture"].get("metadata") or {}).get("cloud_scope")
        if declared_scope != scope:
            raise ModelError("Model must explicitly declare metadata.cloud_scope matching the observed provider/account/region")
        expected = {}
        ignored = 0
        for component in before["architecture"]["components"]:
            props = component.get("properties") or {}
            arn = props.get("arn") or props.get("resource_arn")
            if not arn:
                ignored += 1
                continue
            parts = str(arn).split(":", 5)
            if len(parts) != 6 or parts[0] != "arn" or not parts[1].startswith("aws") or not parts[5]:
                raise ModelError("Model resource binding requires an AWS ARN")
            scope_matches = (parts[3:5] == ["", ""] and props.get("account_id") == scope["account_id"]
                             and props.get("region") == scope["region"]) if parts[2] == "s3" else parts[3:5] == [scope["region"], scope["account_id"]]
            if not scope_matches:
                raise ModelError("Model ARN is outside its declared scope")
            if parts[2] not in SERVICES:
                ignored += 1
                continue
            if arn in expected:
                raise ModelError("Multiple model components bind to the same ARN")
            controls = props.get("cloud_expected", {})
            if not isinstance(controls, dict):
                raise ModelError("cloud_expected must be an explicit property map")
            expected[arn] = {"id": arn, "service": parts[2], "properties": controls}
        if ignored:
            warnings.append(f"{ignored} model components have no supported ARN binding and were not compared.")
        if not expected:
            raise ModelError("Model has no supported explicit ARN bindings")
        baseline_identity = {"kind": "model", "model_id": before["model_id"], "sha256": digest(before)}
    current = {r["id"]: r for r in after["resources"]}
    changes = []
    for arn in sorted(expected.keys() | current.keys()):
        old, new = expected.get(arn), current.get(arn)
        service = (old or new)["service"]
        if old is None:
            changes.append({"resource_id": arn, "status": "newly_observed", "properties": deepcopy(new["properties"])})
            continue
        if new is None:
            changes.append({"resource_id": arn, "status": "not_observed",
                "collection_status": after["coverage"].get(service, {}).get("status", "not_requested")})
            continue
        fields = []
        for key in sorted(old["properties"].keys() | new["properties"].keys()):
            left, right = old["properties"].get(key), new["properties"].get(key)
            if left is None or right is None:
                fields.append({"property": key, "status": "unknown", "expected": left, "observed": right})
            elif left != right:
                fields.append({"property": key, "status": "changed", "expected": left, "observed": right})
        status = "changed" if any(f["status"] == "changed" for f in fields) else "unknown" if fields else "unchanged"
        changes.append({"resource_id": arn, "status": status, "fields": fields})
    return {"schema_version": DRIFT_VERSION, "scope": scope, "baseline": baseline_identity,
        "observed": {"sha256": digest(after), "observed_at": after["observed_at"]},
        "coverage": after["coverage"], "changes": changes, "warnings": warnings,
        "summary": {status: sum(r["status"] == status for r in changes)
                    for status in ("changed", "unknown", "unchanged", "not_observed", "newly_observed")}}


def discover_aws(*, account_id: str, region: str, services: list[str], profile: str | None = None,
                 max_resources: int = 500, max_requests: int = 20, timeout_seconds: int = 60,
                 session=None, clock=time.monotonic) -> dict:
    """Explicit opt-in collector. Tests supply fake sessions; never follows URLs.

    Bounds cover total requests (including STS), resources and wall time between
    requests. One in-flight SDK call may exceed the deadline by its socket timeout.
    No route, policy or security-group evaluation is claimed from this inventory.
    """
    _scope(account_id, region)
    if not services or set(services) - SERVICES or len(services) != len(set(services)):
        raise ModelError("Select a nonempty unique subset of ec2, rds, lambda, s3")
    if not 1 <= max_resources <= MAX_RESOURCES or not 1 <= max_requests <= 100 or not 1 <= timeout_seconds <= 300:
        raise ModelError("Collection limits exceed supported bounds")
    if session is None:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise RuntimeError("Live AWS discovery requires optional boto3>=1.35,<2") from exc
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1},
                            ignore_configured_endpoint_urls=True)
        except Exception as exc:
            raise RuntimeError("Unable to initialize AWS session; check the selected profile and SDK configuration") from exc
    else:
        config = None
    start = clock()
    requests = 0
    clients, executed_operations = {}, set()

    def call(service, operation=None, **kwargs):
        nonlocal requests
        operation = operation or READ_OPERATIONS[service]
        if operation not in READ_ALLOWLIST.get(service, set()):
            raise ModelError("Cloud mutation or unsupported operation refused")
        if requests >= max_requests or clock() - start >= timeout_seconds:
            raise TimeoutError("collection_limit")
        if service not in clients:
            clients[service] = session.client(service, region_name=region, **({"config": config} if config else {}))
        requests += 1
        executed_operations.add(f"{service}:{operation}")
        return getattr(clients[service], operation)(**kwargs)

    try:
        identity = call("sts")
    except Exception as exc:
        raise RuntimeError("Unable to verify AWS caller identity; no resource discovery was attempted") from exc
    if identity.get("Account") != account_id:
        raise ModelError("Authenticated AWS account does not match requested account; collection stopped")
    partition = str(identity.get("Arn", "")).split(":")[1:2]
    if not partition or partition[0] not in {"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f"}:
        raise ModelError("STS did not return a supported AWS principal ARN")
    resources, coverage = [], {s: {"status": "not_requested"} for s in sorted(SERVICES)}
    seen_resources = set()
    for service in sorted(services):
        if service == "s3":
            s3_resources, s3_coverage = _collect_s3(call, account_id, region, partition[0], max_resources - len(resources))
            resources.extend(s3_resources)
            coverage[service] = s3_coverage
            continue
        coverage[service] = {"status": "partial", "reason": "collection_limit"}
        token, seen_tokens = None, set()
        try:
            while True:
                if len(resources) >= max_resources:
                    raise TimeoutError("resource_limit")
                kwargs = ({"MaxResults": 100} if service == "ec2" else {"MaxRecords": 100} if service == "rds" else {"MaxItems": 50})
                token_key = "NextToken" if service == "ec2" else "Marker"
                if token:
                    kwargs[token_key] = token
                page = call(service, **kwargs)
                rows = ([i for r in page.get("Reservations", []) for i in r.get("Instances", [])] if service == "ec2"
                        else page.get("DBInstances", []) if service == "rds" else page.get("Functions", []))
                for row in rows:
                    if len(resources) >= max_resources:
                        raise TimeoutError("resource_limit")
                    resource = _aws_resource(service, row, account_id, region, partition[0])
                    if resource["id"] in seen_resources:
                        raise TimeoutError("duplicate_resource_in_collection")
                    seen_resources.add(resource["id"])
                    resources.append(resource)
                token = page.get("NextToken" if service == "ec2" else "Marker" if service == "rds" else "NextMarker")
                if not token:
                    coverage[service] = {"status": "complete"}
                    break
                if token in seen_tokens:
                    raise TimeoutError("repeated_page_token")
                seen_tokens.add(token)
        except Exception as exc:
            # SDK exception messages can include endpoint/credential information.
            # Return only a bounded AWS error code, never raw exception text.
            code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "collection_failed")
            if isinstance(exc, TimeoutError):
                code = str(exc)
            coverage[service] = {"status": "partial", "reason": re.sub(r"[^a-zA-Z0-9_-]", "", str(code))[:80]}
    result = {"schema_version": SNAPSHOT_VERSION, "provider": "aws", "account_id": account_id, "region": region,
        "observed_at": datetime.now(timezone.utc).isoformat(), "resources": resources, "coverage": coverage,
        "provenance": {"collector": "aegis-readonly/1", "requests": requests,
            "operations": sorted(executed_operations), "account_verified": True,
            "limitations": ["EC2/RDS/Lambda metadata and selected S3 configuration only; no route, IAM/KMS effective-policy, ACL/access-point, WAF or exploit verification.",
                            "S3 policy-public status and block-public-access settings do not establish effective public access; missing encryption state is not a finding."]}}
    return validate_snapshot(result)


def _error_code(exc):
    if isinstance(exc, TimeoutError):
        return str(exc)
    code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "collection_failed")
    return re.sub(r"[^a-zA-Z0-9_-]", "", str(code))[:80]


def _collect_s3(call, account, region, partition, limit):
    """List only account-owned buckets, then owner-check location before inclusion.

    S3 ARNs lack account and region, so both must be retained separately. No
    bucket contents, ACLs, policy text, credentials or object URLs are retrieved.
    """
    resources, gaps, seen_buckets, seen_tokens = [], [], set(), set()
    if limit <= 0:
        return [], {"status": "partial", "reason": "resource_limit"}
    account_block = None
    try:
        account_block = call("s3control", AccountId=account).get("PublicAccessBlockConfiguration")
        if not isinstance(account_block, dict):
            gaps.append("account_public_access_block:unobserved")
    except Exception as exc:
        gaps.append("account_public_access_block:" + _error_code(exc))
    token = None
    try:
        while True:
            page = call("s3", MaxBuckets=100, **({"ContinuationToken": token} if token else {}))
            for bucket in page.get("Buckets", []):
                if len(resources) >= limit:
                    raise TimeoutError("resource_limit")
                name = bucket["Name"]
                if name in seen_buckets:
                    raise TimeoutError("duplicate_resource_in_collection")
                seen_buckets.add(name)
                owner_args = {"Bucket": name, "ExpectedBucketOwner": account}
                try:
                    location = call("s3", "get_bucket_location", **owner_args)
                    if "LocationConstraint" not in location:
                        raise ValueError("unobserved_location")
                    bucket_region = location["LocationConstraint"] or "us-east-1"
                    if bucket_region == "EU":
                        bucket_region = "eu-west-1"
                except TimeoutError:
                    raise
                except Exception as exc:
                    # Region and ownership could not be confirmed; cannot include
                    # this bucket in the requested regional inventory.
                    gaps.append("bucket_location:" + _error_code(exc))
                    continue
                if bucket_region != region:
                    continue
                props = {}
                if isinstance(account_block, dict):
                    props["account_public_access_block"] = deepcopy(account_block)
                checks = (("get_public_access_block", "PublicAccessBlockConfiguration", "bucket_public_access_block"),
                          ("get_bucket_policy_status", "PolicyStatus", "bucket_policy_status"),
                          ("get_bucket_encryption", "ServerSideEncryptionConfiguration", "default_encryption_configuration"))
                for operation, response_key, property_name in checks:
                    try:
                        response = call("s3", operation, **owner_args)
                        state = response.get(response_key)
                        if isinstance(state, dict):
                            props[property_name] = state
                        else:
                            gaps.append(property_name + ":unobserved")
                    except Exception as exc:
                        # AccessDenied / absent configuration never becomes false
                        # control presence or a public-exposure/encryption finding.
                        gaps.append(property_name + ":" + _error_code(exc))
                resources.append({"id": f"arn:{partition}:s3:::{name}", "name": name, "service": "s3",
                    "type": TYPES["s3"], "account_id": account, "region": region, "properties": props})
            token = page.get("ContinuationToken")
            if not token:
                break
            if token in seen_tokens:
                raise TimeoutError("repeated_page_token")
            seen_tokens.add(token)
    except Exception as exc:
        gaps.append(_error_code(exc))
    return resources, {"status": "partial" if gaps else "complete", "observation_gaps": sorted(set(gaps))}


def _aws_resource(service, row, account, region, partition):
    props = {}
    if service == "ec2":
        identifier = row["InstanceId"]
        arn = f"arn:{partition}:ec2:{region}:{account}:instance/{identifier}"
        pairs = {"InstanceType": "instance_type", "VpcId": "vpc_id", "SubnetId": "subnet_id"}
        for key, value in (row.get("MetadataOptions") or {}).items():
            if key in {"HttpTokens", "HttpEndpoint", "HttpPutResponseHopLimit"}:
                props["metadata_" + key] = value
        if "PublicIpAddress" in row:
            props["public_ip_assigned"] = bool(row["PublicIpAddress"])
        if "SecurityGroups" in row:
            props["security_group_ids"] = sorted(g["GroupId"] for g in row["SecurityGroups"])
    elif service == "rds":
        arn, identifier = row["DBInstanceArn"], row["DBInstanceIdentifier"]
        pairs = {"PubliclyAccessible": "publicly_accessible_setting", "StorageEncrypted": "encryption_at_rest",
                 "Engine": "database_engine", "EngineVersion": "engine_version", "IAMDatabaseAuthenticationEnabled": "iam_database_authentication"}
    else:
        arn, identifier = row["FunctionArn"], row["FunctionName"]
        pairs = {"Runtime": "runtime", "Role": "execution_role_arn", "MemorySize": "memory_mb",
                 "Timeout": "timeout_seconds", "KMSKeyArn": "kms_key_arn"}
        # Never retain Environment variables, code URLs, tags or credentials.
    for source, target in pairs.items():
        if source in row:
            props[target] = row[source]
    return {"id": arn, "name": identifier, "service": service, "type": TYPES[service], "properties": props}
