"""Deterministic, resource-level IaC security checks.

This module deliberately keeps parsing conservative: findings require an explicit
insecure value or a public/excessive permission.  It complements architecture
threat modeling with evidence-backed configuration findings.
"""

from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml
import hcl2

from .policy_semantics import allow_statements, unrestricted_public_allow, values


class IaCSecurityAnalyzer:
    """Find high-signal security issues in AWS, Azure, GCP, and container IaC."""

    _terraform_resource = re.compile(
        r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{', re.MULTILINE
    )
    _terraform_module = re.compile(r'^\s*module\s+"(?P<name>[^"]+)"\s*\{', re.MULTILINE)

    def __init__(self) -> None:
        self.rule_catalog = self._load_rule_catalog()

    def analyze(self, content: str, format_hint: str = "auto", documents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        format_name = (format_hint or "auto").lower()
        findings: List[Dict[str, Any]] = []

        if format_name == "terraform" or self._terraform_resource.search(content):
            findings.extend(self._analyze_terraform(content))

        if format_name == "arm":
            arm_document = (documents or [{}])[0]
            findings.extend(self._analyze_arm(arm_document, content))
        elif format_name in {"bicep", "pulumi", "helm-values"}:
            findings.extend(self._analyze_source_iac(content, format_name))
        elif format_name == "ci":
            findings.extend(self._analyze_ci(content))

        if documents is None and format_name != "terraform":
            try:
                documents = [doc for doc in yaml.safe_load_all(content) if isinstance(doc, dict)]
            except yaml.YAMLError:
                documents = []

        flattened_documents: List[Dict[str, Any]] = []
        for document in documents or []:
            if document.get("kind") == "List" and isinstance(document.get("items"), list):
                flattened_documents.extend(item for item in document["items"] if isinstance(item, dict))
            else:
                flattened_documents.append(document)

        kubernetes_context = self._kubernetes_context(flattened_documents)
        for document in flattened_documents:
            if "Resources" in document or "AWSTemplateFormatVersion" in document:
                findings.extend(self._analyze_cloudformation(document, content))
            if "apiVersion" in document and "kind" in document:
                findings.extend(self._analyze_kubernetes(document, content, kubernetes_context))
            if "services" in document:
                findings.extend(self._analyze_compose(document, content))

        return self._deduplicate(findings)

    def _analyze_arm(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for index, resource in enumerate(document.get("resources") or []):
            if not isinstance(resource, dict):
                continue
            resource_type = str(resource.get("type") or "Azure resource")
            resource_id = str(resource.get("name") or f"resource-{index + 1}")
            properties = resource.get("properties") or {}
            line = self._line_for(content, resource_id)
            if resource_type.lower() == "microsoft.storage/storageaccounts" and properties.get("allowBlobPublicAccess") is True:
                findings.append(self._finding(
                    "IAC-AZURE-TEMPLATE-PUBLIC-STORAGE", resource_id, line, "High",
                    "Azure storage permits public blob access",
                    "allowBlobPublicAccess is explicitly true, permitting containers to be configured for anonymous access.",
                    "Set allowBlobPublicAccess to false and grant access through Entra ID identities or short-lived scoped SAS tokens.",
                    "Information Disclosure", "CWE-668",
                ))
            resource_json = json.dumps(resource, sort_keys=True)
            internet_wide = bool(
                re.search(r'0\.0\.0\.0/0|"startIpAddress"\s*:\s*"0\.0\.0\.0"[^}]*"endIpAddress"\s*:\s*"255\.255\.255\.255"', resource_json, re.I)
                or (
                    properties.get("publicNetworkAccess") in {"Enabled", "enabled", True}
                    and (properties.get("networkAcls") or {}).get("defaultAction") in {"Allow", "allow"}
                    and not (properties.get("networkAcls") or {}).get("ipRules")
                )
            )
            if internet_wide:
                findings.append(self._finding(
                    "IAC-AZURE-TEMPLATE-PUBLIC-NETWORK", resource_id, line, "High",
                    "Azure resource permits public network access",
                    "The resource combines public network access with an internet-wide firewall or allow-by-default network ACL.",
                    "Disable public network access or restrict it with private endpoints, firewall rules, and approved source networks.",
                    "Information Disclosure", "CWE-668",
                ))
            if str(properties.get("minimumTlsVersion") or properties.get("minTlsVersion") or "").upper() in {"TLS1_0", "1.0", "TLSV1_0"}:
                findings.append(self._finding(
                    "IAC-AZURE-TEMPLATE-TLS10", resource_id, line, "High",
                    "Azure resource permits obsolete TLS",
                    "The resource explicitly permits TLS 1.0.",
                    "Require TLS 1.2 or later and validate all dependent clients before deployment.",
                    "Information Disclosure", "CWE-326",
                ))
        return findings

    def _analyze_source_iac(self, content: str, format_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        has_secret = self._contains_literal_secret(content) or bool(re.search(
            r'(?mi)^\s*(?:param\s+)?[\w]*(?:password|secret|token|api[_-]?key)[\w]*'
            r'(?:\s+\w+)?\s*(?:=|:)\s*["\'][^"\']{8,}["\']',
            content,
        ))
        if has_secret:
            rule_id = {
                "bicep": "IAC-BICEP-HARDCODED-SECRET",
                "pulumi": "IAC-PULUMI-HARDCODED-SECRET",
                "helm-values": "IAC-HELM-VALUES-HARDCODED-SECRET",
            }[format_name]
            findings.append(self._finding(
                rule_id, f"{format_name}.configuration", 1, "Critical",
                f"{format_name.title()} source contains a hard-coded secret",
                "A credential-like property is assigned a literal value in source-controlled infrastructure code.",
                "Use the platform secret store and pass a secret reference; rotate the exposed credential.",
                "Information Disclosure", "CWE-798",
            ))
        bicep_lines = content.splitlines()
        insecure_parameter = next((
            (index, line) for index, line in enumerate(bicep_lines)
            if re.search(r"(?i)^\s*param\s+[\w]*(?:password|secret|token|api[_-]?key)[\w]*\s+string\b", line)
            and not (index > 0 and re.search(r"(?i)^\s*@secure\(\)\s*$", bicep_lines[index - 1]))
        ), None) if format_name == "bicep" else None
        if insecure_parameter:
            findings.append(self._finding(
                "IAC-BICEP-SECRET-PARAM-NOT-SECURE", "bicep.configuration", insecure_parameter[0] + 1, "High",
                "Bicep secret parameter is not marked secure",
                "A credential-like Bicep string parameter lacks the @secure() decorator and may be logged or exposed in deployment history.",
                "Add @secure() immediately before the parameter and pass it from Key Vault or a protected deployment input.",
                "Information Disclosure", "CWE-532",
            ))
        return findings

    def _analyze_ci(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        resource_id = "ci.pipeline"
        try:
            workflow = yaml.safe_load(content)
        except yaml.YAMLError:
            return findings
        if not isinstance(workflow, dict):
            return findings
        # YAML 1.1 parses the GitHub key `on` as True. No uploaded code runs.
        triggers = workflow.get("on", workflow.get(True, {}))
        trigger_names = set(triggers) if isinstance(triggers, (dict, list)) else {triggers}
        jobs = workflow.get("jobs") or {}
        unsafe_checkout = False
        for job in jobs.values() if isinstance(jobs, dict) else []:
            if not isinstance(job, dict):
                continue
            steps = [step for step in job.get("steps", []) if isinstance(step, dict)]
            untrusted = False
            for step in steps:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    checkout = step.get("with") or {}
                    untrusted = bool(re.search(
                        r"github\.event\.pull_request\.head\.(?:sha|ref|repo)",
                        json.dumps(checkout),
                    ))
                elif untrusted and (step.get("run") or str(step.get("uses", "")).startswith("./")):
                    unsafe_checkout = True
        if re.search(r"(?mi)^\s*permissions\s*:\s*write-all\s*$", content):
            findings.append(self._finding(
                "IAC-CI-WRITE-ALL", resource_id, self._line_for(content, "write-all"), "Critical",
                "CI workflow grants write access to all token scopes",
                "The workflow grants the automation token write access to every available permission scope.",
                "Set top-level permissions to read-all or {}, then grant the minimum job-specific scopes.",
                "Elevation of Privilege", "CWE-250",
            ))
        for match in re.finditer(r"(?mi)^\s*(?:-|\s)*uses\s*:\s*([^\s#]+)", content):
            reference = match.group(1)
            if reference.startswith(("./", "docker://")):
                continue
            version = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if not re.fullmatch(r"[0-9a-fA-F]{40}", version):
                findings.append(self._finding(
                    "IAC-CI-UNPINNED-ACTION", reference, content[:match.start()].count("\n") + 1, "High",
                    "CI workflow action is not pinned to an immutable commit",
                    f"The action reference {reference} is mutable or does not specify an immutable commit SHA.",
                    "Pin third-party actions to a reviewed full commit SHA and use dependency automation to update it.",
                    "Tampering", "CWE-829",
                ))
        if "pull_request_target" in trigger_names and unsafe_checkout:
            findings.append(self._finding(
                "IAC-CI-PR-TARGET-CHECKOUT", resource_id, self._line_for(content, "pull_request_target"), "Critical",
                "Privileged pull-request workflow checks out untrusted code",
                "A pull_request_target job checks out the pull request head and subsequently executes code from that checkout. Effective token permissions and secret access must also be reviewed.",
                "Use pull_request for untrusted code, split privileged follow-up work into a reviewed workflow, and never execute fork code with secrets.",
                "Elevation of Privilege", "CWE-829",
            ))
        if re.search(r"(?is)\brun\s*:[^\n]*\$\{\{\s*secrets\.", content):
            findings.append(self._finding(
                "IAC-CI-SECRET-IN-SHELL", resource_id, 1, "High",
                "CI secret is interpolated directly into a shell command",
                "A secret expression is expanded in a shell command, where quoting, command injection, and process output can expose it.",
                "Pass secrets through a narrowly scoped environment variable and quote it in the shell; avoid commands that echo arguments.",
                "Information Disclosure", "CWE-78",
            ))
        if re.search(r"(?i)(?:privileged\s*:\s*true|/var/run/docker\.sock)", content):
            findings.append(self._finding(
                "IAC-CI-PRIVILEGED-RUNNER", resource_id, 1, "Critical",
                "CI job uses a privileged container or Docker socket",
                "The pipeline can control the container host through privileged execution or the Docker socket.",
                "Use an isolated ephemeral runner and a rootless build service without host socket access.",
                "Elevation of Privilege", "CWE-250",
            ))
        return findings

    def _analyze_terraform(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = self._analyze_terraform_globals(content)
        resources = list(self._terraform_blocks(content))
        resources_by_type: Dict[str, List[Tuple[str, str, int]]] = {}
        for item_type, item_name, item_block, item_line in resources:
            resources_by_type.setdefault(item_type, []).append((item_name, item_block, item_line))

        for resource_type, name, block, line in resources:
            resource_id = f"{resource_type}.{name}"
            lowered = block.lower()

            if resource_type == "aws_s3_bucket":
                if re.search(r'\bacl\s*=\s*"public-(?:read|read-write|write)"', block, re.I):
                    findings.append(self._finding("IAC-AWS-S3-PUBLIC-ACL", resource_id, line, "Critical", "Public S3 bucket ACL", "The bucket ACL explicitly grants public access, allowing anonymous data exposure or modification.", "Disable public ACLs, enable all S3 public-access blocks, and grant access through narrowly scoped IAM policies.", "Information Disclosure", "CWE-200"))
                if not self._has_related_terraform_resource(resources_by_type, "aws_s3_bucket_public_access_block", resource_type, name):
                    findings.append(self._finding("IAC-AWS-S3-MISSING-PAB", resource_id, line, "High", "S3 bucket lacks a public-access block", "No aws_s3_bucket_public_access_block resource is present, so an ACL or policy can later expose the bucket publicly.", "Create a public-access block for this bucket with all four block settings enabled.", "Information Disclosure", "CWE-284"))
                # S3 encrypts new objects by default. Absence of a bucket-level
                # encryption resource is therefore not evidence of unencrypted
                # data and must not be reported as a confirmed vulnerability.
                has_versioning = "versioning" in lowered or self._has_related_terraform_resource(
                    resources_by_type, "aws_s3_bucket_versioning", resource_type, name
                )
                if not has_versioning:
                    findings.append(self._finding("IAC-AWS-S3-NO-VERSIONING", resource_id, line, "Medium", "S3 bucket versioning is not configured", "Object versioning is absent, increasing the impact of accidental or malicious object deletion.", "Enable S3 versioning and use lifecycle controls appropriate for the data retention policy.", "Tampering", "CWE-693"))

            if resource_type == "aws_s3_bucket_public_access_block" and re.search(r'\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AWS-S3-PAB-DISABLED", resource_id, line, "High", "S3 public-access protections are disabled", "At least one S3 public-access block setting is explicitly disabled.", "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.", "Information Disclosure", "CWE-284"))

            if resource_type == "aws_s3_bucket_policy" and self._public_principal(block):
                findings.append(self._finding("IAC-AWS-S3-PUBLIC-POLICY", resource_id, line, "Critical", "S3 bucket policy permits public access", "The bucket policy contains a wildcard principal, allowing anonymous access when actions and conditions permit it.", "Restrict the Principal and resources to required IAM roles; add explicit secure-transport and organization conditions.", "Information Disclosure", "CWE-200"))
            elif resource_type in {"aws_iam_policy", "aws_iam_role", "aws_iam_user_policy", "aws_iam_role_policy", "aws_iam_group_policy"}:
                findings.extend(self._analyze_policy_text(block, resource_id, line))

            if resource_type == "aws_iam_role" and "AdministratorAccess" in block:
                findings.append(self._finding("IAC-AWS-IAM-MANAGED-ADMIN", resource_id, line, "Critical", "IAM role attaches AdministratorAccess", "The role attaches the AWS managed AdministratorAccess policy.", "Replace AdministratorAccess with a workload-specific policy limited to required actions and resources.", "Elevation of Privilege", "CWE-250"))

            if resource_type == "aws_kms_key":
                if self._public_principal(block):
                    findings.append(self._finding("IAC-AWS-KMS-PUBLIC-KEY", resource_id, line, "Critical", "KMS key policy permits a public principal", "The KMS key policy contains a wildcard principal, enabling unauthorized use or administration of cryptographic keys.", "Restrict key-policy principals to required roles and accounts; never use a wildcard principal.", "Elevation of Privilege", "CWE-284"))
                if re.search(r'\benable_key_rotation\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-KMS-ROTATION-DISABLED", resource_id, line, "High", "KMS key rotation is disabled", "Automatic rotation is explicitly disabled for a customer-managed KMS key.", "Enable automatic key rotation and define a rotation and revocation process.", "Information Disclosure", "CWE-320"))
                if re.search(r'\bdeletion_window_in_days\s*=\s*[0-6]\b', block, re.I):
                    findings.append(self._finding("IAC-AWS-KMS-SHORT-DELETION", resource_id, line, "Medium", "KMS key deletion window is too short", "The KMS key can be permanently deleted with less than the recommended seven-day recovery window.", "Use a deletion window of at least seven days and protect critical keys with organizational controls.", "Denial of Service", "CWE-693"))

            if resource_type == "aws_lambda_permission" and re.search(r'\bprincipal\s*=\s*"\*"', block, re.I):
                findings.append(self._finding("IAC-AWS-LAMBDA-PUBLIC-INVOKE", resource_id, line, "Critical", "Lambda permission allows public invocation", "The Lambda permission grants invocation to every AWS principal.", "Limit the principal and source ARN/account to the exact trusted event source or API Gateway.", "Spoofing", "CWE-284"))

            if resource_type == "aws_lambda_function":
                if self._contains_literal_secret(block):
                    findings.append(self._finding("IAC-AWS-LAMBDA-HARDCODED-SECRET", resource_id, line, "High", "Lambda environment contains a likely hard-coded secret", "A secret-like environment variable is assigned a literal value in the function configuration.", "Store the secret in AWS Secrets Manager or SSM Parameter Store and grant the execution role read access only to that secret.", "Information Disclosure", "CWE-798"))
                if re.search(r'\btimeout\s*=\s*(?:[3-9]\d{2}|[1-9]\d{3,})', block, re.I):
                    findings.append(self._finding("IAC-AWS-LAMBDA-LONG-TIMEOUT", resource_id, line, "Medium", "Lambda timeout is excessively long", "The configured timeout is at least five minutes, increasing the blast radius of abusive or stuck invocations.", "Set the shortest practical timeout and configure reserved concurrency and alarms.", "Denial of Service", "CWE-400"))

            if resource_type == "aws_lambda_function_url" and re.search(r'\bauthorization_type\s*=\s*"NONE"', block, re.I):
                findings.append(self._finding("IAC-AWS-LAMBDA-URL-PUBLIC", resource_id, line, "High", "Lambda function URL has no authorization", "The Lambda function URL explicitly uses authorization_type = NONE.", "Use AWS_IAM authorization or place the function behind an authenticated API Gateway.", "Spoofing", "CWE-306"))

            if resource_type in {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}:
                findings.extend(self._analyze_security_group(block, resource_id, line))

            if resource_type == "aws_instance":
                if re.search(r'\bassociate_public_ip_address\s*=\s*true', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-PUBLIC-IP", resource_id, line, "High", "EC2 instance receives a public IP address", "The instance is explicitly configured with a public IP, increasing its internet exposure.", "Place workloads in private subnets and expose only controlled load balancers or bastions.", "Information Disclosure", "CWE-668"))
                if re.search(r'\bhttp_tokens\s*=\s*"optional"', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-IMDSV1", resource_id, line, "High", "EC2 instance permits IMDSv1", "Instance metadata tokens are optional, allowing tokenless metadata requests that are vulnerable to SSRF abuse.", "Set metadata_options.http_tokens to required and restrict metadata hop limits.", "Information Disclosure", "CWE-918"))
                if re.search(r'\bencrypted\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-UNENCRYPTED-EBS", resource_id, line, "High", "EC2 block storage encryption is disabled", "An EBS block device is explicitly configured without encryption.", "Enable EBS encryption using an approved KMS key for every root and data volume.", "Information Disclosure", "CWE-311"))

            if resource_type == "aws_db_instance":
                if re.search(r'\bpublicly_accessible\s*=\s*true', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-PUBLIC", resource_id, line, "Critical", "RDS instance is publicly accessible", "The database is explicitly reachable from outside its VPC when security-group rules allow it.", "Set publicly_accessible to false, use private subnets, and restrict database security groups to application sources.", "Information Disclosure", "CWE-668"))
                if re.search(r'\bstorage_encrypted\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-NO-ENCRYPTION", resource_id, line, "High", "RDS storage encryption is disabled", "The database storage is explicitly configured without encryption at rest.", "Enable storage_encrypted and use a managed KMS key with a restricted key policy.", "Information Disclosure", "CWE-311"))
                if re.search(r'\bbackup_retention_period\s*=\s*0', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-NO-BACKUP", resource_id, line, "High", "RDS automated backups are disabled", "The backup retention period is set to zero, preventing point-in-time recovery.", "Set a non-zero backup-retention period and test recovery procedures.", "Denial of Service", "CWE-693"))

            if resource_type == "aws_api_gateway_method" and re.search(r'\bauthorization\s*=\s*"NONE"', block, re.I):
                findings.append(self._finding("IAC-AWS-APIGW-NO-AUTH", resource_id, line, "High", "API Gateway method has no authorization", "The method explicitly uses authorization = NONE.", "Require IAM, Cognito, JWT, or a Lambda authorizer for non-public operations.", "Spoofing", "CWE-306"))

            if resource_type == "aws_eks_cluster" and re.search(r'\bendpoint_public_access\s*=\s*true', block, re.I) and self._terraform_public_cidrs(block, "public_access_cidrs"):
                findings.append(self._finding("IAC-AWS-EKS-PUBLIC-ENDPOINT", resource_id, line, "Critical", "EKS control-plane endpoint is public", "The EKS cluster explicitly enables a public Kubernetes API endpoint.", "Disable public endpoint access or tightly restrict public_access_cidrs and enforce strong IAM/RBAC.", "Elevation of Privilege", "CWE-284"))

            findings.extend(self._analyze_additional_terraform_resource(resource_type, resource_id, block, line))

        return findings

    def _analyze_terraform_globals(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        credential_match = re.search(
            r'\b(?:access_key|secret_key|client_secret|credentials)\s*=\s*["\'][^"\'${}]{8,}["\']',
            content,
            re.I,
        )
        if credential_match:
            line = content.count("\n", 0, credential_match.start()) + 1
            findings.append(self._finding("IAC-TF-HARDCODED-PROVIDER-CREDENTIAL", "terraform.configuration", line, "Critical", "Terraform configuration contains a provider credential", "A provider credential is assigned a literal value and will be exposed in source control or state.", "Use workload identity or environment-based provider authentication and rotate the exposed credential.", "Information Disclosure", "CWE-798"))
        variable_pattern = re.compile(
            r'variable\s+["\'](?P<name>[^"\']+)["\']\s*\{(?P<body>.*?)\}',
            re.I | re.S,
        )
        for match in variable_pattern.finditer(content):
            if self._looks_like_secret_name(match.group("name")) and re.search(r'\bdefault\s*=\s*["\'][^"\']{8,}["\']', match.group("body"), re.I):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(self._finding("IAC-TF-SECRET-DEFAULT", f"variable.{match.group('name')}", line, "High", "Sensitive Terraform variable has a literal default", "A secret-like input variable includes a plaintext default that can be committed and persisted in state.", "Remove the default, mark the variable sensitive, and retrieve the value from a managed secret store.", "Information Disclosure", "CWE-798"))
        for name, block, line in self._terraform_modules(content):
            source_match = re.search(r'\bsource\s*=\s*["\'](?P<source>[^"\']+)["\']', block, re.I)
            source = source_match.group("source") if source_match else ""
            if source.startswith("http://") or source.startswith("git::http://"):
                findings.append(self._finding("IAC-TF-INSECURE-MODULE-SOURCE", f"module.{name}", line, "High", "Terraform module uses an insecure source", "The module is downloaded over plaintext HTTP and can be modified in transit.", "Use an authenticated HTTPS or SSH source and pin an immutable version or commit.", "Tampering", "CWE-319"))
            remote_source = bool(source and not source.startswith(("./", "../")))
            registry_version = bool(re.search(r'\bversion\s*=\s*["\'][^"\']+["\']', block, re.I))
            vcs_ref = "?ref=" in source
            if remote_source and not registry_version and not vcs_ref:
                findings.append(self._finding("IAC-TF-UNPINNED-MODULE", f"module.{name}", line, "Medium", "Terraform module source is not version-pinned", "The remote module has no registry version constraint or VCS ref, so future runs can resolve different code.", "Pin a reviewed module version or immutable commit SHA and update it through controlled review.", "Tampering", "CWE-829"))
        return findings

    def _analyze_additional_terraform_resource(self, resource_type: str, resource_id: str, block: str, line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if resource_type == "aws_cloudtrail":
            if re.search(r'\benable_logging\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AWS-CLOUDTRAIL-DISABLED", resource_id, line, "Critical", "CloudTrail logging is disabled", "The trail explicitly disables event delivery, removing a primary AWS audit source.", "Set enable_logging to true and monitor trail delivery failures.", "Repudiation", "CWE-778"))
            if re.search(r'\benable_log_file_validation\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AWS-CLOUDTRAIL-NO-VALIDATION", resource_id, line, "High", "CloudTrail log validation is disabled", "Log file integrity validation is explicitly disabled, weakening detection of altered audit records.", "Enable log file validation and protect the destination bucket and KMS key.", "Tampering", "CWE-345"))
        elif resource_type == "aws_ecr_repository":
            if re.search(r'\bscan_on_push\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AWS-ECR-SCAN-DISABLED", resource_id, line, "High", "ECR image scanning on push is disabled", "New container images are not scanned when pushed to the repository.", "Enable scan-on-push or enhanced ECR scanning and gate deployment on actionable findings.", "Tampering", "CWE-1104"))
            if re.search(r'\bimage_tag_mutability\s*=\s*["\']MUTABLE["\']', block, re.I):
                findings.append(self._finding("IAC-AWS-ECR-MUTABLE-TAGS", resource_id, line, "Medium", "ECR image tags are mutable", "An existing image tag can be replaced, weakening deployment provenance.", "Use immutable tags and deploy images by digest.", "Tampering", "CWE-829"))
        elif resource_type == "aws_dynamodb_table" and re.search(r'\benabled\s*=\s*false', self._nested_block(block, "point_in_time_recovery"), re.I):
            findings.append(self._finding("IAC-AWS-DDB-PITR-DISABLED", resource_id, line, "High", "DynamoDB point-in-time recovery is disabled", "The table explicitly disables point-in-time recovery.", "Enable PITR and test restoration procedures.", "Denial of Service", "CWE-693"))
        elif resource_type == "aws_sqs_queue" and re.search(r'\bsqs_managed_sse_enabled\s*=\s*false', block, re.I):
            findings.append(self._finding("IAC-AWS-SQS-ENCRYPTION-DISABLED", resource_id, line, "High", "SQS managed encryption is disabled", "The queue explicitly disables SQS-managed server-side encryption.", "Enable SQS-managed SSE or configure a restricted KMS key.", "Information Disclosure", "CWE-311"))
        elif resource_type == "aws_secretsmanager_secret" and re.search(r'\brecovery_window_in_days\s*=\s*0\b', block, re.I):
            findings.append(self._finding("IAC-AWS-SECRET-FORCE-DELETE", resource_id, line, "High", "Secrets Manager recovery window is disabled", "The secret can be deleted immediately without a recovery period.", "Use an appropriate recovery window and restrict destructive secret-management permissions.", "Denial of Service", "CWE-693"))
        elif resource_type == "aws_ebs_volume" and re.search(r'\bencrypted\s*=\s*false', block, re.I):
            findings.append(self._finding("IAC-AWS-EBS-NO-ENCRYPTION", resource_id, line, "High", "EBS volume encryption is disabled", "The standalone EBS volume is explicitly unencrypted.", "Enable encryption with an approved KMS key and replace existing unencrypted volumes safely.", "Information Disclosure", "CWE-311"))
        elif resource_type in {"aws_lb_listener", "aws_alb_listener"} and re.search(r'\bprotocol\s*=\s*["\']HTTP["\']', block, re.I):
            findings.append(self._finding("IAC-AWS-LB-PLAINTEXT-LISTENER", resource_id, line, "High", "Load balancer listener accepts plaintext HTTP", "The listener uses HTTP without transport encryption.", "Use an HTTPS listener with a modern TLS policy and redirect HTTP to HTTPS.", "Information Disclosure", "CWE-319"))

        if resource_type == "azurerm_storage_account":
            if re.search(r'\ballow_nested_items_to_be_public\s*=\s*true', block, re.I):
                findings.append(self._finding("IAC-AZURE-STORAGE-PUBLIC-BLOBS", resource_id, line, "Critical", "Azure Storage permits public nested items", "Blob containers can be configured for anonymous public access.", "Disable public blob access and use identity-based authorization or short-lived scoped SAS tokens.", "Information Disclosure", "CWE-668"))
            if re.search(r'\bmin_tls_version\s*=\s*["\']TLS1_0["\']', block, re.I):
                findings.append(self._finding("IAC-AZURE-STORAGE-LEGACY-TLS", resource_id, line, "High", "Azure Storage permits legacy TLS", "The minimum TLS version is set to TLS 1.0.", "Require TLS 1.2 or later and validate client compatibility.", "Information Disclosure", "CWE-326"))
            if re.search(r'\bshared_access_key_enabled\s*=\s*true', block, re.I):
                findings.append(self._finding("IAC-AZURE-STORAGE-SHARED-KEY", resource_id, line, "Medium", "Azure Storage shared-key authorization is enabled", "Long-lived account keys can bypass identity-based authorization and fine-grained access governance.", "Disable shared-key access where supported and use managed identities with RBAC.", "Elevation of Privilege", "CWE-522"))
        elif resource_type == "azurerm_key_vault":
            if re.search(r'\bpurge_protection_enabled\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AZURE-KV-NO-PURGE-PROTECTION", resource_id, line, "High", "Key Vault purge protection is disabled", "Deleted keys and secrets can be permanently purged during the retention period.", "Enable purge protection and restrict purge permissions.", "Denial of Service", "CWE-693"))
            if re.search(r'\bpublic_network_access_enabled\s*=\s*true', block, re.I):
                findings.append(self._finding("IAC-AZURE-KV-PUBLIC-NETWORK", resource_id, line, "High", "Key Vault public network access is enabled", "The vault data plane is reachable through its public endpoint.", "Use a private endpoint and deny public network access, with a documented exception if required.", "Information Disclosure", "CWE-668"))
        elif resource_type in {"azurerm_mssql_server", "azurerm_postgresql_flexible_server"}:
            if re.search(r'\bpublic_network_access_enabled\s*=\s*true', block, re.I):
                findings.append(self._finding("IAC-AZURE-DB-PUBLIC-NETWORK", resource_id, line, "Critical", "Azure database public network access is enabled", "The managed database exposes a public data-plane endpoint.", "Disable public access and use private endpoints with narrowly scoped network rules.", "Information Disclosure", "CWE-668"))
            if re.search(r'\bminimum_tls_version\s*=\s*["\'](?:1\.0|TLS1_0)["\']', block, re.I):
                findings.append(self._finding("IAC-AZURE-DB-LEGACY-TLS", resource_id, line, "High", "Azure database permits legacy TLS", "The database server accepts TLS 1.0.", "Require TLS 1.2 or later.", "Information Disclosure", "CWE-326"))
        elif resource_type == "azurerm_network_security_rule":
            if re.search(r'\baccess\s*=\s*["\']Allow["\']', block, re.I) and re.search(r'\bdirection\s*=\s*["\']Inbound["\']', block, re.I) and re.search(r'\bsource_address_prefix\s*=\s*["\'](?:\*|0\.0\.0\.0/0|Internet)["\']', block, re.I):
                port = self._first_port(block, "destination_port_range")
                severity = "Critical" if port in {22, 3389, 3306, 5432, 6379, 27017} else "High"
                findings.append(self._finding("IAC-AZURE-NSG-INTERNET-INGRESS", resource_id, line, severity, "Azure NSG allows internet ingress", f"The inbound rule allows an internet-wide source to destination port {port or 'any'}.", "Restrict source prefixes and destination ports to the exact application requirement.", "Elevation of Privilege", "CWE-284"))
        elif resource_type == "azurerm_kubernetes_cluster":
            if re.search(r'\bprivate_cluster_enabled\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AZURE-AKS-PUBLIC-API", resource_id, line, "High", "AKS API server is public", "The cluster explicitly disables private-cluster mode.", "Enable a private cluster or restrict authorized API server IP ranges and enforce Entra ID/RBAC.", "Elevation of Privilege", "CWE-668"))
            if re.search(r'\blocal_account_disabled\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AZURE-AKS-LOCAL-ACCOUNTS", resource_id, line, "High", "AKS local administrator accounts are enabled", "Local cluster credentials can bypass centralized identity controls.", "Disable local accounts and require Entra ID integrated Kubernetes RBAC.", "Spoofing", "CWE-287"))
        elif resource_type == "azurerm_container_registry" and re.search(r'\badmin_enabled\s*=\s*true', block, re.I):
            findings.append(self._finding("IAC-AZURE-ACR-ADMIN-ENABLED", resource_id, line, "High", "Azure Container Registry admin account is enabled", "The registry exposes long-lived shared administrator credentials.", "Disable the admin account and use managed identities with scoped repository permissions.", "Spoofing", "CWE-522"))

        if resource_type == "google_storage_bucket" and re.search(r'\buniform_bucket_level_access\s*=\s*false', block, re.I):
            findings.append(self._finding("IAC-GCP-BUCKET-NO-UNIFORM-ACCESS", resource_id, line, "High", "Cloud Storage uniform access is disabled", "Object ACLs remain available and can bypass centralized IAM policy management.", "Enable uniform bucket-level access and remove legacy ACL dependencies.", "Elevation of Privilege", "CWE-284"))
        elif resource_type in {"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"} and re.search(r'\b(?:member|members)\s*=.*\ballUsers\b', block, re.I | re.S):
            findings.append(self._finding("IAC-GCP-BUCKET-PUBLIC-IAM", resource_id, line, "Critical", "Cloud Storage bucket grants public IAM access", "The bucket IAM policy includes allUsers.", "Remove public members and grant access only to named principals or controlled delivery services.", "Information Disclosure", "CWE-668"))
        elif resource_type == "google_compute_firewall" and re.search(r'\bsource_ranges\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\']', block, re.I | re.S):
            ports = {int(value) for value in re.findall(r'["\'](\d+)["\']', self._nested_block(block, "allow"))}
            severity = "Critical" if ports & {22, 3389, 3306, 5432, 6379, 27017} else "High"
            findings.append(self._finding("IAC-GCP-FIREWALL-INTERNET-INGRESS", resource_id, line, severity, "GCP firewall allows internet ingress", f"The firewall permits 0.0.0.0/0 to ports {', '.join(map(str, sorted(ports))) or 'all configured ports'}.", "Restrict source ranges and target the rule to specific service accounts or network tags.", "Elevation of Privilege", "CWE-284"))
        elif resource_type == "google_sql_database_instance":
            ip_config = self._nested_block(block, "ip_configuration")
            if re.search(r'\bipv4_enabled\s*=\s*true', ip_config, re.I) and re.search(r'\bvalue\s*=\s*["\']0\.0\.0\.0/0["\']', ip_config, re.I):
                findings.append(self._finding("IAC-GCP-SQL-PUBLIC", resource_id, line, "Critical", "Cloud SQL permits internet-wide access", "The instance has a public IPv4 endpoint and an authorized network of 0.0.0.0/0.", "Use private IP and restrict authorized networks to controlled sources.", "Information Disclosure", "CWE-668"))
            if re.search(r'\brequire_ssl\s*=\s*false', ip_config, re.I):
                findings.append(self._finding("IAC-GCP-SQL-NO-TLS", resource_id, line, "High", "Cloud SQL does not require TLS", "Database clients are not required to use encrypted transport.", "Require SSL/TLS and enforce trusted client certificates or connector-based access.", "Information Disclosure", "CWE-319"))
        elif resource_type == "google_container_cluster":
            private_config = self._nested_block(block, "private_cluster_config")
            if re.search(r'\benable_private_endpoint\s*=\s*false', private_config, re.I) and self._terraform_public_cidrs(block, "cidr_block"):
                findings.append(self._finding("IAC-GCP-GKE-PUBLIC-CONTROL-PLANE", resource_id, line, "High", "GKE control plane is publicly reachable", "The cluster disables its private endpoint without a restrictive authorized-network configuration.", "Enable the private endpoint or tightly restrict master authorized networks.", "Elevation of Privilege", "CWE-668"))
        elif resource_type == "google_compute_instance" and "access_config" in block:
            findings.append(self._finding("IAC-GCP-COMPUTE-PUBLIC-IP", resource_id, line, "High", "Compute Engine instance receives a public IP", "A network interface includes access_config, which assigns an external address.", "Remove access_config and expose the workload through a controlled load balancer, proxy, or identity-aware access path.", "Information Disclosure", "CWE-668"))
        elif resource_type in {"google_project_iam_member", "google_project_iam_binding"} and re.search(r'\brole\s*=\s*["\']roles/(?:owner|editor)["\']', block, re.I):
            findings.append(self._finding("IAC-GCP-PRIMITIVE-IAM-ROLE", resource_id, line, "Critical", "GCP primitive project role grants excessive access", "The binding grants the broad Owner or Editor role.", "Replace primitive roles with predefined or custom least-privilege roles.", "Elevation of Privilege", "CWE-250"))

        return findings

    def _analyze_cloudformation(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for logical_id, resource in (document.get("Resources") or {}).items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type", "")
            props = resource.get("Properties") or {}
            line = self._line_for(content, str(logical_id))
            if resource_type == "AWS::S3::Bucket":
                access_block = props.get("PublicAccessBlockConfiguration") or {}
                if not access_block:
                    findings.append(self._finding("IAC-AWS-S3-MISSING-PAB", logical_id, line, "High", "S3 bucket lacks a public-access block", "The CloudFormation bucket has no bucket-level public-access-block configuration.", "Enable all four S3 public-access-block settings or document the enforced account-level control.", "Information Disclosure", "CWE-284"))
                if any(access_block.get(key) is False for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                    findings.append(self._finding("IAC-AWS-S3-PAB-DISABLED", logical_id, line, "High", "S3 public-access protections are disabled", "The CloudFormation bucket disables at least one public-access-block setting.", "Enable all S3 public-access-block settings and use least-privilege bucket policies.", "Information Disclosure", "CWE-284"))
                if props.get("AccessControl") in {"PublicRead", "PublicReadWrite", "AuthenticatedRead"}:
                    findings.append(self._finding("IAC-AWS-S3-PUBLIC-ACL", logical_id, line, "Critical", "Public S3 bucket ACL", "The bucket AccessControl property grants broad access.", "Remove the public ACL and grant access using restricted IAM policies.", "Information Disclosure", "CWE-200"))
                if not props.get("VersioningConfiguration") or props.get("VersioningConfiguration", {}).get("Status") != "Enabled":
                    findings.append(self._finding("IAC-AWS-S3-NO-VERSIONING", logical_id, line, "Medium", "S3 bucket versioning is not configured", "The bucket does not explicitly enable object versioning.", "Enable S3 versioning and apply an appropriate retention policy.", "Tampering", "CWE-693"))
            elif resource_type == "AWS::RDS::DBInstance":
                if props.get("PubliclyAccessible") is True:
                    findings.append(self._finding("IAC-AWS-RDS-PUBLIC", logical_id, line, "Critical", "RDS instance is publicly accessible", "PubliclyAccessible is explicitly true.", "Set PubliclyAccessible to false and use private subnets and restricted security groups.", "Information Disclosure", "CWE-668"))
                if props.get("StorageEncrypted") is False:
                    findings.append(self._finding("IAC-AWS-RDS-NO-ENCRYPTION", logical_id, line, "High", "RDS storage encryption is disabled", "StorageEncrypted is explicitly false.", "Enable encryption at rest with KMS.", "Information Disclosure", "CWE-311"))
            elif resource_type == "AWS::Lambda::Permission" and props.get("Principal") == "*":
                findings.append(self._finding("IAC-AWS-LAMBDA-PUBLIC-INVOKE", logical_id, line, "Critical", "Lambda permission allows public invocation", "The Lambda permission principal is a wildcard.", "Restrict the principal and SourceArn to the trusted invoking service.", "Spoofing", "CWE-284"))
            elif resource_type == "AWS::EC2::SecurityGroup":
                for rule in props.get("SecurityGroupIngress") or []:
                    if isinstance(rule, dict) and rule.get("CidrIp") in {"0.0.0.0/0", "::/0"}:
                        port = rule.get("FromPort")
                        severity = "Critical" if port in {22, 3389, 3306, 5432, 6379, 27017} else "High"
                        findings.append(self._finding("IAC-AWS-EC2-OPEN-SECURITY-GROUP", logical_id, line, severity, "Security group exposes a port to the internet", f"Ingress permits {rule.get('CidrIp')} on port {port}.", "Restrict the source CIDR to trusted ranges or use a security-group reference.", "Elevation of Privilege", "CWE-284"))
            elif resource_type == "AWS::IAM::ManagedPolicy":
                findings.extend(self._analyze_policy_text(json.dumps(props.get("PolicyDocument", {})), logical_id, line))
            elif resource_type == "AWS::KMS::Key" and self._public_principal(json.dumps(props.get("KeyPolicy", {}))):
                findings.append(self._finding("IAC-AWS-KMS-PUBLIC-KEY", logical_id, line, "Critical", "KMS key policy permits a public principal", "The KMS KeyPolicy contains a wildcard principal.", "Restrict principals to the minimum required IAM roles and accounts.", "Elevation of Privilege", "CWE-284"))
            findings.extend(self._analyze_additional_cloudformation_resource(resource_type, logical_id, props, line))
        return findings

    def _analyze_additional_cloudformation_resource(self, resource_type: str, resource_id: str, props: Dict[str, Any], line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        props_text = json.dumps(props, default=str)

        if resource_type in {"AWS::IAM::Role", "AWS::IAM::Policy"}:
            findings.extend(self._analyze_policy_text(props_text, resource_id, line))
        if resource_type == "AWS::IAM::Role":
            findings.extend(self._analyze_policy_text(json.dumps(props.get("AssumeRolePolicyDocument") or {}, default=str), resource_id, line))
            if any("AdministratorAccess" in str(item) for item in props.get("ManagedPolicyArns") or []):
                findings.append(self._finding("IAC-AWS-IAM-MANAGED-ADMIN", resource_id, line, "Critical", "IAM role attaches AdministratorAccess", "The role attaches the AWS managed AdministratorAccess policy.", "Replace AdministratorAccess with a workload-specific least-privilege policy.", "Elevation of Privilege", "CWE-250"))
        elif resource_type == "AWS::Lambda::Function":
            variables = ((props.get("Environment") or {}).get("Variables") or {})
            if any(self._looks_like_secret_name(str(key)) and self._is_literal_secret_value(value) for key, value in variables.items()):
                findings.append(self._finding("IAC-AWS-LAMBDA-HARDCODED-SECRET", resource_id, line, "High", "Lambda environment contains a likely hard-coded secret", "A secret-like environment variable is assigned a literal value in the function configuration.", "Store the secret in AWS Secrets Manager and reference it at runtime.", "Information Disclosure", "CWE-798"))
        elif resource_type == "AWS::Lambda::Url" and props.get("AuthType") == "NONE":
            findings.append(self._finding("IAC-AWS-LAMBDA-URL-PUBLIC", resource_id, line, "High", "Lambda function URL has no authorization", "The function URL explicitly uses AuthType NONE.", "Use AWS_IAM authorization or an authenticated API Gateway.", "Spoofing", "CWE-306"))
        elif resource_type == "AWS::ApiGateway::Method" and props.get("AuthorizationType") == "NONE":
            findings.append(self._finding("IAC-AWS-APIGW-NO-AUTH", resource_id, line, "High", "API Gateway method has no authorization", "The method explicitly uses AuthorizationType NONE.", "Require IAM, Cognito, JWT, or a Lambda authorizer for non-public operations.", "Spoofing", "CWE-306"))
        elif resource_type == "AWS::EC2::Instance":
            metadata_options = props.get("MetadataOptions") or {}
            if metadata_options.get("HttpTokens") == "optional":
                findings.append(self._finding("IAC-AWS-EC2-IMDSV1", resource_id, line, "High", "EC2 instance permits IMDSv1", "Metadata HttpTokens is optional, allowing tokenless metadata requests.", "Set HttpTokens to required and use a restrictive hop limit.", "Information Disclosure", "CWE-918"))
            for mapping in props.get("BlockDeviceMappings") or []:
                if isinstance(mapping, dict) and (mapping.get("Ebs") or {}).get("Encrypted") is False:
                    findings.append(self._finding("IAC-AWS-EC2-UNENCRYPTED-EBS", resource_id, line, "High", "EC2 block storage encryption is disabled", "A block-device mapping explicitly disables encryption.", "Enable EBS encryption with an approved KMS key.", "Information Disclosure", "CWE-311"))
        elif resource_type == "AWS::RDS::DBInstance":
            if props.get("BackupRetentionPeriod") == 0:
                findings.append(self._finding("IAC-AWS-RDS-NO-BACKUP", resource_id, line, "High", "RDS automated backups are disabled", "BackupRetentionPeriod is zero.", "Set a non-zero retention period and test point-in-time restoration.", "Denial of Service", "CWE-693"))
            if props.get("DeletionProtection") is False:
                findings.append(self._finding("IAC-AWS-RDS-NO-DELETION-PROTECTION", resource_id, line, "Medium", "RDS deletion protection is disabled", "DeletionProtection is explicitly false.", "Enable deletion protection for production databases and restrict destructive API permissions.", "Denial of Service", "CWE-693"))
        elif resource_type == "AWS::CloudTrail::Trail":
            if props.get("IsLogging") is False:
                findings.append(self._finding("IAC-AWS-CLOUDTRAIL-DISABLED", resource_id, line, "Critical", "CloudTrail logging is disabled", "IsLogging is explicitly false.", "Enable the trail and monitor delivery health.", "Repudiation", "CWE-778"))
            if props.get("EnableLogFileValidation") is False:
                findings.append(self._finding("IAC-AWS-CLOUDTRAIL-NO-VALIDATION", resource_id, line, "High", "CloudTrail log validation is disabled", "EnableLogFileValidation is explicitly false.", "Enable log file validation and protect the log destination.", "Tampering", "CWE-345"))
        elif resource_type == "AWS::ECR::Repository":
            if (props.get("ImageScanningConfiguration") or {}).get("ScanOnPush") is False:
                findings.append(self._finding("IAC-AWS-ECR-SCAN-DISABLED", resource_id, line, "High", "ECR image scanning on push is disabled", "ScanOnPush is explicitly false.", "Enable image scanning and gate deployment on results.", "Tampering", "CWE-1104"))
            if props.get("ImageTagMutability") == "MUTABLE":
                findings.append(self._finding("IAC-AWS-ECR-MUTABLE-TAGS", resource_id, line, "Medium", "ECR image tags are mutable", "ImageTagMutability is MUTABLE.", "Use immutable tags and deploy by digest.", "Tampering", "CWE-829"))
        elif resource_type == "AWS::DynamoDB::Table" and (props.get("PointInTimeRecoverySpecification") or {}).get("PointInTimeRecoveryEnabled") is False:
            findings.append(self._finding("IAC-AWS-DDB-PITR-DISABLED", resource_id, line, "High", "DynamoDB point-in-time recovery is disabled", "PointInTimeRecoveryEnabled is false.", "Enable PITR and test restoration.", "Denial of Service", "CWE-693"))
        elif resource_type == "AWS::SQS::Queue" and props.get("SqsManagedSseEnabled") is False:
            findings.append(self._finding("IAC-AWS-SQS-ENCRYPTION-DISABLED", resource_id, line, "High", "SQS managed encryption is disabled", "SqsManagedSseEnabled is false.", "Enable SQS-managed SSE or configure a KMS key.", "Information Disclosure", "CWE-311"))
        elif resource_type == "AWS::SecretsManager::Secret" and props.get("ForceDeleteWithoutRecovery") is True:
            findings.append(self._finding("IAC-AWS-SECRET-FORCE-DELETE", resource_id, line, "High", "Secrets Manager recovery window is disabled", "ForceDeleteWithoutRecovery is true.", "Use a recovery window and restrict destructive permissions.", "Denial of Service", "CWE-693"))
        elif resource_type == "AWS::EKS::Cluster":
            vpc_config = ((props.get("ResourcesVpcConfig") or {}))
            public_cidrs = vpc_config.get("PublicAccessCidrs") or ["0.0.0.0/0"]
            if vpc_config.get("EndpointPublicAccess") is True and any(cidr in {"0.0.0.0/0", "::/0"} for cidr in public_cidrs):
                findings.append(self._finding("IAC-AWS-EKS-PUBLIC-ENDPOINT", resource_id, line, "Critical", "EKS control-plane endpoint is public", "The public Kubernetes API endpoint permits an internet-wide CIDR.", "Disable public endpoint access or restrict CIDRs tightly.", "Elevation of Privilege", "CWE-284"))
        elif resource_type in {"AWS::ElasticLoadBalancingV2::Listener", "AWS::ElasticLoadBalancing::LoadBalancer"}:
            protocols = [str(props.get("Protocol", ""))] + [str(item.get("Protocol", "")) for item in props.get("Listeners") or [] if isinstance(item, dict)]
            if "HTTP" in protocols:
                findings.append(self._finding("IAC-AWS-LB-PLAINTEXT-LISTENER", resource_id, line, "High", "Load balancer listener accepts plaintext HTTP", "A load balancer listener uses HTTP.", "Use HTTPS with a modern TLS policy and redirect HTTP.", "Information Disclosure", "CWE-319"))
        elif resource_type == "AWS::KMS::Key":
            if props.get("EnableKeyRotation") is False:
                findings.append(self._finding("IAC-AWS-KMS-ROTATION-DISABLED", resource_id, line, "High", "KMS key rotation is disabled", "EnableKeyRotation is false.", "Enable automatic key rotation.", "Information Disclosure", "CWE-320"))
            if isinstance(props.get("PendingWindowInDays"), int) and props["PendingWindowInDays"] < 7:
                findings.append(self._finding("IAC-AWS-KMS-SHORT-DELETION", resource_id, line, "Medium", "KMS key deletion window is too short", "PendingWindowInDays is less than seven.", "Use a deletion window of at least seven days.", "Denial of Service", "CWE-693"))

        return findings

    def _analyze_kubernetes(self, document: Dict[str, Any], content: str, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        kind = document.get("kind", "")
        name = (document.get("metadata") or {}).get("name", kind)
        workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}
        resource_id = name if kind in workload_kinds else f"{kind.lower()}.{name}"
        line = self._line_for(content, str(name))
        spec = document.get("spec") or {}
        if kind == "CronJob":
            pod_spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        else:
            pod_spec = spec.get("template", {}).get("spec", spec) if kind != "Pod" else spec

        if kind == "Service" and spec.get("type") in {"LoadBalancer", "NodePort"}:
            findings.append(self._finding("IAC-K8S-PUBLIC-SERVICE", resource_id, line, "High", "Kubernetes Service exposes workloads externally", f"Service type {spec.get('type')} exposes the workload outside the cluster.", "Use ClusterIP by default and expose only authenticated ingress endpoints with network policies.", "Information Disclosure", "CWE-668"))
        if kind in {"Role", "ClusterRole"}:
            for rule in document.get("rules") or []:
                verbs = rule.get("verbs") or []
                resources = rule.get("resources") or []
                if "*" in verbs or "*" in resources:
                    findings.append(self._finding("IAC-K8S-RBAC-WILDCARD", resource_id, line, "Critical", "Kubernetes RBAC grants wildcard privileges", "The role permits all verbs on all resources.", "Grant only required verbs and resources; avoid cluster-admin for workloads.", "Elevation of Privilege", "CWE-250"))
                if set(resources) & {"secrets"} and set(verbs) & {"get", "list", "watch", "*"}:
                    findings.append(self._finding("IAC-K8S-RBAC-SECRET-READ", resource_id, line, "High", "Kubernetes RBAC permits secret disclosure", "The role can read or enumerate Kubernetes Secrets.", "Limit secret access to named resources and only the service accounts that require it.", "Information Disclosure", "CWE-284"))
                if set(resources) & {"pods/exec", "pods/attach"} and set(verbs) & {"create", "*"}:
                    findings.append(self._finding("IAC-K8S-RBAC-POD-EXEC", resource_id, line, "High", "Kubernetes RBAC permits pod command execution", "The role can create pod exec or attach sessions.", "Restrict exec and attach permissions to audited operational roles.", "Elevation of Privilege", "CWE-250"))
        if kind in {"RoleBinding", "ClusterRoleBinding"} and (document.get("roleRef") or {}).get("name") == "cluster-admin":
            findings.append(self._finding("IAC-K8S-CLUSTER-ADMIN-BINDING", resource_id, line, "Critical", "Kubernetes subject is bound to cluster-admin", "The binding grants unrestricted cluster administration to its subjects.", "Replace cluster-admin with a purpose-built least-privilege role and tightly control emergency administration.", "Elevation of Privilege", "CWE-250"))
        if kind == "Ingress":
            if not spec.get("tls"):
                findings.append(self._finding("IAC-K8S-INGRESS-NO-TLS", resource_id, line, "High", "Kubernetes Ingress does not configure TLS", "The Ingress has host rules but no TLS configuration, allowing plaintext client traffic unless another documented edge terminates TLS.", "Configure TLS with a trusted certificate and redirect HTTP to HTTPS at the ingress controller.", "Information Disclosure", "CWE-319"))
            annotations = (document.get("metadata") or {}).get("annotations") or {}
            if str(annotations.get("nginx.ingress.kubernetes.io/ssl-redirect", "true")).lower() == "false":
                findings.append(self._finding("IAC-K8S-INGRESS-SSL-REDIRECT-DISABLED", resource_id, line, "Medium", "Ingress HTTPS redirect is disabled", "The ingress annotation explicitly permits continued HTTP access.", "Enable SSL redirect and enforce HSTS after validating application compatibility.", "Information Disclosure", "CWE-319"))
        if kind == "Secret" and (document.get("data") or document.get("stringData")):
            findings.append(self._finding("IAC-K8S-SECRET-IN-MANIFEST", resource_id, line, "High", "Kubernetes Secret value is stored in the manifest", "Secret material is embedded in source-controlled IaC; base64 encoding does not provide confidentiality.", "Reference an external secret manager or encrypted secret workflow and rotate any committed values.", "Information Disclosure", "CWE-798"))
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}:
            namespace = (document.get("metadata") or {}).get("namespace", "default")
            if kind == "CronJob":
                template = spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
            elif kind == "Pod":
                template = document
            else:
                template = spec.get("template", {})
            pod_labels = (template.get("metadata") or {}).get("labels") or {}
            if pod_spec.get("hostNetwork") is True or pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
                findings.append(self._finding("IAC-K8S-HOST-NAMESPACE", name, line, "High", "Pod shares a host namespace", "hostNetwork or hostPID is enabled, reducing container isolation.", "Disable host namespace sharing unless a documented platform exception requires it.", "Elevation of Privilege", "CWE-250"))
            if pod_spec.get("automountServiceAccountToken") is True:
                findings.append(self._finding("IAC-K8S-AUTOMOUNT-TOKEN", name, line, "Medium", "Pod explicitly mounts a service-account token", "The workload mounts Kubernetes API credentials even though its need is not established in the manifest.", "Set automountServiceAccountToken to false unless the workload calls the Kubernetes API, then scope RBAC narrowly.", "Information Disclosure", "CWE-522"))
            for volume in pod_spec.get("volumes") or []:
                if isinstance(volume, dict) and volume.get("hostPath"):
                    findings.append(self._finding("IAC-K8S-HOSTPATH", name, line, "Critical", "Pod mounts a hostPath volume", f"Volume {volume.get('name', 'unnamed')} exposes a node filesystem path to the pod.", "Replace hostPath with a managed volume; if unavoidable, restrict the path, mount read-only, and isolate the workload.", "Elevation of Privilege", "CWE-250"))
            all_containers = (pod_spec.get("initContainers") or []) + (pod_spec.get("containers") or []) + (pod_spec.get("ephemeralContainers") or [])
            regular_containers = pod_spec.get("containers") or []
            if any(not self._has_resource_bounds(container) for container in regular_containers):
                findings.append(self._finding("IAC-K8S-MISSING-RESOURCE-BOUNDS", name, line, "Medium", "Workload resource requests or limits require validation", "At least one application container does not declare CPU and memory requests and limits in the submitted workload.", "Define workload-specific CPU and memory requests and limits, or document the admission policy that injects and enforces them.", "Denial of Service", "CWE-770"))
            if any((container.get("securityContext") or {}).get("readOnlyRootFilesystem") is not True for container in all_containers):
                findings.append(self._finding("IAC-K8S-MISSING-READONLY-ROOTFS", name, line, "Low", "Read-only root filesystem is not declared", "At least one container does not declare readOnlyRootFilesystem: true; an admission control may still enforce it outside this manifest.", "Set readOnlyRootFilesystem to true and mount narrowly scoped writable volumes where required.", "Tampering", "CWE-693"))
            if any("ALL" not in set(((container.get("securityContext") or {}).get("capabilities") or {}).get("drop") or []) for container in all_containers):
                findings.append(self._finding("IAC-K8S-MISSING-CAPABILITY-DROP", name, line, "Medium", "Container capability baseline is not declared", "At least one container does not explicitly drop all Linux capabilities in the submitted workload.", "Set capabilities.drop to ALL and add back only capabilities justified by the workload.", "Elevation of Privilege", "CWE-250"))
            pod_seccomp = str(((pod_spec.get("securityContext") or {}).get("seccompProfile") or {}).get("type", ""))
            if not pod_seccomp and any(not ((container.get("securityContext") or {}).get("seccompProfile")) for container in all_containers):
                findings.append(self._finding("IAC-K8S-MISSING-SECCOMP", name, line, "Medium", "Seccomp profile is not declared", "Neither the pod nor every container declares a seccomp profile in the submitted workload.", "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile, or document the enforcing admission policy.", "Elevation of Privilege", "CWE-693"))
            if any(not container.get("livenessProbe") or not container.get("readinessProbe") for container in regular_containers):
                findings.append(self._finding("IAC-K8S-MISSING-HEALTH-PROBES", name, line, "Low", "Workload health probes are incomplete", "At least one application container lacks a liveness or readiness probe.", "Configure protocol-appropriate readiness and liveness probes with conservative thresholds.", "Denial of Service", "CWE-693"))
            if not self._matching_policy(context or {}, "network_policies", namespace, pod_labels):
                findings.append(self._finding("IAC-K8S-MISSING-NETWORK-POLICY", name, line, "Medium", "No matching NetworkPolicy is present in the submitted manifests", "No submitted NetworkPolicy selector matches this workload; cluster-level or separately managed policy remains unverified.", "Add default-deny ingress and egress policies plus narrowly scoped allow policies, or provide evidence of the external policy source.", "Elevation of Privilege", "CWE-923"))
            if kind in {"Deployment", "StatefulSet"} and not self._matching_policy(context or {}, "pod_disruption_budgets", namespace, pod_labels):
                findings.append(self._finding("IAC-K8S-MISSING-PDB", name, line, "Low", "No matching PodDisruptionBudget is present in the submitted manifests", "No submitted PodDisruptionBudget selector matches this replicated workload.", "Define a PodDisruptionBudget consistent with replica count and availability objectives, or document an external policy.", "Denial of Service", "CWE-693"))
            if (
                str(pod_spec.get("serviceAccountName") or "default") == "default"
                and pod_spec.get("automountServiceAccountToken") is not False
            ):
                findings.append(self._finding("IAC-K8S-DEFAULT-SERVICE-ACCOUNT", name, line, "Medium", "Workload identity and token mounting require validation", "The workload uses the default service account and does not disable automatic API token mounting.", "Create a dedicated service account, disable token automount unless the API is required, and bind only the required namespaced permissions.", "Elevation of Privilege", "CWE-250"))
            for container in all_containers:
                security = container.get("securityContext") or {}
                image = str(container.get("image", ""))
                if security.get("privileged") is True:
                    findings.append(self._finding("IAC-K8S-PRIVILEGED-CONTAINER", name, line, "Critical", "Kubernetes container runs privileged", "A container security context explicitly enables privileged mode.", "Set privileged to false and remove unnecessary Linux capabilities.", "Elevation of Privilege", "CWE-250"))
                if security.get("allowPrivilegeEscalation") is True:
                    findings.append(self._finding("IAC-K8S-PRIV-ESCALATION", name, line, "High", "Kubernetes container allows privilege escalation", "allowPrivilegeEscalation is explicitly true.", "Set allowPrivilegeEscalation to false and enforce the restricted Pod Security Standard.", "Elevation of Privilege", "CWE-269"))
                if image.endswith(":latest") or ":" not in image:
                    findings.append(self._finding("IAC-K8S-UNPINNED-IMAGE", name, line, "Medium", "Container image is not pinned", "The image uses latest or has no immutable tag.", "Pin images by immutable digest and enforce image provenance controls.", "Tampering", "CWE-829"))
                if security.get("runAsUser") == 0 or security.get("runAsNonRoot") is False:
                    findings.append(self._finding("IAC-K8S-RUN-AS-ROOT", name, line, "High", "Kubernetes container is configured to run as root", "The container security context explicitly permits UID 0 execution.", "Set runAsNonRoot to true and use a fixed non-zero runAsUser value supported by the image.", "Elevation of Privilege", "CWE-250"))
                dangerous_caps = set((security.get("capabilities") or {}).get("add") or []) & {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "ALL"}
                if dangerous_caps:
                    findings.append(self._finding("IAC-K8S-DANGEROUS-CAPABILITY", name, line, "Critical", "Container adds dangerous Linux capabilities", f"The container adds high-impact capabilities: {', '.join(sorted(dangerous_caps))}.", "Drop ALL capabilities and add back only the narrowly required set.", "Elevation of Privilege", "CWE-250"))
                if str((security.get("seccompProfile") or {}).get("type", "")).lower() == "unconfined":
                    findings.append(self._finding("IAC-K8S-SECCOMP-UNCONFINED", name, line, "High", "Container disables seccomp confinement", "The security context explicitly selects an Unconfined seccomp profile.", "Use RuntimeDefault or a tested Localhost seccomp profile.", "Elevation of Privilege", "CWE-693"))
                for env_var in container.get("env") or []:
                    if self._literal_secret_entry(env_var):
                        findings.append(self._finding("IAC-K8S-HARDCODED-SECRET", name, line, "High", "Container environment contains a hard-coded secret", f"Environment variable {env_var.get('name')} contains a literal secret value.", "Load secrets through secretKeyRef or an external secrets provider and rotate the exposed value.", "Information Disclosure", "CWE-798"))
        return findings

    def _analyze_compose(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for name, service in (document.get("services") or {}).items():
            if not isinstance(service, dict):
                continue
            line = self._line_for(content, str(name))
            if service.get("privileged") is True:
                findings.append(self._finding("IAC-COMPOSE-PRIVILEGED", name, line, "Critical", "Compose service runs privileged", "The service explicitly enables privileged mode.", "Remove privileged mode and add only the specific capabilities required.", "Elevation of Privilege", "CWE-250"))
            if service.get("network_mode") == "host":
                findings.append(self._finding("IAC-COMPOSE-HOST-NETWORK", name, line, "High", "Compose service uses the host network", "network_mode: host removes network isolation from the container.", "Use a dedicated Docker network and expose only required ports.", "Elevation of Privilege", "CWE-668"))
            if service.get("pid") == "host" or service.get("ipc") == "host":
                findings.append(self._finding("IAC-COMPOSE-HOST-NAMESPACE", name, line, "High", "Compose service shares a host namespace", "The service shares the host PID or IPC namespace, weakening container isolation.", "Remove host PID/IPC sharing and use an isolated namespace.", "Elevation of Privilege", "CWE-250"))
            image = str(service.get("image", ""))
            if image.endswith(":latest") or (image and ":" not in image):
                findings.append(self._finding("IAC-COMPOSE-UNPINNED-IMAGE", name, line, "Medium", "Container image is not pinned", "The service image uses latest or has no immutable tag.", "Pin images by immutable digest and enforce image provenance controls.", "Tampering", "CWE-829"))
            if str(service.get("user", "")).lower() in {"root", "0", "0:0"}:
                findings.append(self._finding("IAC-COMPOSE-RUN-AS-ROOT", name, line, "High", "Compose service explicitly runs as root", "The service user is set to root or UID 0.", "Run the container as a dedicated non-root UID/GID and restrict filesystem permissions.", "Elevation of Privilege", "CWE-250"))
            dangerous_caps = set(service.get("cap_add") or []) & {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "ALL"}
            if dangerous_caps:
                findings.append(self._finding("IAC-COMPOSE-DANGEROUS-CAPABILITY", name, line, "Critical", "Compose service adds dangerous Linux capabilities", f"The service adds high-impact capabilities: {', '.join(sorted(dangerous_caps))}.", "Drop all capabilities and add only the minimum explicitly required.", "Elevation of Privilege", "CWE-250"))
            for volume in service.get("volumes") or []:
                volume_text = str(volume)
                if "/var/run/docker.sock" in volume_text:
                    findings.append(self._finding("IAC-COMPOSE-DOCKER-SOCKET", name, line, "Critical", "Compose service mounts the Docker socket", "The container can control the host Docker daemon and effectively obtain host-level privileges.", "Remove the Docker socket mount or place a restricted audited proxy in front of the daemon.", "Elevation of Privilege", "CWE-250"))
                elif re.match(r'^\s*/(?::|$)', volume_text) or re.match(r'^\s*/[^:]+:/', volume_text):
                    findings.append(self._finding("IAC-COMPOSE-HOST-MOUNT", name, line, "High", "Compose service mounts a host filesystem path", f"The service bind-mounts a host path: {volume_text}.", "Use a named volume or restrict the bind mount to a narrow read-only path.", "Elevation of Privilege", "CWE-250"))
            environment = service.get("environment") or {}
            entries = list(environment.items()) if isinstance(environment, dict) else list(
                (str(item).split("=", 1) + [""])[:2] for item in environment
            )
            for env_name, env_value in entries:
                if self._looks_like_secret_name(str(env_name)) and self._is_literal_secret_value(env_value):
                    findings.append(self._finding("IAC-COMPOSE-HARDCODED-SECRET", name, line, "High", "Compose environment contains a hard-coded secret", f"Environment variable {env_name} contains a literal secret value.", "Use Docker secrets or an external secret manager and rotate the exposed value.", "Information Disclosure", "CWE-798"))
                if (
                    re.search(r'(?:allowed[_-]?origins?|cors[_-]?(?:origins?|allow[_-]?origin))', str(env_name), re.I)
                    and re.search(r'(?:^|[,\s])\*(?:$|[,\s}])|:-\*}', str(env_value))
                ):
                    findings.append(self._finding("IAC-COMPOSE-CORS-WILDCARD", name, line, "High", "Compose service permits wildcard CORS origins", f"Environment variable {env_name} permits every browser origin through value {env_value}.", "Set an explicit allowlist of trusted HTTPS origins and reject wildcard origins when credentials or sensitive responses are possible.", "Information Disclosure", "CWE-942"))
            for port_entry in service.get("ports") or []:
                port_text = str(port_entry)
                if isinstance(port_entry, dict):
                    target = str(port_entry.get("target", ""))
                    host = str(port_entry.get("host_ip", "0.0.0.0"))
                else:
                    parts = port_text.split("/", 1)[0].rsplit(":", 2)
                    target = parts[-1]
                    host = parts[0] if len(parts) == 3 else "0.0.0.0"
                sensitive_port = int(target) if target.isdigit() and int(target) in {22, 2375, 3306, 5432, 6379, 9200, 27017} else None
                if sensitive_port and host.strip("[]") in {"0.0.0.0", "::", ""}:
                    findings.append(self._finding("IAC-COMPOSE-PUBLIC-SENSITIVE-PORT", name, line, "High", "Compose publishes a sensitive service port", f"Port mapping {port_text} publishes sensitive port {sensitive_port} on host interfaces. Internet reachability depends on the host routing and firewall and is not established by this file.", "Remove the published port or bind it to loopback; verify host routing and firewall restrictions.", "Information Disclosure", "CWE-668"))
        return findings

    def _analyze_policy_text(self, text: str, resource_id: str, line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        statements = list(allow_statements(text))
        unconditioned = [statement for statement in statements if not statement.get("Condition")]
        action_wildcard = any("*" in values(s.get("Action")) for s in unconditioned)
        admin = any("*" in values(s.get("Action")) and "*" in values(s.get("Resource")) for s in unconditioned)
        resource_wildcard = admin
        if action_wildcard and resource_wildcard:
            findings.append(self._finding("IAC-AWS-IAM-ADMIN", resource_id, line, "Critical", "IAM policy contains an unrestricted administrative allow", "An unconditional Allow statement requests every action on every resource. Effective access still depends on other policies, explicit denies, permission boundaries and organization controls.", "Replace wildcard permissions with the minimum required actions, resources, and conditions; verify effective access including explicit denies.", "Elevation of Privilege", "CWE-250"))
        elif action_wildcard:
            findings.append(self._finding("IAC-AWS-IAM-WILDCARD-ACTION", resource_id, line, "High", "IAM policy uses a wildcard action", "The policy permits all actions, exceeding least-privilege boundaries.", "Enumerate only required actions and constrain access with resources and conditions.", "Elevation of Privilege", "CWE-250"))
        if self._public_principal(text):
            findings.append(self._finding("IAC-AWS-IAM-PUBLIC-TRUST", resource_id, line, "Critical", "IAM policy trusts every principal", "The policy or trust relationship contains a wildcard principal.", "Restrict Principal to known accounts, roles, or services and add external-ID conditions for third parties.", "Spoofing", "CWE-284"))
        if any("iam:passrole" in [str(action).lower() for action in values(s.get("Action"))] and "*" in values(s.get("Resource")) for s in unconditioned):
            findings.append(self._finding("IAC-AWS-IAM-PASSROLE", resource_id, line, "Critical", "IAM policy can pass arbitrary roles", "iam:PassRole is combined with an unrestricted resource.", "Restrict iam:PassRole to named roles and add iam:PassedToService conditions.", "Elevation of Privilege", "CWE-269"))
        return findings

    def _analyze_security_group(self, block: str, resource_id: str, line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            parsed = hcl2.loads(block)
            groups = [properties for resource in parsed.get("resource", []) for named in resource.values() for properties in named.values()]
        except Exception:
            # Unresolved or malformed HCL must not fall back to cross-block regex matching.
            return findings
        for group in groups:
            rules = group.get("ingress", []) if resource_id.startswith("aws_security_group.") else [group]
            for rule in rules:
                if not isinstance(rule, dict) or rule.get("type") == "egress":
                    continue
                cidrs = list(rule.get("cidr_blocks") or []) + list(rule.get("ipv6_cidr_blocks") or [])
                cidrs += [rule.get("cidr_ipv4"), rule.get("cidr_ipv6")]
                if not any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs if isinstance(cidr, str)):
                    continue
                start, end = rule.get("from_port"), rule.get("to_port")
                protocol = str(rule.get("ip_protocol", rule.get("protocol", "unknown"))).lower()
                administrative = protocol == "-1" or (protocol in {"tcp", "6", "udp", "17"} and type(start) is int and type(end) is int and any(start <= port <= end for port in {22, 3389, 3306, 5432, 6379, 27017, 9200}))
                severity = "Critical" if administrative else "High"
                finding = self._finding("IAC-AWS-EC2-OPEN-SECURITY-GROUP", resource_id, line, severity, "Security group permits unrestricted ingress", f"An ingress rule allows 0.0.0.0/0 or ::/0 for protocol {protocol}, ports {start} to {end}. Public routing and workload attachment are not established by this rule alone.", "Restrict ingress to trusted CIDRs or security-group references; verify attachment, routing and effective access.", "Elevation of Privilege", "CWE-284")
                finding["exposure"] = "unrestricted_ingress_rule"
                findings.append(finding)
        return findings

    @staticmethod
    def _has_related_terraform_resource(resources_by_type: Dict[str, List[Tuple[str, str, int]]], related_type: str, target_type: str, target_name: str) -> bool:
        reference = f"{target_type}.{target_name}"
        for related_name, related_block, _ in resources_by_type.get(related_type, []):
            if related_name == target_name or reference in related_block:
                return True
        return False

    @staticmethod
    def _terraform_public_cidrs(block: str, field_name: str) -> bool:
        match = re.search(rf'\b{re.escape(field_name)}\s*=\s*\[(?P<values>[^\]]*)\]', block, re.I | re.S)
        if not match:
            return True
        values = match.group("values")
        return bool(re.search(r'["\'](?:0\.0\.0\.0/0|::/0)["\']', values))

    @staticmethod
    def _nested_block(block: str, block_name: str) -> str:
        match = re.search(rf'\b{re.escape(block_name)}\s*\{{', block, re.I)
        if not match:
            return ""
        start = match.start()
        index = match.end()
        depth = 1
        quote: Optional[str] = None
        escaped = False
        while index < len(block) and depth:
            char = block[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {'"', "'"}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        return block[start:index]

    @staticmethod
    def _first_port(block: str, field_name: str) -> Optional[int]:
        match = re.search(rf'\b{re.escape(field_name)}\s*=\s*["\']?(\d+)', block, re.I)
        return int(match.group(1)) if match else None

    @staticmethod
    def _looks_like_secret_name(name: str) -> bool:
        return bool(re.search(r'(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)', name, re.I))

    @staticmethod
    def _is_literal_secret_value(value: Any) -> bool:
        if value is None or isinstance(value, (dict, list)):
            return False
        text = str(value).strip()
        if len(text) < 8 or text.startswith(("${", "{{", "<", "arn:")):
            return False
        return text.lower() not in {"changeme", "example", "placeholder", "redacted"}

    def _literal_secret_entry(self, entry: Any) -> bool:
        return (
            isinstance(entry, dict)
            and self._looks_like_secret_name(str(entry.get("name", "")))
            and "value" in entry
            and self._is_literal_secret_value(entry.get("value"))
        )

    @staticmethod
    def _kubernetes_context(documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "service_accounts": {
                ((item.get("metadata") or {}).get("namespace", "default"), (item.get("metadata") or {}).get("name")): item
                for item in documents
                if item.get("kind") == "ServiceAccount"
            },
            "network_policies": [
                (
                    (item.get("metadata") or {}).get("namespace", "default"),
                    ((item.get("spec") or {}).get("podSelector") or {}).get("matchLabels") or {},
                )
                for item in documents if item.get("kind") == "NetworkPolicy"
            ],
            "pod_disruption_budgets": [
                (
                    (item.get("metadata") or {}).get("namespace", "default"),
                    (((item.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}),
                )
                for item in documents if item.get("kind") == "PodDisruptionBudget"
            ],
        }

    @staticmethod
    def _matching_policy(context: Dict[str, Any], key: str, namespace: str, labels: Dict[str, str]) -> bool:
        for policy_namespace, selector in context.get(key, []):
            if policy_namespace != namespace:
                continue
            if not selector or all(labels.get(name) == value for name, value in selector.items()):
                return True
        return False

    @staticmethod
    def _has_resource_bounds(container: Dict[str, Any]) -> bool:
        resources = container.get("resources") or {}
        requests = resources.get("requests") or {}
        limits = resources.get("limits") or {}
        return all(key in requests and key in limits for key in ("cpu", "memory"))

    @staticmethod
    def _load_rule_catalog() -> Dict[str, Dict[str, Any]]:
        path = Path(__file__).resolve().parent.parent / "knowledge_base" / "iac_security_rules.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"IaC security rule catalog could not be loaded: {exc}") from exc
        rules = payload.get("rules") if isinstance(payload, dict) else None
        profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
        if not isinstance(rules, list):
            raise RuntimeError("IaC security rule catalog must contain a rules list")
        catalog: Dict[str, Dict[str, Any]] = {}
        valid_severities = {"Critical", "High", "Medium", "Low"}
        valid_stride = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
        for raw_rule in rules:
            if not isinstance(raw_rule, dict):
                raise RuntimeError("Every IaC security rule must be an object")
            rule = {**profiles.get(raw_rule.get("profile"), {}), **raw_rule}
            rule_id = str(rule.get("id", ""))
            if not rule_id or rule_id in catalog:
                raise RuntimeError(f"IaC security rule has a missing or duplicate id: {rule_id}")
            if rule.get("severity") not in valid_severities or rule.get("category") not in valid_stride:
                raise RuntimeError(f"IaC security rule {rule_id} has invalid severity or STRIDE category")
            for field in ("title", "formats", "resource_types", "cwe", "owasp_top_10", "nist_800_53", "references"):
                if not rule.get(field):
                    raise RuntimeError(f"IaC security rule {rule_id} is missing {field}")
            catalog[rule_id] = rule
        return catalog

    def _terraform_blocks(self, content: str) -> Iterable[Tuple[str, str, str, int]]:
        for match in self._terraform_resource.finditer(content):
            start = match.end()
            depth = 1
            index = start
            quote = None
            escaped = False
            while index < len(content) and depth:
                char = content[index]
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = None
                elif char in {"\"", "'"}:
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                index += 1
            yield match.group("type"), match.group("name"), content[match.start():index], content.count("\n", 0, match.start()) + 1

    def _terraform_modules(self, content: str) -> Iterable[Tuple[str, str, int]]:
        for match in self._terraform_module.finditer(content):
            start = match.end()
            depth = 1
            index = start
            quote: Optional[str] = None
            escaped = False
            while index < len(content) and depth:
                char = content[index]
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = None
                elif char in {'"', "'"}:
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                index += 1
            yield match.group("name"), content[match.start():index], content.count("\n", 0, match.start()) + 1

    @staticmethod
    def _public_principal(text: str) -> bool:
        return unrestricted_public_allow(text)

    @staticmethod
    def _contains_literal_secret(text: str) -> bool:
        match = re.search(
            r'\b[A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)'
            r'[A-Za-z0-9_]*\s*=\s*["\'](?P<value>[^"\']{8,})["\']',
            text,
            re.I,
        )
        if not match:
            return False
        value = match.group('value').strip()
        return not value.startswith(('${', '{{', 'arn:')) and value.lower() not in {
            'placeholder', 'example-value', 'redacted-value',
        }

    @staticmethod
    def _line_for(content: str, token: str) -> int:
        location = content.find(token)
        return content.count("\n", 0, location) + 1 if location >= 0 else 1

    def _finding(self, rule_id: str, resource_id: str, line: int, severity: str, title: str, description: str, mitigation: str, category: str, cwe: str) -> Dict[str, Any]:
        rule = self.rule_catalog.get(rule_id)
        if rule is None:
            raise RuntimeError(f"IaC detector emitted unknown rule id {rule_id}")
        return {
            "id": f"{rule_id}:{resource_id}",
            "rule_id": rule_id,
            "resource_id": resource_id,
            "line": line,
            "severity": severity,
            "title": rule.get("title", title),
            "description": description,
            "mitigation": mitigation,
            "category": rule.get("category", category),
            "cwe": rule.get("cwe") or [cwe],
            "owasp_top_10": rule.get("owasp_top_10", []),
            "nist_800_53": rule.get("nist_800_53", []),
            "references": rule.get("references", []),
            "rule_metadata": {
                "formats": rule.get("formats", []),
                "resource_types": rule.get("resource_types", []),
                "catalog_version": rule.get("version", "1.0"),
            },
            "evidence_kind": rule.get("evidence_kind", "explicit"),
            "exposure": "host_interfaces" if rule_id == "IAC-COMPOSE-PUBLIC-SENSITIVE-PORT" else "unknown",
            "verification": "Inspect the effective deployed configuration and test the documented access restriction with an authorized test identity. A static match alone does not prove exploitability.",
            "evidence": [f"IaC resource {resource_id}, line {line}: {description}"],
        }

    @staticmethod
    def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            unique[finding["id"]] = finding
        return list(unique.values())
