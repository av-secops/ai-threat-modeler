import os
import sys
import re
import pytest
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.append(str(backend_dir))

from app.engine.iac_parser import IaCParser
from app.engine.iac_security import IaCSecurityAnalyzer
from app.engine.analyzer import ThreatAnalyzer


def test_iac_rule_catalog_matches_every_detector_rule():
    analyzer = IaCSecurityAnalyzer()
    source = (backend_dir / 'app' / 'engine' / 'iac_security.py').read_text(encoding='utf-8')
    emitted_ids = set(re.findall(r'IAC-[A-Z0-9-]+', source))
    assert emitted_ids == set(analyzer.rule_catalog)
    assert len(emitted_ids) >= 80
    assert all(rule['owasp_top_10'] and rule['nist_800_53'] and rule['references'] for rule in analyzer.rule_catalog.values())


def test_iac_project_resolves_cross_file_terraform_and_keeps_provenance():
    architecture = IaCParser().parse_project([
        {
            "filename": "function.tf",
            "content": '''resource "aws_lambda_function" "processor" {
  function_name = "processor"
  role = aws_iam_role.processor.arn
  environment { variables = { BUCKET = aws_s3_bucket.images.id } }
}''',
        },
        {
            "filename": "storage.tf",
            "content": '''resource "aws_s3_bucket" "images" { bucket = "images" }
resource "aws_iam_role" "processor" { name = "processor" }''',
        },
    ])

    by_id = {component.id: component for component in architecture.components}
    assert by_id["aws_lambda_function.processor"].properties["source_file"] == "function.tf"
    assert by_id["aws_s3_bucket.images"].properties["source_file"] == "storage.tf"
    assert any(
        flow.source_id == "aws_lambda_function.processor"
        and flow.target_id == "aws_s3_bucket.images"
        for flow in architecture.flows
    )
    assert architecture.metadata["source_files"] == ["function.tf", "storage.tf"]


@pytest.mark.parametrize(
    ("filename", "content", "expected_format", "expected_rule"),
    [
        (
            "main.json",
            '{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",'
            '"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"images",'
            '"properties":{"allowBlobPublicAccess":true,"minimumTlsVersion":"TLS1_0"}}]}',
            "arm",
            "IAC-AZURE-TEMPLATE-PUBLIC-STORAGE",
        ),
        (
            ".github/workflows/build.yml",
            "on: {pull_request: {}}\npermissions: write-all\njobs:\n  build:\n    steps:\n      - uses: vendor/action@v1\n",
            "ci",
            "IAC-CI-WRITE-ALL",
        ),
        (
            "main.bicep",
            "param adminPassword string = 'literal-password-value'\nresource db 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {}",
            "bicep",
            "IAC-BICEP-HARDCODED-SECRET",
        ),
        (
            "values.yaml",
            "database:\n  password: 'literal-password-value'\n",
            "helm-values",
            "IAC-HELM-VALUES-HARDCODED-SECRET",
        ),
    ],
)
def test_additional_iac_formats_are_detected_and_checked(filename, content, expected_format, expected_rule):
    parser = IaCParser()
    assert parser.detect_format(content, filename) == expected_format
    architecture = parser.parse(content, filename=filename)
    assert expected_rule in {finding["rule_id"] for finding in architecture.metadata["iac_findings"]}


def test_terraform_module_only_configuration_is_analyzed():
    terraform = '''
module "network" {
  source = "git::http://git.example.com/platform/network.git"
}
'''
    architecture = IaCParser().parse(terraform, 'terraform')
    rules = {finding['rule_id'] for finding in architecture.metadata['iac_findings']}
    assert {item.id for item in architecture.components} == {
        "terraform.configuration", "module.network",
    }
    assert any(item.id == 'module.network' for item in architecture.components)
    assert {'IAC-TF-INSECURE-MODULE-SOURCE', 'IAC-TF-UNPINNED-MODULE'} <= rules


def test_terraform_ast_summary_covers_structural_hcl_sections(monkeypatch):
    from app.engine import iac_parser

    class FakeHcl2:
        @staticmethod
        def loads(_content):
            return {
                "provider": [{"aws": {"alias": "audit"}}],
                "variable": [{"region": {"type": "string"}}],
                "module": [{"network": {"source": "./network"}}],
                "resource": [{"aws_s3_bucket": {"evidence": {"bucket": "evidence"}}}],
                "output": [{"bucket_id": {"value": "aws_s3_bucket.evidence.id"}}],
            }

    monkeypatch.setattr(iac_parser, "hcl2", FakeHcl2())
    summary = IaCParser._terraform_ast_summary("resource content")

    assert summary == {
        "mode": "python-hcl2", "available": True, "resource_count": 1,
        "modules": ["network"], "providers": ["aws"],
        "variables": ["region"], "outputs": ["bucket_id"],
    }

def test_docker_compose_parsing():
    compose_yaml = """
version: '3.8'
services:
  web_frontend:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - api_server
      
  api_server:
    image: myapp/api:v1
    environment:
      - DATABASE_URL=postgres://user:pass@db_postgres:5432/mydb
      - REDIS_URL=redis://cache_redis:6379/0
      
  db_postgres:
    image: postgres:14
    environment:
      - POSTGRES_PASSWORD=supersecret
      
  cache_redis:
    image: redis:alpine
"""
    parser = IaCParser()
    architecture = parser.parse(compose_yaml, format_hint='docker-compose')
    
    # 4 services = 4 components
    assert len(architecture.components) == 4
    
    # Check types
    web = next(c for c in architecture.components if c.id == 'web_frontend')
    api = next(c for c in architecture.components if c.id == 'api_server')
    db = next(c for c in architecture.components if c.id == 'db_postgres')
    cache = next(c for c in architecture.components if c.id == 'cache_redis')
    
    assert web.type == 'WebClient'
    assert api.type == 'API'
    assert db.type == 'Database'
    
    # Check properties
    assert web.properties.get('public_access') is True
    assert db.properties.get('secrets_in_env') is True
    
    
    # Check flows
    flows = architecture.flows
    web_targets = [f.target_id for f in flows if f.source_id == 'web_frontend']
    api_targets = [f.target_id for f in flows if f.source_id == 'api_server']

    assert 'api_server' in web_targets  # From depends_on
    assert 'db_postgres' in api_targets # From env var URL matching
    assert 'cache_redis' in api_targets # From env var URL matching

def test_kubernetes_parsing():
    k8s_yaml = """
apiVersion: v1
kind: Service
metadata:
  name: my-api-service
spec:
  type: LoadBalancer
  selector:
    app: my-api
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-api-deployment
spec:
  template:
    metadata:
      labels:
        app: my-api
    spec:
      containers:
      - name: api
        image: python-fastapi:latest
        securityContext:
          privileged: true
"""
    parser = IaCParser()
    architecture = parser.parse(k8s_yaml, format_hint='kubernetes')
    
    # Workloads and routing resources are modeled independently so findings
    # and data flows can point to the exact manifest object.
    assert len(architecture.components) == 2
    
    api = next(component for component in architecture.components if component.id == 'my-api-deployment')
    assert api.id == 'my-api-deployment'
    assert api.type == 'API'
    
    # Linked via service selector implicitly
    assert api.properties.get('containerized') is True
    assert any(flow.source_id == 'service.my-api-service' and flow.target_id == api.id for flow in architecture.flows)


def test_terraform_security_findings_include_critical_aws_misconfigurations():
    terraform = '''
resource "aws_s3_bucket" "uploads" {
  bucket = "customer-uploads"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_lambda_permission" "public" {
  action        = "lambda:InvokeFunction"
  function_name = "processor"
  principal     = "*"
}

resource "aws_security_group" "database" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "primary" {
  publicly_accessible = true
  storage_encrypted   = false
}
'''
    architecture = IaCParser().parse(terraform, format_hint='terraform')
    findings = architecture.metadata['iac_findings']
    rule_ids = {finding['rule_id'] for finding in findings}

    assert 'IAC-AWS-S3-PUBLIC-ACL' in rule_ids
    assert 'IAC-AWS-IAM-ADMIN' in rule_ids
    assert 'IAC-AWS-LAMBDA-PUBLIC-INVOKE' in rule_ids
    assert 'IAC-AWS-EC2-OPEN-SECURITY-GROUP' in rule_ids
    assert 'IAC-AWS-RDS-PUBLIC' in rule_ids

    result = ThreatAnalyzer().analyze(architecture, 'Terraform Critical Findings')
    assert any(threat.id.startswith('IAC-AWS-IAM-ADMIN') and threat.tier == 'Confirmed' for threat in result.threats)


def test_cloudformation_and_kubernetes_critical_findings_are_preserved():
    cloudformation = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: false
  PublicFunction:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: processor
      Principal: '*'
'''
    cfn_architecture = IaCParser().parse(cloudformation, format_hint='cloudformation')
    cfn_rules = {finding['rule_id'] for finding in cfn_architecture.metadata['iac_findings']}
    assert {'IAC-AWS-RDS-PUBLIC', 'IAC-AWS-RDS-NO-ENCRYPTION', 'IAC-AWS-LAMBDA-PUBLIC-INVOKE'} <= cfn_rules

    kubernetes = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: processor
spec:
  template:
    metadata:
      labels:
        app: processor
    spec:
      hostNetwork: true
      containers:
        - name: processor
          image: example/processor:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
'''
    k8s_architecture = IaCParser().parse(kubernetes, format_hint='kubernetes')
    k8s_rules = {finding['rule_id'] for finding in k8s_architecture.metadata['iac_findings']}
    assert {'IAC-K8S-HOST-NAMESPACE', 'IAC-K8S-PRIVILEGED-CONTAINER', 'IAC-K8S-PRIV-ESCALATION'} <= k8s_rules


def test_terraform_s3_companion_resources_are_matched_per_bucket():
    terraform = '''
resource "aws_s3_bucket" "secure" { bucket = "secure" }
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket" "unprotected" { bucket = "unprotected" }
'''
    architecture = IaCParser().parse(terraform, 'terraform')
    findings = architecture.metadata['iac_findings']
    keys = {(finding['rule_id'], finding['resource_id']) for finding in findings}

    assert ('IAC-AWS-S3-MISSING-PAB', 'aws_s3_bucket.secure') not in keys
    assert ('IAC-AWS-S3-NO-VERSIONING', 'aws_s3_bucket.secure') not in keys
    assert ('IAC-AWS-S3-MISSING-PAB', 'aws_s3_bucket.unprotected') in keys
    assert ('IAC-AWS-S3-NO-VERSIONING', 'aws_s3_bucket.unprotected') in keys
    assert not any(rule_id == 'IAC-AWS-S3-NO-ENCRYPTION' for rule_id, _ in keys)

    result = ThreatAnalyzer().analyze(architecture, 'S3 Relationship Review')
    absence_findings = [threat for threat in result.threats if threat.id.startswith('IAC-AWS-S3-MISSING-PAB')]
    assert absence_findings
    assert all(threat.tier == 'Potential' for threat in absence_findings)


def test_terraform_aws_azure_and_gcp_extended_controls_are_detected():
    terraform = '''
resource "aws_cloudtrail" "audit" {
  enable_logging = false
  enable_log_file_validation = false
}
resource "aws_ecr_repository" "images" {
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = false }
}
resource "azurerm_storage_account" "uploads" {
  allow_nested_items_to_be_public = true
  min_tls_version = "TLS1_0"
}
resource "azurerm_key_vault" "keys" {
  purge_protection_enabled = false
  public_network_access_enabled = true
}
resource "google_compute_firewall" "admin" {
  source_ranges = ["0.0.0.0/0"]
  allow { protocol = "tcp" ports = ["22"] }
}
resource "google_sql_database_instance" "orders" {
  settings {
    ip_configuration {
      ipv4_enabled = true
      require_ssl = false
      authorized_networks { value = "0.0.0.0/0" }
    }
  }
}
'''
    architecture = IaCParser().parse(terraform, 'terraform')
    rules = {finding['rule_id'] for finding in architecture.metadata['iac_findings']}

    assert {
        'IAC-AWS-CLOUDTRAIL-DISABLED',
        'IAC-AWS-CLOUDTRAIL-NO-VALIDATION',
        'IAC-AWS-ECR-SCAN-DISABLED',
        'IAC-AWS-ECR-MUTABLE-TAGS',
        'IAC-AZURE-STORAGE-PUBLIC-BLOBS',
        'IAC-AZURE-STORAGE-LEGACY-TLS',
        'IAC-AZURE-KV-NO-PURGE-PROTECTION',
        'IAC-AZURE-KV-PUBLIC-NETWORK',
        'IAC-GCP-FIREWALL-INTERNET-INGRESS',
        'IAC-GCP-SQL-PUBLIC',
        'IAC-GCP-SQL-NO-TLS',
    } <= rules
    assert {component.properties.get('cloud_provider') for component in architecture.components} >= {'aws', 'azure', 'gcp'}


def test_kubernetes_list_cronjob_rbac_ingress_and_secret_controls():
    manifest = '''
apiVersion: v1
kind: List
items:
- apiVersion: batch/v1
  kind: CronJob
  metadata: {name: importer}
  spec:
    jobTemplate:
      spec:
        template:
          spec:
            restartPolicy: Never
            automountServiceAccountToken: true
            volumes: [{name: host, hostPath: {path: /}}]
            containers:
            - name: importer
              image: repo/importer:latest
              securityContext: {runAsUser: 0, capabilities: {add: [SYS_ADMIN]}}
              env: [{name: API_TOKEN, value: hardcoded-secret-value}]
- apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata: {name: importer}
  spec: {rules: [{host: importer.example.com, http: {paths: []}}]}
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata: {name: importer-admin}
  roleRef: {kind: ClusterRole, name: cluster-admin}
  subjects: [{kind: ServiceAccount, name: default, namespace: default}]
- apiVersion: v1
  kind: Secret
  metadata: {name: importer-secret}
  stringData: {token: plaintext-secret}
'''
    architecture = IaCParser().parse(manifest, 'kubernetes')
    findings = architecture.metadata['iac_findings']
    rules = {finding['rule_id'] for finding in findings}

    assert {
        'IAC-K8S-AUTOMOUNT-TOKEN',
        'IAC-K8S-HOSTPATH',
        'IAC-K8S-RUN-AS-ROOT',
        'IAC-K8S-DANGEROUS-CAPABILITY',
        'IAC-K8S-HARDCODED-SECRET',
        'IAC-K8S-INGRESS-NO-TLS',
        'IAC-K8S-CLUSTER-ADMIN-BINDING',
        'IAC-K8S-SECRET-IN-MANIFEST',
    } <= rules
    assert any(finding['resource_id'] == 'ingress.importer' for finding in findings)
    assert any(component.id == 'ingress.importer' for component in architecture.components)
    assert any(component.id == 'clusterrolebinding.importer-admin' for component in architecture.components)


def test_compose_host_escape_secrets_and_public_data_port_are_detected():
    compose = '''
services:
  api:
    image: example/api:latest
    user: root
    cap_add: [SYS_ADMIN]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
    environment: {API_TOKEN: hardcoded-secret-value}
  database:
    image: postgres:latest
    ports: ["0.0.0.0:5432:5432"]
'''
    findings = IaCParser().parse(compose, 'docker-compose').metadata['iac_findings']
    rules = {finding['rule_id'] for finding in findings}
    assert {
        'IAC-COMPOSE-RUN-AS-ROOT',
        'IAC-COMPOSE-DANGEROUS-CAPABILITY',
        'IAC-COMPOSE-DOCKER-SOCKET',
        'IAC-COMPOSE-HOST-MOUNT',
        'IAC-COMPOSE-HARDCODED-SECRET',
        'IAC-COMPOSE-PUBLIC-SENSITIVE-PORT',
    } <= rules


def test_compose_wildcard_cors_default_is_detected_without_treating_interpolation_as_a_secret():
    compose = '''
services:
  api:
    build: .
    environment:
      - ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-*}
      - API_TOKEN=${API_TOKEN}
'''
    findings = IaCParser().parse(compose, 'docker-compose').metadata['iac_findings']
    rules = {finding['rule_id'] for finding in findings}

    assert 'IAC-COMPOSE-CORS-WILDCARD' in rules
    assert 'IAC-COMPOSE-HARDCODED-SECRET' not in rules


def test_cloudformation_intrinsic_tags_and_rule_provenance_are_preserved():
    template = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AuditTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      S3BucketName: !Ref AuditBucket
      IsLogging: false
      EnableLogFileValidation: false
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${AWS::StackName}-admin'
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {AWS: '*'}, Action: 'sts:AssumeRole'}]
      Policies:
      - PolicyName: admin
        PolicyDocument:
          Statement: [{Effect: Allow, Action: '*', Resource: '*'}]
'''
    findings = IaCParser().parse(template, 'cloudformation').metadata['iac_findings']
    rules = {finding['rule_id'] for finding in findings}
    assert {'IAC-AWS-CLOUDTRAIL-DISABLED', 'IAC-AWS-CLOUDTRAIL-NO-VALIDATION', 'IAC-AWS-IAM-ADMIN', 'IAC-AWS-IAM-PUBLIC-TRUST'} <= rules
    for finding in findings:
        assert finding['owasp_top_10']
        assert finding['nist_800_53']
        assert finding['references']
        assert finding['rule_metadata']['catalog_version']

if __name__ == '__main__':
    print("Running IaC parsing tests...")
    test_docker_compose_parsing()
    print("Docker Compose parsing: PASSED")
    test_kubernetes_parsing()
    print("Kubernetes parsing: PASSED")
    print("All tests passed.")
