"""Inspect submitted Terraform plan JSON without running Terraform or providers."""

from typing import Any

from app.models import Component, SystemArchitecture


CHECKS = (
    ('aws_db_instance', ('storage_encrypted',), False, 'IAC-AWS-RDS-NO-ENCRYPTION', 'Enable storage encryption with an approved key.'),
    ('aws_db_instance', ('backup_retention_period',), 0, 'IAC-AWS-RDS-NO-BACKUP', 'Enable and test automated backups.'),
    ('aws_db_instance', ('publicly_accessible',), True, 'IAC-AWS-RDS-PUBLIC', 'Review subnet routing and ingress; prefer a private database endpoint.'),
    ('aws_instance', ('metadata_options', 'http_tokens'), 'optional', 'IAC-AWS-EC2-IMDSV1', 'Require IMDSv2 tokens and restrict metadata hop limits.'),
    ('aws_instance', ('root_block_device', 'encrypted'), False, 'IAC-AWS-EC2-UNENCRYPTED-EBS', 'Encrypt root and data volumes.'),
    ('aws_lambda_function_url', ('authorization_type',), 'NONE', 'IAC-AWS-LAMBDA-URL-PUBLIC', 'Require IAM authorization or a separately authenticated ingress.'),
    ('aws_kms_key', ('enable_key_rotation',), False, 'IAC-AWS-KMS-ROTATION-DISABLED', 'Enable supported key rotation and define a revocation process.'),
    ('aws_s3_bucket', ('acl',), 'public-read', 'IAC-AWS-S3-PUBLIC-ACL', 'Remove public ACLs and verify effective public-access block controls.'),
    ('aws_s3_bucket', ('acl',), 'public-read-write', 'IAC-AWS-S3-PUBLIC-ACL', 'Remove public ACLs and verify effective public-access block controls.'),
    ('azurerm_storage_account', ('min_tls_version',), 'TLS1_0', 'IAC-AZURE-STORAGE-LEGACY-TLS', 'Require TLS 1.2 or later.'),
    ('google_sql_database_instance', ('settings', 'ip_configuration', 'require_ssl'), False, 'IAC-GCP-SQL-NO-TLS', 'Require encrypted database client connections.'),
)


def at(value: Any, path: tuple):
    for key in path:
        if isinstance(value, list):
            value = value[0] if value else None
        value = value.get(key) if isinstance(value, dict) else None
    return value


def resources(module: dict, depth: int = 0):
    if depth > 32:
        raise ValueError('Terraform plan module nesting exceeds 32 levels.')
    yield from (item for item in module.get('resources', []) if isinstance(item, dict) and item.get('mode', 'managed') == 'managed')
    for child in module.get('child_modules', []):
        yield from resources(child, depth + 1)


def unknown_paths(value: Any, prefix: str = '') -> list[str]:
    if value is True:
        return [prefix]
    if isinstance(value, dict):
        return [path for key, child in value.items() for path in unknown_paths(child, f'{prefix}.{key}'.strip('.'))]
    if isinstance(value, list):
        return [path for index, child in enumerate(value) for path in unknown_paths(child, f'{prefix}.{index}')]
    return []


def parse_plan(document: dict, analyzer) -> SystemArchitecture:
    root = (document.get('planned_values') or {}).get('root_module')
    if not isinstance(root, dict):
        raise ValueError('Terraform plan JSON must contain planned_values.root_module.')
    rows = list(resources(root))
    if len(rows) > 5000:
        raise ValueError('Terraform plan exceeds the 5000-resource analysis limit.')
    changes = {item.get('address'): item.get('change', {}) for item in document.get('resource_changes', []) if isinstance(item, dict)}
    components, findings, unresolved = [], [], []
    for row in rows:
        resource_id, resource_type = row.get('address'), row.get('type', '')
        if not resource_id:
            raise ValueError('Every Terraform plan resource requires an address.')
        fields = row.get('values') or {}
        unknown_tree = changes.get(resource_id, {}).get('after_unknown', {})
        unknown = unknown_paths(unknown_tree)

        def is_unknown(path):
            return '' in unknown or at(unknown_tree, path) is True or any(
                '.'.join(path) == key or '.'.join(path).startswith(key + '.') for key in unknown
            )
        unresolved.extend({'resource_id': resource_id, 'property': path, 'reason': 'unknown_until_apply'} for path in unknown)
        component_type = 'Database' if any(word in resource_type for word in ('db_instance', 'sql_database', 'database')) else 'Object Storage' if 'bucket' in resource_type or 'storage_account' in resource_type else 'Secrets Manager' if 'kms' in resource_type else 'API' if 'gateway' in resource_type else 'Service'
        properties = {'authoritative': True, 'deployment': 'terraform-plan', 'iac_resource_type': resource_type,
            'cloud_provider': {'aws': 'aws', 'azurerm': 'azure', 'google': 'gcp'}.get(resource_type.split('_')[0], ''),
            'unresolved_properties': unknown, 'source_locator': f'planned_values:{resource_id}'}
        components.append(Component(id=resource_id, name=row.get('name') or resource_id, type=component_type, properties=properties, confidence='High'))
        for expected_type, path, insecure, rule_id, mitigation in CHECKS:
            value = at(fields, path)
            if resource_type != expected_type or value is None or type(value) is not type(insecure) or value != insecure:
                continue
            # A contradictory supplied plan is not made authoritative by its JSON shape.
            if is_unknown(path):
                continue
            rule = analyzer.rule_catalog.get(rule_id)
            if rule is None:
                raise RuntimeError(f'Unknown Terraform-plan check: {rule_id}')
            description = f"Resolved plan value {'.'.join(path)} is {value!r}. This is submitted configuration, not a live deployment verification."
            finding = analyzer._finding(rule_id, resource_id, None, rule['severity'], rule['title'], description, mitigation, rule['category'], rule['cwe'][0])
            finding['locator'] = f"planned_values:{resource_id}:{'.'.join(path)}"
            findings.append(finding)
        for key in ('policy', 'assume_role_policy'):
            if fields.get(key) and not is_unknown((key,)):
                findings.extend(analyzer._analyze_policy_text(fields[key], resource_id, None))
    return SystemArchitecture(components=components, flows=[], metadata={
        'source': 'terraform-plan', 'terraform_parser': {'mode': 'resolved_plan_json', 'available': True},
        'iac_findings': analyzer._deduplicate(findings), 'unresolved_references': unresolved,
        'analysis_limits': ['A plan is not proof of the applied deployment.', 'Dependency references are not automatically data flows.', 'Only documented plan checks are executable; source checks have broader coverage.'],
        'iac_findings_count': len(analyzer._deduplicate(findings)),
    })
