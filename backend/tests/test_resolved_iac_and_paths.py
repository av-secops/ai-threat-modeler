import json

from app.engine.iac_parser import IaCParser
from app.engine.attack_path_engine import _permission_state
from app.models import Component, DataFlow


def test_plan_uses_resolved_values_and_reports_unknowns():
    plan = {'format_version': '1.2', 'planned_values': {'root_module': {'resources': [
        {'address': 'module.records.aws_db_instance.db', 'name': 'db', 'type': 'aws_db_instance', 'values': {'storage_encrypted': False, 'publicly_accessible': None}},
    ]}}, 'resource_changes': [{'address': 'module.records.aws_db_instance.db', 'change': {'after_unknown': {'publicly_accessible': True}}}]}
    result = IaCParser().parse(json.dumps(plan))
    assert result.components[0].id == 'module.records.aws_db_instance.db'
    assert [finding['rule_id'] for finding in result.metadata['iac_findings']] == ['IAC-AWS-RDS-NO-ENCRYPTION']
    assert result.metadata['unresolved_references'][0]['property'] == 'publicly_accessible'
    assert result.flows == []


def test_permission_evidence_is_identity_action_and_resource_scoped():
    source = Component(id='api', name='API', type='API', properties={'iam_role': 'app-role'})
    target = Component(id='bucket', name='Bucket', type='Object Storage')
    flow = DataFlow(source_id='api', target_id='bucket', protocol='HTTPS', assumed=False,
        properties={'required_permissions': ['s3:GetObject'], 'authorization_evidence': {
            'identity': 'app-role', 'resource': 'bucket', 'actions': ['s3:GetObject'],
            'decision': 'allow', 'source_ref': 'policy:42',
        }})
    assert _permission_state(flow, source, target) == 'allowed'
    flow.properties['authorization_evidence']['resource'] = 'different-bucket'
    assert _permission_state(flow, source, target) == 'unknown'
    flow.properties['authorization_evidence']['resource'] = 'bucket'
    flow.properties['authorization_evidence']['decision'] = 'deny'
    assert _permission_state(flow, source, target) == 'denied'


def test_plan_unknown_nested_blocks_and_policy_do_not_emit_static_claims():
    plan = {'planned_values': {'root_module': {'resources': [
        {'address': 'aws_instance.app', 'type': 'aws_instance', 'values': {'root_block_device': [{'encrypted': False}]}},
        {'address': 'aws_iam_policy.app', 'type': 'aws_iam_policy', 'values': {'policy': '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}},
    ]}}, 'resource_changes': [
        {'address': 'aws_instance.app', 'change': {'after_unknown': {'root_block_device': [{'encrypted': True}]}}},
        {'address': 'aws_iam_policy.app', 'change': {'after_unknown': {'policy': True}}},
    ]}
    result = IaCParser().parse(json.dumps(plan))
    assert not result.metadata['iac_findings']
    assert len(result.metadata['unresolved_references']) == 2
