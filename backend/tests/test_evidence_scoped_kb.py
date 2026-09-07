import pytest

from app.engine.knowledge_threat_engine import KnowledgeThreatEngine
from app.engine.known_issue_taxonomy import classify_generic_weaknesses
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Component, SystemArchitecture


KB = ThreatKnowledgeBase()
NEW_RULES = [rule for rule in KB.get_all_threats() if rule['source_module'] == 'evidence_scoped_controls.json']


@pytest.mark.parametrize('rule', NEW_RULES, ids=lambda rule: rule['id'])
@pytest.mark.parametrize('state', ['absent', 'present', 'unknown', 'conflicting'])
def test_every_new_rule_has_four_evidence_states(rule, state):
    field = rule['detection']['logic']['conditions'][0]['field']
    properties = {'cloud_provider': (rule.get('cloud_platform') or [''])[0].lower()}
    if state != 'unknown':
        properties[field] = state == 'present'
    if state == 'conflicting':
        properties['control_assertions'] = {field: 'conflicting'}
    component = Component(id='subject', name='Subject', type=rule['components'][0], confidence='High', properties=properties)
    threats, _ = KnowledgeThreatEngine(KB).analyze(SystemArchitecture(components=[component], flows=[]))
    matching = [threat for threat in threats if threat.id == f"KB-{rule['id']}-subject"]
    assert bool(matching) is (state == 'absent')
    assert rule['verification'] and rule['references']
    assert set(rule['taxonomy_mapping_quality'].values()) == {'curated'}


@pytest.mark.parametrize('text,expected', [
    ('Tenant identifiers from requests are trusted without checking the authenticated tenant.', 'GENERIC-TENANT-ISOLATION-001'),
    ('A public S3 bucket stores invoices.', 'GENERIC-PUBLIC-EXPOSURE-001'),
    ('EC2 instances do not require IMDSv2.', 'GENERIC-IMDSV2-001'),
    ('Refund tool calls have no human approval.', 'GENERIC-APPROVAL-BYPASS-001'),
    ('GitHub Actions accepts fork PRs with write permissions.', 'GENERIC-CI-UNTRUSTED-WRITE-001'),
])
def test_previous_unclassified_issues(text, expected):
    assert expected in {rule['id'] for rule in classify_generic_weaknesses(text)}
