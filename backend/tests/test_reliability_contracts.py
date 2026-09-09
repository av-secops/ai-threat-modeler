from app.engine.issue_inventory import extract_issues, dispositions
from app.engine.control_statements import read
from app.engine.parser import ArchitectureParser
from app.engine.structured_local_slm import StructuredLocalSLM
from app.models import Component, SystemArchitecture


def test_declared_markdown_table_and_alternative_heading():
    text = '## Security weaknesses\n| ID | Description | Remediation |\n|---|---|---|\n| K1 | API has no rate limiting | Add throttling |\n## Controls\nAPI uses TLS'
    issues = extract_issues(text)
    assert len(issues) == 1 and issues[0]['statement'] == 'API has no rate limiting'
    assert len(ArchitectureParser().parse_known_issues(text)) == 1


def test_issue_identity_survives_reordering_and_ledger_detects_missing_parser_issue():
    first = 'Known issues:\n- API lacks MFA\n- API lacks rate limiting'
    second = 'Known issues:\n- API lacks rate limiting\n- API lacks MFA'
    assert {i['id'] for i in extract_issues(first)} == {i['id'] for i in extract_issues(second)}
    architecture = SystemArchitecture(components=[], flows=[], metadata={'source_text': first, 'known_issues': []})
    assert dispositions(architecture, [])['unaccounted'] == 2


def test_explanatory_comparisons_do_not_establish_control_polarity():
    for text in ['CloudTrail is not a complete substitute for application audit logging.',
                 'Neither WAF nor encryption at rest proves tenant authorization.']:
        assert not read(text).denied and not read(text).affirmed


def test_local_model_rejects_malformed_and_wrong_subject_evidence():
    architecture = SystemArchitecture(components=[Component(id='api', name='API', type='API')], flows=[])
    accepted, rejected = StructuredLocalSLM.validate_candidates([None, {'element_id': 'api', 'stride_category': 'Spoofing',
        'evidence': ['Database has no authentication']}], architecture, 'Database has no authentication',
        [{'element_id': 'api', 'category': 'Spoofing'}])
    assert accepted == [] and rejected == 2
