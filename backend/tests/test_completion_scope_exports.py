"""Integration regressions for source scoping and exported remediation contracts."""

import pytest

from app.engine.parser import ArchitectureParser
from app.engine.reporter import ReportGenerator
from app.models import AnalysisResult, Component, SystemArchitecture, Threat


@pytest.mark.parametrize('identifier,name,properties', [
    ('s3', 'S3', {}),
    ('invoices', 'Invoice storage', {'cloud_service': 's3'}),
])
def test_literal_s3_issue_does_not_expand_to_other_compatible_resources(identifier, name, properties):
    parser = ArchitectureParser()
    components = {item.id: item for item in [
        Component(id='aws_api_gateway', name='AWS API Gateway', type='API Gateway'),
        Component(id=identifier, name=name, type='Object Storage', properties=properties),
        Component(id='dynamodb', name='DynamoDB', type='Database'),
    ]}
    issue = parser._classify_known_issue('The S3 bucket is public and stores customer invoices.')
    linked, = parser._link_known_issues_to_components([issue], components)
    assert linked['component_hints'] == [identifier]
    assert linked['component_resolution'] in {'named_subject', 'literal_issue_evidence'}


def test_literal_technology_scope_precedes_broad_rule_scope():
    parser = ArchitectureParser()
    components = {item.id: item for item in [
        Component(id='orders', name='Orders API', type='API', properties={'technology': 'node.js'}),
        Component(id='billing', name='Billing API', type='API', properties={'technology': 'go'}),
    ]}
    linked, = parser._link_known_issues_to_components([{
        'description': 'Node.js concatenates user input into SQL queries.',
        'suggested_threat_id': 'WEB-SQL-INJECTION-ORDER-001',
    }], components)
    assert linked['component_hints'] == ['orders']


def test_subjectless_issue_retains_rule_scope_fallback():
    parser = ArchitectureParser()
    components = {'orders': Component(id='orders', name='Orders API', type='API')}
    linked, = parser._link_known_issues_to_components([{
        'description': 'User input is concatenated into SQL queries.',
        'suggested_threat_id': 'WEB-SQL-INJECTION-ORDER-001',
    }], components)
    assert linked['component_hints'] == ['orders']
    assert linked['component_resolution'] == 'rule_scope_match'


def test_markdown_exports_verification_criteria_without_claiming_execution():
    risk = Threat(id='sql', title='Unsafe query construction', category='Tampering',
        severity='High', description='Queries use untrusted input.', mitigation='Bind parameters.',
        explanation={'remediation_validation': {'criteria': [{
            'procedure': 'Review query parameter binding and run injection regression tests.',
            'acceptance_condition': 'Untrusted values remain bound parameters.',
            'required_evidence': ['Code review reference', 'Regression test result'],
        }]}})
    result = AnalysisResult(project_name='Export fixture', summary='Review required',
        threats=[risk], architecture=SystemArchitecture(components=[], flows=[]), score=50)
    markdown = '\n'.join(ReportGenerator._mitigations(result))
    assert 'Verification procedure (not performed)' in markdown
    assert 'Untrusted values remain bound parameters.' in markdown
    assert 'Code review reference; Regression test result' in markdown
