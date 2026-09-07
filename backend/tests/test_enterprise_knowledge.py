"""New rules must survive ingestion, enforce evidence boundaries and keep citations."""

from copy import deepcopy

import pytest

from app.engine.control_statements import CONTROL_TERMS, read
from app.engine.analyzer import ThreatAnalyzer
from app.engine.knowledge_threat_engine import KnowledgeThreatEngine
from app.engine.parser import ArchitectureParser
from app.engine.retrieval_quality import rule_provenance
from app.knowledge_base.frameworks import coverage_report, registry, resolve_mappings, rule_mappings
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Component, SystemArchitecture


KB = ThreatKnowledgeBase()
RULES = [rule for rule in KB.threats if rule['source_module'] == 'enterprise_product_controls.json']
ENGINE = KnowledgeThreatEngine(KB)


@pytest.mark.parametrize('rule', RULES, ids=lambda rule: rule['id'])
@pytest.mark.parametrize('state', ['absent', 'present', 'unknown', 'uncertain', 'conflicting', 'wrong_type'])
def test_enterprise_predicate_evidence_contract(rule, state):
    field = rule['detection']['logic']['conditions'][0]['field']
    props = {'cloud_provider': (rule.get('cloud_platform') or [''])[0].lower()}
    if state != 'unknown':
        props[field] = True if state == 'present' else 'unknown' if state == 'uncertain' else False
    if state == 'conflicting':
        props['control_assertions'] = {field: 'conflicting'}
    component = Component(id='subject', name='Subject', type='Unrelated Device' if state == 'wrong_type' else rule['components'][0], confidence='High', properties=props)
    findings, _ = ENGINE.analyze(SystemArchitecture(components=[component], flows=[]))
    matched = [item for item in findings if item.id == f"KB-{rule['id']}-subject"]
    assert bool(matched) is (state == 'absent')
    assert rule['rule_kind'] == 'deterministic'
    assert rule['verification'] and rule['references']
    assert not rule['framework_mapping_issues']
    if matched:
        assert matched[0].explanation['matched_controls'] == [field]
        assert matched[0].explanation['framework_mappings'] == rule['framework_mappings']


@pytest.mark.parametrize('rule', RULES, ids=lambda rule: rule['id'])
def test_every_new_control_has_a_case_insensitive_prose_producer(rule):
    field = rule['detection']['logic']['conditions'][0]['field']
    phrase = CONTROL_TERMS[field][0]
    assert read(f'The component has no {phrase.upper()}.').value(field) is False
    assert read(f'The component enforces {phrase.upper()}.').value(field) is True
    assert read('The component was deployed yesterday.').value(field) is None


@pytest.mark.parametrize('name,expected', [
    ('ASP.NET Core', 'API'), ('Jenkins', 'CI/CD'), ('GitLab CI', 'CI/CD'),
    ('Azure Pipelines', 'CI/CD'), ('Google Compute Engine', 'Compute'),
    ('PingFederate', 'Identity Provider'), ('Android app', 'Mobile App'),
    ('JFrog Artifactory', 'Container Registry'),
])
def test_enterprise_technologies_reach_the_correct_rule_family(name, expected):
    architecture = ArchitectureParser().parse(f'The product uses {name}.')
    assert expected in {item.type for item in architecture.components}


def test_aws_customer_binding_is_not_applied_to_an_azure_identity():
    component = Component(id='identity', name='Entra ID', type='Identity Provider', confidence='High',
                          properties={'cloud_provider': 'azure', 'cross_account_external_id': False})
    findings, _ = ENGINE.analyze(SystemArchitecture(components=[component], flows=[]))
    assert not any(item.id.startswith('KB-ENT-CLOUD-EXTERNAL-ID-') for item in findings)


@pytest.mark.parametrize('text,rule_id', [
    ('Node.js API has no parameterized queries.', 'ENT-WEB-QUERY'),
    ('Keycloak has no OAuth PKCE.', 'ENT-IDENTITY-PKCE'),
    ('Node.js API has no tenant cache isolation.', 'ENT-SAAS-CACHE'),
    ('GitHub Actions has no untrusted build isolation.', 'ENT-SUPPLY-RUNNER'),
    ('Kubernetes has no pod security enforcement.', 'ENT-K8S-ADMISSION'),
    ('AWS KMS has no key deletion protection.', 'ENT-CLOUD-KEY-DELETE'),
    ('An OpenAI agent has no agent resource budget.', 'ENT-AI-BUDGET'),
    ('The MCP server has no MCP tool definition integrity.', 'ENT-AI-TOOLS'),
    ('The IoT device has no verified boot.', 'ENT-DEVICE-BOOT'),
])
def test_prose_reaches_the_real_knowledge_engine(text, rule_id):
    findings, _ = ENGINE.analyze(ArchitectureParser().parse(text))
    assert any(item.id.startswith(f'KB-{rule_id}-') for item in findings)


def test_new_technology_hypotheses_are_grounded_but_not_executable():
    architecture = ArchitectureParser().parse('A native parser handles documents. An Android app calls the parser.')
    assert {'Native Service', 'Mobile App'} <= {item.type for item in architecture.components}
    assert all(item['rule_kind'] == 'candidate' for item in KB.threats if item['source_module'] == 'enterprise_review_patterns.json')
    findings, _ = ENGINE.analyze(architecture)
    assert not any(item.id.startswith('KB-ENT-NATIVE') for item in findings)


def test_framework_registry_and_curated_overlay_have_no_orphans():
    assert set(rule_mappings()) <= set(KB.threats_by_id)
    assert not [issue for issue in KB.validation_issues if 'framework' in issue['issue'].lower()]
    assert registry()['sources'] and all(len(item['sha256']) == 64 for item in registry()['sources'])
    report = coverage_report(KB.threats)
    for framework in ('owasp_web', 'owasp_api', 'owasp_llm', 'owasp_agentic'):
        assert not report['frameworks'][framework]['unmapped_ids']


def test_versions_do_not_relabel_old_category_numbers():
    mappings, issues = resolve_mappings({'cwe': ['CWE-918'], 'owasp_top_10': ['A10:2021']})
    assert not issues
    assert any(item['framework'] == 'owasp_web' and item['version'] == '2025' and item['id'] == 'A01' for item in mappings)
    assert not any(item['framework'] == 'owasp_web' and item['id'] == 'A10' for item in mappings)
    assert any(item['id'] == 'LLM06' and item['version'] == '2026' for item in KB.get_by_id('AI-007')['framework_mappings'])


def test_unknown_versions_and_techniques_are_diagnosed_not_invented():
    mappings, issues = resolve_mappings({'framework_mappings': [
        {'framework': 'owasp_web', 'version': '2021', 'id': 'A01'},
        {'framework': 'mitre_atlas', 'version': '2026.08', 'id': 'AML.T9999'},
    ]})
    assert mappings == [] and len(issues) == 2
    mappings, _ = resolve_mappings({'cwe': ['CWE-89'], 'taxonomy_mapping_quality': {'cwe': 'stride_category_fallback'}})
    assert mappings == []


def test_control_changes_invalidate_derived_index_provenance():
    rule = deepcopy(RULES[0])
    before = rule_provenance(rule)['content_digest']
    rule['detection']['logic']['conditions'][0]['value'] = True
    assert rule_provenance(rule)['content_digest'] != before


def test_public_ai_and_missing_logging_do_not_prove_attacks():
    architecture = SystemArchitecture(components=[Component(id='model', name='Model', type='ML Service', confidence='High',
        properties={'ml_pipeline': True, 'public_access': True, 'logging_enabled': False, 'input_validation': False})], flows=[])
    findings, _ = ENGINE.analyze(architecture)
    assert not any(item.id.startswith(('KB-AI-001-', 'KB-AI-002-', 'KB-AI-004-', 'KB-AI-005-')) for item in findings)
    architecture.components[0].properties['training_data_validation'] = False
    findings, _ = ENGINE.analyze(architecture)
    assert any(item.id == 'KB-AI-005-model' for item in findings)
    architecture.components[0].properties['training_data_validation'] = True
    findings, _ = ENGINE.analyze(architecture)
    assert not any(item.id == 'KB-AI-005-model' for item in findings)


@pytest.mark.parametrize('description,expected', [
    ('A multi-tenant SaaS has a React frontend, Node.js API, Keycloak and PostgreSQL. '
     'React calls Node.js over HTTPS. Node.js reads PostgreSQL over TLS. '
     'Node.js API has no tenant-scoped cache keys. Node.js API has no function-level authorization. '
     'Keycloak has no PKCE. GitHub Actions has no isolated build runners.',
     ['ENT-SAAS-CACHE', 'ENT-SAAS-FUNCTION', 'ENT-IDENTITY-PKCE', 'ENT-SUPPLY-RUNNER']),
    ('An AWS product uses CloudFront, WAF, EC2, Node.js, AWS KMS and PostgreSQL. '
     'EC2 has no origin access restriction. AWS KMS has no key deletion protection. '
     'PostgreSQL has no restore authorization.',
     ['ENT-CLOUD-ORIGIN', 'ENT-CLOUD-KEY-DELETE', 'ENT-DATA-RESTORE']),
    ('An OpenAI agent uses a GitHub MCP server to process customer support tickets. '
     'OpenAI has no agent resource budget. OpenAI has no agent memory integrity. '
     'OpenAI has no sandboxed tool execution. The GitHub MCP server has no MCP tool definition integrity.',
     ['ENT-AI-BUDGET', 'ENT-AI-MEMORY', 'ENT-AI-SANDBOX', 'ENT-AI-TOOLS']),
])
def test_enterprise_findings_survive_the_complete_report_pipeline(description, expected):
    result = ThreatAnalyzer().analyze_from_text(description, 'Enterprise KB regression', use_local_slm=False)
    for identifier in expected:
        matches = [item for item in result.threats if item.id.startswith(f'KB-{identifier}-')]
        assert matches, (identifier, [(item.id, item.title) for item in result.threats])
        assert all(item.explanation.get('framework_mappings') for item in matches)
    assert len({item.id for item in result.threats}) == len(result.threats)
    assert all(item.affected_component in {component.id for component in result.architecture.components}
               for item in result.threats if item.affected_component)
