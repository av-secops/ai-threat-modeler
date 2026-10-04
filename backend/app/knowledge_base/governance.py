"""Rule governance reports engineering coverage separately from human approval."""

from collections import Counter
import hashlib
import json
from urllib.parse import urlparse


REMEDIATIONS = {
    'missing_primary_reference': ('source_review', 'Record a primary source URL and the exact section supporting this rule.'),
    'missing_verification': ('verification', 'Add a scoped acceptance check and the evidence required to demonstrate the control.'),
    'missing_counterexamples': ('false_positive_control', 'Describe protected, out-of-scope and unknown-control counterexamples.'),
    'missing_executable_test_contract': ('regression_coverage', 'Add executable positive and negative fixtures; do not count retrieval matches as detection.'),
    'invalid_test_contract': ('regression_coverage', 'Repair the fixture fields and declare every required control-state case.'),
    'unversioned_source': ('source_review', 'Record the source edition or living-document snapshot date.'),
    'independent_review_not_recorded': ('human_review', 'Obtain a named content-bound review; engineering-generated fixtures are not independent review.'),
    'category_fallback_mapping': ('taxonomy_review', 'Review each STRIDE-derived mapping against the actual weakness or explicitly leave it unmapped.'),
    'unresolved_framework_mapping': ('taxonomy_review', 'Resolve the framework version and exact identifier; never guess a replacement identifier.'),
    'unsupported_predicate': ('implementation', 'Implement an authoritative property producer and supported predicate or retain retrieval-only status.'),
}


def contract_errors(rule):
    """Validate the current single-control fixture without inventing test coverage."""
    fixture = rule.get('test_contract')
    if not fixture:
        return []
    if not isinstance(fixture, dict):
        return ['test_contract must be an object']
    errors = []
    for key in ('control', 'component_type', 'component_name'):
        if not isinstance(fixture.get(key), str) or not fixture[key].strip():
            errors.append(f'{key} must be a non-empty string')
    if not isinstance(fixture.get('properties', {}), dict):
        errors.append('properties must be an object')
    cases = fixture.get('cases')
    required = {'positive', 'protected', 'unknown', 'conflicting', 'planned', 'partial', 'wrong_scope'}
    if not isinstance(cases, list) or any(not isinstance(case, str) for case in cases) or set(cases) != required:
        errors.append('cases must declare all seven supported control states')
    if not (rule.get('detection') or {}).get('auto_detectable'):
        errors.append('single-control contracts require an executable rule')
    return errors

# Changes to the bundled catalog are code-reviewed repository changes. Merely
# copying a new JSON file into this directory must not activate an imported pack.
BUNDLED_MODULES = frozenset({
    'ai_agent_threats.json', 'auth_authz_threats.json', 'cloud_aws_threats.json',
    'cloud_azure_threats.json', 'cloud_gcp_threats.json', 'container_k8s_threats.json',
    'context_specific_controls.json', 'custom_ai_llm_threats.json', 'data_pipeline_threats.json',
    'database_threats.json', 'domain_threats.json', 'emerging_threats.json',
    'enterprise_product_controls.json', 'enterprise_review_patterns.json', 'evidence_scoped_controls.json',
    'identity_zero_trust_threats.json', 'infrastructure_threats.json', 'owasp_api_top10.json',
    'owasp_web_top10.json', 'professional_threat_catalog.json', 'rag_vector_store_threats.json',
    'secrets_management_threats.json', 'serverless_threats.json', 'supply_chain_threats.json', 'threats.json',
})


def review_digest(rule):
    content = {k: v for k, v in rule.items() if k not in {
        '_source_module', 'approval', 'lifecycle', 'review_status', 'last_reviewed'}}
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def quarantine_reason(rule):
    if rule.get('lifecycle', 'active') != 'active':
        return 'Rule is not active.'
    if rule.get('origin') == 'external':
        approval = rule.get('approval') if isinstance(rule.get('approval'), dict) else {}
        if not approval.get('reviewer') or not approval.get('reviewed_at') or approval.get('content_digest') != review_digest(rule):
            return 'External rule requires a named, content-bound approval.'
    return None


def audit_contracts(rules):
    issues, counts = [], Counter()
    for rule in rules:
        executable = bool(rule.get('detection', {}).get('auto_detectable'))
        counts['executable' if executable else 'retrieval_only'] += 1
        if (rule.get('curation') or {}).get('version') == 'legacy-curation-1':
            counts['legacy_rules_source_curated'] += 1
        gaps = []
        if not any(isinstance(ref, str) and urlparse(ref).scheme == 'https' and urlparse(ref).hostname
                   for ref in rule.get('references') or []):
            gaps.append('missing_primary_reference')
        if not rule.get('verification'):
            gaps.append('missing_verification')
        if not rule.get('counterexamples'):
            gaps.append('missing_counterexamples')
        if not rule.get('test_contract'):
            gaps.append('missing_executable_test_contract')
        fixture_errors = contract_errors(rule)
        if fixture_errors:
            gaps.append('invalid_test_contract')
        if not rule.get('source_version'):
            gaps.append('unversioned_source')
        approved = rule.get('approval') if isinstance(rule.get('approval'), dict) else {}
        if not approved.get('reviewer') or not approved.get('reviewed_at') or approved.get('content_digest') != review_digest(rule.get('raw') or rule):
            gaps.append('independent_review_not_recorded')
        else:
            counts['content_bound_reviews'] += 1
        if 'stride_category_fallback' in (rule.get('taxonomy_mapping_quality') or {}).values():
            gaps.append('category_fallback_mapping')
        if rule.get('framework_mapping_issues'):
            gaps.append('unresolved_framework_mapping')
        if (rule.get('predicate_support') or {}).get('unsupported_reasons'):
            gaps.append('unsupported_predicate')
        for gap in gaps:
            counts[gap] += 1
        if rule.get('test_contract') and not fixture_errors:
            counts['contract_testable'] += 1
        if gaps:
            issues.append({'rule_id': rule['id'], 'module': rule.get('source_module'),
                'rule_kind': 'deterministic' if executable else 'candidate', 'gaps': gaps,
                'contract_errors': fixture_errors,
                'actions': [{'code': code, 'workstream': REMEDIATIONS[code][0], 'action': REMEDIATIONS[code][1],
                    'priority': 'high' if executable or code == 'unresolved_framework_mapping' else 'normal'} for code in gaps]})
    return {'counts': dict(counts), 'issues': issues, 'independent_accuracy_established': False,
        'reference_presence_is_not_source_verification': True,
        'workstreams': dict(Counter(action['workstream'] for issue in issues for action in issue['actions'])),
        'policy': 'Rule fixtures check implementation, not independent threat-model recall. External imports require content-bound approval.'}
