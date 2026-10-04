"""Report contracts for conditional reasoning, coverage and remediation review.

These are validation requirements, not executed tests or proof of protection.
"""

from collections import Counter
from copy import deepcopy
import hashlib
import json

from .control_contracts import CONTROL_ALIASES, presence


_CONTROL_CHECKS = {
    'parameterized_queries': ('Review every database call on the affected request path for bound parameters.',
        'Untrusted values remain data; query structure cannot be changed by user input.'),
    'object_level_auth': ('Test access to another user or tenant resource with a valid low-privilege identity.',
        'Cross-owner and cross-tenant requests are denied while permitted requests succeed.'),
    'function_level_authorization': ('Test each protected operation using permitted and prohibited roles.',
        'The server enforces the operation permission independently of the client interface.'),
    'mfa_enabled': ('Review identity-provider policy and test enrollment, recovery, and privileged sign-in.',
        'Required sign-in and recovery paths enforce the approved additional authentication factor.'),
    'rate_limiting': ('Review limits and run a bounded, authorized request-volume test for each protected route.',
        'The configured limit is enforced per intended principal/tenant without bypass through alternate ingress.'),
    'session_invalidation': ('Change a test account password and reuse previously issued session and refresh credentials.',
        'Previously issued credentials are rejected according to the documented revocation policy.'),
    'session_timeout': ('Verify configured idle and absolute session expiry with a controlled test account.',
        'Sessions stop authorizing access when the documented lifetime expires.'),
    'token_revocation': ('Revoke a test session or change its password, then reuse old access and refresh credentials.',
        'Previously issued credentials cannot authorize requests beyond the documented revocation window.'),
    'query_depth_limiting': ('Inspect GraphQL depth, cost, pagination and resolver execution limits with bounded test queries.',
        'Queries over the approved cost/depth budget are rejected before expensive resolver work.'),
    'tenant_isolation': ('Run read/write operations using two test tenants and tampered client-supplied tenant identifiers.',
        'Server-derived tenant scope prevents cross-tenant reads and writes, including background jobs and exports.'),
    'jwt_issuer_validation': ('Inspect token validation and submit a test token from an untrusted issuer.',
        'The service rejects tokens outside the configured issuer allowlist, independently of signature validity.'),
    'jwt_audience_validation': ('Submit a valid test token intended for a different relying service.',
        'The service rejects tokens whose audience does not include that service.'),
    'transport_encryption': ('Review the actual endpoint, TLS termination, and each subsequent network hop.',
        'Sensitive traffic is protected on all required hops; invalid certificates and disallowed plaintext are rejected.'),
    'encryption_at_rest': ('Inspect the affected resource encryption configuration and key access policy.',
        'The identified resource and its backups use the approved encryption and restricted key access.'),
    'logging_enabled': ('Perform a permitted and rejected sensitive action and inspect redacted audit events.',
        'Events include actor, target, outcome and time without exposing secrets or prohibited personal data.'),
    'webhook_signature_validation': ('Test a valid, invalid-signature, and replayed webhook in an isolated test environment.',
        'Invalid or replayed messages cannot trigger the business operation; valid messages still succeed.'),
    'payment_amount_binding': ('Compare order state and payment-provider events while varying client-submitted amounts and currencies.',
        'Payment confirmation is bound to the server-owned order, amount, currency and authenticated provider event.'),
    'key_policy_restriction': ('Review the key policy, grants, identity policies and applicable organization ceilings together.',
        'Only intended principals can use or administer the exact key in the assessed account and deployment.'),
    'ssrf_protection': ('Review outbound destination parsing, redirects, DNS resolution and network egress restrictions.',
        'Unapproved internal, loopback and metadata destinations remain unreachable through the affected request path.'),
    'html_sanitization': ('Review output contexts and test rendering with inert context-breaking sentinel inputs.',
        'Untrusted content is encoded or sanitized for its actual HTML, attribute, URL or script context.'),
    'tool_authorization': ('Review the agent tool allowlist and exercise permitted and denied tool operations.',
        'The execution service enforces tool and resource authorization independently of model-generated instructions.'),
    'rag_document_authorization': ('Retrieve documents using test identities from different access groups and tenants.',
        'Retrieval applies caller authorization before context is supplied to the model.'),
    'untrusted_context_separation': ('Review how retrieved content reaches the model and test harmless conflicting instructions in retrieved documents.',
        'Untrusted content cannot change tool policy or data access; enforcement remains outside the model.'),
    'human_approval': ('Exercise sensitive agent actions with valid, absent, expired and changed approval records.',
        'The execution service binds approval to the exact action, arguments, actor and deployment before execution.'),
    'waf_enabled': ('Inspect rule actions and the actual ingress association using approved non-disruptive checks.',
        'The intended traffic traverses the configured WAF; this does not establish application input or authorization safety.'),
}


def remediation_contract(threat, components):
    explanation = threat.explanation or {}
    identifiers = sorted(set(threat.affected_components or []) | {
        value for value in (threat.component, threat.component_id, threat.affected_component) if value})
    targets = [components[identifier] for identifier in identifiers if identifier in components]
    controls = sorted({CONTROL_ALIASES.get(control, control) for control in explanation.get('matched_controls') or []})
    criteria = []
    for control in controls or [None]:
        check = _CONTROL_CHECKS.get(control)
        steps, expected = check or (
            'Review the stated weakness with the component owner and define a reproducible acceptance test.',
            'Owner-approved positive and negative tests demonstrate that the stated weakness is addressed.')
        identity = json.dumps([threat.id, control, identifiers], sort_keys=True)
        criteria.append({'id': 'verify-' + hashlib.sha256(identity.encode()).hexdigest()[:20],
            'control': control, 'component_ids': identifiers,
            'flow_refs': deepcopy(threat.affected_flow_refs), 'status': 'not_performed',
            'test_definition_status': 'defined' if check else 'owner_definition_required',
            'procedure': steps, 'acceptance_condition': expected,
            'required_evidence': ['Reviewed configuration or code at an identified revision',
                'Positive and negative test results with environment, date and reviewer'],
            'scope': [{'component_id': target.id, 'technology': target.properties.get('technology') or target.type,
                **{key: target.properties.get(key) for key in ('environment', 'deployment_version', 'tenant_id',
                    'cloud_account', 'cloud_provider', 'region', 'trust_boundary', 'canonical_boundaries') if target.properties.get(key)}}
                for target in targets],
            'runtime_verified': False})
    return {'version': 'reasoning-controls-2', 'status': 'validation_required',
        'criteria': criteria, 'closure_requires': ['matching_scope_evidence', 'reviewer_approval'],
        'runtime_verified': False}


def finalize_path_assurance(result):
    """Keep legacy route candidates out of evidence-backed final path counts."""
    chains = result.attack_chains or {}
    previous = chains.get('paths') or []
    finding_ids = {threat.id for threat in result.threats}
    explicit, hypotheses = [], [path for path in chains.get('hypotheses') or []
        if path.get('related_threat_id') in finding_ids]
    seen = {path.get('id') for path in hypotheses}
    for path in previous:
        if path.get('related_threat_id') not in finding_ids:
            continue
        supported = (path.get('evidence_supported') is not False and path.get('path_status') == 'explicit'
            and path.get('hops') and not path.get('inferred_hops')
            and all(hop.get('evidence_status') == 'explicit' for hop in path['hops'])
            and not any(check.get('state') == 'contradicted' for check in path.get('precondition_checks') or []))
        if supported:
            explicit.append(path)
        elif path.get('id') not in seen:
            hypotheses.append(path)
            seen.add(path.get('id'))
    by_finding = {path.get('related_threat_id'): path for path in explicit}
    explicit_ids = {path.get('id') for path in explicit}
    hypotheses = [path for path in hypotheses if path.get('id') not in explicit_ids]
    for threat in result.threats:
        if threat.id in by_finding:
            threat.attack_path = by_finding[threat.id]
            explanation = dict(threat.explanation or {})
            explanation.pop('attack_path_reason', None)
            threat.explanation = {**explanation, 'attack_path_status': 'explicit'}
        elif threat.attack_path:
            threat.attack_path = None
            threat.explanation = {**(threat.explanation or {}), 'attack_path_status': 'not_modeled',
                'attack_path_reason': 'inferred_route_requires_review'}
    result.attack_chains = {**chains, 'paths': explicit, 'count': len(explicit),
        'hypotheses': hypotheses, 'hypothesis_count': len(hypotheses),
        'semantics': 'Explicit connectivity is conditional on exploit and authorization prerequisites, not demonstrated access.',
        'runtime_verified': False} if explicit or hypotheses else {'paths': [], 'count': 0}
    result.summary = (result.summary or '').replace(f'and {len(previous)} modeled attack paths.',
        f'and {len(explicit)} modeled attack paths.')
    return result


def coverage_assurance(result):
    coverage = result.stride_coverage or {}
    cells = [cell for cell in coverage.get('cells') or [] if cell.get('status') != 'not_applicable']
    unresolved = [cell for cell in cells if cell.get('status') in {'unknown', 'potential'}
        or cell.get('unresolved_controls') or any(state not in {'present', 'absent'}
            for state in cell.get('control_assessment', {}).get('controls', {}).values())]
    metadata = result.architecture.metadata or {}
    correlation = metadata.get('source_correlation') or {}
    counts = Counter(cell.get('status') for cell in cells)
    return {'version': 'reasoning-controls-2', 'applicable_cells': len(cells),
        'evidence_resolved_cells': len(cells) - len(unresolved), 'unresolved_cells': len(unresolved),
        'evidence_resolution_percent': round(100 * (len(cells) - len(unresolved)) / len(cells), 1) if cells else None,
        'status_counts': dict(counts), 'assessment_scope': 'modeled_elements_and_implemented_controls_only',
        'unknown_is_absent': False, 'independent_accuracy_established': False, 'runtime_verified': False,
        'unresolved_source_claims': len(correlation.get('unresolved_claims') or []),
        'conflicting_source_claims': len(correlation.get('conflicts') or []),
        'assumed_flows': sum(flow.assumed or presence(flow.properties.get('assumed')) is True for flow in result.architecture.flows),
        'diagram_candidates_requiring_review': sum(bool(c.properties.get('diagram_review_required')) for c in result.architecture.components),
        'interpretation': 'Coverage measures evidence resolution inside the supplied model. It is not vulnerability recall, compliance, or production verification.'}
