"""Check explicitly supplied business invariants; names alone imply no defect."""

from ..models import Threat

INVARIANTS = {
    'atomic_debit': ('Tampering', 'CWE-362', 'Make balance checks and debits one atomic transaction.'),
    'replay_protection': ('Tampering', 'CWE-294', 'Bind idempotency keys to the transaction and retain them through its replay window.'),
    'tenant_binding': ('Elevation of Privilege', 'CWE-639', 'Bind queued work and its execution identity to a server-validated tenant.'),
    'separation_of_duties': ('Elevation of Privilege', 'CWE-269', 'Require an independent authorized approver for the consequential transition.'),
    'delegated_authority': ('Elevation of Privilege', 'CWE-863', 'Enforce tool, resource and action scope at execution, not only in the agent prompt.'),
    'state_transition_validation': ('Tampering', 'CWE-841', 'Validate allowed transitions, prerequisites and authorization atomically.'),
}

SPECIALIST_INVARIANTS = {
    'subscriber_authorization': ('Elevation of Privilege', 'CWE-639', 'Authorize each subscriber operation against the authenticated account before provisioning.'),
    'usage_record_integrity': ('Tampering', 'CWE-345', 'Validate producer identity, immutable event IDs and usage record integrity before charging.'),
    'entitlement_transition_validation': ('Tampering', 'CWE-841', 'Enforce entitlement prerequisites and valid state transitions atomically.'),
    'webhook_business_binding': ('Tampering', 'CWE-863', 'Bind each authenticated callback to its account, order, amount, currency and provider state.'),
    'tool_approval_binding': ('Elevation of Privilege', 'CWE-367', 'Bind approval to the exact tool, target, arguments, identity and expiry at execution.'),
}


def analyze_workflows(architecture):
    threats, assessments = [], []
    components = {c.id: c for c in architecture.components if not c.properties.get('diagram_review_required')}
    for workflow in (architecture.metadata or {}).get('workflows', [])[:100]:
        if not isinstance(workflow, dict):
            continue
        scope = [cid for cid in workflow.get('components', []) if cid in components]
        checks = {**INVARIANTS, **{k: v for k, v in SPECIALIST_INVARIANTS.items() if k in workflow.get('invariants', {})}}
        for name, (category, cwe, mitigation) in checks.items():
            from .source_correlation import _applicable
            evidence = [e for e in workflow.get('evidence', []) if isinstance(e, dict) and e.get('control') == name and e.get('statement')
                and e.get('state', 'absent') == 'absent' and e.get('applicable') is not False and e.get('evidence_scope') != 'topology'
                and e.get('workflow_id', workflow.get('id')) == workflow.get('id')
                and (not e.get('element_id') or e['element_id'] in scope)
                and all(_applicable(e.get('scope') or {}, components[cid]) for cid in scope)]
            value = workflow.get('invariants', {}).get(name)
            state = 'present' if value is True else 'absent' if value is False else 'unknown'
            assessments.append({'workflow': workflow.get('id'), 'control': name, 'state': state, 'components': scope})
            if value is not False or not evidence or not scope:
                continue
            threats.append(Threat(id=f"WORKFLOW-{workflow.get('id', 'unnamed')}-{name}", title=f"{workflow.get('name', 'Workflow')}: {name.replace('_', ' ')} absent",
                description=f"The supplied workflow explicitly declares {name} absent.", category=category,
                severity='High', severity_source='rule', confidence='High', tier='Confirmed',
                finding_type='control_gap', component=scope[0], affected_components=scope,
                mitigation=mitigation, cwe=[cwe], evidence_details=evidence,
                evidence=[str(e.get('statement', '')) for e in evidence],
                explanation={'origin': 'workflow_invariant', 'matched_controls': [name], 'workflow_id': workflow.get('id')}))
    return threats, assessments
