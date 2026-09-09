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


def analyze_workflows(architecture):
    threats, assessments = [], []
    component_ids = {c.id for c in architecture.components}
    for workflow in (architecture.metadata or {}).get('workflows', [])[:100]:
        if not isinstance(workflow, dict):
            continue
        scope = [cid for cid in workflow.get('components', []) if cid in component_ids]
        for name, (category, cwe, mitigation) in INVARIANTS.items():
            evidence = [e for e in workflow.get('evidence', []) if isinstance(e, dict) and e.get('control') == name and e.get('statement')]
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
