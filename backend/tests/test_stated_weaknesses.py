"""A weakness written in ordinary prose must be reported, and reported against
the component the sentence is about."""

from app.engine.analyzer import ThreatAnalyzer
from app.engine.parser import ArchitectureParser


DESCRIPTION = (
    'The system is a payments platform. A React web portal calls a payments service over HTTPS.\n'
    'The payments service stores transactions in a PostgreSQL database and publishes events to a Kafka queue.\n'
    'An admin portal lets support staff issue refunds. The admin portal has no multi-factor authentication.\n'
    'The payments service accepts webhook callbacks from Stripe without signature verification.\n'
    'The Kafka queue has no access control for consumer groups.\n'
    'Audit events from the admin portal are not logged to a central system.\n'
)


def _weaknesses_by_component(architecture):
    return {
        component.id: {
            item['rule_id'] for item in (component.properties or {}).get('stated_weaknesses') or []
        }
        for component in architecture.components
    }


def test_prose_weaknesses_are_attributed_to_the_component_described():
    architecture = ArchitectureParser().parse(DESCRIPTION)
    stated = _weaknesses_by_component(architecture)

    assert 'GENERIC-MISSING-MFA-001' in stated.get('admin_portal', set())
    assert 'GENERIC-AUDIT-LOGGING-001' in stated.get('admin_portal', set())
    assert 'GENERIC-MISSING-AUTHORIZATION-001' in stated.get('kafka', set())
    assert 'GENERIC-MISSING-INTEGRITY-VERIFICATION-001' in stated.get('payments_service', set())


def test_a_control_that_is_present_is_not_recorded_as_a_weakness():
    architecture = ArchitectureParser().parse(DESCRIPTION)
    stated = _weaknesses_by_component(architecture)

    # "calls a payments service over HTTPS" states a control, not a weakness.
    for component_id, rule_ids in stated.items():
        assert 'GENERIC-ENCRYPTION-IN-TRANSIT-001' not in rule_ids, component_id


def test_weakness_named_with_two_components_goes_to_the_subject():
    architecture = ArchitectureParser().parse(DESCRIPTION)
    stated = _weaknesses_by_component(architecture)

    # Stripe is named in the webhook sentence but is not its subject.
    for component_id, rule_ids in stated.items():
        if component_id != 'payments_service':
            assert 'GENERIC-MISSING-INTEGRITY-VERIFICATION-001' not in rule_ids, component_id


def test_stated_weaknesses_become_confirmed_findings():
    result = ThreatAnalyzer().analyze_from_text(
        DESCRIPTION, project_name='Stated Weakness Test', use_local_slm=False,
    )
    confirmed = [threat for threat in result.threats if threat.tier == 'Confirmed']
    titles = ' | '.join(threat.title for threat in confirmed)

    assert 'access control for consumer groups' in titles

    # The missing second factor is reported once, by whichever route names it
    # best, and the sentence that stated it is part of the finding either way.
    mfa = [
        threat for threat in confirmed
        if threat.affected_component == 'admin_portal'
        and ('CWE-308' in (threat.cwe or []) or 'multi-factor' in threat.title.lower())
    ]
    assert len(mfa) == 1
    assert mfa[0].owasp_top_10 == ['A07:2021 Identification and Authentication Failures']
    assert mfa[0].cwe == ['CWE-308']
    assert any('admin portal has no multi-factor' in item for item in mfa[0].evidence)


def test_a_rule_finding_on_the_same_control_replaces_the_restatement():
    """A stated absence drives a rule; the generic restatement then stays quiet.

    "The ledger database is not encrypted at rest" sets the encryption property,
    which a knowledge-base predicate reports as Unencrypted Data at Rest. Adding
    a second Confirmed finding that repeats the sentence would bill one problem
    to the analyst twice.
    """
    result = ThreatAnalyzer().analyze_from_text(
        'A records service stores patient data in a ledger database. '
        'The ledger database is not encrypted at rest.',
        project_name='Single Finding Test', use_local_slm=False,
    )
    encryption = [
        threat for threat in result.threats
        if threat.affected_component == 'ledger_database'
        and ('ncrypt' in threat.title)
    ]

    assert len(encryption) == 1
    assert encryption[0].tier == 'Confirmed'


def test_a_stated_weakness_is_not_reported_twice():
    """The same weakness listed in prose and under Known issues appears once."""
    description = DESCRIPTION + (
        'Known issues:\n'
        '- The admin portal has no multi-factor authentication.\n'
    )
    result = ThreatAnalyzer().analyze_from_text(
        description, project_name='Duplicate Weakness Test', use_local_slm=False,
    )
    mfa_findings = [
        threat for threat in result.threats
        if 'multi-factor' in threat.title.lower() and threat.affected_component == 'admin_portal'
    ]

    assert len(mfa_findings) == 1


def test_unscoped_explicit_weakness_is_retained_as_confirmed_and_unmapped():
    description = (
        'An AI operations platform uses an agent service and a tenant vector index. '
        'Retrieved support tickets are inserted into system instructions without separating instructions.'
    )

    result = ThreatAnalyzer().analyze_from_text(
        description, project_name='Unscoped Weakness Test', use_local_slm=False,
    )
    finding = next(
        threat for threat in result.threats
        if threat.id.startswith('GENERIC-INDIRECT-PROMPT-INJECTION-001')
    )

    assert finding.tier == 'Confirmed'
    assert finding.confidence == 'High'
    assert finding.component is None
    assert finding.explanation['scope_resolution'] == 'unresolved_explicit_statement'
