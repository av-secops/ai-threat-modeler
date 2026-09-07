import pytest

from app.engine.known_issue_taxonomy import GENERIC_SCOPE_TYPES, GENERIC_WEAKNESS_RULES, classify_generic_weakness
from app.engine.owasp_mapping import owasp_for
from app.engine.parser import ArchitectureParser


# Plainly worded weaknesses that reviewers expect to be classified without
# matching a scenario-specific phrasing.
CLASSIFIED_CASES = [
    ('there is no dedicated user role for KMS', 'GENERIC-MISSING-AUTHORIZATION-001'),
    ('admin users do not use MFA', 'GENERIC-MISSING-MFA-001'),
    ('MFA is not enabled for the administrator console', 'GENERIC-MISSING-MFA-001'),
    ('the back-office dashboard has no access control', 'GENERIC-MISSING-AUTHORIZATION-001'),
    ('the order service accepts requests without authentication', 'GENERIC-MISSING-AUTHENTICATION-001'),
    ('the JWT signing key is stored in an environment variable', 'GENERIC-SECRET-EXPOSURE-001'),
    ('database credentials are hardcoded in the deployment manifest', 'GENERIC-SECRET-EXPOSURE-001'),
    ('the MySQL database has no encryption at rest', 'GENERIC-ENCRYPTION-AT-REST-001'),
    ('internal traffic between services uses plain http', 'GENERIC-ENCRYPTION-IN-TRANSIT-001'),
    ('the audit events are not logged to a central system', 'GENERIC-AUDIT-LOGGING-001'),
    ('the public API has no rate limiting on the login endpoint', 'GENERIC-RATE-LIMITING-001'),
    ('nginx 1.18 is an outdated version with known vulnerabilities', 'GENERIC-OUTDATED-COMPONENT-001'),
    ('the S3 bucket is publicly accessible', 'GENERIC-PUBLIC-EXPOSURE-001'),
    ('the container runs privileged with root privileges', 'GENERIC-EXCESSIVE-PRIVILEGE-001'),
    ('session tokens do not expire', 'GENERIC-SESSION-LIFETIME-001'),
    ('passwords are hashed with MD5', 'GENERIC-WEAK-CRYPTOGRAPHY-001'),
    ('all microservices share the same service account', 'GENERIC-SHARED-IDENTITY-001'),
    ('the API is vulnerable to SQL injection', 'GENERIC-SQL-INJECTION-001'),
    ('stack traces are returned to the client', 'GENERIC-VERBOSE-ERRORS-001'),
    ('the network is flat with no segmentation between tiers', 'GENERIC-NETWORK-SEGMENTATION-001'),
    ('the service accepts webhook callbacks from Stripe without signature verification',
     'GENERIC-MISSING-INTEGRITY-VERIFICATION-001'),
    ('the workspace filter is applied only after vector retrieval, allowing another tenant records',
     'GENERIC-TENANT-ISOLATION-001'),
    ('retrieved support tickets are inserted into system instructions without separating instructions',
     'GENERIC-INDIRECT-PROMPT-INJECTION-001'),
    ('the model chooses shell tool arguments without server-side authorization or an allowlist',
     'GENERIC-AGENT-TOOL-AUTHORIZATION-001'),
    ('one owner-scoped GitHub token is reused across every tenant',
     'GENERIC-DELEGATED-CREDENTIAL-SHARING-001'),
    ('approval is only in the browser and the API accepts direct calls without checking identity',
     'GENERIC-APPROVAL-BYPASS-001'),
    ('traces retain prompts, OAuth tokens and complete tool output',
     'GENERIC-SENSITIVE-TELEMETRY-001'),
    ('MCP servers are not mutually authenticated and responses have no integrity signature',
     'GENERIC-MCP-PEER-AUTHENTICITY-001'),
    ('signed evidence URLs remain valid after the user is disabled',
     'GENERIC-REVOCABLE-SIGNED-LINK-001'),
    ('recursive agent tool loops have no token budget or tenant quota',
     'GENERIC-AGENT-RESOURCE-EXHAUSTION-001'),
]

# Statements describing a control that is present must not be read as a weakness.
CONTROL_PRESENT_CASES = [
    'the service uses TLS 1.3 and enforces MFA for all administrators',
    'each workload has a dedicated IAM role scoped to least privilege',
    'the API validates all input against a JSON schema',
    'access control is enforced at the gateway and again at the service',
    'the database is encrypted at rest with a customer-managed KMS key',
    'audit events are written to an immutable log store and alerted on',
    'orders are published to a RabbitMQ queue for downstream processing',
    'the storefront is a Next.js application served through CloudFront',
    # "over http" must not match inside "over https"
    'a React web portal calls a payments service over HTTPS',
    'the worker pulls messages over https from the queue',
]


@pytest.mark.parametrize('text,expected_id', CLASSIFIED_CASES)
def test_plainly_worded_weakness_is_classified(text, expected_id):
    result = classify_generic_weakness(text)

    assert result is not None, f'no generic class matched: {text}'
    assert result['id'] == expected_id


@pytest.mark.parametrize('text', CONTROL_PRESENT_CASES)
def test_control_statement_is_not_a_weakness(text):
    assert classify_generic_weakness(text) is None


def test_every_generic_rule_carries_a_complete_mapping():
    for rule in GENERIC_WEAKNESS_RULES:
        assert rule['groups'] and all(rule['groups'])
        assert rule['category'] and rule['severity'] in {'critical', 'high', 'medium', 'low'}
        assert rule['control'] and rule['mitigation']
        assert rule['owasp'] and rule['cwe'] and rule['stride']
        assert rule['id'] in GENERIC_SCOPE_TYPES, f"{rule['id']} has no fallback scope"


def test_declared_owasp_agrees_with_the_cwe_mapping():
    """A rule must not contradict the mapping the rest of the tool applies."""
    for rule in GENERIC_WEAKNESS_RULES:
        derived = owasp_for(rule['cwe'], rule['category'])

        assert rule['owasp'][0] == derived[0], (
            f"{rule['id']} declares {rule['owasp'][0]} but its primary CWE "
            f"{rule['cwe'][0]} maps to {derived[0]}"
        )


def test_generic_rule_ids_are_unique():
    ids = [rule['id'] for rule in GENERIC_WEAKNESS_RULES]

    assert len(ids) == len(set(ids))


def test_known_issues_are_classified_and_uniquely_identified():
    text = (
        'Known issues:\n'
        '- The back-office dashboard has no access control.\n'
        '- The JWT signing key is stored in an environment variable.\n'
        '- Something entirely unfamiliar happens during reconciliation.\n'
    )

    issues = ArchitectureParser().parse_known_issues(text)
    ids = [issue['suggested_threat_id'] for issue in issues]

    assert 'GENERIC-MISSING-AUTHORIZATION-001' in ids
    assert 'GENERIC-SECRET-EXPOSURE-001' in ids
    assert len(ids) == len(set(ids)), f'duplicate known-issue identifiers: {ids}'


def test_unclassified_known_issues_are_numbered_individually():
    text = (
        'Known issues:\n'
        '- Reconciliation drifts during month-end in an unfamiliar way.\n'
        '- The nightly ledger step behaves inconsistently for legacy tenants.\n'
    )

    issues = ArchitectureParser().parse_known_issues(text)
    ids = [issue['suggested_threat_id'] for issue in issues]

    assert ids == ['UNCLASSIFIED-KNOWN-ISSUE-001', 'UNCLASSIFIED-KNOWN-ISSUE-002']


def test_request_header_tenant_scope_is_classified_as_bola():
    issues = ArchitectureParser().parse_known_issues(
        'Known issues:\n'
        '- Tenant ID is accepted from a request header without server-side ownership validation.\n'
    )

    assert issues[0]['suggested_threat_id'] == 'API-BOLA-TENANT-CONTROL-001'
    assert issues[0]['category'] == 'Elevation of Privilege'


def test_owasp_category_follows_the_cwe_rather_than_a_fixed_default():
    assert owasp_for(['CWE-89']) == ['A03:2021 Injection']
    assert owasp_for(['CWE-79']) == ['A03:2021 Injection']
    assert owasp_for(['CWE-862']) == ['A01:2021 Broken Access Control']
    assert owasp_for(['CWE-311']) == ['A02:2021 Cryptographic Failures']
    assert owasp_for(['CWE-918']) == ['A10:2021 Server-Side Request Forgery']
    assert owasp_for(['CWE-1104']) == ['A06:2021 Vulnerable and Outdated Components']
    assert owasp_for(['CWE-778']) == ['A09:2021 Security Logging and Monitoring Failures']


def test_owasp_falls_back_to_stride_then_misconfiguration():
    assert owasp_for([], 'Repudiation') == ['A09:2021 Security Logging and Monitoring Failures']
    assert owasp_for(['CWE-99999'], 'Spoofing') == ['A07:2021 Identification and Authentication Failures']
    assert owasp_for([], None) == ['A05:2021 Security Misconfiguration']
