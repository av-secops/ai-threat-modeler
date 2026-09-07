import json

import pytest

from app.engine.iac_security import IaCSecurityAnalyzer
from app.engine.stride_coverage_engine import _control_state


def policy_findings(statements):
    return IaCSecurityAnalyzer()._analyze_policy_text(json.dumps({"Statement": statements}), "policy", 1)


def test_deny_is_not_an_administrative_grant():
    assert not policy_findings([{"Effect": "Deny", "Action": "*", "Resource": "*"}])


def test_wildcards_cannot_join_across_statements():
    findings = policy_findings([
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Deny", "Action": "*", "Resource": "arn:aws:s3:::protected/*"},
    ])
    assert not findings


def test_literal_hcl_allow_is_detected():
    source = 'resource "aws_iam_policy" "p" { policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }) }'
    assert any(f["rule_id"] == "IAC-AWS-IAM-ADMIN" for f in IaCSecurityAnalyzer()._analyze_policy_text(source, "p", 1))


@pytest.mark.parametrize("effect,condition", [("Deny", {}), ("Allow", {"StringEquals": {"aws:PrincipalOrgID": "o-trusted"}})])
def test_public_principal_is_not_enough(effect, condition):
    text = json.dumps({"Statement": [{"Effect": effect, "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Condition": condition}]})
    assert not IaCSecurityAnalyzer._public_principal(text)


def test_base_checkout_is_not_untrusted_head_checkout():
    workflow = 'on:\n  pull_request_target:\npermissions: {}\njobs:\n  labels:\n    steps:\n      - uses: actions/checkout@' + 'a' * 40 + '\n'
    assert not IaCSecurityAnalyzer()._analyze_ci(workflow)


def test_untrusted_checkout_with_execution_is_detected():
    workflow = 'on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@' + 'a' * 40 + '\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm install\n'
    assert any(f['rule_id'] == 'IAC-CI-PR-TARGET-CHECKOUT' for f in IaCSecurityAnalyzer()._analyze_ci(workflow))


def test_waf_alone_does_not_establish_resource_limits():
    state, _, _ = _control_state({'kind': 'component', 'type': 'API', 'properties': {'waf_enabled': True}}, 'Denial of Service')
    assert state == 'partial'


def test_false_like_controls_are_not_present():
    state, _, _ = _control_state({'kind': 'component', 'type': 'API', 'properties': {'rate_limiting': 'false'}}, 'Denial of Service')
    assert state == 'absent'


def test_canonicalization_preserves_conflict_and_false_like_values():
    from app.engine.canonical_model import canonicalize_architecture
    from app.models import Component, SystemArchitecture
    architecture = SystemArchitecture(components=[Component(id='api', name='API', type='API', properties={
        'mfa_enabled': 'FALSE', 'input_validation': False,
        'control_assertions': {'input_validation': 'conflicting'},
    })], flows=[])
    model, _ = canonicalize_architecture(architecture)
    assertions = model.components[0].properties['control_assertions']
    assert assertions['mfa_enabled'] == 'absent'
    assert assertions['input_validation'] == 'conflicting'


def test_callback_signature_gap_belongs_to_stated_receiver():
    from app.engine.parser import ArchitectureParser
    from app.models import Component, DataFlow
    components = {
        'stripe': Component(id='stripe', name='Stripe', type='Payment Processor'),
        'billing': Component(id='billing', name='Billing API', type='API'),
    }
    issues = [{'description': 'Stripe webhook signatures are not verified.', 'control': 'webhook_signature_validation'}]
    flows = [DataFlow(source_id='stripe', target_id='billing', protocol='HTTPS', properties={'evidence': 'Stripe sends webhooks to Billing API.'})]
    actual = ArchitectureParser()._link_known_issues_to_components(issues, components, flows)
    assert actual[0]['component_hints'] == ['billing']
