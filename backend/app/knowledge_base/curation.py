"""Bounded, source-checked metadata corrections for exact legacy rule revisions.

No entry is a human approval, a new framework mapping, or a new detector. A changed
base rule invalidates its overlay and remains visible in the governance backlog.
"""

from copy import deepcopy

from .governance import review_digest


CHECKED_AT = '2026-10-04'
CASES = ['positive', 'protected', 'unknown', 'conflicting', 'planned', 'partial', 'wrong_scope']
AWS_DOCS = 'https://docs.aws.amazon.com/'
TENANT_SOURCE = 'https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html'
AGENT_SOURCE = 'https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html'

# Hand-written, rule-specific curation. Digests cover the original source record,
# excluding loader-only module names and review bookkeeping, not just the title.
LEGACY_CURATION = {
    'AWS-S3-001': {
        'base_digest': '7be072c0b958e1af7c84681273b808b62335a99746a75c58cac2e7158d353969',
        'references': [AWS_DOCS + 'AmazonS3/latest/userguide/access-control-block-public-access.html'],
        'source_version': 'AWS S3 User Guide, Block Public Access; living documentation checked 2026-10-04',
        'counterexamples': [
            'A deliberately public image bucket contains only approved public assets; public readability alone does not establish sensitive-data disclosure.',
            'A missing bucket-level block is not effective exposure when account or access-point controls deny the request. Encryption does not replace authorization.'],
        'verification': 'Collect effective account, bucket and access-point public-access blocks, policy and ACL evidence. Use an authorized test object to verify that anonymous and unintended cross-account reads fail; record the classified data scope.',
    },
    'AWS-KMS-001': {
        'base_digest': '942df65e23b0474880fb8a534658afc7783d6f18f816c08add8ce9394c354147',
        'references': [AWS_DOCS + 'kms/latest/developerguide/key-policies.html'],
        'source_version': 'AWS KMS Developer Guide, Key policies; living documentation checked 2026-10-04',
        'counterexamples': [
            'An IAM allow is ineffective unless the key policy permits that authorization path; applicable denies still matter.',
            'The default account delegation statement is not an unauthenticated public decrypt grant. Missing policy evidence is unknown.'],
        'verification': 'Review the exact regional key policy, relevant IAM policies and grants for the caller and operation. Verify an unintended principal cannot decrypt a non-sensitive test ciphertext under the same key and context.',
    },
    'ENT-CLOUD-EXTERNAL-ID': {
        'base_digest': 'db3906203ef585a127c64ca2b4debdc6903ecbed7b5bb0cf65ea4486b8f0a339',
        'references': [AWS_DOCS + 'IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html#external-id'],
        'source_version': 'AWS IAM User Guide, External IDs for third party access; checked 2026-10-04',
        'counterexamples': [
            'The role is not delegated to a third-party service acting for multiple customers; assess its actual trust conditions instead.',
            'The intended provider principal and customer-specific ExternalId are both enforced. ExternalId is a customer binding, not a secret.'],
        'verification': 'In a test account, try AssumeRole with the intended provider using the correct, missing and another customer ExternalId. Only the authorized customer context should succeed; retain the trust policy and outcomes.',
        'contract': ('cross_account_external_id', 'Service', {'cloud_provider': 'aws'}),
    },
    'ENT-CLOUD-KEY-DELETE': {
        'base_digest': 'da4c5175b1622aff720e1623ff96028e2b01040faecb3b6107c80526af4cb357',
        'references': [AWS_DOCS + 'kms/latest/developerguide/deleting-keys.html'],
        'source_version': 'AWS KMS Developer Guide, Delete an AWS KMS key; checked 2026-10-04',
        'counterexamples': [
            'Key-use permission does not imply permission to schedule deletion.',
            'A waiting period enables cancellation but does not preserve availability while the key is pending deletion. Never test destructive actions on production keys.'],
        'verification': 'Review ScheduleKeyDeletion and DisableKey permissions independently of key use. For a disposable test key, verify unauthorized identities are denied and authorized requests generate alerts with a documented cancellation procedure.',
        'contract': ('key_deletion_protection', 'Key Management', {'cloud_provider': 'aws'}),
    },
    'ENT-SAAS-CACHE': {
        'base_digest': '44bb23d377fede08745a183a76af36b31195e0bd7a05b75165bc807016c0db01',
        'references': [TENANT_SOURCE + '#4-cache-session-isolation'],
        'source_version': 'OWASP Multi-Tenant Application Security Cheat Sheet, Cache and Session Isolation; checked 2026-10-04',
        'counterexamples': [
            'A classified global public reference value does not require artificial tenant scope.',
            'Tenant-scoped keys plus authorization on cache hits prevent cross-tenant reuse; separate key names alone do not prove authorization.'],
        'verification': 'Prime a protected cache entry as tenant A, then request the same identifier as tenant B and after permission removal. Inspect cache hits and confirm no unauthorized value is returned.',
        'contract': ('tenant_cache_isolation', 'Service', {'multi_tenant': True}),
    },
    'ENT-SAAS-JOBS': {
        'base_digest': 'e4a6d64ceeba21d7bbfe429b0dd8640602961513e4ce8ce9c111a71a5d527261',
        'references': [TENANT_SOURCE + '#tenant-aware-asynchronous-work'],
        'source_version': 'OWASP Multi-Tenant Application Security Cheat Sheet, Tenant-Aware Asynchronous Work; checked 2026-10-04',
        'counterexamples': [
            'An explicitly authorized global maintenance job is not an ordinary tenant request.',
            'A shared queue is acceptable when trusted producer context and consumer resource authorization enforce isolation.'],
        'verification': 'Submit a tenant A job, alter its target to tenant B, and repeat after revoking A membership. The worker must reject unauthorized work, including retries; preserve producer, consumer and resource evidence.',
        'contract': ('tenant_job_isolation', 'Service', {'multi_tenant': True}),
    },
    'PAY-001': {
        'base_digest': '182c7b8e682aff165ccdd80c147403d27376b37c2f9b00b3ff62568fa74bee90',
        'references': ['https://docs.stripe.com/webhooks#verify-signatures'],
        'source_version': 'Stripe Webhooks documentation, Verify webhook signatures; checked 2026-10-04',
        'counterexamples': [
            'A receiver verifies the raw request body against its endpoint signing secret before updating orders.',
            'TLS or an authenticated outbound Stripe API call does not establish inbound webhook authenticity; absent implementation detail remains unknown.'],
        'verification': 'In Stripe test mode, send valid and tampered payloads, a wrong-endpoint signature and a stale signed event. Rejected events must not mutate payment state; verify raw-body handling before JSON parsing.',
    },
    'PAY-002': {
        'base_digest': '12e124c85820495227a1ac146fb6fd13de62038925cd1acccdf65a21d50dfb22',
        'references': ['https://docs.stripe.com/api/idempotent_requests'],
        'source_version': 'Stripe API documentation, Idempotent requests; checked 2026-10-04',
        'counterexamples': [
            'Retries of one logical operation reuse a stable key and the server atomically deduplicates local effects.',
            'Distinct purchases need distinct identities. Provider request idempotency alone does not deduplicate webhook delivery or internal fulfillment.'],
        'verification': 'Issue concurrent retries of one test purchase using its stable idempotency key. Verify one provider operation and one local ledger or fulfillment effect; changed parameters must not silently reuse the original operation.',
    },
    'ENT-PAYMENT-STATE': {
        'base_digest': '32b8065eba53869b8d9cc6142a0dbfa8614450850ac813a6c7c3200dbc246b75',
        'references': ['https://docs.stripe.com/payments/paymentintents/lifecycle'],
        'source_version': 'Stripe PaymentIntents documentation, Lifecycle; checked 2026-10-04',
        'counterexamples': [
            'A client success page is presentation only; fulfillment independently verifies provider status and order binding.',
            'A processing state is not a successful completed payment. Out-of-order events must not regress a validated terminal state.'],
        'verification': 'Test failed, processing, succeeded and wrong-order PaymentIntents in test mode. Only the server-validated eligible order may be fulfilled; retain event IDs, status decisions and the resulting order state.',
        'contract': ('payment_state_validation', 'API', {}),
    },
    'ENT-AI-SANDBOX': {
        'base_digest': '83204cf7669f9f01f4d61a60d29abf71cc5a66cb52c8459fb0fd2ff1899d74ca',
        'references': ['https://github.com/OWASP/www-project-ai-security-and-privacy-guide/blob/main/content/ai_exchange/content/docs/4_runtime_application_security_threats.md#49-agent-sandboxing-and-isolation'],
        'source_version': 'OWASP AI Exchange, section 4.9 Agent sandboxing and isolation; checked 2026-10-04',
        'counterexamples': [
            'A text-only assistant has no code execution tool.',
            'A container name alone is not evidence of an isolation boundary; privileges, mounts, secrets and egress determine its actual scope.'],
        'verification': 'Run benign canary operations through the real tool executor against forbidden files, credentials and network destinations. Confirm isolation outside the model and retain sandbox policy plus denial logs.',
        'contract': ('agent_execution_sandbox', 'ML Service', {}),
    },
    'ENT-AI-MEMORY': {
        'base_digest': '4e945383317e5bd64cf064749bea8368680268bb560bf1f8238bb394f618393e',
        'references': [AGENT_SOURCE + '#3-memory-context-security'],
        'source_version': 'OWASP AI Agent Security Cheat Sheet, Memory and Context Security; checked 2026-10-04',
        'counterexamples': [
            'The agent has no persistent memory.',
            'Authenticated, scoped memory writes retain provenance and never elevate retrieved data into privileged instructions.'],
        'verification': 'Attempt an unauthorized memory write and a cross-user read. Then insert a benign instruction canary as untrusted data; later tasks must not treat it as trusted policy.',
        'contract': ('agent_memory_integrity', 'ML Service', {}),
    },
    'ENT-AI-BUDGET': {
        'base_digest': '7f55e6cd588362d4a3b98cbbf3aab112a24882b72aab6a3cf69570e403a6883c',
        'references': ['https://github.com/OWASP/www-project-ai-testing-guide/blob/main/Document/content/tests/AITG-APP-06_Testing_for_Agentic_Behavior_Limits.md'],
        'source_version': 'OWASP AI Testing Guide, AITG-APP-06 Agentic Behavior Limits; checked 2026-10-04',
        'counterexamples': [
            'A deterministic single operation cannot delegate or repeat tools.',
            'An enforced aggregate task budget covers retries and child agents; a prompt telling the agent to stop is not enforcement.'],
        'verification': 'Use a bounded test loop with retries and a child task. Confirm the server stops aggregate token, tool-call and elapsed-time consumption at the configured limit and records termination.',
        'contract': ('agent_resource_budget', 'ML Service', {}),
    },
}


def apply_legacy_curation(raw):
    entry = LEGACY_CURATION.get(raw.get('id') or raw.get('threat_id'))
    if not entry:
        return raw, None
    if review_digest(raw) != entry['base_digest']:
        return raw, 'Legacy curation is stale: source rule content changed; recheck references and regression fixtures.'
    result = deepcopy(raw)
    references = result.get('references')
    if isinstance(references, dict):
        references['external_links'] = list(dict.fromkeys([*entry['references'], *(references.get('external_links') or [])]))
    else:
        result['references'] = list(dict.fromkeys([*entry['references'], *(references or [])]))
    for field in ('source_version', 'counterexamples', 'verification'):
        result[field] = deepcopy(entry[field])
    result.update(source_checked_at=CHECKED_AT, last_reviewed=None,
        review_status='source_checked_pending_independent_review',
        curation={'version': 'legacy-curation-1', 'base_digest': entry['base_digest'], 'checked_at': CHECKED_AT,
            'independent_approval': False})
    if entry.get('contract'):
        control, kind, properties = entry['contract']
        result['taxonomy_policy'] = 'explicit_only'
        result['test_contract'] = {'control': control, 'component_type': kind,
            'component_name': 'Scoped workload', 'properties': deepcopy(properties), 'cases': list(CASES)}
    return result, None
