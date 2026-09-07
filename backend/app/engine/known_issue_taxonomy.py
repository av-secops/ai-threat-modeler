"""
Generic classification for plainly worded security weaknesses.

The scenario catalogs in the parser match very specific phrasings taken from
reference threat models. Anything worded differently falls through to the
unclassified bucket, which blocks report publication. This module covers the
broad weakness classes in wording-independent terms so that an ordinary
sentence such as "the dashboard has no access control" still resolves to a
STRIDE category, an OWASP entry and a CWE.

Rules are evaluated in order and the first match wins, so narrower classes are
listed before broader ones. A rule matches when every phrase group contains at
least one phrase present in the text.

Phrases are literal except for two markers. `*` stands for up to three
intervening words within the same clause, which keeps "no dedicated user role"
and "MFA is not enabled" matchable without hand-writing a regex per wording;
punctuation stops the wildcard, so it cannot bridge two sentences. A trailing
`!` disables the default inflection allowance for phrases where a longer word
means something else, as in "over http" against "over https".
"""

import re
from functools import lru_cache
from typing import Any, Dict, List, Optional


# Each rule requires all groups to match; a group matches on any of its phrases.
GENERIC_WEAKNESS_RULES: List[Dict[str, Any]] = [
    {
        'id': 'GENERIC-SQL-INJECTION-001',
        'groups': [['sql injection', 'sqli!']],
        'category': 'Tampering',
        'severity': 'critical',
        'control': 'parameterized_queries',
        'mitigation': 'Use parameterized queries or a query builder that binds parameters, validate input server side, and apply least-privilege database credentials.',
        'owasp': ['A03:2021 Injection'],
        'cwe': ['CWE-89'],
        'stride': ['Tampering', 'Information Disclosure', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-COMMAND-INJECTION-001',
        'groups': [['command injection', 'os command', 'shell injection', 'remote code execution', 'arbitrary code execution']],
        'category': 'Elevation of Privilege',
        'severity': 'critical',
        'control': 'safe_process_execution',
        'mitigation': 'Avoid shell interpolation, pass arguments as a list to the process API, allowlist permitted commands, and run the workload without privileges.',
        'owasp': ['A03:2021 Injection'],
        'cwe': ['CWE-78'],
        'stride': ['Elevation of Privilege', 'Tampering'],
    },
    {
        'id': 'GENERIC-XSS-001',
        'groups': [['xss', 'cross-site scripting', 'cross site scripting']],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'output_encoding',
        'mitigation': 'Encode output for its rendering context, avoid raw HTML sinks, and add a content security policy that blocks inline script.',
        'owasp': ['A03:2021 Injection'],
        'cwe': ['CWE-79'],
        'stride': ['Tampering', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-SSRF-001',
        'groups': [['ssrf', 'server-side request forgery', 'server side request forgery']],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'egress_allowlisting',
        'mitigation': 'Allowlist outbound destinations, re-check the address after DNS resolution to block private and link-local ranges, and isolate egress from metadata services.',
        'owasp': ['A10:2021 Server-Side Request Forgery'],
        'cwe': ['CWE-918'],
        'stride': ['Information Disclosure', 'Spoofing'],
    },
    {
        'id': 'GENERIC-CSRF-001',
        'groups': [['no csrf', 'without csrf', 'missing csrf', 'no anti-csrf', 'csrf protection is not', 'csrf token is not', 'cross-site request forgery']],
        'category': 'Tampering',
        'severity': 'medium',
        'control': 'csrf_tokens',
        'mitigation': 'Require a per-session anti-forgery token on state-changing requests and set session cookies to SameSite strict or lax.',
        'owasp': ['A01:2021 Broken Access Control'],
        'cwe': ['CWE-352'],
        'stride': ['Tampering', 'Spoofing'],
    },
    {
        'id': 'GENERIC-MISSING-INTEGRITY-VERIFICATION-001',
        'groups': [['without *signature verification', 'no *signature verification',
                    'signature *not verified', 'does not verify *signature',
                    'without verifying *signature', 'signature *not checked',
                    'no *integrity check', 'no *checksum', 'no *hmac', 'unsigned',
                    'without *provenance', 'no *provenance']],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'payload_authenticity_verification',
        'mitigation': 'Verify the sender signature over the raw payload before processing, reject unsigned or stale messages, and rotate the signing secret on a schedule.',
        'owasp': ['A08:2021 Software and Data Integrity Failures'],
        'cwe': ['CWE-345'],
        'stride': ['Tampering', 'Spoofing'],
    },
    {
        'id': 'GENERIC-DEFAULT-CREDENTIALS-001',
        'groups': [['default password', 'default credential', 'default admin', 'factory default', 'unchanged password']],
        'category': 'Spoofing',
        'severity': 'critical',
        'control': 'credential_rotation',
        'mitigation': 'Remove default accounts, force a credential change on first use, and verify no default credential remains through a deployment check.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-1392', 'CWE-798'],
        'stride': ['Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-SECRET-EXPOSURE-001',
        'groups': [
            ['environment variable', 'hardcoded', 'hard-coded', 'hard coded', 'plaintext', 'plain text',
             'source control', 'git repositor', 'in the repositor', 'config file', 'configuration file',
             'in the codebase', 'stored in code', 'checked into', 'committed'],
            ['secret', 'password', 'credential', 'api key', 'private key', 'signing key',
             'access key', 'token', 'connection string'],
        ],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'managed_secret_storage',
        'mitigation': 'Move the secret into a managed secrets store, inject it at runtime with a short-lived lease, rotate the exposed value, and scan history for further exposure.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-798', 'CWE-522'],
        'stride': ['Information Disclosure', 'Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-ENCRYPTION-AT-REST-001',
        'groups': [
            ['at rest', 'on disk', 'in the database', 'stored unencrypted', 'backup'],
            ['no *encryption', 'not encrypted', 'unencrypted', 'without *encryption',
             'encryption *not', 'encryption is disabled', 'plaintext', 'plain text'],
        ],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'encryption_at_rest',
        'mitigation': 'Enable storage encryption with a customer-managed key, restrict key use to the owning workload identity, and confirm backups and snapshots inherit encryption.',
        'owasp': ['A02:2021 Cryptographic Failures'],
        'cwe': ['CWE-311'],
        'stride': ['Information Disclosure'],
    },
    {
        'id': 'GENERIC-ENCRYPTION-IN-TRANSIT-001',
        'groups': [['no tls', 'without tls', 'no ssl', 'plain http!', 'over http!', 'http instead of https',
                    'not encrypted in transit', 'unencrypted traffic', 'unencrypted connection',
                    'cleartext', 'clear text', 'tls is not', 'tls is disabled', 'no mutual tls', 'no mtls']],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'encryption_in_transit',
        'mitigation': 'Require TLS 1.2 or above on every hop, verify certificates, redirect plaintext listeners, and use mutual TLS where the peer identity matters.',
        'owasp': ['A02:2021 Cryptographic Failures'],
        'cwe': ['CWE-319'],
        'stride': ['Information Disclosure', 'Tampering', 'Spoofing'],
    },
    {
        'id': 'GENERIC-WEAK-CRYPTOGRAPHY-001',
        'groups': [['md5', 'sha-1', 'rc4', 'ecb mode', 'weak cipher', 'weak hash', 'weak algorithm',
                    'deprecated cipher', 'deprecated algorithm', 'unsalted', 'no salt']],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'approved_cryptography',
        'mitigation': 'Replace the algorithm with an approved primitive, use a memory-hard hash with a per-record salt for passwords, and record the migration path for stored values.',
        'owasp': ['A02:2021 Cryptographic Failures'],
        'cwe': ['CWE-327', 'CWE-328'],
        'stride': ['Tampering', 'Information Disclosure', 'Spoofing'],
    },
    {
        'id': 'GENERIC-MISSING-MFA-001',
        'groups': [['no *multi-factor', 'no *multi factor', 'no *mfa', 'without *mfa',
                    'without *multi-factor', 'single-factor', 'single factor',
                    'mfa *not', 'multi-factor *not', 'not use mfa', 'not require mfa',
                    'not use multi-factor', 'not require multi-factor', 'not enforce mfa',
                    'mfa is disabled', 'no second factor', 'no 2fa', 'no two-factor']],
        'category': 'Spoofing',
        'severity': 'high',
        'control': 'multi_factor_authentication',
        'mitigation': 'Require phishing-resistant multi-factor authentication for the affected access path, with priority on administrative and remote entry points.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-308'],
        'stride': ['Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-MISSING-AUTHENTICATION-001',
        'groups': [['no *authentication', 'without *authentication', 'not authenticated', 'unauthenticated',
                    'anonymous access', 'no login', 'does not authenticate', 'lacks *authentication',
                    'missing *authentication', 'authentication *not', 'authentication is disabled',
                    'no credentials required', 'open access', 'no *credential']],
        'unless': ['multi-factor', 'multifactor', 'multi factor', 'two-factor', 'two factor',
                   'second factor', 'mfa!', '2fa!', 'step-up'],
        'category': 'Spoofing',
        'severity': 'critical',
        'control': 'authentication_required',
        'mitigation': 'Require authenticated identity on every request path, reject unauthenticated calls at the edge and at the service, and verify the control with a negative test.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-306'],
        'stride': ['Spoofing', 'Elevation of Privilege', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-MISSING-AUTHORIZATION-001',
        'groups': [['no *access control', 'without *access control', 'no *authorization',
                    'without *authorization', 'not authorized', 'no rbac', 'no *role-based',
                    'no role based', 'missing *access control', 'does not check permission',
                    'no *permission check', 'any user can', 'all users can', 'any authenticated user',
                    'lacks *access control', 'no object-level authorization', 'authorization *not',
                    'no *role', 'access control *not', 'unrestricted access', 'no *segregation of duties',
                    'not restricted', 'no *least privilege']],
        'category': 'Elevation of Privilege',
        'severity': 'high',
        'control': 'authorization_enforcement',
        'mitigation': 'Enforce server-side authorization per request from the authenticated identity, deny by default, and cover the object level as well as the route level.',
        'owasp': ['A01:2021 Broken Access Control'],
        'cwe': ['CWE-862', 'CWE-284'],
        'stride': ['Elevation of Privilege', 'Information Disclosure', 'Tampering'],
    },
    {
        'id': 'GENERIC-EXCESSIVE-PRIVILEGE-001',
        'groups': [['excessive privilege', 'overly permissive', 'over-permissive', 'over permissive',
                    'wildcard permission', 'full admin', 'admin privileges', 'administrator privileges',
                    'root privileges', 'runs as root', 'privileged container', 'privileged mode',
                    'least privilege is not', 'allows all actions', 'full access to', 'broad permissions',
                    'more permissions than']],
        'category': 'Elevation of Privilege',
        'severity': 'high',
        'control': 'least_privilege',
        'mitigation': 'Scope the identity to the actions and resources it needs, split administrative duties, and review the grant against observed usage.',
        'owasp': ['A01:2021 Broken Access Control'],
        'cwe': ['CWE-732', 'CWE-269'],
        'stride': ['Elevation of Privilege', 'Tampering'],
    },
    {
        'id': 'GENERIC-CREDENTIAL-ROTATION-001',
        'groups': [
            ['credential', 'password', 'api key', 'access key', 'secret', 'signing key',
             'private key', 'token', 'certificate'],
            ['never *rotated', 'not *rotated', 'no *rotation', 'unrotated',
             'never been changed', 'never changed', 'has not changed', 'same since'],
        ],
        'category': 'Spoofing',
        'severity': 'high',
        'control': 'credential_rotation',
        'mitigation': 'Rotate the credential now, give it a maximum lifetime with automated renewal, and alert when an unrotated credential passes its age limit.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-798', 'CWE-522'],
        'stride': ['Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-LOG-INTEGRITY-001',
        'groups': [
            ['audit log', 'audit trail', 'log', 'logs', 'log stream'],
            ['writable', 'write access', 'can be modified', 'can be deleted', 'can modify',
             'can delete', 'tamper', 'not *immutable', 'no *append-only', 'not *write-once',
             'deletable', 'editable'],
        ],
        'category': 'Repudiation',
        'severity': 'high',
        'control': 'log_integrity_protection',
        'mitigation': 'Ship audit events to storage the audited workload cannot alter, grant it append-only rights, and detect gaps or edits with a sequence or hash chain.',
        'owasp': ['A09:2021 Security Logging and Monitoring Failures'],
        'cwe': ['CWE-778', 'CWE-284'],
        'stride': ['Repudiation', 'Tampering'],
    },
    {
        'id': 'GENERIC-SHARED-IDENTITY-001',
        # "shared key" is matched strictly: a "shared S3 bucket keyed by tenant
        # prefix" shares storage, not a credential.
        'groups': [['shared account', 'shared credential', 'shared *credential', 'shared service account',
                    'same credentials', 'same *credential', 'shared api key', 'shared key!',
                    'shared keys!', 'generic account', 'same service account',
                    'single service account', 'one service account']],
        'category': 'Repudiation',
        'severity': 'high',
        'control': 'per_workload_identity',
        'mitigation': 'Issue a distinct identity per workload or person, remove the shared credential, and confirm audit events attribute actions to a single actor.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-522'],
        'stride': ['Repudiation', 'Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-SESSION-LIFETIME-001',
        'groups': [['session does not expire', 'sessions do not expire', 'never expire', 'no session timeout',
                    'no timeout', 'session timeout is not', 'long-lived session', 'long lived token',
                    'tokens do not expire', 'no token expiry', 'no expiration', 'does not expire',
                    'no revocation', 'cannot be revoked']],
        'category': 'Spoofing',
        'severity': 'medium',
        'control': 'session_lifetime_and_revocation',
        'mitigation': 'Set a short access-token lifetime with refresh, expire idle sessions, and support server-side revocation on credential change or logout.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-613'],
        'stride': ['Spoofing', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-PUBLIC-EXPOSURE-001',
        'groups': [['publicly accessible', 'public internet', 'exposed to the internet', 'internet-facing',
                    'internet facing', '0.0.0.0/0', '::/0', 'public ip', 'publicly exposed',
                    'open to the world', 'anyone on the internet', 'no firewall', 'no network polic',
                    'publicly readable', 'public bucket', 'public s3 bucket', 'bucket is public']],
        'unless': ['not public', 'not publicly', 'no public', 'public access is blocked', 'public access is disabled'],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'network_exposure_reduction',
        'mitigation': 'Remove public reachability, place the resource behind a private network path with an allowlist, and confirm exposure with an external scan.',
        'owasp': ['A01:2021 Broken Access Control'],
        'cwe': ['CWE-284'],
        'stride': ['Information Disclosure', 'Elevation of Privilege', 'Denial of Service'],
    },
    {
        'id': 'GENERIC-NETWORK-SEGMENTATION-001',
        'groups': [['flat network', 'no segmentation', 'not segmented', 'no network isolation',
                    'same network segment', 'no isolation between', 'shared network']],
        'category': 'Elevation of Privilege',
        'severity': 'medium',
        'control': 'network_segmentation',
        'mitigation': 'Segment the network by trust zone, default-deny east-west traffic, and allow only the flows the architecture declares.',
        'owasp': ['A05:2021 Security Misconfiguration'],
        'cwe': ['CWE-923'],
        'stride': ['Elevation of Privilege', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-OUTDATED-COMPONENT-001',
        'groups': [['outdated', 'unpatched', 'not patched', 'end of life', 'end-of-life', 'out of support',
                    'known vulnerabilit', 'old version', 'deprecated version', 'no patching',
                    'not updated', 'unsupported version', 'cve-']],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'dependency_currency',
        'mitigation': 'Upgrade to a supported version, add dependency scanning to the pipeline with a fix service level, and track exceptions with an owner and date.',
        'owasp': ['A06:2021 Vulnerable and Outdated Components'],
        'cwe': ['CWE-1104', 'CWE-1035'],
        'stride': ['Tampering', 'Elevation of Privilege', 'Denial of Service'],
    },
    {
        'id': 'GENERIC-RATE-LIMITING-001',
        'groups': [['no *rate limit', 'without *rate limit', 'rate limiting *not', 'no *throttl',
                    'unlimited request', 'no *quota', 'unbounded request', 'no backpressure']],
        'category': 'Denial of Service',
        'severity': 'medium',
        'control': 'rate_limiting',
        'mitigation': 'Apply per-identity and per-route rate limits with quotas, shed load at the edge, and alert on sustained limit breaches.',
        'owasp': ['A04:2021 Insecure Design'],
        'cwe': ['CWE-770'],
        'stride': ['Denial of Service', 'Spoofing'],
    },
    {
        'id': 'GENERIC-AUDIT-LOGGING-001',
        'groups': [['no *audit', 'not logged', 'no *logging', 'without *logging', 'no *audit trail',
                    'logging *not', 'logs are not', 'not recorded', 'no *monitoring', 'not monitored',
                    'no *alerting', 'no alerts', 'logs are stored locally', 'no *log retention',
                    'no *traceability']],
        'category': 'Repudiation',
        'severity': 'medium',
        'control': 'audit_logging_and_alerting',
        'mitigation': 'Record security-relevant events with actor, action, object and result, ship them to tamper-evident storage, and alert on the cases that need response.',
        'owasp': ['A09:2021 Security Logging and Monitoring Failures'],
        'cwe': ['CWE-778'],
        'stride': ['Repudiation', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-VERBOSE-ERRORS-001',
        'groups': [['stack trace', 'verbose error', 'detailed error', 'error messages reveal',
                    'debug mode', 'debug enabled', 'debug endpoint', 'exposes internal']],
        'category': 'Information Disclosure',
        'severity': 'medium',
        'control': 'error_handling_hygiene',
        'mitigation': 'Return a generic error to the caller, keep detail in server-side logs with a correlation id, and disable debug facilities outside development.',
        'owasp': ['A05:2021 Security Misconfiguration'],
        'cwe': ['CWE-209', 'CWE-489'],
        'stride': ['Information Disclosure'],
    },
    {
        'id': 'GENERIC-INPUT-VALIDATION-001',
        'groups': [['no input validation', 'not validated', 'without validation', 'unsanitized',
                    'not sanitized', 'no sanitization', 'string concatenation', 'dynamic sql',
                    'raw sql', 'user input directly', 'no schema validation', 'trusts client']],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'input_validation',
        'mitigation': 'Validate input server side against a schema with type, range and format checks, reject on failure, and treat client-supplied values as untrusted.',
        'owasp': ['A03:2021 Injection'],
        'cwe': ['CWE-20'],
        'stride': ['Tampering', 'Denial of Service', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-UNSCANNED-UPLOAD-001',
        'groups': [
            ['upload', 'attachment', 'document', 'file', 'ingested content', 'user content'],
            ['not scanned', 'no *scanning', 'without *scanning', 'unscanned', 'no malware',
             'no antivirus', 'no *virus scan', 'no content inspection', 'not inspected',
             'no file type validation', 'any file type', 'unrestricted upload'],
        ],
        'category': 'Tampering',
        'severity': 'high',
        'control': 'upload_scanning',
        'mitigation': 'Restrict accepted file types and sizes, scan every upload for malware before it is stored or indexed, store it outside the web root, and serve it from a separate origin.',
        'owasp': ['A04:2021 Insecure Design'],
        'cwe': ['CWE-434'],
        'stride': ['Tampering', 'Denial of Service', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-TENANT-ISOLATION-001',
        'groups': [
            ['tenant', 'workspace', 'customer', 'account', 'organization', 'project'],
            ['cross-tenant', 'another *tenant', 'another *customer', 'filter *after retrieval',
             'filter is applied *after', 'filter applied *after', 'no *tenant filter',
             'without *tenant filter', 'caller-provided tenant', 'client-supplied tenant',
             'model-provided tenant', 'tenant key *model', 'tenant scope *model',
             'not bound *authenticated', 'instead of binding *authenticated',
             'does not check ownership', 'without *ownership validation',
             'trusted without checking *authenticated tenant', 'trusts *tenant identifier',
             'tenant identifiers from requests', 'tenant id from *request'],
        ],
        'unless': ['does not trust', 'never trusts', 'identifiers are not trusted', 'tenant id from authenticated'],
        'category': 'Elevation of Privilege',
        'severity': 'critical',
        'control': 'tenant_isolation',
        'mitigation': 'Derive tenant scope from the authenticated identity, enforce it inside every query and retrieval operation before results are selected, and add cross-tenant negative tests.',
        'owasp': ['A01:2021 Broken Access Control'],
        'cwe': ['CWE-639', 'CWE-862'],
        'stride': ['Elevation of Privilege', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-INDIRECT-PROMPT-INJECTION-001',
        'groups': [
            ['retrieved content', 'retrieved document', 'retrieved ticket', 'support ticket',
             'tool output', 'external content', 'untrusted content'],
            ['inserted into *instruction', 'placed in *instruction', 'system instruction',
             'treated as instruction', 'without separating *instruction',
             'not separated from *instruction', 'highest-priority instruction',
             'executable direction', 'treated as executable', 'can instruct *agent'],
        ],
        'category': 'Tampering',
        'severity': 'critical',
        'control': 'untrusted_context_separation',
        'mitigation': 'Keep retrieved and tool-provided content in a clearly delimited untrusted-data channel, prevent it from changing system instructions, and independently authorize every consequential action.',
        'owasp': ['A03:2021 Injection', 'LLM01:2025 Prompt Injection'],
        'cwe': ['CWE-74'],
        'stride': ['Tampering', 'Elevation of Privilege', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-AGENT-TOOL-AUTHORIZATION-001',
        'groups': [
            ['tool call', 'tool argument', 'tool server', 'model chooses', 'model-selected',
             'generated by *model', 'model-generated argument', 'shell tool',
             'filesystem tool', 'command and path'],
            ['without *server-side authorization', 'no *server-side authorization',
             'does not authorize', 'neither authorizes', 'no *allowlist',
             'without *allowlist', 'not allowlisted', 'model controls *argument',
             'decide access *argument', 'decides access *argument',
             'rather than *authorizing', 'not independently authoriz'],
        ],
        'category': 'Elevation of Privilege',
        'severity': 'critical',
        'control': 'agent_tool_authorization',
        'mitigation': 'Authorize every tool invocation server side against the user, tenant, tool and exact arguments; use typed schemas and command, path and destination allowlists.',
        'owasp': ['A01:2021 Broken Access Control', 'LLM06:2025 Excessive Agency'],
        'cwe': ['CWE-862', 'CWE-78'],
        'stride': ['Elevation of Privilege', 'Tampering'],
    },
    {
        'id': 'GENERIC-DELEGATED-CREDENTIAL-SHARING-001',
        'groups': [
            ['token', 'credential', 'api key', 'access key', 'oauth grant'],
            ['reused across', 'reused for all', 'forwarded to multiple', 'shared across',
             'owner-scoped', 'one *token for all', 'same *token for',
             'same *credential', 'forwarded unchanged', 'forwarded *every'],
        ],
        'category': 'Spoofing',
        'severity': 'critical',
        'control': 'delegated_credential_isolation',
        'mitigation': 'Issue a least-privilege delegated credential per tenant, user and downstream server; use audience restriction and token exchange rather than forwarding an owner credential.',
        'owasp': ['A07:2021 Identification and Authentication Failures', 'A01:2021 Broken Access Control'],
        'cwe': ['CWE-522', 'CWE-269'],
        'stride': ['Spoofing', 'Elevation of Privilege', 'Information Disclosure', 'Repudiation'],
    },
    {
        'id': 'GENERIC-APPROVAL-BYPASS-001',
        'groups': [
            ['approval', 'human review', 'human confirmation'],
            ['only in the browser', 'ui only', 'client-side only', 'accepts direct call',
             'direct call *without', 'does not check *approving identity',
             'not bound to *argument', 'without binding *argument',
             'background retry', 'approval *declined', 'was declined', 'bypass',
             'no human approval', 'without human approval', 'human approval is not required'],
        ],
        'unless': ['cannot run without', 'does not execute without', 'requires human approval'],
        'category': 'Elevation of Privilege',
        'severity': 'critical',
        'control': 'server_side_action_approval',
        'mitigation': 'Enforce approval in the execution service, authenticate the approver, and cryptographically bind the approval to the tenant, action, target and exact arguments with a short expiry.',
        'owasp': ['A04:2021 Insecure Design', 'LLM06:2025 Excessive Agency'],
        'cwe': ['CWE-602', 'CWE-862'],
        'stride': ['Elevation of Privilege', 'Tampering', 'Repudiation'],
    },
    {
        'id': 'GENERIC-SENSITIVE-TELEMETRY-001',
        'groups': [
            ['trace', 'telemetry', 'log', 'logs', 'observability'],
            ['prompt', 'token', 'secret', 'credential', 'customer record', 'phi', 'pii', 'tool output'],
            ['retain', 'persist', 'store', 'contain', 'record complete', 'record full'],
        ],
        'category': 'Information Disclosure',
        'severity': 'high',
        'control': 'sensitive_telemetry_redaction',
        'mitigation': 'Minimize and redact prompts, credentials, retrieved records and tool output before telemetry leaves the workload; apply tenant-aware access control and short retention.',
        'owasp': ['A09:2021 Security Logging and Monitoring Failures'],
        'cwe': ['CWE-532'],
        'stride': ['Information Disclosure', 'Repudiation'],
    },
    {
        'id': 'GENERIC-MCP-PEER-AUTHENTICITY-001',
        'groups': [
            ['mcp server', 'mcp peer', 'tool server', 'agent server'],
            ['not mutually authenticated', 'no mutual authentication', 'server identity *not authenticated',
             'responses have no *signature', 'response is not signed', 'responses are not signed',
             'no *integrity signature', 'without *integrity protection',
             'without authenticating', 'without *authenticating',
             'without authenticating *or protecting',
             'without *message integrity', 'not protecting *integrity'],
        ],
        'category': 'Spoofing',
        'severity': 'high',
        'control': 'mcp_peer_authenticity_and_integrity',
        'mitigation': 'Mutually authenticate MCP peers, pin the expected server identity, protect responses in transit, and bind tool responses to the request with integrity and replay protection.',
        'owasp': ['A07:2021 Identification and Authentication Failures'],
        'cwe': ['CWE-287', 'CWE-345'],
        'stride': ['Spoofing', 'Tampering'],
    },
    {
        'id': 'GENERIC-REVOCABLE-SIGNED-LINK-001',
        'groups': [
            ['signed url', 'signed *url', 'signed link', 'signed *link',
             'presigned url', 'pre-signed url', 'download link'],
            ['remain valid *after', 'remains valid *after', 'cannot be revoked', 'no *revocation',
             'survives *revocation', 'valid after *disabled', 'valid after *deprovision'],
        ],
        'category': 'Spoofing',
        'severity': 'high',
        'control': 'revocable_resource_access',
        'mitigation': 'Use short-lived audience-bound links, re-check authorization at download time for sensitive objects, and provide server-side revocation on account or entitlement changes.',
        'owasp': ['A07:2021 Identification and Authentication Failures', 'A01:2021 Broken Access Control'],
        'cwe': ['CWE-613', 'CWE-639'],
        'stride': ['Spoofing', 'Elevation of Privilege', 'Information Disclosure'],
    },
    {
        'id': 'GENERIC-AGENT-RESOURCE-EXHAUSTION-001',
        'groups': [
            ['agent loop', 'tool loop', 'recursive agent', 'recursive tool', 'model loop',
             'agent run', 'tool-call', 'tool call budget', 'recursion'],
            ['no *token budget', 'no *concurrency', 'no *quota', 'unbounded',
             'without *budget', 'without *concurrency', 'without *quota',
             'no recursion', 'no *tool-call budget', 'no *tool call budget'],
        ],
        'category': 'Denial of Service',
        'severity': 'high',
        'control': 'agent_execution_budget',
        'mitigation': 'Enforce per-run step and token budgets, recursion depth, wall-clock deadlines, per-tenant concurrency and spend quotas, with cancellation and circuit breaking.',
        'owasp': ['A04:2021 Insecure Design', 'LLM10:2025 Unbounded Consumption'],
        'cwe': ['CWE-770'],
        'stride': ['Denial of Service'],
    },
    {
        'id': 'GENERIC-IMDSV2-001',
        'groups': [['ec2', 'instance metadata', 'imds'], ['do not require imdsv2', 'does not require imdsv2', 'imdsv1 is enabled', 'metadata tokens are optional', 'http_tokens = "optional"']],
        'category': 'Information Disclosure', 'severity': 'high',
        'control': 'metadata_token_enforcement',
        'mitigation': 'Require IMDSv2 tokens, restrict metadata hop limits, and prevent untrusted URL fetches from reaching instance metadata. Verify effective metadata options for each instance.',
        'owasp': ['A10:2021 Server-Side Request Forgery'], 'cwe': ['CWE-918'],
        'stride': ['Information Disclosure', 'Elevation of Privilege'],
    },
    {
        'id': 'GENERIC-CI-UNTRUSTED-WRITE-001',
        'groups': [['github actions', 'ci workflow', 'pipeline'], ['fork pull request', 'fork prs', 'fork pr', 'pull requests from forks'], ['write permissions', 'write-all', 'write token']],
        'unless': ['no write permissions', 'without write permissions', 'read-only token'],
        'category': 'Elevation of Privilege', 'severity': 'high',
        'control': 'untrusted_pipeline_isolation',
        'mitigation': 'Run untrusted fork code with read-only permissions on isolated runners. Review the event, checkout ref, effective job permissions and secret exposure before granting privileged follow-up actions.',
        'owasp': ['A08:2021 Software and Data Integrity Failures'], 'cwe': ['CWE-829'],
        'stride': ['Elevation of Privilege', 'Tampering'],
    },
]


# Fallback scope for a generic weakness that names no component of its own.
# Literal component evidence in the issue text always takes precedence over
# these types; they only prevent an unrelated component from being blamed.
GENERIC_SCOPE_TYPES: Dict[str, tuple] = {
    'GENERIC-IMDSV2-001': ('Compute',),
    'GENERIC-CI-UNTRUSTED-WRITE-001': ('CI/CD', 'Service'),
    'GENERIC-SQL-INJECTION-001': ('API', 'Service', 'API Gateway'),
    'GENERIC-COMMAND-INJECTION-001': ('Service', 'Worker', 'API'),
    'GENERIC-XSS-001': ('WebClient', 'API', 'Service'),
    'GENERIC-SSRF-001': ('Service', 'API', 'Worker'),
    'GENERIC-CSRF-001': ('WebClient', 'API', 'API Gateway'),
    'GENERIC-MISSING-INTEGRITY-VERIFICATION-001': ('API', 'Service', 'Worker'),
    'GENERIC-DEFAULT-CREDENTIALS-001': ('Identity Provider', 'Database', 'Service'),
    'GENERIC-SECRET-EXPOSURE-001': ('Secrets Manager', 'Service', 'API', 'Container Platform'),
    'GENERIC-ENCRYPTION-AT-REST-001': ('Database', 'Object Storage', 'Data Warehouse'),
    'GENERIC-ENCRYPTION-IN-TRANSIT-001': ('API Gateway', 'Load Balancer', 'API', 'Service'),
    'GENERIC-WEAK-CRYPTOGRAPHY-001': ('Service', 'API', 'Identity Provider'),
    'GENERIC-MISSING-MFA-001': ('Identity Provider', 'WebClient', 'API Gateway'),
    'GENERIC-MISSING-AUTHENTICATION-001': ('API', 'API Gateway', 'Service'),
    'GENERIC-MISSING-AUTHORIZATION-001': ('API', 'API Gateway', 'Service'),
    'GENERIC-EXCESSIVE-PRIVILEGE-001': ('IAM', 'Service', 'Container Platform'),
    'GENERIC-CREDENTIAL-ROTATION-001': ('Secrets Manager', 'Identity Provider', 'Service'),
    'GENERIC-LOG-INTEGRITY-001': ('Monitoring', 'Database', 'Service'),
    'GENERIC-SHARED-IDENTITY-001': ('Service', 'Identity Provider', 'API'),
    'GENERIC-SESSION-LIFETIME-001': ('Identity Provider', 'API', 'Service'),
    'GENERIC-PUBLIC-EXPOSURE-001': ('Load Balancer', 'API Gateway', 'Object Storage', 'Database'),
    'GENERIC-NETWORK-SEGMENTATION-001': ('Container Platform', 'Service', 'Database'),
    'GENERIC-OUTDATED-COMPONENT-001': ('Service', 'API', 'Container Platform'),
    'GENERIC-RATE-LIMITING-001': ('API Gateway', 'API', 'Service'),
    'GENERIC-AUDIT-LOGGING-001': ('Monitoring', 'Service', 'API'),
    'GENERIC-VERBOSE-ERRORS-001': ('API', 'Service', 'WebClient'),
    'GENERIC-INPUT-VALIDATION-001': ('API', 'Service', 'API Gateway'),
    'GENERIC-UNSCANNED-UPLOAD-001': ('Object Storage', 'Service', 'API'),
    'GENERIC-TENANT-ISOLATION-001': ('API', 'Service', 'Database', 'ML Service'),
    'GENERIC-INDIRECT-PROMPT-INJECTION-001': ('ML Service', 'MCP Server', 'Service'),
    'GENERIC-AGENT-TOOL-AUTHORIZATION-001': ('ML Service', 'MCP Server', 'Service', 'Worker'),
    'GENERIC-DELEGATED-CREDENTIAL-SHARING-001': ('MCP Server', 'ML Service', 'Service'),
    'GENERIC-APPROVAL-BYPASS-001': ('Service', 'API', 'ML Service'),
    'GENERIC-SENSITIVE-TELEMETRY-001': ('Monitoring', 'ML Service', 'Service'),
    'GENERIC-MCP-PEER-AUTHENTICITY-001': ('MCP Server', 'ML Service'),
    'GENERIC-REVOCABLE-SIGNED-LINK-001': ('Object Storage', 'API', 'Service'),
    'GENERIC-AGENT-RESOURCE-EXHAUSTION-001': ('ML Service', 'MCP Server', 'Service'),
}


GENERIC_WEAKNESS_RULES_BY_ID: Dict[str, Dict[str, Any]] = {
    rule['id']: rule for rule in GENERIC_WEAKNESS_RULES
}


# The component properties that express each control. A weakness reaches a
# report twice when the sentence stating it is classified here and the property
# it sets also matches a knowledge-base predicate; this mapping lets the second
# route recognise the first and stay quiet.
CONTROL_PROPERTIES: Dict[str, tuple] = {
    'metadata_token_enforcement': ('imdsv2_required',),
    'untrusted_pipeline_isolation': ('untrusted_pipeline_isolation',),
    'encryption_at_rest': ('encryption_at_rest',),
    'encryption_in_transit': ('encryption_in_transit', 'mtls_enabled'),
    'multi_factor_authentication': ('mfa_enabled',),
    'authentication_required': ('auth_type',),
    'authorization_enforcement': ('rbac_enabled',),
    'rate_limiting': ('rate_limiting',),
    'input_validation': ('input_validation',),
    'audit_logging_and_alerting': ('logging_enabled', 'audit_logging', 'monitoring_enabled'),
    'managed_secret_storage': ('secrets_management',),
    'payload_authenticity_verification': ('webhook_signature_validation',),
    'network_segmentation': ('network_policies',),
    'network_exposure_reduction': ('public_access', 'private_subnet'),
    'upload_scanning': ('content_type_validation',),
    'output_encoding': ('html_sanitization',),
    'csrf_tokens': ('csrf_protection',),
    'session_lifetime_and_revocation': ('absolute_timeout',),
    'log_integrity_protection': ('log_integrity',),
    'approved_cryptography': ('kms_enabled',),
    'tenant_isolation': ('tenant_isolation', 'object_level_auth'),
    'untrusted_context_separation': ('untrusted_context_separation',),
    'agent_tool_authorization': ('tool_authorization',),
    'delegated_credential_isolation': ('delegated_authorization',),
    'server_side_action_approval': ('human_approval',),
    'sensitive_telemetry_redaction': ('sensitive_log_redaction',),
    'mcp_peer_authenticity_and_integrity': ('mtls_enabled', 'message_validation'),
    'revocable_resource_access': ('token_revocation',),
    'agent_execution_budget': ('rate_limiting', 'concurrency_limits'),
}


_INFLECTION = r'(?:s|es|ies|ing|ed|d|y)?'


@lru_cache(maxsize=2048)
def _compile(phrase: str) -> 're.Pattern[str]':
    strict = phrase.endswith('!')
    text = phrase[:-1] if strict else phrase
    body = re.escape(text).replace(r'\*', r'(?:\w+[\s-]+){0,3}')
    prefix = r'\b' if text[:1].isalnum() or text[:1] == '_' else ''
    if not (text[-1:].isalnum() or text[-1:] == '_'):
        suffix = ''
    else:
        # A trailing inflection keeps "credentials" and "rate limiting"
        # matchable. Strict phrases opt out where a longer word would be a
        # different meaning, as in "over http" against "over https".
        suffix = r'\b' if strict else _INFLECTION + r'\b'
    return re.compile(f'{prefix}{body}{suffix}')


def classify_generic_weaknesses(issue_text: str) -> List[Dict[str, Any]]:
    """Return every generic weakness class the text matches.

    One sentence can state two weaknesses: "the service has no rate limiting and
    prompts are not validated" is a denial-of-service gap and a validation gap,
    and reporting only the first would silently drop the second.
    """
    text = (issue_text or '').lower()
    if not text:
        return []
    matches = [
        rule for rule in GENERIC_WEAKNESS_RULES
        if all(
            any(_compile(phrase).search(text) for phrase in group)
            for group in rule['groups']
        )
        # A narrower weakness is not the broader one. "No multi-factor
        # authentication" is a second-factor gap, not an absence of
        # authentication, and reporting both would overstate the finding.
        and not any(_compile(phrase).search(text) for phrase in rule.get('unless', ()))
    ]
    # Domain-specific rules outrank a broader class that happens to share words
    # such as "authorization". List order remains the tie-breaker so existing
    # catalog behaviour is stable.
    return sorted(matches, key=lambda rule: rule.get('priority', 100 if rule['id'].startswith((
        'GENERIC-TENANT-', 'GENERIC-INDIRECT-', 'GENERIC-AGENT-', 'GENERIC-DELEGATED-',
        'GENERIC-APPROVAL-', 'GENERIC-SENSITIVE-', 'GENERIC-MCP-', 'GENERIC-REVOCABLE-',
    )) else 0), reverse=True)


def classify_generic_weakness(issue_text: str) -> Optional[Dict[str, Any]]:
    """Return the first generic weakness class the text matches, if any."""
    matches = classify_generic_weaknesses(issue_text)
    return matches[0] if matches else None
