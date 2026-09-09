"""Reads security controls out of prose together with the polarity of the claim.

Naming a control is not evidence that the control exists: "the portal has no
MFA" mentions MFA in order to deny it. Detection therefore reads a polarity per
clause rather than testing whether a word appears, and one vocabulary answers
both questions, so a control cannot be recognised when it is claimed and missed
when it is denied.

Polarity is decided from the clause the term sits in:

* a cue before the term denies it ("no MFA", "without encryption", "lacks
  logging"), provided nothing between the cue and the term starts a new
  predicate - "the portal has no MFA, and the API enforces rate limiting"
  denies MFA only;
* a cue immediately after the term denies it ("MFA is not enforced", "logging
  is disabled"), provided the negation attaches to the term's own verb -
  "MFA is enforced and sessions do not expire" still affirms MFA;
* a term that is a denial in itself ("unencrypted", "unauthenticated") denies
  its control wherever it appears.

Anything else affirms, which preserves the long-standing reading that mentioning
a control in an architecture description claims it is present.
"""

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, FrozenSet, List, Tuple

from .prose import divide_on_new_subject, unwrap

#: Control property -> the phrases an architecture description uses for it.
#: This is the single vocabulary: whatever can be credited here can also be
#: denied here, which is what stops a stated absence becoming an assurance.
CONTROL_TERMS: Dict[str, Tuple[str, ...]] = {
    'encryption_at_rest': ('encrypted', 'encrypts', 'encryption at rest', 'tde',
                           'transparent data encryption'),
    'encryption_in_transit': ('https', 'tls', 'ssl'),
    'mtls_enabled': ('mtls', 'mutual tls', 'mutual authentication'),
    'kms_enabled': ('kms', 'key management', 'customer-managed key'),
    'logging_enabled': ('logging', 'logs', 'audit log', 'audit trail', 'audit'),
    'centralized_logging': ('cloudwatch', 'datadog', 'splunk', 'elk', 'log aggregation'),
    'audit_logging': ('cloudtrail', 'audit logging'),
    'monitoring_enabled': ('monitoring', 'monitored'),
    'threat_detection': ('guardduty', 'threat detection', 'intrusion detection'),
    'waf_enabled': ('waf', 'web application firewall'),
    'rate_limiting': ('rate limit', 'rate limiting', 'throttling', 'throttle', 'quota'),
    'input_validation': ('input validation', 'sanitization', 'schema validation'),
    'rbac_enabled': ('rbac', 'role-based access control', 'role based access control'),
    'mfa_enabled': ('mfa', 'multi-factor', 'multi factor', 'multifactor', '2fa',
                    'two-factor', 'second factor'),
    'service_mesh': ('service mesh', 'istio', 'linkerd'),
    'zero_trust': ('zero trust', 'zero-trust'),
    'private_subnet': ('private subnet', 'private network'),
    'signed_urls': ('signed url', 'pre-signed url', 'presigned url'),
    'webhook_signature_validation': ('webhook signature', 'signature validation',
                                     'hmac signature'),
    'dlp_enabled': ('dlp', 'data loss prevention'),
    'secrets_management': ('vault', 'key vault', 'secrets manager', 'secret store',
                           'secrets store'),
    'query_depth_limiting': ('query depth limit', 'depth limiting', 'query complexity limit',
                             'query cost limit'),
    'container_image_scanning': ('image scanning', 'container scanning', 'ecr scanning',
                                 'trivy', 'clair'),
    'backup_enabled': ('backup', 'glacier', 'snapshot'),
    'prompt_sanitization': ('prompt sanitization', 'prompt filtering'),
    'output_validation': ('output validation', 'output filtering'),
    'network_policies': ('network polic', 'network segmentation', 'microsegmentation'),
    'content_type_validation': ('content-type validation', 'content type validation'),
    'csrf_protection': ('csrf token', 'anti-csrf', 'csrf protection'),
    'html_sanitization': ('html sanitization', 'output encoding'),
    'csp_header': ('content security policy', 'csp'),
    'ssrf_protection': ('ssrf protection', 'outbound url validation', 'destination allowlist'),
    'request_size_limit': ('request size limit', 'body size limit', 'payload size limit'),
    'concurrency_limits': ('concurrency limit', 'concurrent request limit'),
    'token_revocation': ('token revocation', 'session revocation'),
    'tenant_isolation': ('tenant isolation', 'server-derived tenant scope', 'tenant ownership validation'),
    'object_level_auth': ('object-level authorization', 'object level authorization', 'resource ownership check'),
    'log_integrity': ('log integrity', 'tamper-evident audit', 'immutable audit', 'audit log signing'),
    'message_validation': ('message validation', 'message signature verification'),
    'versioning_enabled': ('object versioning', 'bucket versioning'),
    'code_signing': ('code signing', 'artifact signature verification'),
    'training_data_validation': ('training data validation', 'dataset integrity validation'),
    'local_encryption': ('local storage encryption', 'device storage encryption'),
    'tool_authorization': ('tool authorization', 'tool invocation authorization'),
    'human_approval': ('human approval', 'server-side action approval'),
    'delegated_authorization': ('audience-bound delegation', 'per-tenant delegated credentials'),
    'sensitive_log_redaction': ('sensitive log redaction', 'telemetry redaction'),
    'idempotency_enforced': ('idempotency enforcement', 'idempotency key validation'),
    'payment_amount_binding': ('payment amount binding', 'server-side amount validation'),
    'consent_enforcement': ('consent enforcement', 'patient consent validation'),
    'emergency_access_auditing': ('emergency access auditing', 'break-glass auditing'),
    'workload_identity': ('workload identity', 'managed workload identity'),
    'untrusted_context_separation': ('untrusted context separation', 'retrieval instruction isolation'),
    'egress_allowlist': ('egress allowlist', 'outbound destination allowlist'),
    'memory_isolation': ('agent memory isolation', 'per-tenant agent memory'),
    'jwt_issuer_validation': ('jwt issuer validation', 'token issuer validation'),
    'jwt_audience_validation': ('jwt audience validation', 'token audience validation'),
    'account_linking_verification': ('account linking verification', 'verified account linking'),
    'audit_identity_binding': ('audit identity binding', 'per-user audit attribution'),
    'deletion_auditing': ('deletion auditing', 'data deletion audit'),
    'administrative_auditing': ('administrative action auditing', 'administrator activity auditing'),
    'tool_call_auditing': ('tool call auditing', 'agent action auditing'),
    'refund_auditing': ('refund auditing', 'refund audit trail'),
    'export_authorization': ('bulk export authorization', 'export authorization'),
    'replay_protection': ('replay protection', 'webhook replay prevention'),
    'imdsv2_required': ('imdsv2 enforcement', 'required metadata tokens'),
    'key_policy_restriction': ('key policy restriction', 'kms principal restriction'),
    'workload_federation_restriction': ('federated subject restriction', 'workload federation restriction'),
    'backup_restore_testing': ('backup restore testing', 'recovery testing'),
    'parameterized_queries': ('parameterized queries', 'parameterised queries', 'prepared statements', 'query parameter binding'),
    'nosql_operator_validation': ('nosql operator validation',),
    'command_argument_isolation': ('command argument isolation',),
    'path_canonicalization': ('path canonicalization',),
    'xml_external_entities_disabled': ('xml external entity blocking',),
    'safe_deserialization': ('safe deserialization',),
    'fail_closed_error_handling': ('fail-closed error handling',),
    'atomic_state_transitions': ('atomic state transitions',),
    'oauth_pkce': ('oauth pkce', 'pkce', 'proof key for code exchange'),
    'redirect_uri_validation': ('exact redirect uri validation',),
    'session_id_rotation': ('session id rotation', 'session identifier rotation'),
    'account_recovery_verification': ('account recovery verification',),
    'function_level_authorization': ('function-level authorization',),
    'property_level_authorization': ('property-level authorization',),
    'tenant_cache_isolation': ('tenant cache isolation', 'tenant-scoped cache keys'),
    'tenant_job_isolation': ('tenant job isolation',),
    'payment_state_validation': ('payment state validation',),
    'payment_reconciliation': ('payment reconciliation',),
    'dependency_integrity_verification': ('dependency integrity verification',),
    'build_provenance_verification': ('build provenance verification',),
    'untrusted_build_isolation': ('untrusted build isolation', 'isolated build runners'),
    'cross_account_external_id': ('cross-account external id validation',),
    'key_deletion_protection': ('key deletion protection',),
    'origin_access_restriction': ('origin access restriction',),
    'pod_security_enforcement': ('pod security enforcement', 'pod security admission'),
    'service_account_token_scoping': ('service account token scoping',),
    'agent_execution_sandbox': ('agent execution sandbox', 'sandboxed tool execution'),
    'mcp_tool_integrity': ('mcp tool definition integrity',),
    'agent_memory_integrity': ('agent memory integrity',),
    'inter_agent_authentication': ('inter-agent authentication',),
    'agent_resource_budget': ('agent resource budget',),
    'agent_circuit_breaker': ('agent circuit breaker',),
    'retention_enforcement': ('retention enforcement',),
    'restore_authorization': ('restore authorization',),
    'verified_boot': ('verified boot',),
    'unique_device_credentials': ('unique device credentials',),
}

#: Terms that deny their control by themselves, whatever surrounds them.
DENIAL_TERMS: Dict[str, Tuple[str, ...]] = {
    'encryption_at_rest': ('unencrypted', 'stored in plaintext', 'stored in plain text'),
    'encryption_in_transit': ('cleartext', 'clear text', 'plain http', 'unencrypted traffic',
                              'unencrypted connection'),
}

#: Affirming one of these implies the other is claimed too. Denial never
#: propagates: no Splunk is not the absence of logging.
IMPLIED_BY: Dict[str, Tuple[str, ...]] = {
    'centralized_logging': ('logging_enabled',),
    'audit_logging': ('logging_enabled',),
}

# A contrastive connector ends the reach of a negation: what follows it is a
# separate claim, not more of the same one.
_CLAUSE_BREAK = re.compile(
    r'(?<=[.!?;:])\s+|[\r\n]+|\s+(?:but|however|whereas|although|though|while|yet)\s+|\s+-\s+',
    re.IGNORECASE,
)

_NEGATION_CUE = re.compile(
    r"(?<![a-z0-9])(?:no|not|none|never|without|lack|lacks|lacking|lacked|missing|absent|"
    r"neither|nor|omits|omitted|disabled|unprotected|bypasses|bypassed|skips|skipped|"
    r"n't|fails to|failed to)(?![a-z0-9])",
    re.IGNORECASE,
)

# "does not require MFA": an auxiliary before "not" shows the negation governs
# the verb that follows it, so that verb is part of the denial rather than a new
# claim. This is true of verbal negation only: in "has no MFA, and the gateway
# enforces rate limiting" the "no" belongs to its noun and reaches no further.
_GOVERNS_NEXT_VERB = re.compile(
    r"(?:does|do|did|is|are|was|were|can|could|will|would|has|have|had|shall|should|may|might)\s+$",
    re.IGNORECASE,
)
_VERBAL_CUES = frozenset({'not', "n't", 'never'})

# Material that may sit between a cue and the term it denies: articles,
# quantifiers, conjunctions, prepositions and the nouns of the thing itself.
# A finite verb may not, because it begins a claim of its own.
_PREDICATE = re.compile(
    r"(?<![a-z0-9])(?:is|are|was|were|be|been|being|enforces?|enforced|enables?|enabled|"
    r"uses?|used|requires?|required|has|have|had|implements?|implemented|configures?|configured|"
    r"provides?|provided|protects?|protected|encrypts?|encrypted|validates?|validated|"
    r"verifies|verified|applies|applied|terminates?|terminated|logs|logged|scans?|scanned|"
    r"monitors?|monitored|restricts?|restricted|supports?|supported|stores?|stored|sends?|sent|"
    r"calls?|called|routes?|routed|writes?|written|reads?|sits?|runs?|deploys?|deployed|"
    r"authenticates?|authorises?|authorizes?|signs?|signed|rotates?|rotated)(?![a-z0-9])",
    re.IGNORECASE,
)

# A denial that attaches to the term's own verb. Between the term and the verb
# only the rest of the term's noun phrase may stand, so "multi-factor
# authentication is not available" is a denial while "MFA is enforced and
# sessions do not expire" is not.
_NOUN_PHRASE_TAIL = (
    r"(?:\s+(?:authentication|auth|authorisation|authorization|access|control|controls|"
    r"encryption|logging|logs|log|protection|validation|verification|scanning|scans|"
    r"enforcement|policy|policies|token|tokens|key|keys|check|checks|header|headers|"
    r"limiting|limits|rules?|traffic|at rest|in transit)){0,3}"
)
_POST_DENIAL = re.compile(
    r"^" + _NOUN_PHRASE_TAIL + r"\s*(?:\([^)]*\)\s*)?"
    r"(?:(?:is|are|was|were|does|do|did|has|have|had|will|would|can|could|remains?|stays?|"
    r"gets?|appears?|seems?)\s+)?"
    r"(?:(?:currently|presently|still|yet|also|always|ever|actually|really)\s+)?"
    r"(?:not(?![a-z])|never(?![a-z])|n't|no longer|disabled|missing|absent|off(?![a-z])|"
    r"lacking|unavailable|nonexistent|non-existent|unenforced|unconfigured|unimplemented|"
    r"neither|nowhere)",
    re.IGNORECASE,
)

# A comma followed by a new noun phrase starts a separate claim, so a negation
# before it does not reach the controls after it: "no MFA on the portal, the
# audit log is writable" denies MFA and says nothing about logging. A bare list
# under one negation has no determiner, which keeps "without MFA, TLS or rate
# limiting" denying all three.
_NEW_CLAUSE_AFTER_COMMA = re.compile(
    r",\s*(?:the|a|an|its|their|our|his|her|this|that|these|those|all|every|each)(?![a-z])",
    re.IGNORECASE,
)

_INFLECTION = r'(?:s|es|ies|ing|ed|d|y)?'

_LOOKBACK = 60
_LOOKAHEAD = 48


@dataclass(frozen=True)
class ControlStatement:
    """One claim about one control, and the clause that made it."""

    control: str
    affirmed: bool
    clause: str


@dataclass(frozen=True)
class ControlReading:
    """What a piece of text claims about security controls."""

    affirmed: FrozenSet[str]
    denied: FrozenSet[str]

    def affirms(self, control: str) -> bool:
        # A denial outranks a claim for the same control in the same text: the
        # sentence that bothered to say a control is absent is the one carrying
        # security meaning, and the claim is usually the same words being read
        # a second time.
        return control in self.affirmed and control not in self.denied

    def denies(self, control: str) -> bool:
        return control in self.denied

    def value(self, control: str):
        """True, False, or None when the text says nothing about the control."""
        if control in self.denied:
            return False
        if control in self.affirmed:
            return True
        return None

    def conflicts(self, control: str) -> bool:
        return control in self.affirmed and control in self.denied


@lru_cache(maxsize=4096)
def _term_pattern(term: str) -> 're.Pattern[str]':
    body = re.escape(term).replace(r'\ ', r'[\s-]+')
    suffix = _INFLECTION if term[-1:].isalnum() else ''
    return re.compile(rf'(?<![a-z0-9]){body}{suffix}(?![a-z0-9])', re.IGNORECASE)


def _clauses(text: str) -> List[str]:
    # Wrapping is undone first: a claim broken at the margin still names its
    # subject, and reading the fragments separately loses it. A conjunction that
    # hands the sentence to a new subject then ends the clause as surely as a
    # contrastive one does - "the portal has no MFA and the bucket is not
    # encrypted" is two claims, and read as one the second was attributed to the
    # portal, because the portal is the first component the clause names.
    return [
        clause
        for segment in _CLAUSE_BREAK.split(unwrap(text or ''))
        for clause in divide_on_new_subject(segment)
        if clause and clause.strip()
    ]


def _denied_before(clause: str, start: int) -> bool:
    window = clause[max(0, start - _LOOKBACK):start]
    for cue in reversed(list(_NEGATION_CUE.finditer(window))):
        between = window[cue.end():]
        cue_word = cue.group(0).lower()
        verbal = cue_word in _VERBAL_CUES and bool(_GOVERNS_NEXT_VERB.search(window[:cue.start()]))
        if verbal or cue_word == 'without':
            # The negated auxiliary or the preposition already owns the verb
            # that follows it, as in "does not require MFA" or "without using
            # TLS", so that verb does not end the denial.
            between = _PREDICATE.sub(' ', between, count=1)
        if _PREDICATE.search(between) or _NEW_CLAUSE_AFTER_COMMA.search(between):
            continue
        return True
    return False


def _denied_after(clause: str, end: int) -> bool:
    return bool(_POST_DENIAL.match(clause[end:end + _LOOKAHEAD]))


def statements(text: str) -> List[ControlStatement]:
    """Every control claim in the text, with the clause that carries it."""
    found: List[ControlStatement] = []
    for clause in _clauses(text):
        if non_assertion(clause):
            continue
        for control, terms in DENIAL_TERMS.items():
            if any(_term_pattern(term).search(clause) for term in terms):
                found.append(ControlStatement(control, False, clause.strip()))
        for control, terms in CONTROL_TERMS.items():
            for term in terms:
                for match in _term_pattern(term).finditer(clause):
                    denied = (
                        _denied_before(clause, match.start())
                        or _denied_after(clause, match.end())
                    )
                    found.append(ControlStatement(control, not denied, clause.strip()))
    return found


def non_assertion(clause: str) -> bool:
    """A comparison of controls does not claim their deployment state."""
    return bool(re.search(r'\b(?:does? not|cannot|can not|neither|not a (?:complete )?substitute)\b.*\b(?:prove|proves|guarantee|guarantees|substitute|replace|replacement)\b', clause, re.I)
        or re.search(r'\bnot a (?:complete )?substitute\b', clause, re.I))


@lru_cache(maxsize=1024)
def read(text: str) -> ControlReading:
    """Summarise what the text claims, control by control."""
    affirmed = set()
    denied = set()
    for statement in statements(text):
        if statement.affirmed:
            affirmed.add(statement.control)
            affirmed.update(IMPLIED_BY.get(statement.control, ()))
        else:
            denied.add(statement.control)
    return ControlReading(frozenset(affirmed), frozenset(denied))
