"""Versionable, declarative pre-DFD questions. No expressions or code execution."""

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..engine.control_contracts import presence
from ..engine.source_correlation import control_dependency_digest, normalize_environment
from .model_review import CONTROL_TERMS, EXTRA_CONTROLS, STRING_CONTROLS

APPLICATION_TYPES = {'ui': 'UI', 'frontend': 'Frontend', 'backend': 'Backend',
    'web': 'Web application', 'mobile': 'Mobile application', 'api': 'API or service', 'other': 'Other'}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class QuestionCondition(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question_key: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    values: list[str] = Field(min_length=1, max_length=30)
    scope: Literal['assessment', 'same_component'] = 'assessment'


class Question(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    text: str = Field(min_length=5, max_length=1000)
    section: str = Field(default='Architecture', min_length=1, max_length=100)
    answer_type: Literal['text', 'choice', 'number', 'control'] = 'control'
    required: bool = True
    application_types: list[str] = Field(default_factory=list, max_length=7)
    component_types: list[str] = Field(default_factory=list, max_length=30)
    control: str = Field(default='', max_length=100)
    options: list[str] = Field(default_factory=list, max_length=30)
    priority: Literal['high', 'normal', 'low'] = 'normal'
    technologies: list[str] = Field(default_factory=list, max_length=30)
    when: QuestionCondition | None = None

    @model_validator(mode='after')
    def valid_mapping(self):
        if not set(self.application_types) <= APPLICATION_TYPES.keys():
            raise ValueError('Unsupported application type.')
        if self.control and self.control not in set(CONTROL_TERMS) | EXTRA_CONTROLS | STRING_CONTROLS:
            raise ValueError('Unsupported security control mapping.')
        if self.control and (not self.component_types or self.control == 'protocol'):
            raise ValueError('Control mappings require scoped component types; flow protocols are edited in the DFD.')
        if self.control and (self.answer_type != 'control' or self.control in STRING_CONTROLS):
            raise ValueError('Only state-valued control questions can map to component controls.')
        if self.answer_type == 'choice' and not self.options:
            raise ValueError('Choice questions require options.')
        if any(not x.strip() or len(x) > 200 for x in [*self.component_types, *self.options, *self.technologies]):
            raise ValueError('Question options and component types must be nonempty and bounded.')
        return self


class TemplateInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=200)
    questions: list[Question] = Field(min_length=1, max_length=100)
    expected_revision: int = Field(default=0, ge=0)

    @model_validator(mode='after')
    def unique_keys(self):
        if len({q.key for q in self.questions}) != len(self.questions):
            raise ValueError('Question keys must be unique within a template.')
        previous = {}
        for q in self.questions:
            if q.when:
                parent = previous.get(q.when.question_key)
                if not parent:
                    raise ValueError('Conditional questions must reference an earlier question; cycles are not allowed.')
                if q.when.scope == 'assessment' and parent.component_types:
                    raise ValueError('An assessment condition must reference an assessment-level question.')
                if q.when.scope == 'same_component' and (not q.component_types or not parent.component_types):
                    raise ValueError('Same-component conditions require component-scoped questions.')
                allowed = {'present', 'absent', 'partial', 'unknown', 'not_applicable'} if parent.answer_type == 'control' else set(parent.options) | {'unknown'}
                if parent.answer_type not in {'control', 'choice'} or not set(q.when.values) <= allowed:
                    raise ValueError('Conditions must use declared control or choice answers.')
            previous[q.key] = q
        return self


class QuestionResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question_id: str = Field(min_length=1, max_length=600)
    value: str = Field(min_length=1, max_length=3000)
    note: str = Field(default='', max_length=3000)
    evidence_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_ids: list[str] = Field(default_factory=list, max_length=20)
    basis: Literal['manual', 'source', 'carry_forward'] = 'manual'
    proposal_digest: str = Field(default='', max_length=64)
    owner: str = Field(default='', max_length=200)


_TEXT_HINTS = {
    'actors': r'\b(?:users?|subscribers?|customers?|operators?|administrators?|partners?)\b',
    'entry-points': r'\b(?:public|private|internet|partner-facing|ingress|entry point)\b',
    'data': r'\b(?:pii|phi|sensitive|personal|addresses|telephone|payment|credentials|invoices|usage records)\b',
    'integrations': r'\b(?:integrat\w*|external|third.party|partner|stripe|sendgrid|cognito|identity provider)\b',
}


def _eligible_sources(payload):
    return {s.id: s for s in payload.sources if s.included and s.metadata.get('role') != 'reference_report'
            and (not normalize_environment(s.environment) or normalize_environment(s.environment) == normalize_environment(payload.environment))
            and (not s.metadata.get('deployment_version') or s.metadata['deployment_version'] == payload.deployment_version)}


def _proposal(row, value, evidence, basis='source', previous=None):
    sources = sorted({e['source_id'] for e in evidence if e.get('source_id')})
    note = '\n'.join(f"{e.get('document', e.get('source_id', ''))}{':' + str(e['line']) if e.get('line') else ''}: {e.get('statement', '')}" for e in evidence)[:3000]
    result = {'value': value, 'note': note, 'source_ids': sources, 'evidence': evidence,
              'basis': basis, 'previous': previous}
    result['digest'] = fingerprint([row['id'], row['evidence_digest'], result])
    return result


def _source_proposal(row, target, sources, source_texts):
    if target and row['control']:
        control = row['control']
        assertion = target.properties.get('control_assertions', {}).get(control)
        row['conflicting'] = assertion == 'conflicting'
        row['evidence'] = [e for e in target.properties.get('correlation_evidence', []) if e.get('control') == control]
        row['requires_individual_review'] = row['conflicting'] or any(
            e.get('scope', {}).get('endpoints') or e.get('scope', {}).get('workflow_restricted')
            or e.get('applicable') is False for e in row['evidence'])
        records = [e for e in target.properties.get('control_evidence', {}).get(control, [])
                   if e.get('source_id') in sources and e.get('applicable', True)
                   and e.get('kind') == 'control' and e.get('control') == control and e.get('element_id') == target.id
                   and not e.get('scope', {}).get('endpoints') and not e.get('scope', {}).get('workflow_restricted')
                   and e.get('state') in {'present', 'absent'} and e.get('statement')
                   and ' '.join(e['statement'].casefold().split()) in source_texts[e['source_id']]]
        states = {e['state'] for e in records}
        state = presence(target.properties.get(control))
        # A property without a matching citation may be parser inference. Never
        # turn it into a batch-confirmable claim about a deployed control.
        if not row['requires_individual_review'] and assertion not in {'conflicting', 'partial', 'planned', 'unknown'} and len(states) == 1 and state is not None:
            value = 'present' if state else 'absent'
            if states == {value} and len({e['source_id'] for e in records}) <= 20:
                return _proposal(row, value, records)
    elif row['answer_type'] == 'text' and row['key'] in _TEXT_HINTS:
        evidence = []
        for source in sources.values():
            for number, line in enumerate(source.text.splitlines(), 1):
                if len(line.strip()) > 12 and re.search(_TEXT_HINTS[row['key']], line, re.I):
                    evidence.append({'source_id': source.id, 'document': source.name, 'line': number, 'statement': line.strip()[:700]})
                    if len(evidence) == 5:
                        break
            if len(evidence) == 5:
                break
        if evidence:
            return _proposal(row, '\n'.join(e['statement'] for e in evidence)[:3000], evidence)
    return None


def _reusable_control_context(architecture, target, control):
    # The release label itself changes on a clone. Keep explicit claim scopes,
    # environment, identity and incident flows; none of these are inherited away.
    return [target.id, target.type, target.trust_level,
            {k: target.properties.get(k) for k in ('environment', 'cloud_account', 'tenant_id', control)},
            [e for e in target.properties.get('correlation_evidence', []) if e.get('control') == control],
            sorted((f.source_id, f.target_id, f.protocol, f.data_type) for f in architecture.flows if target.id in {f.source_id, f.target_id})]


def default_template():
    questions = [
        {'key': 'actors', 'text': 'Which users, administrators and external systems interact with this application?', 'answer_type': 'text', 'priority': 'high'},
        {'key': 'entry-points', 'text': 'Which interfaces are public, private or partner-facing?', 'answer_type': 'text', 'priority': 'high'},
        {'key': 'data', 'text': 'Which sensitive data is processed, stored or sent to third parties?', 'answer_type': 'text', 'priority': 'high'},
    ]
    services = ['Service', 'API', 'API Gateway', 'Web Application', 'Identity Provider']
    for key, text, types in [
        ('authentication', 'Is authentication enforced, and for which operations?', services),
        ('authorization', 'Are resource-level authorization and tenant checks enforced?', services),
        ('input_validation', 'Is untrusted input validated before processing or database access?', services),
        ('rate_limiting', 'Are request limits enforced on exposed and expensive operations?', services),
        ('token_revocation', 'Are sessions revoked on password changes and account disablement?', ['Identity Provider', 'API', 'Service']),
        ('audit_logging', 'Are sensitive access and administrative changes recorded in audit logs?', services + ['Database']),
        ('encryption_at_rest', 'Is sensitive stored data encrypted at rest?', ['Database', 'Object Storage', 'Cache']),
        ('least_privilege', 'Are workload identities and permissions scoped to least privilege?', ['Compute', 'Service', 'API', 'ML Service']),
    ]:
        # Authentication is represented by the existing authenticated contract.
        control = 'authenticated' if key == 'authentication' else key
        questions.append({'key': key.replace('_', '-'), 'text': text, 'section': 'Security controls',
            'answer_type': 'control', 'component_types': types, 'control': control,
            'priority': 'high' if key in {'authentication', 'authorization', 'token_revocation'} else 'normal'})
    questions.extend([
        {'key': 'mobile', 'text': 'How are local credentials, device storage and mobile API access protected?', 'answer_type': 'text', 'application_types': ['mobile'], 'section': 'Mobile'},
        {'key': 'integrations', 'text': 'Which third-party, AI, payment or partner integrations exist, and who owns their access?', 'answer_type': 'text', 'section': 'Integrations'},
    ])
    return TemplateInput(name='Application assessment', questions=questions).model_dump(exclude={'expected_revision'})


def build_questions(template, architecture, payload, previous_answers=None):
    rows = []
    sources = _eligible_sources(payload)
    source_texts = {key: ' '.join(source.text.casefold().split()) for key, source in sources.items()}
    source_ids = {s.id for s in payload.sources if s.included}
    source_scope = [(s.id, s.environment, s.version) for s in payload.sources if s.included]
    validated = list(map(QuestionResponse.model_validate, payload.questionnaire_answers))
    responses = {a.question_id: a for a in validated}
    if len(responses) != len(validated):
        raise ValueError('A question must have one current answer; duplicate responses are not allowed.')
    by_id = {}
    for definition in template['questions']:
        q = Question.model_validate(definition)
        if q.application_types and not set(q.application_types) & set(payload.application_types):
            continue
        candidates = [c for c in architecture.components if c.type.casefold() in {t.casefold() for t in q.component_types}]
        if q.technologies:
            candidates = [c for c in candidates if any(re.search(r'(?<!\w)' + re.escape(tech) + r'(?!\w)',
                ' '.join(str(v) for v in (c.id, c.name, c.properties.get('technology', ''), c.properties.get('resource_type', ''))), re.I) for tech in q.technologies)]
            if not q.component_types and not candidates:
                # Assessment questions may explicitly depend on a technology
                # anywhere in the modeled system.
                if not any(any(re.search(r'(?<!\w)' + re.escape(tech) + r'(?!\w)', f'{c.id} {c.name}', re.I) for tech in q.technologies) for c in architecture.components):
                    continue
        targets = candidates if q.component_types else [None]
        for target in targets:
            identifier = f'{q.key}:{target.id if target else "assessment"}'
            dependency = control_dependency_digest(architecture, target.id, q.control) if target and q.control else fingerprint([
                [(c.id, c.name, c.type) for c in architecture.components], source_scope,
                [(s.id, fingerprint(s.text)) for s in payload.sources if s.included],
                [f.model_dump(exclude={'flow_number'}) for f in architecture.flows],
                [b.model_dump() for b in architecture.trust_boundaries]])
            reuse_dependency = _reusable_control_context(architecture, target, q.control) if target and q.control else dependency
            parent = by_id.get(f'{q.when.question_key}:{target.id if target and q.when.scope == "same_component" else "assessment"}') if q.when else None
            parent_value = parent['response']['value'] if parent and parent['status'] == 'answered' else None
            condition = 'not_triggered' if (parent and parent['status'] == 'not_triggered') or (parent_value and parent_value not in q.when.values and parent_value not in {'unknown', 'partial'}) else 'active'
            context = [target.trust_level, {k: target.properties.get(k) for k in ('environment', 'cloud_account', 'tenant_id')},
                       sorted(b.id or b.name for b in architecture.trust_boundaries if target.id in b.components)] if target else ['assessment']
            row = {**q.model_dump(), 'id': identifier, 'element_id': target.id if target else 'assessment',
                'element_name': target.name if target else 'Assessment',
                'evidence_digest': fingerprint([template['version'], definition, dependency, payload.application_types,
                    payload.other_application_type, payload.environment, payload.deployment_version, context, parent_value]),
                'reuse_digest': fingerprint([definition, reuse_dependency, sorted(payload.application_types), payload.other_application_type, payload.environment, context, parent_value]),
                'group_key': q.key + ':' + fingerprint(context)[:12], 'condition_state': condition,
                'suggestion': None, 'proposal': None, 'evidence': [], 'conflicting': False, 'requires_individual_review': False}
            if 'priority' not in definition and q.key in {'actors', 'entry-points', 'data', 'authentication', 'authorization', 'token-revocation'}:
                row['priority'] = 'high'
            row['proposal'] = _source_proposal(row, target, sources, source_texts)
            old = (previous_answers or {}).get(identifier)
            sources_unchanged = old and all(old.get('source_fingerprints', {}).get(key) == fingerprint(sources[key].text)
                for key in old.get('source_ids', []) if key in sources)
            if not row['proposal'] and old and old.get('reuse_digest') == row['reuse_digest'] and not row['requires_individual_review'] and old.get('value') != 'not_applicable' and set(old.get('source_ids', [])) <= sources.keys() and sources_unchanged:
                row['proposal'] = _proposal(row, old['value'], [{'statement': old['note'], 'document': 'Previous release review'}], 'carry_forward',
                    {'assessment_id': old['assessment_id'], 'reviewer': old['reviewer'], 'answered_at': old['answered_at']})
                row['proposal']['source_ids'] = old.get('source_ids', [])
                row['proposal']['digest'] = fingerprint([row['evidence_digest'], row['proposal']])
            if row['proposal']:
                row['suggestion'] = row['proposal']['value']
            _validate_response(row, responses.get(identifier), source_ids)
            if condition == 'not_triggered':
                row['status'] = 'not_triggered'
                row['proposal'] = None
                row['suggestion'] = None
            # Order existing questions by review value; never add a question or
            # convert an unknown answer into a missing-control assertion here.
            props = target.properties if target else {}
            reasons = []
            score = {'high': 30, 'normal': 20, 'low': 10}.get(row.get('priority'), 20)
            if row.get('conflicting'):
                score += 100
                reasons.append('Conflicting source statements')
            if target and (target.trust_level in {'public', 'external'} or props.get('public_access') is True):
                score += 8
                reasons.append('Exposed component')
            if props.get('data_sensitivity') in {'pii', 'phi', 'financial', 'credentials', 'secrets'}:
                score += 5
                reasons.append('Sensitive data')
            row['review_priority'] = {'score': score, 'reasons': reasons}
            rows.append(row)
            by_id[identifier] = row
    return rows


def _validate_response(row, answer, source_ids):
    row['response'] = answer.model_dump() if answer else None
    row['status'] = 'unanswered'
    if answer:
        row['status'] = 'answered' if answer.evidence_digest == row['evidence_digest'] and set(answer.source_ids) <= source_ids else 'stale'
        if row['answer_type'] == 'control' and answer.value not in {'present', 'absent', 'partial', 'unknown', 'not_applicable'}:
            raise ValueError('Select a valid control state.')
        if row['answer_type'] == 'choice' and answer.value not in row['options'] and answer.value != 'unknown':
            raise ValueError('Select an available answer.')
        if row['answer_type'] == 'number' and answer.value != 'unknown':
            import math
            try:
                if not math.isfinite(float(answer.value)):
                    raise ValueError()
            except ValueError as exc:
                raise ValueError('Numeric questions require a finite number or unknown.') from exc
        if answer.basis != 'manual' and row['status'] == 'answered':
            proposal = row['proposal']
            if not proposal or proposal['basis'] != answer.basis or proposal['digest'] != answer.proposal_digest or proposal['value'] != answer.value or set(proposal['source_ids']) != set(answer.source_ids):
                raise ValueError('The suggested answer changed or has incompatible evidence. Refresh and review it again.')
            row['response']['note'] = proposal['note']
        if answer.basis == 'manual' and (not answer.note.strip() or len(answer.note.strip()) < 3):
            raise ValueError('All answers require an explanation, including unknown and not applicable.')
