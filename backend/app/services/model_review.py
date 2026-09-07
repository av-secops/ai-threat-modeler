"""Stateless, source-preserving preparation and explicit reviewer corrections.

Preparation runs the same parser and coverage assessment as analysis, but does
not generate findings. The client persists revisions; no project-name global
state or uploaded code execution is needed to resume a review.
"""

import hashlib
import json
from collections import OrderedDict
from functools import lru_cache
from threading import RLock
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models import Component, DataFlow, SystemArchitecture
from ..engine.parser import ArchitectureParser
from ..engine.canonical_model import canonicalize_architecture
from ..engine.control_contracts import presence
from ..engine.stride_coverage_engine import StrideCoverageEngine
from ..engine.control_statements import CONTROL_TERMS
from ..engine.mermaid_generator import generate_mermaid, _sanitize_id
from ..engine.graph_builder import GraphBuilder
from ..engine.source_correlation import control_dependency_digest

_parse_cache = OrderedDict()
_parse_lock = RLock()
_PARSE_CACHE_BYTES = 8_000_000


def _parse_text(text):
    key = digest(['model-review-parser-2', text])
    with _parse_lock:
        if key in _parse_cache:
            _parse_cache.move_to_end(key)
            return _parse_cache[key][0].model_copy(deep=True), True
    model = ArchitectureParser().parse(text)
    size = len(text.encode()) + len(model.model_dump_json().encode())
    if size <= _PARSE_CACHE_BYTES:
        with _parse_lock:
            _parse_cache[key] = (model.model_copy(deep=True), size)
            while len(_parse_cache) > 16 or sum(item[1] for item in _parse_cache.values()) > _PARSE_CACHE_BYTES:
                _parse_cache.popitem(last=False)
    return model, False


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class ReviewSource(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200, pattern=r'^[^\r\n]+$')
    text: str = Field(max_length=500000)
    kind: str = Field(default='text', max_length=30, pattern=r'^[A-Za-z0-9_-]+$')
    included: bool = True
    environment: str = Field(default='unspecified', max_length=100)
    version: str = Field(default='', max_length=100)
    metadata: dict = Field(default_factory=dict)


class ReviewEdit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    element_id: str = Field(min_length=1, max_length=500)
    field: str = Field(min_length=1, max_length=100)
    value: Any
    reason: str = Field(min_length=3, max_length=2000)


class ReviewAnswer(BaseModel):
    model_config = ConfigDict(extra='forbid')
    element_id: str = Field(min_length=1, max_length=500)
    control: str = Field(min_length=1, max_length=100)
    state: Literal['present', 'absent', 'unknown', 'not_applicable']
    value: str = Field(default='', max_length=300)
    note: str = Field(default='', max_length=3000)
    reviewer: str = Field(default='Architecture owner', max_length=200)
    source_ids: list[str] = Field(default_factory=list, max_length=20)
    source_digest: str = Field(default='', max_length=64)
    evidence_digest: str = Field(default='', max_length=64)
    source_digests: dict[str, str] = Field(default_factory=dict, max_length=20)
    answered_at: str = Field(default='', max_length=100)

    @model_validator(mode='after')
    def require_explanation(self):
        if self.state != 'unknown' and len(self.note.strip()) < 3:
            raise ValueError('Known answers and scope exceptions need an explanation.')
        return self


class ModelReviewRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    project_name: str = Field(min_length=1, max_length=200)
    sources: list[ReviewSource] = Field(default_factory=list, max_length=40)
    baseline: SystemArchitecture | None = None
    edits: list[ReviewEdit] = Field(default_factory=list, max_length=1000)
    answers: list[ReviewAnswer] = Field(default_factory=list, max_length=2000)
    use_local_slm: bool = True
    analysis_mode: Literal['fast', 'standard', 'deep'] = 'standard'
    domain_profile: Literal['general', 'saas', 'fintech', 'healthcare', 'ai', 'platform'] = 'general'
    input_kind: Literal['architecture', 'iac'] = 'architecture'
    environment: str = Field(default='', max_length=100)
    deployment_version: str = Field(default='', max_length=100)

    @model_validator(mode='after')
    def bound_input(self):
        if len({source.id for source in self.sources}) != len(self.sources):
            raise ValueError('Source IDs must be unique.')
        if len({source.name for source in self.sources if source.included}) != sum(s.included for s in self.sources):
            raise ValueError('Included sources must have unique names; replace an existing file or rename the new source.')
        if sum(len(source.text) for source in self.sources) > 1000000 or len(json.dumps(self.model_dump())) > 2000000:
            raise ValueError('The review exceeds the one-million-character input limit.')
        if self.baseline and (len(self.baseline.components) > 1000 or len(self.baseline.flows) > 3000):
            raise ValueError('The imported model exceeds the review size limit.')
        return self


COMPONENT_FIELDS = {'name', 'type', 'trust_level', 'description', 'data_sensitivity', 'cloud_account', 'tenant_id', 'environment', 'aliases'}
FLOW_FIELDS = {'source_id', 'target_id', 'protocol', 'data_type', 'assumed'}
STRING_CONTROLS = {'auth_type', 'data_sensitivity', 'protocol'}
CONTROL_OPTIONS = {
    'auth_type': ['OAuth2/OIDC', 'JWT', 'mTLS', 'session cookie', 'API key'],
    'data_sensitivity': ['public', 'internal', 'confidential', 'pii', 'phi', 'financial', 'credentials'],
    'protocol': ['HTTPS', 'TLS', 'mTLS', 'WSS', 'gRPCS', 'HTTP', 'WS', 'TCP', 'unknown'],
}
EXTRA_CONTROLS = {'authorization', 'rbac_enabled', 'abac_enabled', 'authenticated', 'auth_checks',
    'integrity_validation', 'log_integrity', 'resilience', 'replication', 'autoscaling',
    'encryption_in_transit', 'transport_encryption', 'least_privilege', 'masking', 'tokenization'}


def flow_id(flow):
    return (flow.properties or {}).get('review_id') or 'flow:' + digest([flow.source_id, flow.target_id, flow.protocol, flow.data_type])[:20]


def _source_bundle(payload):
    active = [s for s in payload.sources if s.included]
    documents = []
    bodies = []
    for source in active:
        metadata = {**source.metadata, 'filename': source.name, 'type': source.kind,
            'source_id': source.id,
            'characters': len(source.text), 'environment': source.environment,
            'document_version': source.version, 'content_hash': digest(source.text)}
        documents.append(metadata)
        # Prior reports remain references, never declarations of deployed technology.
        role = metadata.get('role', 'source_design')
        if role != 'reference_report':
            bodies.append(f'Document: {source.name}\nType: {source.kind}\nRole: {role}\nContent:\n{source.text}')
    return '\n\n---\n\n'.join(bodies), documents


def _record(statement, **extra):
    return {'source_type': 'architecture_input', 'source_ref': 'reviewer_clarification',
        'statement': statement, 'evidence_basis': 'user_declared',
        'verification_status': 'not_runtime_verified', **extra}


def _apply_edits(architecture, edits, warnings):
    components = {c.id: c for c in architecture.components}
    excluded = {}
    for flow in architecture.flows:
        flow.properties['review_id'] = flow_id(flow)
    flows = {flow_id(f): f for f in architecture.flows}
    for edit in sorted(edits, key=lambda item: item.field not in {'add_component', 'add_flow'}):
        evidence = _record(edit.reason, property=edit.field)
        if edit.field == 'add_component':
            component = Component.model_validate(edit.value)
            if component.id != edit.element_id or component.id in components:
                raise ValueError('A new component needs a unique matching ID.')
            component.evidence = [evidence]
            component.properties = {**component.properties, 'authoritative': True, 'reviewer_declared': True}
            components[component.id] = component
        elif edit.field == 'add_flow':
            flow = DataFlow.model_validate(edit.value)
            flow.evidence = [evidence]
            flow.properties = {**flow.properties, 'assumed': flow.assumed, 'reviewer_declared': True, 'review_id': edit.element_id}
            flows[edit.element_id] = flow
        elif edit.element_id in components:
            target = components[edit.element_id]
            if edit.field == 'remove':
                components.pop(edit.element_id)
                excluded[edit.element_id] = edit.reason
                continue
            if edit.field not in COMPONENT_FIELDS or not isinstance(edit.value, str) or (edit.field != 'aliases' and not edit.value.strip()):
                raise ValueError(f'Invalid component correction: {edit.field}.')
            if edit.field == 'aliases':
                target.properties['aliases'] = list(dict.fromkeys(v.strip() for v in edit.value.split(',') if v.strip()))
            elif edit.field in {'name', 'type', 'trust_level', 'description'}:
                setattr(target, edit.field, edit.value.strip())
            else:
                target.properties[edit.field] = edit.value.strip()
            target.properties['authoritative'] = True
            target.properties['reviewer_declared'] = True
            target.evidence.append(evidence)
        elif edit.element_id in flows:
            target = flows[edit.element_id]
            if edit.field == 'remove':
                flows.pop(edit.element_id)
                continue
            if edit.field not in FLOW_FIELDS:
                raise ValueError(f'Invalid flow correction: {edit.field}.')
            if edit.field == 'assumed' and not isinstance(edit.value, bool):
                raise ValueError('Flow assumption must be a boolean.')
            if edit.field != 'assumed' and (not isinstance(edit.value, str) or not edit.value.strip()):
                raise ValueError('Flow corrections need a nonempty value.')
            if edit.field in {'source_id', 'target_id'} and edit.value not in components:
                raise ValueError('A corrected flow endpoint must name an included component.')
            setattr(target, edit.field, edit.value)
            target.properties['assumed'] = target.assumed
            target.evidence.append(evidence)
        else:
            warnings.append({'type': 'stale_edit', 'message': f'Correction for {edit.element_id} no longer has a target; review it before proceeding.'})
    architecture.components = list(components.values())
    architecture.flows = []
    for flow in flows.values():
        if flow.source_id in components and flow.target_id in components:
            architecture.flows.append(flow)
        else:
            warnings.append({'type': 'removed_flow', 'message': f'Flow {flow.source_id} -> {flow.target_id} was excluded because an endpoint is absent.'})
    for boundary in architecture.trust_boundaries:
        boundary.components = [item for item in boundary.components if item in components]
    architecture.assets = [a for a in architecture.assets if not a.related_component_id or a.related_component_id in components]
    metadata = architecture.metadata or {}
    exclusions = list(metadata.get('review_exclusions') or [])
    for key in ('iac_findings', 'security_findings'):
        active = []
        for finding in metadata.get(key) or []:
            if finding.get('resource_id') in excluded:
                exclusions.append({'kind': key, 'finding': finding,
                    'reason': excluded[finding['resource_id']], 'status': 'out_of_scope_not_remediated'})
            else:
                active.append(finding)
        if key in metadata:
            metadata[key] = active
    if 'iac_findings' in metadata:
        metadata['iac_findings_count'] = len(metadata['iac_findings'])
    if exclusions:
        metadata['review_exclusions'] = exclusions
        warnings.append({'type': 'excluded_findings', 'message': f'{len(exclusions)} source findings are retained as out of scope. Their remediation has not been verified.'})
    architecture.metadata = metadata


def _apply_answers(architecture, payload, source_digest, warnings, dependencies=None):
    components = {c.id: c for c in architecture.components}
    flows = {flow_id(f): f for f in architecture.flows}
    sources = {s.id: s for s in payload.sources if s.included}
    latest = {(a.element_id, a.control): a for a in payload.answers}
    for answer in latest.values():
        target = components.get(answer.element_id) or flows.get(answer.element_id)
        expected = dependencies(answer.element_id, answer.control) if dependencies else None
        stale = answer.evidence_digest != expected if answer.evidence_digest else answer.source_digest != source_digest
        if answer.evidence_digest:
            stale = stale or any(answer.source_digests.get(identifier) != digest(sources[identifier].model_dump())
                for identifier in answer.source_ids if identifier in sources)
        if target is None or stale or any(s not in sources for s in answer.source_ids):
            warnings.append({'type': 'stale_answer', 'message': f'Reconfirm {answer.control} for {answer.element_id}: its source material or target changed.'})
            continue
        if answer.control not in set(CONTROL_TERMS) | EXTRA_CONTROLS | STRING_CONTROLS:
            raise ValueError(f'Unsupported review control: {answer.control}.')
        if isinstance(target, DataFlow) and answer.control in {'transport_encryption', 'encryption_in_transit'}:
            raise ValueError('Specify the flow protocol; transport encryption is derived by the coverage engine.')
        record = _record(answer.note or 'The owner does not know this control state.',
            state=answer.state, reviewer=answer.reviewer, answered_at=answer.answered_at,
            source_ids=answer.source_ids, source_digest=source_digest)
        target.properties.setdefault('review_answers', {})[answer.control] = record
        if answer.state in {'unknown', 'not_applicable'}:
            if answer.state == 'not_applicable':
                warnings.append({'type': 'scope_exception', 'message': f'{answer.control} on {answer.element_id}: proposed out of scope ({answer.note}). No detector was suppressed.'})
            continue
        if answer.control in STRING_CONTROLS:
            if answer.state == 'absent' and answer.control in {'protocol', 'data_sensitivity'}:
                raise ValueError(f'{answer.control} needs a specified value or an unknown answer.')
            if answer.state == 'present' and not answer.value.strip():
                raise ValueError(f'Specify a value for {answer.control}.')
            value = answer.value.strip() if answer.state == 'present' else 'none'
            if answer.state == 'present':
                options = {v.lower(): v for v in CONTROL_OPTIONS[answer.control]}
                if value.lower() not in options:
                    raise ValueError(f'Select a supported value for {answer.control}.')
                value = options[value.lower()]
        else:
            value = answer.state == 'present'
        if isinstance(target, DataFlow) and answer.control == 'protocol':
            if value not in CONTROL_OPTIONS['protocol']:
                raise ValueError('Select a supported flow protocol.')
            old = target.protocol.lower()
            if old in {'http', 'ws'} and value.lower() in {'https', 'tls', 'mtls', 'wss', 'grpcs'}:
                warnings.append({'type': 'conflicting_answer', 'message': f'The protocol answer for {answer.element_id} contradicts its stated {target.protocol} flow. Correct the flow or source to reconcile it.'})
            else:
                target.protocol = value
        elif answer.control == 'protocol':
            raise ValueError('Protocol answers must target a data flow.')
        else:
            old = target.properties.get(answer.control)
            records = target.properties.setdefault('control_evidence', {}).setdefault(answer.control, [])
            if old is not None and presence(old) != presence(value) and not records:
                records.append(_record(f'Submitted model states {answer.control} = {old}.', state='present' if presence(old) else 'absent'))
            records.append(record)
            if any(r.get('state') in {'present', 'absent'} and r['state'] != answer.state for r in records):
                target.properties.setdefault('control_assertions', {})[answer.control] = 'conflicting'
                warnings.append({'type': 'conflicting_answer', 'message': f'The answer for {answer.control} on {answer.element_id} contradicts an existing source. Replace or correct that source to reconcile it.'})
            target.properties[answer.control] = value
        target.evidence.append(record)


def _questions(architecture, coverage, dependencies=None):
    components = {c.id: c for c in architecture.components}
    flows = {f'flow:{f.source_id}->{f.target_id}': f for f in architecture.flows}
    grouped = {}
    for cell in coverage['cells']:
        if cell['element_kind'] not in {'component', 'flow'}:
            continue
        target = components.get(cell['element_id']) or flows.get(cell['element_id'])
        if target is None or isinstance(target, DataFlow) and target.assumed:
            continue
        element_id = flow_id(target) if isinstance(target, DataFlow) else target.id
        for control in cell.get('unresolved_controls', []):
            if isinstance(target, DataFlow) and control in {'transport_encryption', 'encryption_in_transit'}:
                control = 'protocol'
            if control not in set(CONTROL_TERMS) | EXTRA_CONTROLS | STRING_CONTROLS:
                continue
            key = f'{element_id}:{control}'
            row = grouped.setdefault(key, {'id': key, 'element_id': element_id,
                'element_name': cell['element_name'], 'control': control, 'categories': [],
                'label': control.replace('_', ' ').capitalize(),
                'question': f"What is the {control.replace('_', ' ')} configuration for {cell['element_name']}?",
                'evidence_digest': dependencies(element_id, control) if dependencies else '',
                'options': CONTROL_OPTIONS.get(control, []),
                'priority': 'High' if getattr(target, 'trust_level', '') in {'public', 'external'} or (target.properties or {}).get('data_sensitivity') in {'pii', 'phi', 'financial', 'credentials'} else 'Medium',
                'answer': (target.properties or {}).get('review_answers', {}).get(control),
                'why': 'This answer changes the control assessment for this element only; it is not deployment verification.'})
            if cell['category'] not in row['categories']:
                row['categories'].append(cell['category'])
    importance = {'auth_type': 8, 'authorization': 8, 'tenant_isolation': 8, 'data_sensitivity': 7,
        'token_revocation': 7, 'query_depth_limiting': 7, 'protocol': 7, 'input_validation': 6,
        'encryption_at_rest': 6, 'rate_limiting': 5}
    return sorted(grouped.values(), key=lambda q: (q['answer'] is not None, q['priority'] != 'High', -importance.get(q['control'], 1), -len(q['categories']), q['id']))


def prepare_model(payload: ModelReviewRequest):
    text, documents = _source_bundle(payload)
    parse_cache_hit = False
    if not text.strip() and payload.baseline is None:
        raise ValueError('Include architecture text or a readable design file before reviewing the model.')
    if payload.input_kind == 'iac' and text.strip():
        from ..engine.iac_parser import IaCParser
        active = [s for s in payload.sources if s.included and s.metadata.get('role') != 'reference_report']
        context = [s for s in active if s.kind.lower() in {'text', 'txt', 'md', 'pdf', 'docx', 'csv'}]
        code = [s for s in active if s not in context]
        context_text, _ = _source_bundle(payload.model_copy(update={'sources': context}))
        architecture, parse_cache_hit = _parse_text(context_text) if context_text.strip() else (SystemArchitecture(components=[], flows=[]), False)
        if code:
            iac = IaCParser().parse_project([{'filename': s.name, 'content': ArchitectureParser._without_structured_paths(s.text),
                'format_hint': s.metadata.get('iac_format', 'auto')} for s in code])
            components = {c.id: c for c in architecture.components}
            findings = ArchitectureParser._merge_embedded_iac(components, architecture.flows,
                [{'architecture': iac, 'document': 'IaC project'}])
            architecture.components = list(components.values())
            architecture.metadata = {**(architecture.metadata or {}), **(iac.metadata or {}), 'iac_findings': findings}
    else:
        architecture, parse_cache_hit = _parse_text(text) if text.strip() else (SystemArchitecture(components=[], flows=[]), False)
    warnings = []
    if payload.baseline:
        # Legacy reports can be refined even when original uploads are unavailable.
        baseline = payload.baseline.model_copy(deep=True)
        known = {c.id for c in baseline.components}
        baseline.components.extend(c for c in architecture.components if c.id not in known)
        paths = {flow_id(f) for f in baseline.flows}
        baseline.flows.extend(f for f in architecture.flows if flow_id(f) not in paths)
        for key in ('known_issues', 'iac_findings'):
            baseline.metadata = baseline.metadata or {}
            baseline.metadata[key] = [*(baseline.metadata.get(key) or []), *((architecture.metadata or {}).get(key) or [])]
        architecture = baseline
        warnings.append({'type': 'legacy_model', 'message': 'This review includes a saved model snapshot. Original files may be unavailable; it is not a fresh verification of those files.'})
    if len(architecture.components) > 1000 or len(architecture.flows) > 3000:
        raise ValueError('The parsed model exceeds the review size limit.')
    architecture.metadata = {**(architecture.metadata or {}), 'source_documents': documents or (architecture.metadata or {}).get('source_documents', []),
        'source_text': text or (architecture.metadata or {}).get('source_text', '')}
    source_digest = digest({'sources': [s.model_dump() for s in payload.sources if s.included],
        'baseline': payload.baseline.model_dump() if payload.baseline else None,
        'edits': [e.model_dump() for e in payload.edits]})
    _apply_edits(architecture, payload.edits, warnings)
    for component in architecture.components:
        for key, value in [('environment', payload.environment), ('deployment_version', payload.deployment_version)]:
            if value and not component.properties.get(key):
                component.properties[key] = value
    architecture, _ = canonicalize_architecture(architecture)
    before_answers = architecture.model_copy(deep=True)
    @lru_cache(maxsize=4000)
    def dependencies(identifier, control):
        return control_dependency_digest(before_answers, identifier, control)
    _apply_answers(architecture, payload, source_digest, warnings, dependencies)
    architecture, validation = canonicalize_architecture(architecture)
    _, coverage = StrideCoverageEngine().assess(architecture, [], generate_candidates=False)
    for issue in validation.get('issues', []):
        warnings.append({'type': issue.get('type', 'model_gap'), 'message': issue.get('message', str(issue))})
    for document in documents:
        quality = document.get('extraction_quality', '')
        if quality and quality not in {'text_complete', 'semantic_text_complete', 'structured_complete', 'structured_text_complete'}:
            warnings.append({'type': 'incomplete_extraction', 'message': f"{document['filename']}: {document.get('warning') or quality}"})
    for limit in (architecture.metadata or {}).get('analysis_limits', []):
        warnings.append({'type': 'analysis_limit', 'message': str(limit)})
    unresolved = (architecture.metadata or {}).get('unresolved_references', [])
    if unresolved:
        warnings.append({'type': 'unresolved_iac', 'message': f'{len(unresolved)} IaC references or values remain unresolved.'})
    environments = {s.environment for s in payload.sources if s.included and s.environment not in {'', 'unspecified'}}
    if len(environments) > 1:
        warnings.append({'type': 'mixed_environments', 'message': 'Included sources describe multiple environments. Exclude unrelated sources or confirm that the combined scope is intentional.'})
    if not architecture.components:
        warnings.append({'type': 'empty_model', 'message': 'No components were recognized. Add a component or correct the source before analysis.'})
    questions = _questions(architecture, coverage, dependencies)
    readiness = {'components': len(architecture.components), 'stated_components': sum(c.properties.get('evidence_status') == 'explicit' for c in architecture.components),
        'flows': len(architecture.flows), 'assumed_flows': sum(f.assumed for f in architecture.flows),
        'open_questions': len(questions), 'warnings': len(warnings), 'status': 'preliminary' if questions or warnings else 'ready_for_review',
        'is_security_score': False}
    architecture.metadata['model_review'] = {'source_digest': source_digest, 'readiness': readiness,
        'answers': [a.model_dump() for a in payload.answers], 'edits': [e.model_dump() for e in payload.edits],
        'warnings': warnings, 'verification_status': 'not_runtime_verified'}
    return {'architecture': architecture.model_dump(), 'source_digest': source_digest,
        'source_digests': {source.id: digest(source.model_dump()) for source in payload.sources if source.included},
        'correlation': architecture.metadata.get('source_correlation', {}),
        'performance': {'parse_cache_hit': parse_cache_hit},
        'questions': questions, 'readiness': readiness, 'warnings': warnings, 'validation': validation,
        'flows': [{**f.model_dump(), 'review_id': flow_id(f)} for f in architecture.flows],
        'diagram_bindings': {'nodes': [{'diagram_id': _sanitize_id(c.id), 'element_id': c.id} for c in architecture.components],
            'flows': [{'source': _sanitize_id(f.source_id), 'target': _sanitize_id(f.target_id), 'element_id': flow_id(f)} for f in architecture.flows]},
        'diagram': generate_mermaid(GraphBuilder(architecture).get_graph(), enhanced=True),
        'prepared_at': datetime.now(timezone.utc).isoformat()}
