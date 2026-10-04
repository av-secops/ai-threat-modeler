"""Executable, synthetic rule contracts. These are not independent accuracy data."""

from copy import deepcopy
from time import perf_counter
import hashlib
from pathlib import Path

from ..engine.knowledge_threat_engine import KnowledgeThreatEngine
from ..models import Component, SystemArchitecture
from .governance import contract_errors, review_digest

CASES = ('positive', 'protected', 'unknown', 'conflicting', 'planned', 'partial', 'wrong_scope')


def evaluator_digest():
    root = Path(__file__).resolve().parents[1]
    sources = ('knowledge_base/evaluation.py', 'knowledge_base/governance.py',
        'engine/knowledge_threat_engine.py', 'engine/control_contracts.py', 'models.py')
    digest = hashlib.sha256()
    for source in sources:
        digest.update(source.encode())
        # Normalize checkout line endings, but bind review to executable sources.
        digest.update((root / source).read_text(encoding='utf-8').replace('\r\n', '\n').encode())
    return digest.hexdigest()


def contract_model(rule, case):
    fixture = rule['test_contract']
    control = fixture['control']
    props = {**deepcopy(fixture.get('properties', {})), control: False}
    if case == 'protected':
        props[control] = True
    elif case == 'unknown':
        props.pop(control)
    elif case in {'conflicting', 'planned', 'partial'}:
        props['correlated_controls'] = {control: {'state': case}}
    name, kind = fixture['component_name'], fixture['component_type']
    if case == 'wrong_scope':
        name, kind = 'Unrelated target', 'Unrelated Resource'
    state = 'present' if case == 'protected' else 'absent' if case in {'positive', 'wrong_scope'} else case
    evidence = {'source_type': 'architecture_input', 'source_ref': 'contract-fixture', 'control': control,
        'state': state, 'element_id': 'target', 'evidence_scope': 'control',
        'statement': f'{name}: {control.replace("_", " ")} is {state}.'}
    return SystemArchitecture(components=[Component(id='target', name=name, type=kind, properties=props,
        confidence='High', evidence=[evidence])], flows=[])


def evaluate_contracts(knowledge_base):
    started = perf_counter()
    engine = KnowledgeThreatEngine(knowledge_base)
    results = []
    rules = knowledge_base.get_all_threats()
    tested, untested = [], []
    for rule in rules:
        if not rule.get('test_contract'):
            untested.append(rule['id'])
            continue
        errors = contract_errors(rule)
        if errors:
            results.append({'rule_id': rule['id'], 'case': 'fixture_schema', 'passed': False, 'errors': errors})
            continue
        tested.append(rule['id'])
        for case in CASES:
            try:
                findings, _ = engine.analyze(contract_model(rule, case))
                found = any(f.id == f"KB-{rule['id']}-target" for f in findings)
                results.append({'rule_id': rule['id'], 'rule_digest': review_digest(rule.get('raw') or rule),
                    'case': case, 'expected_match': case == 'positive', 'actual_match': found,
                    'passed': found == (case == 'positive')})
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                results.append({'rule_id': rule['id'], 'case': case, 'passed': False,
                    'error': f'{type(exc).__name__}: {exc}'})
    return {'suite': 'synthetic_rule_contracts', 'independent_accuracy': False,
        'evaluator_digest': evaluator_digest(),
        'coverage': {'catalog_rules': len(rules), 'tested_rules': len(tested), 'tested_rule_ids': tested,
            'untested_rule_ids': untested, 'required_cases': list(CASES)},
        'cases': len(results), 'passed': sum(r['passed'] for r in results),
        'results': results,
        'failures': [r for r in results if not r['passed']],
        'elapsed_ms': round((perf_counter() - started) * 1000, 1)}
