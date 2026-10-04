"""Reconcile diagram identities and apply source-bound human topology decisions."""

from collections import Counter
from copy import deepcopy

from ..models import DataFlow, SystemArchitecture
from .diagram_vision import key, label


def align_snapshot(snapshot, extracted):
    """Reuse a legacy identity only for an unambiguous named instance in the same scope."""
    counts = Counter(label(c.name) for c in extracted.components)
    mapping = {}
    for component in extracted.components:
        name = label(component.name)
        matches = [c for c in snapshot.components if label(c.name) == name and c.type == component.type
            and counts[name] == 1 and name not in {'api', 'service', 'database', 'frontend', 'backend'}
            and all(c.properties.get(k) == component.properties.get(k) for k in ('environment', 'cloud_account', 'tenant_id', 'deployment_version'))]
        if len(matches) != 1 or component.id == matches[0].id:
            continue
        target = matches[0]
        mapping[component.id] = target.id
        target.evidence.extend(component.evidence)
        for field, value in component.properties.items():
            if field not in target.properties:
                target.properties[field] = deepcopy(value)
        target.properties['aliases'] = list(dict.fromkeys([*target.properties.get('aliases', []), component.id]))
    extracted.components = [c for c in extracted.components if c.id not in mapping]
    for flow in extracted.flows:
        flow.source_id = mapping.get(flow.source_id, flow.source_id)
        flow.target_id = mapping.get(flow.target_id, flow.target_id)
    for boundary in extracted.trust_boundaries:
        boundary.components = [mapping.get(i, i) for i in boundary.components]
    for group in (extracted.metadata or {}).get('diagram_groups', []):
        group['components'] = [mapping.get(i, i) for i in group.get('components', [])]
    for relation in (extracted.metadata or {}).get('diagram_relationships', []):
        for field in ('source_id', 'target_id'):
            relation[field] = mapping.get(relation.get(field), relation.get(field))
    for asset in extracted.assets:
        asset.related_component_id = mapping.get(asset.related_component_id, asset.related_component_id)
    for field in ('iac_findings', 'security_findings'):
        for finding in (extracted.metadata or {}).get(field, []):
            finding['resource_id'] = mapping.get(finding.get('resource_id'), finding.get('resource_id'))


def import_sources(architecture, sources, warnings):
    metadata = architecture.metadata = architecture.metadata or {}
    tasks = metadata.setdefault('diagram_review_tasks', [])
    for source in sources:
        if not source.included or not source.metadata.get('diagram_model') or source.metadata.get('role') == 'reference_report':
            continue
        imported = SystemArchitecture.model_validate(source.metadata['diagram_model'])
        artifact = source.metadata.get('artifact_hash') or source.metadata.get('content_hash') or key(source.metadata['diagram_model'])
        remap = {}
        original = list(architecture.components)
        counts = Counter(label(c.name) for c in imported.components)
        for component in imported.components:
            name = label(component.name)
            scope = {k: source.metadata.get(k) for k in ('tenant_id', 'cloud_account', 'deployment_version')}
            scope['environment'] = source.environment if source.environment not in {'', 'unspecified'} else None
            candidates = [c for c in original if name and name in {label(c.name), *(label(a) for a in c.properties.get('aliases', []))}
                and name not in {'api', 'service', 'database', 'frontend', 'backend'} and counts[name] == 1
                and all(not (scope.get(k) or c.properties.get(k)) or label(scope.get(k) or '') == label(c.properties.get(k) or '') for k in scope)
                and (c.type == component.type or component.type == 'Service')]
            for record in component.evidence:
                record.update({'source_id': source.id, 'artifact_hash': artifact})
            if len(candidates) == 1:
                target = candidates[0]
                remap[component.id] = target.id
                target.evidence.extend(component.evidence)
                target.properties.setdefault('diagram_sources', []).append(source.id)
                metadata.setdefault('diagram_matches', []).append({'source_id': source.id, 'diagram_element_id': component.id,
                    'element_id': target.id, 'basis': 'unique_exact_name_and_compatible_scope'})
            else:
                remap[component.id] = component.id
                component.properties.update({k: v for k, v in scope.items() if v})
                if not any(c.id == component.id for c in architecture.components):
                    architecture.components.append(component)
            if component.properties.get('diagram_review_required'):
                tasks.append(_task(source, artifact, remap[component.id], 'component', f'Is "{component.name}" a component, with the correct label?', ['confirm', 'exclude'], component.evidence))
        for flow in imported.flows:
            flow.source_id, flow.target_id = remap[flow.source_id], remap[flow.target_id]
            for record in flow.evidence:
                record.update({'source_id': source.id, 'artifact_hash': artifact})
            peers = [f for f in architecture.flows if f.source_id == flow.source_id and f.target_id == flow.target_id]
            exact = [f for f in peers if f.protocol.lower() == flow.protocol.lower() and f.description == flow.description
                and not f.assumed and not flow.assumed]
            if len(exact) == 1:
                exact[0].evidence.extend(flow.evidence)
                continue
            if not flow.assumed:
                # Replace only parser-guessed paths; distinct stated workflows stay separate.
                architecture.flows = [f for f in architecture.flows if not (f in peers and f.assumed and
                    not any(e.get('source_type') == 'diagram_import' for e in f.evidence))]
            conflicting = [f for f in peers if not f.assumed and f.protocol.lower() not in {'unknown', flow.protocol.lower()}
                and flow.protocol.lower() != 'unknown']
            if conflicting:
                tasks.append(_task(source, artifact, flow.id, 'flow',
                    f'Sources describe different protocols on this connection ({flow.protocol} versus {", ".join(sorted({f.protocol for f in conflicting}))}). Are these separate runtime flows?',
                    ['confirm', 'exclude', 'dependency'], flow.evidence))
            if not any(f.id == flow.id for f in architecture.flows):
                architecture.flows.append(flow)
            if flow.assumed or flow.properties.get('diagram_review_required'):
                names = {c.id: c.name for c in architecture.components}
                tasks.append(_task(source, artifact, flow.id, 'flow', f'Is this a runtime flow from {names[flow.source_id]} to {names[flow.target_id]}?',
                    ['confirm', 'reverse', 'dependency', 'exclude'], flow.evidence))
        for boundary in imported.trust_boundaries:
            boundary.components = [remap[c] for c in boundary.components if c in remap]
            for record in boundary.evidence:
                record.update({'source_id': source.id, 'artifact_hash': artifact})
            if not any(b.id == boundary.id for b in architecture.trust_boundaries):
                architecture.trust_boundaries.append(boundary)
            if boundary.boundary_type == 'proposed':
                tasks.append(_task(source, artifact, boundary.id, 'boundary', f'Does "{boundary.name}" represent a real change of trust?', ['confirm', 'exclude'], boundary.evidence))
        for relation in (imported.metadata or {}).get('diagram_relationships', []):
            relation = deepcopy(relation)
            for field in ('source_id', 'target_id'):
                relation[field] = remap.get(relation[field], relation[field])
            for record in relation.get('evidence', []):
                record.update({'source_id': source.id, 'artifact_hash': artifact})
            metadata.setdefault('diagram_relationships', []).append(relation)
            if relation['kind'] == 'unknown':
                names = {c.id: c.name for c in architecture.components}
                tasks.append(_task(source, artifact, relation['id'], 'relationship', f'Connection between {names.get(relation["source_id"], "group")} and {names.get(relation["target_id"], "group")}: which direction and purpose?',
                    ['dependency', 'forward_flow', 'reverse_flow', 'exclude'], relation.get('evidence', [])))
        for issue in (imported.metadata or {}).get('diagram_issues', []):
            identifier = remap.get(issue['element_id'], issue['element_id'])
            tasks.insert(0, _task(source, artifact, identifier, issue['kind'], issue['message'], ['confirm'], []))
        for group in (imported.metadata or {}).get('diagram_groups', []):
            group = deepcopy(group)
            group['components'] = [remap.get(i, i) for i in group.get('components', [])]
            metadata.setdefault('diagram_groups', []).append(group)
        for network in (imported.metadata or {}).get('diagram_unresolved_networks', []):
            network = deepcopy(network)
            network['components'] = [remap.get(i, i) for i in network.get('components', [])]
            network['source_id'] = source.id
            metadata.setdefault('diagram_unresolved_networks', []).append(network)
        if (imported.metadata or {}).get('diagram_extraction', {}).get('method') in {'ocr_only', 'ocr_vision'}:
            tasks.append(_task(source, artifact, 'topology:' + source.id, 'topology',
                'Compare the model with the original image. Add missing flows, resolve branches and review deployment groups. Confirm only when the runtime topology is complete, or explain why no runtime flows belong in scope.',
                ['confirm'], []))
        metadata.setdefault('diagram_extractions', []).append({'source_id': source.id, 'artifact_hash': artifact,
            **(imported.metadata or {}).get('diagram_extraction', {}), 'pages': (imported.metadata or {}).get('diagram_pages', [])})
        if (imported.metadata or {}).get('diagram_unassigned_labels'):
            warnings.append({'type': 'diagram_unassigned_labels', 'message': f'{source.name}: OCR found labels outside identified components. Check the original diagram for omitted elements.'})
    metadata['diagram_review_tasks'] = list({t['id']: t for t in tasks}.values())


def _task(source, artifact, element_id, kind, question, actions, evidence):
    return {'id': 'diagram-question:' + key([source.id, element_id, kind]), 'source_id': source.id,
        'artifact_hash': artifact, 'element_id': element_id, 'kind': kind, 'question': question,
        'actions': actions, 'evidence': evidence, 'status': 'pending',
        'priority': 'High' if kind in {'flow', 'boundary', 'relationship', 'label_disagreement'} else 'Medium'}


def apply_decisions(architecture, decisions, warnings):
    metadata = architecture.metadata
    tasks = {t['id']: t for t in metadata.get('diagram_review_tasks', [])}
    components = {c.id: c for c in architecture.components}
    flows = {f.id: f for f in architecture.flows}
    boundaries = {b.id: b for b in architecture.trust_boundaries}
    relations = {r['id']: r for r in metadata.get('diagram_relationships', [])}
    for decision in decisions:
        task = tasks.get(decision.task_id)
        if not task or task['artifact_hash'] != decision.artifact_hash:
            warnings.append({'type': 'stale_diagram_decision', 'message': 'A diagram decision refers to replaced source evidence and needs review.'})
            continue
        if decision.action not in task['actions']:
            raise ValueError('The diagram decision is not valid for this question.')
        identifier, action = task['element_id'], decision.action
        record = {'source_type': 'architecture_input', 'source_ref': 'reviewer_clarification', 'statement': decision.note,
            'evidence_scope': 'topology',
            'evidence_basis': 'user_declared', 'verification_status': 'not_runtime_verified', 'artifact_hash': decision.artifact_hash}
        if task['kind'] == 'topology':
            metadata.setdefault('diagram_topology_reviews', []).append(record)
        elif task['kind'] in {'component', 'label_disagreement'} and identifier in components:
            component = components[identifier]
            if action == 'exclude':
                components.pop(identifier)
            else:
                component.properties.update({'diagram_review_required': False, 'reviewer_declared': True})
                component.evidence.append(record)
        elif task['kind'] == 'flow' and identifier in flows:
            flow = flows[identifier]
            if action in {'exclude', 'dependency'}:
                flows.pop(identifier)
                if action == 'dependency':
                    relations[identifier] = {'id': identifier, 'source_id': flow.source_id, 'target_id': flow.target_id,
                        'kind': 'depends_on', 'description': flow.description, 'evidence': [*flow.evidence, record]}
            else:
                if action == 'reverse':
                    flow.source_id, flow.target_id = flow.target_id, flow.source_id
                flow.assumed = False
                flow.properties.update({'assumed': False, 'diagram_review_required': False, 'reviewer_declared': True})
                flow.evidence.append(record)
        elif task['kind'] == 'boundary' and identifier in boundaries:
            if action == 'exclude':
                boundaries.pop(identifier)
            else:
                boundaries[identifier].boundary_type = 'explicit'
                boundaries[identifier].evidence.append(record)
        elif task['kind'] == 'relationship' and identifier in relations:
            relation = relations[identifier]
            if action == 'exclude':
                relations.pop(identifier)
            elif action == 'dependency':
                relation['kind'] = 'depends_on'
                relation.setdefault('evidence', []).append(record)
            else:
                source, target = relation['source_id'], relation['target_id']
                if action == 'reverse_flow':
                    source, target = target, source
                if source not in components or target not in components:
                    raise ValueError('A runtime flow must connect included components, not deployment groups.')
                flows[identifier] = DataFlow(id=identifier, source_id=source, target_id=target, protocol='unknown',
                    description=relation.get('description', ''), evidence=[*relation.get('evidence', []), record], properties={'reviewer_declared': True})
                relations.pop(identifier)
        else:
            warnings.append({'type': 'stale_diagram_decision', 'message': f'The element for {task["question"]} is no longer present.'})
            continue
        task.update({'status': 'reviewed', 'decision': action, 'note': decision.note})
    architecture.components = list(components.values())
    architecture.flows = [f for f in flows.values() if f.source_id in components and f.target_id in components]
    architecture.trust_boundaries = list(boundaries.values())
    for boundary in architecture.trust_boundaries:
        boundary.components = [i for i in boundary.components if i in components]
        if boundary.parent_id not in boundaries:
            boundary.parent_id = None
    metadata['diagram_relationships'] = list(relations.values())
    for task in tasks.values():
        if task['status'] == 'pending' and task['kind'] != 'topology' and task['element_id'] not in components.keys() | flows.keys() | boundaries.keys() | relations.keys():
            task['status'] = 'excluded'
    metadata['diagram_review_tasks'] = sorted(tasks.values(), key=lambda t: (t['status'] != 'pending', t['priority'] != 'High', t['id']))
