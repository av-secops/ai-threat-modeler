"""Render canonical flows, including parallel flows, without rebuilding topology."""

from collections import defaultdict
import hashlib
import html
from .control_contracts import boundary_dimensions, boundary_members


def identifier(value):
    return 'n_' + hashlib.sha256(value.encode()).hexdigest()[:16]


def label(value):
    return html.escape(str(value), quote=False).replace('"', "'").replace('\n', ' ').replace('|', '/')


def render_view(architecture, selected=None, node_limit=80, flow_limit=120, threats=()):
    components = {c.id: c for c in architecture.components}
    wanted = set(components) if selected is None else set(selected) & components.keys()
    visible = set(sorted(wanted)[:node_limit])
    boundaries = architecture.trust_boundaries
    members = boundary_members(architecture)
    boundary_ids = [b.id or identifier('boundary:' + b.name) for b in boundaries]
    parents = {boundary_ids[i]: b.parent_id for i, b in enumerate(boundaries) if b.parent_id in boundary_ids}
    membership = {c: tuple(b.name for i, b in enumerate(boundaries) if c in members[i]) for c in components}
    names = {boundary_ids[i]: b.name for i, b in enumerate(boundaries)}
    deployment = {g['id']: g for g in (architecture.metadata or {}).get('diagram_groups', []) if g.get('id') and g.get('components')}
    for gid, group in deployment.items():
        names[gid] = group['name'] + ' (deployment)'
        if group.get('parent_id') in deployment:
            parents[gid] = group['parent_id']
    groups = defaultdict(list)
    for cid in sorted(visible):
        containers = {boundary_ids[i] for i in range(len(boundaries)) if cid in members[i]}
        if not containers:
            containers = {gid for gid, g in deployment.items() if cid in g['components']}
        ancestors = set()
        for container in containers:
            seen = {container}
            parent = parents.get(container)
            while parent and parent not in seen:
                ancestors.add(parent)
                seen.add(parent)
                parent = parents.get(parent)
        leaf = containers - ancestors
        if len(leaf) == 1:
            key = next(iter(leaf))
        else:
            key = identifier('overlap:' + '|'.join(sorted(leaf))) if leaf else 'unassigned'
            names[key] = 'Overlapping boundaries: ' + ' / '.join(names[x] for x in sorted(leaf)) if leaf else 'Unassigned boundary'
        groups[key].append(components[cid])
    lines = ['flowchart LR', '    %% Canonical model: parallel flows and explicit boundary memberships retained']
    needed = set(groups)
    for group in list(needed):
        seen = {group}
        parent = parents.get(group)
        while parent and parent not in seen:
            needed.add(parent)
            seen.add(parent)
            parent = parents.get(parent)
    emitted = set()
    def emit(group):
        if group in emitted:
            return
        emitted.add(group)
        group_id = identifier('boundary:' + group)
        lines.append(f'    subgraph {group_id}["{label(names[group])}"]')
        lines.append('    direction TB')
        for child in sorted(needed):
            if parents.get(child) == group:
                emit(child)
        for c in groups[group]:
            name = label(c.name)
            kind = c.type.lower()
            external = c.trust_level in {'external', 'third_party'} or 'external' in kind or 'identity provider' in kind
            store = any(word in kind for word in ('database', 'storage', 'cache', 'queue'))
            shape = ('[', ']') if external else ('[(', ')]') if store else ('((', '))')
            lines.append(f'        {identifier(c.id)}{shape[0]}"{name}"{shape[1]}')
        dash = '' if group in deployment else ',stroke-dasharray:5 5'
        lines.extend(['    end', f'    style {group_id} fill:transparent,stroke:#64748b{dash}'])
    for group in sorted(needed):
        if parents.get(group) not in needed:
            emit(group)
    for group in sorted(needed - emitted):
        emit(group)
    eligible = [(i, f) for i, f in enumerate(architecture.flows) if f.source_id in visible and f.target_id in visible]
    selected_flows = eligible[:flow_limit]
    crossings = 0
    for _, flow in selected_flows:
        crossing = membership[flow.source_id] != membership[flow.target_id] or bool(boundary_dimensions(components[flow.source_id], components[flow.target_id]))
        crossings += int(crossing)
        arrow = '-.->' if flow.assumed else '==>' if crossing else '-->'
        prefix = f'{flow.flow_number}: ' if flow.flow_number else ''
        text = prefix + (flow.description or f'{flow.protocol} / {flow.data_type}') + (' (assumed)' if flow.assumed else '')
        lines.append(f'    {identifier(flow.source_id)} {arrow}|"{label(text)}"| {identifier(flow.target_id)}')
    relationships = [r for r in (architecture.metadata or {}).get('diagram_relationships', [])
        if r.get('source_id') in visible and r.get('target_id') in visible][:flow_limit]
    for relation in relationships:
        text = {'unknown': 'Connection needs review', 'depends_on': 'Dependency', 'hosts': 'Hosts'}.get(relation.get('kind'), 'Relationship')
        lines.append(f'    {identifier(relation["source_id"])} -.-|"{text}"| {identifier(relation["target_id"])}')
    confirmed = {cid for threat in threats if threat.tier == 'Confirmed'
        for cid in [threat.component, *(threat.affected_components or [])] if cid in visible}
    for cid in sorted(confirmed):
        lines.append(f'    style {identifier(cid)} stroke:#dc2626,stroke-width:3px')
    stats = {'components_in_model': len(components), 'components_drawn': len(visible),
        'components_hidden_for_readability': len(components) - len(visible), 'components_excluded_as_non_flow': 0,
        'flows_in_model': len(architecture.flows), 'flows_drawn': len(selected_flows),
        'relationships_drawn': len(relationships), 'deployment_groups_drawn': len(needed & deployment.keys()),
        'flows_hidden_for_readability': len(architecture.flows) - len(selected_flows),
        'component_ids': sorted(visible), 'flow_indexes': [i for i, _ in selected_flows],
        'boundary_membership': membership, 'boundary_crossings_drawn': crossings,
        'complete': len(visible) == len(components) and len(selected_flows) == len(architecture.flows)}
    return {'diagram': '\n'.join(lines), 'coverage': stats}


def diagram_views(architecture, threats=()):
    views = [{'id': 'system', 'name': 'System', **render_view(architecture, threats=threats)}]
    for boundary in architecture.trust_boundaries[:20]:
        selected = set(boundary.components)
        for flow in architecture.flows:
            if flow.source_id in boundary.components or flow.target_id in boundary.components:
                selected.update((flow.source_id, flow.target_id))
        views.append({'id': identifier(boundary.name), 'name': boundary.name, **render_view(architecture, selected, threats=threats)})
    workflows = defaultdict(set)
    for flow in architecture.flows:
        if flow.properties.get('workflow'):
            workflows[str(flow.properties['workflow'])].update((flow.source_id, flow.target_id))
    for name, selected in sorted(workflows.items())[:20]:
        views.append({'id': identifier('workflow:' + name), 'name': name, **render_view(architecture, selected, threats=threats)})
    return views
