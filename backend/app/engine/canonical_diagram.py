"""Render canonical flows, including parallel flows, without rebuilding topology."""

from collections import defaultdict
import hashlib
import html
from .control_contracts import boundary_dimensions


def identifier(value):
    return 'n_' + hashlib.sha256(value.encode()).hexdigest()[:16]


def label(value):
    return html.escape(str(value), quote=False).replace('"', "'").replace('\n', ' ').replace('|', '/')


def render_view(architecture, selected=None, node_limit=80, flow_limit=120, threats=()):
    components = {c.id: c for c in architecture.components}
    wanted = set(components) if selected is None else set(selected) & components.keys()
    visible = set(sorted(wanted)[:node_limit])
    membership = {c: tuple(b.name for b in architecture.trust_boundaries if c in b.components) for c in components}
    groups = defaultdict(list)
    for cid in sorted(visible):
        groups[membership[cid] or ('Unassigned boundary',)].append(components[cid])
    lines = ['flowchart LR', '    %% Canonical model: parallel flows and explicit boundary memberships retained']
    for group, nodes in groups.items():
        group_id = identifier('boundary:' + '|'.join(group))
        lines.append(f'    subgraph {group_id}["{label(" / ".join(group))}"]')
        for c in nodes:
            name = label(c.name)
            kind = c.type.lower()
            external = c.trust_level in {'external', 'third_party'} or 'external' in kind or 'identity provider' in kind
            store = any(word in kind for word in ('database', 'storage', 'cache', 'queue'))
            shape = ('[', ']') if external else ('[(', ')]') if store else ('((', '))')
            lines.append(f'        {identifier(c.id)}{shape[0]}"{name}"{shape[1]}')
        lines += ['    end', f'    style {group_id} fill:transparent,stroke:#64748b,stroke-dasharray:5 5']
    eligible = [(i, f) for i, f in enumerate(architecture.flows) if f.source_id in visible and f.target_id in visible]
    selected_flows = eligible[:flow_limit]
    crossings = 0
    for _, flow in selected_flows:
        crossing = membership[flow.source_id] != membership[flow.target_id] or bool(boundary_dimensions(components[flow.source_id], components[flow.target_id]))
        crossings += int(crossing)
        arrow = '-.->' if flow.assumed else '==>' if crossing else '-->'
        text = f'{flow.protocol} / {flow.data_type}' + (' (assumed)' if flow.assumed else '')
        lines.append(f'    {identifier(flow.source_id)} {arrow}|"{label(text)}"| {identifier(flow.target_id)}')
    confirmed = {cid for threat in threats if threat.tier == 'Confirmed'
        for cid in [threat.component, *(threat.affected_components or [])] if cid in visible}
    for cid in sorted(confirmed):
        lines.append(f'    style {identifier(cid)} stroke:#dc2626,stroke-width:3px')
    stats = {'components_in_model': len(components), 'components_drawn': len(visible),
        'components_hidden_for_readability': len(components) - len(visible), 'components_excluded_as_non_flow': 0,
        'flows_in_model': len(architecture.flows), 'flows_drawn': len(selected_flows),
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
