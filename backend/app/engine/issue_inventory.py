"""Preserve declared source issues before classification or finding deduplication."""

import hashlib
import re

_HEADING = re.compile(r'^\s*(?:#{1,6}\s*)?(?:\*\*)?(?:known\s+(?:issues?|weaknesses?|vulnerabilities?)|security\s+(?:gaps?|issues?|weaknesses?)|identified\s+(?:risks?|weaknesses?)|risk\s+register)(?:\*\*)?\s*:?(?:\*\*)?\s*$', re.I)
_INLINE = re.compile(r'(?i)\bknown issues?\s*:\s*(.*)')
_END = re.compile(r'^\s*(?:#{1,6}\s+|(?:exclusions?|out of scope|assumptions?|components?|data flows?|architecture|mitigations?|controls?|notes?)\s*:)', re.I)


def issue_id(statement):
    return 'issue-' + hashlib.sha256(' '.join(statement.casefold().split()).encode()).hexdigest()[:20]


def extract_issues(text):
    entries, active = [], False
    table_column = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if _HEADING.match(line):
            active, table_column = True, None
            continue
        inline = _INLINE.search(line)
        if inline:
            active, line = True, inline.group(1)
        elif active and _END.match(line):
            active, table_column = False, None
        if not active or not line:
            continue
        if '|' in line:
            cells = [cell.strip() for cell in line.strip('|').split('|')]
            columns = [re.sub(r'[^a-z ]', '', cell.lower()).strip() for cell in cells]
            headings = {'issue', 'weakness', 'description', 'potential threat', 'known issue', 'risk'}
            if any(cell in headings for cell in columns):
                table_column = next(i for i, cell in enumerate(columns) if cell in headings)
                continue
            if all(re.fullmatch(r'[:\- ]*', cell) for cell in cells):
                continue
            if table_column is not None:
                if table_column >= len(cells):
                    continue
                # Keep the named subject column; remediation columns are not weaknesses.
                subject = cells[0] if table_column > 0 and not re.fullmatch(r'[A-Z]*\d+', cells[0], re.I) else ''
                line = f'{subject}: {cells[table_column]}' if subject else cells[table_column]
        line = re.sub(r'^\s*(?:[-*]\s+|\d+[.)]\s+|[A-Z]+\d+\s*[:.-]\s*)', '', line)
        for statement in re.split(r'(?<=[.!?;])\s+(?=[A-Z0-9])', line):
            statement = statement.strip(' \t.;')
            if statement:
                entries.append({'id': issue_id(statement), 'statement': statement, 'line': number})
    return list({item['id']: item for item in entries}.values())


def dispositions(architecture, threats):
    from .source_correlation import _source_parts, _scope, _applicable
    from .flow_extraction import alias_index, find_mentions
    from .known_issue_taxonomy import classify_generic_weaknesses, CONTROL_PROPERTIES
    metadata = architecture.metadata or {}
    components = {c.id: c for c in architecture.components}
    aliases = alias_index(components)
    parts, documents = _source_parts(architecture)
    entries = {}
    for filename, lines in parts.items():
        for item in extract_issues('\n'.join(line for line, _ in lines)):
            citation = lines[item['line'] - 1][1]
            scope = _scope(item['statement'], documents.get(filename, {}))
            identifier = issue_id(item['statement'] + str(sorted(scope.items())) + filename)
            entries[identifier] = {**item, **citation, 'id': identifier, 'scope': scope, 'document': filename}
    source_statements = {item['statement'].casefold() for item in entries.values()}
    for item in metadata.get('known_issues') or []:
        statement = item.get('description', '')
        if statement and statement.casefold() not in source_statements:
            entries.setdefault(issue_id(statement), {'id': issue_id(statement), 'statement': statement, 'scope': {}})
    rows = []
    for entry in entries.values():
        mentions = find_mentions(entry['statement'], aliases)
        subject = mentions[0][2] if mentions else None
        entry['component'] = subject
        out_of_scope = bool(subject and not _applicable(entry['scope'], components[subject]))
        expected = classify_generic_weaknesses(entry['statement'])

        def addresses_issue(threat):
            explanation = threat.explanation or {}
            if not expected:
                return explanation.get('origin') == 'declared_known_issue' or entry['statement'].casefold() in threat.title.casefold()
            controls = set(explanation.get('matched_controls') or [])
            return any(str(threat.id).startswith(rule['id']) or (
                rule['cwe'][0] == (threat.cwe or [None])[0]
                and (not controls or controls & set(CONTROL_PROPERTIES.get(rule['control'], ())))
            ) for rule in expected)

        matching = [t for t in threats if addresses_issue(t) and (not subject or subject in t.affected_components) and any(
            entry['statement'].casefold() in str(e.get('statement', '')).casefold()
            and (not e.get('document') or not entry.get('document') or e['document'] == entry['document'])
            for e in t.evidence_details)]
        rows.append({**entry, 'finding_ids': [t.id for t in matching],
            'status': 'out_of_scope' if out_of_scope else 'reported' if matching else 'needs_review',
            'reason': 'Source scope does not match the modeled component.' if out_of_scope else 'Source statement retained in finding evidence.' if matching else 'No scoped finding preserves this declared source issue. Review extraction, scope or deduplication.'})
    return {'issues': rows, 'declared': len(rows), 'reported': sum(r['status'] == 'reported' for r in rows),
        'out_of_scope': sum(r['status'] == 'out_of_scope' for r in rows),
        'unaccounted': sum(r['status'] == 'needs_review' for r in rows)}
