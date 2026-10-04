"""Read policy statements without treating deny clauses as permission grants."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

try:
    import hcl2
except ImportError:  # Source installs can still inspect JSON policies.
    hcl2 = None


def values(value: Any) -> list:
    return value if isinstance(value, list) else [] if value is None else [value]


def _encoded_objects(text: str) -> Iterable[dict]:
    """Parse literal jsonencode arguments; never evaluate Terraform functions."""
    start = 0
    while True:
        call = text.find("jsonencode(", start)
        if call < 0:
            return
        begin = call + len("jsonencode(")
        index, depth, quoted, escaped = begin, 1, False, False
        while index < len(text) and depth:
            char = text[index]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            index += 1
        start = max(index, begin + 1)
        if depth or hcl2 is None:
            continue
        try:
            parsed = hcl2.loads("value = " + text[begin:index - 1]).get("value")
            if isinstance(parsed, dict):
                yield parsed
        except Exception:
            continue


def documents(value: Any, depth: int = 0) -> Iterable[dict]:
    if depth > 12:
        return
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            encoded = list(_encoded_objects(value))
            for item in encoded:
                yield from documents(item, depth + 1)
            if not encoded and hcl2 is not None:
                try:
                    parsed = hcl2.loads(value)
                except Exception:
                    return
            else:
                return
        if parsed != value:
            yield from documents(parsed, depth + 1)
    elif isinstance(value, dict):
        if "Statement" in value:
            yield value
        else:
            for child in value.values():
                yield from documents(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from documents(child, depth + 1)


def allow_statements(value: Any) -> Iterable[dict]:
    for document in documents(value):
        statements = [s for s in values(document.get("Statement")) if isinstance(s, dict)]
        # This is only a local, unconditional deny-all. Effective IAM evaluation
        # also needs identity/resource policies, boundaries and organization policy.
        denied_all = any(
            s.get("Effect") == "Deny" and not s.get("Condition")
            and values(s.get("Action")) == ["*"]
            and values(s.get("Resource")) == ["*"]
            and "Principal" not in s and "NotPrincipal" not in s
            for s in statements
        )
        if not denied_all:
            yield from (s for s in statements if s.get("Effect") == "Allow")


def unrestricted_public_allow(value: Any) -> bool:
    for statement in allow_statements(value):
        if statement.get("Condition") or not statement.get("Action"):
            continue
        principal = statement.get("Principal")
        if principal == "*" or isinstance(principal, dict) and "*" in values(principal.get("AWS")):
            return True
    return False


def evaluate_access(query: dict) -> dict:
    """Bounded IAM policy evaluation, not a live effective-permissions simulator.

    Role sessions, policy variables, NotPrincipal and unsupported conditions
    abstain. Organization policies need explicit attachment levels: permissions
    union at one level and intersect across levels, never across each document.
    """
    def unknown(reason):
        return {'decision': 'unknown', 'matched_statements': [], 'limits': [reason], 'runtime_verified': False}

    if not isinstance(query, dict):
        return unknown('Invalid access request')
    sets = query.get('policy_sets', {})
    reasons, matches = [], []
    context = query.get('context', {})
    principal = query.get('principal', '')
    if not isinstance(sets, dict) or not isinstance(context, dict):
        return unknown('Invalid policy inventory or request context')
    if any(not isinstance(query.get(key), str) or not query[key].strip()
            or '${' in query[key] or any(char in query[key] for char in '*?')
            for key in ('principal', 'action', 'resource')):
        return unknown('A concrete principal, action and resource are required')
    if query.get('principal_type', 'iam_user') != 'iam_user' or not re.fullmatch(r'arn:[^:]+:iam::\d{12}:user/.+', principal):
        return unknown('Role-session/resource-policy exceptions require an external IAM evaluator')
    allowed_groups = {'identity', 'resource', 'boundaries', 'scp', 'rcp', 'session'}
    if any(group not in allowed_groups for group in sets):
        return unknown('Unsupported policy set')
    levels = query.get('policy_levels', {})
    if not isinstance(levels, dict) or any(group not in {'scp', 'rcp'} for group in levels):
        return unknown('Invalid organization policy levels')
    sets = dict(sets)
    level_sizes = {}
    for group, attachments in levels.items():
        if group in sets or not isinstance(attachments, list) or not attachments:
            return unknown('Supply organization policies once, grouped by attachment level')
        flattened, sizes = [], []
        seen = set()
        for attachment in attachments:
            if not isinstance(attachment, dict) or not isinstance(attachment.get('id'), str) or not attachment['id'] or attachment['id'] in seen:
                return unknown('Organization attachment levels need unique identifiers')
            policies = attachment.get('policies')
            if not isinstance(policies, list) or not policies:
                return unknown('Organization attachment level has no supplied policies')
            seen.add(attachment['id'])
            flattened.extend(policies)
            sizes.append(len(policies))
        sets[group], level_sizes[group] = flattened, sizes

    def glob(actual, patterns, fold=False):
        # IAM wildcards are * and ?, not shell character classes such as [ab].
        return any(re.fullmatch(re.escape(str(pattern)).replace(r'\*', '.*').replace(r'\?', '.'),
            str(actual), flags=re.I if fold else 0) is not None for pattern in values(patterns))

    def statement_matches(statement, group):
        if statement.get('Effect') not in ('Allow', 'Deny'):
            return None
        if 'NotPrincipal' in statement or '${' in json.dumps(statement):
            return None
        if any(field in statement and 'Not' + field in statement for field in ('Action', 'Resource')):
            return None
        for field, actual, fold in [('Action', query.get('action'), True), ('Resource', query.get('resource'), False)]:
            if not actual or (field not in statement and 'Not' + field not in statement):
                return None
            selected = statement.get(field, statement.get('Not' + field))
            if not values(selected) or any(not isinstance(value, str) or not value for value in values(selected)):
                return None
            if field in statement and not glob(actual, statement[field], fold):
                return False
            if 'Not' + field in statement and glob(actual, statement['Not' + field], fold):
                return False
        declared = statement.get('Principal')
        if group == 'resource' and declared is None:
            return None
        if group != 'resource' and declared is not None:
            return None
        if declared is not None:
            if isinstance(declared, dict):
                if set(declared) != {'AWS'}:
                    return None
                declared = declared['AWS']
            if not values(declared) or any(not isinstance(value, str) or not value for value in values(declared)):
                return None
            if any(re.fullmatch(r'\d{12}', str(v)) or str(v).endswith(':root') or ('*' in str(v) and v != '*') for v in values(declared)):
                return None
            if not principal:
                return None
            if not glob(principal, declared):
                return False
        conditions = statement.get('Condition', {})
        if not isinstance(conditions, dict):
            return None
        for operator, terms in conditions.items():
            if not isinstance(terms, dict):
                return None
            if operator not in {'StringEquals', 'ArnEquals', 'StringLike', 'ArnLike', 'Bool'}:
                return None
            for key, expected in terms.items():
                if key not in context:
                    return None
                if not isinstance(context[key], (str, bool, int, float)):
                    return None
                if not values(expected) or any(not isinstance(item, (str, bool, int, float)) for item in values(expected)):
                    return None
                actual = str(context[key]).lower() if operator == 'Bool' else str(context[key])
                expected = [str(v).lower() if operator == 'Bool' else str(v) for v in values(expected)]
                if operator == 'Bool' and (actual not in {'true', 'false'} or not set(expected) <= {'true', 'false'}):
                    return None
                matched = glob(actual, expected) if operator.endswith('Like') else actual in expected
                if not matched:
                    return False
        return True

    group_results = {}
    for group, policies in sets.items():
        results = []
        for index, policy in enumerate(values(policies)):
            allowed = False
            if not isinstance(policy, dict) or not policy.get('Statement'):
                reasons.append('Invalid or empty policy document')
            for statement in values(policy.get('Statement')) if isinstance(policy, dict) else []:
                if not isinstance(statement, dict):
                    reasons.append('Invalid policy statement')
                    continue
                state = statement_matches(statement, group)
                if state is None:
                    reasons.append(f'{group}[{index}] has unresolved statement semantics')
                elif state:
                    matches.append({'group': group, 'policy': index, 'sid': statement.get('Sid'), 'effect': statement.get('Effect')})
                    if statement.get('Effect') == 'Deny':
                        return {'decision': 'explicit_deny', 'matched_statements': matches, 'limits': reasons, 'runtime_verified': False}
                    allowed |= statement.get('Effect') == 'Allow'
            results.append(allowed)
        group_results[group] = results
    if any(group_results.get('resource', [])) and any(group in sets for group in ('boundaries', 'session')):
        reasons.append('Resource grants interacting with boundaries or session policies require an external IAM evaluator')
    if query.get('policy_inventory_complete') is not True:
        reasons.append('The full policy inventory has not been supplied')
    for group in ('scp', 'rcp'):
        if len(group_results.get(group, [])) > 1 and group not in level_sizes:
            reasons.append(f'{group} attachment levels are required; policies at one level are not independent ceilings')
    if len(group_results.get('boundaries', [])) > 1:
        reasons.append('An IAM identity has at most one permissions boundary')
    if 'session' in sets:
        reasons.append('Session policy semantics require a supported session principal evaluator')
    if query['action'].lower().startswith(('kms:', 'sts:')):
        reasons.append('KMS key policies/grants and STS trust/session rules require a service-specific evaluator')
    if reasons:
        return {'decision': 'unknown', 'matched_statements': matches, 'limits': sorted(set(reasons)), 'runtime_verified': False}
    allowed = any(group_results.get('identity', [])) or any(group_results.get('resource', []))
    principal_account = principal.split(':')[4]
    resource_parts = query['resource'].split(':')
    resource_account = resource_parts[4] if len(resource_parts) > 5 and resource_parts[0] == 'arn' else ''
    if query.get('cross_account') is True or (resource_account and principal_account != resource_account):
        allowed = any(group_results.get('identity', [])) and any(group_results.get('resource', []))
    for group in ('boundaries', 'scp', 'rcp', 'session'):
        if group in group_results:
            results = group_results[group]
            if group in level_sizes:
                offset, ceilings = 0, []
                for size in level_sizes[group]:
                    ceilings.append(any(results[offset:offset + size]))
                    offset += size
                allowed &= all(ceilings)
            elif group == 'session':
                allowed &= any(results)
            else:
                allowed &= bool(results) and all(results)
    return {'decision': 'allowed_in_supplied_policies' if allowed else 'implicit_deny',
        'matched_statements': matches, 'limits': ['Static IAM-user subset; deployment and service-specific policy layers are not verified.'], 'runtime_verified': False}
