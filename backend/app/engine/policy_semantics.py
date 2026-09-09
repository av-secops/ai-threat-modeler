"""Read policy statements without treating deny clauses as permission grants."""

from __future__ import annotations

import json
import fnmatch
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

    Each boundary/SCP/session document is an additional ceiling. Role sessions,
    policy variables, NotPrincipal and unsupported condition operators abstain.
    """
    sets = query.get('policy_sets') or {}
    reasons, matches = [], []
    context = query.get('context') or {}
    principal = query.get('principal', '')
    if not isinstance(sets, dict) or not isinstance(context, dict):
        return {'decision': 'unknown', 'matched_statements': [], 'limits': ['Invalid policy inventory or request context'], 'runtime_verified': False}
    if not principal or not query.get('action') or not query.get('resource'):
        reasons.append('An explicit principal, action and resource are required')

    def glob(actual, patterns, fold=False):
        return any(fnmatch.fnmatchcase(str(actual).lower() if fold else str(actual),
            str(p).lower() if fold else str(p)) for p in values(patterns))

    def statement_matches(statement):
        if statement.get('Effect') not in {'Allow', 'Deny'}:
            return None
        if 'NotPrincipal' in statement or '${' in json.dumps(statement):
            return None
        if any(field in statement and 'Not' + field in statement for field in ('Action', 'Resource')):
            return None
        for field, actual, fold in [('Action', query.get('action'), True), ('Resource', query.get('resource'), False)]:
            if not actual or (field not in statement and 'Not' + field not in statement):
                return None
            if field in statement and not glob(actual, statement[field], fold):
                return False
            if 'Not' + field in statement and glob(actual, statement['Not' + field], fold):
                return False
        declared = statement.get('Principal')
        if declared is not None:
            if isinstance(declared, dict):
                if set(declared) != {'AWS'}:
                    return None
                declared = declared['AWS']
            if any(re.fullmatch(r'\d{12}', str(v)) or str(v).endswith(':root') or ('*' in str(v) and v != '*') for v in values(declared)):
                return None
            if not principal:
                return None
            if not glob(principal, declared):
                return False
        conditions = statement.get('Condition') or {}
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
                actual = str(context[key]).lower() if operator == 'Bool' else str(context[key])
                expected = [str(v).lower() if operator == 'Bool' else str(v) for v in values(expected)]
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
                state = statement_matches(statement)
                if state is None:
                    reasons.append(f'{group}[{index}] has unresolved statement semantics')
                elif state:
                    matches.append({'group': group, 'policy': index, 'sid': statement.get('Sid'), 'effect': statement.get('Effect')})
                    if statement.get('Effect') == 'Deny':
                        return {'decision': 'explicit_deny', 'matched_statements': matches, 'limits': reasons, 'runtime_verified': False}
                    allowed |= statement.get('Effect') == 'Allow'
            results.append(allowed)
        group_results[group] = results
    if query.get('principal_type', 'iam_user') != 'iam_user':
        reasons.append('Role-session/resource-policy exceptions require an external IAM evaluator')
    if any(group_results.get('resource', [])) and any(group in sets for group in ('boundaries', 'session')):
        reasons.append('Resource grants interacting with boundaries or session policies require an external IAM evaluator')
    if not query.get('policy_inventory_complete'):
        reasons.append('The full policy inventory has not been supplied')
    if any(group not in {'identity', 'resource', 'boundaries', 'scp', 'rcp', 'session'} for group in sets):
        reasons.append('Unsupported policy set')
    if reasons:
        return {'decision': 'unknown', 'matched_statements': matches, 'limits': sorted(set(reasons)), 'runtime_verified': False}
    allowed = any(group_results.get('identity', [])) or any(group_results.get('resource', []))
    if query.get('cross_account'):
        allowed = any(group_results.get('identity', [])) and any(group_results.get('resource', []))
    for group in ('boundaries', 'scp', 'rcp', 'session'):
        if group in group_results:
            allowed &= bool(group_results[group]) and all(group_results[group])
    return {'decision': 'allowed_in_supplied_policies' if allowed else 'implicit_deny',
        'matched_statements': matches, 'limits': ['Static IAM-user subset; deployment and service-specific policy layers are not verified.'], 'runtime_verified': False}
