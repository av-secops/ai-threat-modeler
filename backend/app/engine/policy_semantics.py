"""Read policy statements without treating deny clauses as permission grants."""

from __future__ import annotations

import json
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
