"""Shared control values and aliases; unknown is never silently false."""

from typing import Any


CONTROL_ALIASES = {
    "pagination_enabled": "pagination",
    "authorization_checks": "object_level_auth",
    "access_logging_enabled": "logging_enabled",
    "error_handling_verbose": "detailed_errors",
    "runs_as_root": "runs_as_root",
}
ABSENT = frozenset({"false", "no", "none", "off", "disabled", "absent", "0"})
UNKNOWN = frozenset({"", "unknown", "unspecified", "null", "n/a", "unresolved"})


def presence(value: Any):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        folded = value.strip().lower()
        if folded in UNKNOWN or folded.startswith(("${", "{{")):
            return None
        return folded not in ABSENT
    return None


def control_value(properties: dict, name: str) -> str:
    name = CONTROL_ALIASES.get(name, name)
    correlated = (properties.get('correlated_controls') or {}).get(name)
    if correlated and correlated.get('state') in {'partial', 'planned', 'unknown'}:
        return 'unknown'
    assertions = properties.get("control_assertions") or {}
    records = (properties.get("control_evidence") or {}).get(name, [])
    states = {record.get("state") for record in records if isinstance(record, dict)}
    if assertions.get(name) == "conflicting" or {"present", "absent"} <= states:
        return "conflicting"
    value = presence(properties.get(name))
    if name in (properties.get("explicit_negations") or []):
        return "conflicting" if value is True else "absent"
    return "present" if value is True else "absent" if value is False else "unknown"


def normalized_properties(properties: dict) -> dict:
    normalized = dict(properties)
    for alias, canonical in CONTROL_ALIASES.items():
        if canonical not in normalized and alias in normalized:
            normalized[canonical] = normalized[alias]
        if alias not in normalized and canonical in normalized:
            normalized[alias] = normalized[canonical]
    return normalized


def boundary_dimensions(source, target) -> list[str]:
    dimensions = ['trust_level'] if source.trust_level != target.trust_level else []
    left, right = source.properties or {}, target.properties or {}
    if 'canonical_boundaries' in left and 'canonical_boundaries' in right and set(left['canonical_boundaries']) != set(right['canonical_boundaries']):
        dimensions.append('boundary_membership')
    for key in ('trust_boundary', 'cloud_account', 'tenant_id', 'environment'):
        if left.get(key) and right.get(key) and left[key] != right[key]:
            dimensions.append(key)
    return dimensions
