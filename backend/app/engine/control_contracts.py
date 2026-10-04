"""Shared control values and aliases; unknown is never silently false."""

from typing import Any
import re


CONTROL_ALIASES = {
    "pagination_enabled": "pagination",
    "authorization_checks": "object_level_auth",
    "access_logging_enabled": "logging_enabled",
    "error_handling_verbose": "detailed_errors",
    "runs_as_root": "runs_as_root",
}
ABSENT = frozenset({"false", "no", "none", "off", "disabled", "absent", "0"})
UNKNOWN = frozenset({"", "unknown", "unspecified", "null", "n/a", "unresolved"})
PRESENT = frozenset({'true', 'yes', 'on', 'enabled', 'present', '1', 'enforced', 'implemented',
    'configured', 'required', 'active', 'jwt', 'oauth2', 'oauth', 'oidc', 'saml', 'tls', 'mtls', 'https',
    'aes256', 'aes-256', 'aws:kms', 'sse-kms', 'sse-s3'})


def presence(value: Any):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        folded = value.strip().lower()
        if folded in UNKNOWN or folded.startswith(("${", "{{")) or re.search(r'\b(?:planned|partial|partially|proposed|conflicting|unverified|maybe|pending|tbd)\b', folded):
            return None
        if folded in ABSENT or folded in {'not enabled', 'not configured', 'not implemented', 'not enforced'}:
            return False
        return True if folded in PRESENT else None
    return None


def control_value(properties: dict, name: str) -> str:
    name = CONTROL_ALIASES.get(name, name)
    correlated = (properties.get('correlated_controls') or {}).get(name)
    if correlated and correlated.get('state') == 'conflicting':
        return 'conflicting'
    if correlated and correlated.get('state') in {'partial', 'planned', 'unknown'}:
        return 'unknown'
    assertions = properties.get("control_assertions") or {}
    records = (properties.get("control_evidence") or {}).get(name, [])
    had_records = bool(records)
    records = [record for record in records if isinstance(record, dict)
        and record.get('applicable') is not False and scope_matches(record.get('scope') or {}, properties)]
    if had_records and not records:
        return 'unknown'
    states = {record.get("state") for record in records}
    if assertions.get(name) == "conflicting" or {"present", "absent"} <= states:
        return "conflicting"
    if assertions.get(name) in ('planned', 'partial', 'unknown') or states & {'planned', 'partial', 'unknown'}:
        return 'unknown'
    value = presence(properties.get(name))
    if name in properties and properties[name] is not None and value is None:
        return 'unknown'
    if name in (properties.get("explicit_negations") or []):
        return "conflicting" if value is True else "absent"
    return "present" if value is True else "absent" if value is False else "unknown"


SCOPE_DIMENSIONS = ('environment', 'deployment_version', 'tenant_id', 'cloud_account', 'cloud_provider',
    'region', 'cloud_region', 'technology', 'resource_type', 'trust_boundary', 'boundary_ids')


def _scope_values(value):
    if isinstance(value, str):
        return {value.strip()} if value.strip() else set()
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if isinstance(item, str) and item.strip()}
    return set()


def scope_matches(scope, properties, *, component_type=None):
    """Require stated deployment dimensions to match; missing scope is not a match.

    Endpoint/workflow restrictions are intentionally checked separately by the
    caller. A boundary list is conjunctive; technology lists are alternatives.
    """
    if not isinstance(scope, dict):
        return False
    environment_aliases = {'prod': 'production', 'stage': 'staging', 'dev': 'development'}
    for key in SCOPE_DIMENSIONS:
        declared = scope.get(key)
        if declared is None or declared == '' or declared == []:
            continue
        expected = _scope_values(declared)
        if not expected or {v.lower() for v in expected} & {'unknown', 'unspecified', 'unresolved', '*'}:
            return False
        actual = _scope_values(properties.get(key))
        if key == 'environment':
            expected = {environment_aliases.get(v.lower(), v.lower()) for v in expected}
            actual = {environment_aliases.get(v.lower(), v.lower()) for v in actual}
        elif key in {'region', 'cloud_region'}:
            actual |= _scope_values(properties.get('region')) | _scope_values(properties.get('cloud_region'))
        elif key == 'cloud_provider':
            actual |= _scope_values(properties.get('provider'))
            actual, expected = {v.lower() for v in actual}, {v.lower() for v in expected}
        elif key == 'technology':
            actual |= _scope_values(properties.get('technologies'))
            actual |= _scope_values(properties.get('framework')) | _scope_values(properties.get('runtime'))
            actual |= _scope_values(component_type)
            actual, expected = {v.lower() for v in actual}, {v.lower() for v in expected}
        elif key in {'trust_boundary', 'boundary_ids'}:
            actual |= _scope_values(properties.get('canonical_boundaries')) | _scope_values(properties.get('trust_boundary'))
            if not expected <= actual:
                return False
            continue
        if not expected & actual:
            return False
    return True


def control_effectiveness(component, control, *, required_control=None, scope=None):
    """A control declaration supports only that control, never an unrelated defense."""
    control = CONTROL_ALIASES.get(control, control)
    required = CONTROL_ALIASES.get(required_control or control, required_control or control)
    properties = component.properties or {}
    applicable = scope_matches(scope or {}, properties, component_type=component.type)
    equivalent = control == required
    state = control_value(properties, control) if applicable else 'unknown'
    records = (properties.get('control_evidence') or {}).get(control, [])
    applicable_records = [record for record in records if isinstance(record, dict)
        and record.get('applicable') is not False
        and scope_matches(record.get('scope') or {}, properties, component_type=component.type)]
    # A stale property copied from another deployment cannot survive its ledger.
    if records and not applicable_records:
        state = 'unknown'
    endpoint = scope.get('endpoint') if isinstance(scope, dict) else None
    correlated = (properties.get('correlated_controls') or {}).get(control, {})
    scoped = correlated.get('scoped_claims', [])
    endpoint_records = []
    if endpoint:
        endpoint_records = [record for record in scoped if isinstance(record, dict)
            and record.get('applicable') is not False
            and scope_matches(record.get('scope') or {}, properties, component_type=component.type)
            and endpoint in (record.get('scope') or {}).get('endpoints', [])]
        # An explicit endpoint exception is more specific than a blanket claim.
        if endpoint_records:
            applicable_records = endpoint_records
    states = {record.get('state') for record in applicable_records}
    if not applicable:
        state = 'unknown'
    elif not endpoint_records and correlated.get('state') in {'conflicting', 'planned', 'partial', 'unknown'}:
        state = 'conflicting' if correlated['state'] == 'conflicting' else 'unknown'
    elif {'present', 'absent'} <= states:
        state = 'conflicting'
    elif states & {'partial', 'conflicting', 'planned', 'unknown'}:
        state = 'unknown'
    elif states & {'present', 'absent'}:
        evidence_state = next(iter(states & {'present', 'absent'}))
        state = 'conflicting' if not endpoint_records and state in {'present', 'absent'} and state != evidence_state else evidence_state
    return {'control': control, 'required_control': required, 'state': state,
        'applicable': applicable, 'effective_for_claim': applicable and equivalent and state == 'present',
        'basis': 'submitted_control_state' if applicable and equivalent else 'scope_or_control_mismatch',
        'runtime_verified': False}


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


def boundary_members(architecture):
    """Explicit containment adds child members to ancestors, never the reverse."""
    boundaries = architecture.trust_boundaries
    members = [set(boundary.components) for boundary in boundaries]
    by_id = {boundary.id: index for index, boundary in enumerate(boundaries) if boundary.id}
    for index, boundary in enumerate(boundaries):
        seen = {index}
        parent = by_id.get(boundary.parent_id)
        while parent is not None and parent not in seen:
            seen.add(parent)
            members[parent].update(boundary.components)
            parent = by_id.get(boundaries[parent].parent_id)
    return members
