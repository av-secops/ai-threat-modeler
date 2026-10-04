import re
import json
from copy import deepcopy
from typing import Dict, List, Tuple

from ..models import Threat


def deduplicate_threats(threat_list: List[Threat]) -> List[Threat]:
    grouped: Dict[Tuple[str, ...], Threat] = {}

    for threat in threat_list:
        # Each documented issue is independent source evidence. Do not merge it
        # merely because another issue has the same STRIDE category or CWE set.
        if threat.finding_type == "control_gap":
            group_key = ("control_gap", threat.id or "unknown", str(id(threat)))
        else:
            cwe_key = ",".join(sorted(threat.cwe or [])) or "no-cwe"
            stride_key = (threat.stride_category or threat.category or "unknown").lower()
            root_cause_key = _normalize_root_cause(threat.root_cause or threat.title)
            component_scope = sorted(set(filter(None, [
                threat.component, threat.affected_component, threat.component_id,
                *(threat.affected_components or []),
            ])))
            flow_scope = sorted(set(filter(None, [
                threat.data_flow, threat.related_data_flow,
                *(threat.affected_data_flows or []),
            ])))
            asset_scope = sorted(set(filter(None, [threat.asset, *(threat.affected_assets or [])])))
            scope_key = "|".join(component_scope + flow_scope + asset_scope) or "unscoped"
            group_key = (cwe_key, stride_key, root_cause_key, scope_key, evidence_scope(threat))

        if group_key not in grouped:
            grouped[group_key] = threat.model_copy(deep=True)
            if not grouped[group_key].component:
                grouped[group_key].component = threat.affected_component or threat.component_id
            if not grouped[group_key].data_flow:
                grouped[group_key].data_flow = threat.related_data_flow
            if not grouped[group_key].asset:
                grouped[group_key].asset = threat.asset
            continue

        existing = grouped[group_key]
        merge_finding_evidence(existing, threat)
        existing.affected_components = _merge_unique(existing.affected_components, threat.affected_components or [])
        existing.affected_data_flows = _merge_unique(existing.affected_data_flows, threat.affected_data_flows or [])
        existing.affected_assets = _merge_unique(existing.affected_assets, threat.affected_assets or [])
        existing.evidence = _merge_unique(existing.evidence, threat.evidence or [])
        existing.evidence_details = _merge_evidence_details(existing.evidence_details, threat.evidence_details)
        existing.preconditions = _merge_unique(existing.preconditions, threat.preconditions or [])
        existing.owasp_top_10 = _merge_unique(existing.owasp_top_10 or [], threat.owasp_top_10 or [])
        existing.cwe = _merge_unique(existing.cwe or [], threat.cwe or [])
        existing.mitre_attack = _merge_unique(existing.mitre_attack or [], threat.mitre_attack or [])
        existing.mitre_atlas = _merge_unique(existing.mitre_atlas or [], threat.mitre_atlas or [])
        existing.nist_800_53 = _merge_unique(existing.nist_800_53 or [], threat.nist_800_53 or [])

        if threat.affected_component and threat.affected_component not in existing.affected_components:
            existing.affected_components.append(threat.affected_component)
        if threat.related_data_flow and threat.related_data_flow.replace("->", " → ") not in existing.affected_data_flows:
            existing.affected_data_flows.append(threat.related_data_flow.replace("->", " → "))
        if threat.asset and threat.asset not in existing.affected_assets:
            existing.affected_assets.append(threat.asset)

        existing.component = existing.component or threat.component or threat.affected_component or threat.component_id
        existing.data_flow = existing.data_flow or threat.data_flow or threat.related_data_flow
        existing.asset = existing.asset or threat.asset
        existing.attack_scenario = existing.attack_scenario or threat.attack_scenario or threat.realistic_attack_scenario
        existing.realistic_attack_scenario = existing.realistic_attack_scenario or threat.realistic_attack_scenario or threat.attack_scenario
        existing.business_impact = existing.business_impact or threat.business_impact
        existing.root_cause = existing.root_cause or threat.root_cause
        existing.mitigation = existing.mitigation or threat.mitigation

        severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        if severity_rank.get(threat.severity, 1) > severity_rank.get(existing.severity, 1):
            existing.severity = threat.severity
            existing.likelihood = threat.likelihood
            existing.impact = threat.impact
        existing.risk_score = max(existing.risk_score or 0, threat.risk_score or 0)
        if threat.confidence == "High":
            existing.confidence = "High"
        if threat.finding_type in {"code", "iac"}:
            existing.finding_type = threat.finding_type
        if not existing.risk_factors and threat.risk_factors:
            existing.risk_factors = threat.risk_factors

    deduped = list(grouped.values())
    for threat in deduped:
        if threat.component and threat.component not in threat.affected_components:
            threat.affected_components.insert(0, threat.component)
        if threat.data_flow and threat.data_flow.replace("->", " → ") not in threat.affected_data_flows:
            threat.affected_data_flows.insert(0, threat.data_flow.replace("->", " → "))
        if threat.asset and threat.asset not in threat.affected_assets:
            threat.affected_assets.insert(0, threat.asset)
    return deduped


def _normalize_root_cause(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"\s+", " ", normalized)


def _merge_unique(left: List[str], right: List[str]) -> List[str]:
    seen = []
    for item in [*(left or []), *(right or [])]:
        if item and item not in seen:
            seen.append(item)
    return seen


def _merge_evidence_details(left: List[Dict], right: List[Dict]) -> List[Dict]:
    merged = []
    seen = set()
    for item in [*(left or []), *(right or [])]:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def evidence_scope(threat: Threat) -> str:
    scopes = {(json.dumps(e['scope'], sort_keys=True, default=str))
        for e in threat.evidence_details or [] if e.get('scope') and any(e['scope'].values())}
    explicit = (threat.explanation or {}).get('scope')
    if explicit:
        scopes.add(json.dumps(explicit, sort_keys=True, default=str))
    return '|'.join(sorted(scopes))


def merge_finding_evidence(keeper: Threat, other: Threat, *, supporting_only: bool = False) -> None:
    """Retain provenance and reviewer decisions when a producer is superseded."""
    taxonomies = ('cwe', 'owasp_top_10', 'mitre_attack', 'mitre_atlas', 'nist_800_53')
    for field in ('evidence', 'evidence_details', 'preconditions', 'affected_flow_refs',
                  *(() if supporting_only else taxonomies)):
        setattr(keeper, field, deepcopy(_merge_unique(getattr(keeper, field), getattr(other, field))))
    left, right = dict(keeper.explanation or {}), dict(other.explanation or {})
    combined = {**deepcopy(right), **deepcopy(left)}
    if supporting_only:
        combined['superseded_candidate_mappings'] = _merge_unique(left.get('superseded_candidate_mappings', []),
            [{'finding_id': other.id, 'tier': other.tier, **{key: getattr(other, key) for key in taxonomies}}])
    combined['merged_finding_ids'] = _merge_unique(left.get('merged_finding_ids') or [keeper.id],
        right.get('merged_finding_ids') or [other.id])
    for field in ('matched_controls', 'issue_ids', 'correlated_evidence', 'flow_context', 'rule_provenances',
                  'merged_review_decisions', 'merged_severity_decisions'):
        # Some older producers used dictionaries for context fields.
        if isinstance(left.get(field, []), list) and isinstance(right.get(field, []), list):
            combined[field] = deepcopy(_merge_unique(left.get(field, []), right.get(field, [])))
    combined['rule_provenances'] = _merge_unique(combined.get('rule_provenances', []),
        [p for p in (left.get('rule_provenance'), right.get('rule_provenance')) if p])
    combined['merged_severity_decisions'] = _merge_unique(combined.get('merged_severity_decisions', []), [
        {'finding_id': t.id, 'severity': t.severity, 'basis': t.severity_source} for t in (keeper, other)])
    decisions = [{'finding_id': t.id, 'review_status': t.review_status, 'review_state': t.review_state}
        for t in (keeper, other)]
    combined['merged_review_decisions'] = _merge_unique(combined.get('merged_review_decisions', []), decisions)
    if keeper.review_status != other.review_status or keeper.review_state != other.review_state:
        keeper.review_status = 'pending_review'
        keeper.review_state = 'open'
        combined['review_conflict'] = True
    keeper.explanation = combined
