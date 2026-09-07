"""Evidence-aware normalization for the architecture intermediate model."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..models import SystemArchitecture
from . import source_index as sources
from .control_contracts import boundary_dimensions, presence
from .source_correlation import reconcile_claims, source_metadata


CONTROL_KEYS = (
    "auth_type", "mfa_enabled", "rbac_enabled", "abac_enabled", "input_validation",
    "rate_limiting", "waf_enabled", "encryption_at_rest", "encryption_in_transit",
    "logging_enabled", "audit_logging", "mtls_enabled", "private_subnet",
    "secrets_management", "container_image_provenance", "query_depth_limiting",
    "webhook_signature_validation", "dlp_enabled",
)

BLOCKING_ISSUE_TYPES = {
    "duplicate_component_id", "invalid_flow", "invalid_boundary_membership",
    "contradictory_control", "source_conflict",
}


def canonicalize_architecture(architecture: SystemArchitecture) -> Tuple[SystemArchitecture, Dict[str, Any]]:
    """Attach provenance, confidence, actors, identities, and validation gaps.

    The parser remains responsible for extraction. This pass establishes one
    contract for downstream engines, including IaC-created architectures.
    """
    metadata = architecture.metadata or {}
    source_text = metadata.get("source_text") or metadata.get("architecture_text") or ""
    source_documents = [source_metadata(d) for d in metadata.get("source_documents") or []]
    metadata['source_documents'] = source_documents
    index = sources.build(source_text)
    component_ids = {component.id for component in architecture.components or []}
    components_by_id = {component.id: component for component in architecture.components or []}
    issues: List[Dict[str, Any]] = []
    source_conflicts = _source_conflicts(source_documents)
    issues.extend(source_conflicts)
    component_id_counts: Dict[str, int] = {}
    component_name_counts: Dict[str, int] = {}
    for component in architecture.components or []:
        component_id_counts[component.id] = component_id_counts.get(component.id, 0) + 1
        normalized_name = component.name.strip().lower()
        component_name_counts[normalized_name] = component_name_counts.get(normalized_name, 0) + 1
    for component_id, count in component_id_counts.items():
        if count > 1:
            issues.append(_gap(
                "duplicate_component_id", component_id,
                f"Component ID {component_id} is declared {count} times.", "High",
            ))
    for name, count in component_name_counts.items():
        if name and count > 1:
            issues.append(_gap(
                "duplicate_component_name", name,
                f"Component name {name} is declared {count} times.", "Medium",
            ))

    for component in architecture.components or []:
        props = component.properties or {}
        line_number, statement = _find_component_evidence(source_text, component.name, component.id, index)
        explicit = bool(statement) or bool(props.get("authoritative") or props.get("authoritative_external_entity"))
        component.confidence = "High" if explicit else "Medium"
        citation = index.cite(line_number)
        component.evidence = component.evidence or [_evidence(
            "architecture_input" if explicit else "inference",
            statement or f"Component {component.name} inferred from architecture context.",
            component.confidence,
            citation,
        )]
        if citation:
            props["source_document"] = citation.document
        props["evidence_status"] = "explicit" if explicit else "inferred"
        existing_conflicts = {key: state for key, state in (props.get("control_assertions") or {}).items() if state == "conflicting"}
        props["control_assertions"] = {
            key: _assertion_status(props.get(key)) for key in CONTROL_KEYS
        }
        props["control_assertions"].update(existing_conflicts)
        for key, records in (props.get("control_evidence") or {}).items():
            for record in records:
                if isinstance(record, dict):
                    claim_citation = index.find(record.get('statement', ''))
                    if claim_citation and not record.get('source_id'):
                        record.update(claim_citation.as_dict())
            states = {record.get("state") for record in records if isinstance(record, dict)}
            if {"present", "absent"} <= states:
                props["control_assertions"][key] = "conflicting"
                issues.append(_gap("contradictory_control", component.id,
                    f"Sources disagree about {key}; both claims are retained for review.", "High"))
        contradictory = sorted(
            key for key in set(props.get("explicit_negations") or [])
            if presence(props.get(key)) is True
        )
        if contradictory:
            issues.append(_gap(
                "contradictory_control", component.id,
                f"Control evidence is both present and absent for: {', '.join(contradictory)}.", "High",
            ))
        component.properties = props

        if component.type in {"API", "API Gateway", "Service", "ML Service", "Identity Provider"}:
            if props.get("auth_type") in {None, "", "unknown"}:
                issues.append(_gap(
                    "authentication", component.id,
                    f"Authentication is not specified for {component.name}.",
                    "High" if component.trust_level in {"public", "external"} else "Medium",
                ))
            if not props.get("rbac_enabled") and not props.get("abac_enabled"):
                issues.append(_gap(
                    "authorization", component.id,
                    f"Authorization policy is not specified for {component.name}.", "Medium",
                ))

    flow_keys = set()
    boundary_crossings = []
    for flow in architecture.flows or []:
        explicit = not flow.assumed
        statement = (flow.properties or {}).get("evidence") or (
            f"Explicit flow {flow.source_id} to {flow.target_id}." if explicit
            else f"Flow {flow.source_id} to {flow.target_id} inferred by architecture rules."
        )
        flow.confidence = "High" if explicit else "Medium"
        # A stated flow carries the sentence that stated it, so the sentence is
        # what locates it. An inferred flow was in no document to begin with.
        flow.evidence = flow.evidence or [_evidence(
            "architecture_input" if explicit else "inference",
            statement, flow.confidence, index.find(statement) if explicit else None,
        )]
        if flow.source_id not in component_ids or flow.target_id not in component_ids:
            issues.append(_gap(
                "invalid_flow", f"{flow.source_id}->{flow.target_id}",
                "A modeled data flow references a component that does not exist.", "High",
            ))
            continue
        if flow.source_id == flow.target_id:
            issues.append(_gap(
                "self_referential_flow", f"{flow.source_id}->{flow.target_id}",
                "A data flow cannot establish a meaningful trust transition to itself.", "Medium",
            ))
        flow_key = (flow.source_id, flow.target_id, (flow.protocol or "").lower(), flow.data_type)
        if flow_key in flow_keys:
            issues.append(_gap(
                "duplicate_flow", f"{flow.source_id}->{flow.target_id}",
                "The same source, destination, protocol, and data type are modeled more than once.", "Medium",
            ))
        flow_keys.add(flow_key)
        source = components_by_id[flow.source_id]
        target = components_by_id[flow.target_id]
        explicit_crossing = bool((flow.properties or {}).get("crosses_trust_boundary"))
        dimensions = boundary_dimensions(source, target)
        actual_crossing = bool(dimensions)
        flow.properties = {**(flow.properties or {}), 'boundary_dimensions': dimensions, 'crosses_trust_boundary': actual_crossing or explicit_crossing}
        if explicit_crossing and not actual_crossing:
            issues.append(_gap(
                "boundary_contradiction", f"{flow.source_id}->{flow.target_id}",
                "The flow declares a trust boundary not represented by endpoint trust levels, accounts, tenants or environments; confirm the boundary.", "Medium",
            ))
        if actual_crossing:
            boundary_crossings.append({
                "flow": f"{flow.source_id}->{flow.target_id}",
                "source_trust": source.trust_level,
                "target_trust": target.trust_level,
                "explicit": not flow.assumed,
                "dimensions": dimensions,
            })

    for boundary in architecture.trust_boundaries or []:
        unknown_members = sorted(set(boundary.components or []) - component_ids)
        if unknown_members:
            issues.append(_gap(
                "invalid_boundary_membership", f"boundary:{boundary.name}",
                f"Trust boundary references unknown components: {', '.join(unknown_members)}.", "High",
            ))
        if not boundary.components:
            issues.append(_gap(
                "empty_boundary", f"boundary:{boundary.name}",
                "Trust boundary does not contain any modeled components.", "Medium",
            ))

    for asset in architecture.assets or []:
        component = next((item for item in architecture.components if item.id == asset.related_component_id), None)
        asset.confidence = component.confidence if component else "Medium"
        asset.evidence = asset.evidence or (component.evidence if component else [_evidence(
            "inference",
            f"Asset {asset.name} inferred from storage and data classification.", "Medium",
        )])

    architecture.metadata = metadata
    correlation = reconcile_claims(architecture)
    metadata = architecture.metadata
    if correlation['facts']:
        reconciled = {c.id for c in architecture.components if c.properties.get('correlated_controls')}
        issues = [issue for issue in issues if not (issue['type'] == 'contradictory_control' and issue.get('scope') in reconciled)]
        for conflict in correlation['conflicts']:
            issues.append(_gap('contradictory_control', conflict['element_id'],
                f"Sources disagree about {conflict['control']}; inspect the cited claims before resolving this control.", 'High'))
    if metadata.get("authoritative_model") and metadata.get("actors"):
        actors = metadata["actors"]
        identities = metadata.get("identities", [])
    else:
        actors, identities = _extract_actors_and_identities(source_text, architecture)
    metadata["actors"] = actors
    metadata["identities"] = identities
    metadata["canonical_model_version"] = "3.0"
    metadata["source_provenance"] = _provenance(index, source_documents)
    metadata["source_reconciliation"] = _source_reconciliation(source_documents, source_conflicts)
    metadata["source_attribution"] = _attribution(index, architecture)
    metadata["boundary_crossings"] = boundary_crossings
    metadata["architecture_contract"] = {
        "component_ids_unique": not any(item["type"] == "duplicate_component_id" for item in issues),
        "flows_resolve": not any(item["type"] == "invalid_flow" for item in issues),
        "boundaries_resolve": not any(item["type"] == "invalid_boundary_membership" for item in issues),
        "controls_consistent": not any(item["type"] == "contradictory_control" for item in issues),
        "evidence_required": True,
    }
    metadata["architecture_ir"] = _architecture_ir(architecture, actors, identities, issues)
    architecture.metadata = metadata

    explicit_flows = sum(1 for flow in architecture.flows or [] if not flow.assumed)
    blocking_issues = [item for item in issues if item["type"] in BLOCKING_ISSUE_TYPES]
    validation = {
        "version": "canonical-3.0",
        "valid": not blocking_issues,
        "issues": issues,
        "quality_gate": {
            "status": "pass" if not blocking_issues else "fail",
            "blocking_issues": len(blocking_issues),
            "high_priority_review_gaps": sum(
                item["severity"] == "High" and item["type"] not in BLOCKING_ISSUE_TYPES for item in issues
            ),
            "warning_issues": sum(item["severity"] != "High" for item in issues),
            "boundary_crossings": len(boundary_crossings),
        },
        "counts": {
            "components": len(architecture.components or []),
            "explicit_components": sum(1 for component in architecture.components or [] if component.confidence == "High"),
            "flows": len(architecture.flows or []),
            "explicit_flows": explicit_flows,
            "inferred_flows": len(architecture.flows or []) - explicit_flows,
            "actors": len(actors),
            "identities": len(identities),
        },
    }
    return architecture, validation


def _source_conflicts(documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify authoritative inputs that explicitly claim different systems.

    Different files often describe different tiers of one design, so disjoint
    technology lists alone are not a conflict. A conflict requires incompatible
    declared system names, or two complete structured system models with no
    shared technology signal.
    """
    design = [item for item in documents if item.get("role") != "reference_report"]
    conflicts: List[Dict[str, Any]] = []
    for index, left in enumerate(design):
        for right in design[index + 1:]:
            left_name = str(left.get("system_name") or "").strip().lower()
            right_name = str(right.get("system_name") or "").strip().lower()
            left_signals = {item for item in str(left.get("technology_signals") or "").split(",") if item}
            right_signals = {item for item in str(right.get("technology_signals") or "").split(",") if item}
            names_conflict = bool(
                left_name and right_name and left_name != right_name
                and left_name not in right_name and right_name not in left_name
            )
            complete_models_conflict = (
                left.get("structured_kind") == "architecture"
                and right.get("structured_kind") == "architecture"
                and bool(left_signals) and bool(right_signals)
                and not (left_signals & right_signals)
            )
            same_system = bool(left_name and right_name and (
                left_name == right_name or left_name in right_name or right_name in left_name
            ))
            left_environment = str(left.get("environment") or "").lower()
            right_environment = str(right.get("environment") or "").lower()
            same_environment = not left_environment or not right_environment or left_environment == right_environment
            left_version = str(left.get("deployment_version") or left.get('document_version') or "").lower()
            right_version = str(right.get("deployment_version") or right.get('document_version') or "").lower()
            version_conflict = bool(
                same_system and same_environment and left_version and right_version
                and left_version != right_version
                and left.get("structured_kind") == "architecture"
                and right.get("structured_kind") == "architecture"
            )
            if not names_conflict and not complete_models_conflict and not version_conflict:
                continue
            conflicts.append(_gap(
                "source_conflict",
                f"{left.get('filename', 'source 1')}|{right.get('filename', 'source 2')}",
                (
                    "Uploaded authoritative sources are incompatible or describe different model versions: "
                    f"{left.get('filename', 'source 1')} ({left.get('system_name') or 'unnamed'}) and "
                    f"{right.get('filename', 'source 2')} ({right.get('system_name') or 'unnamed'})."
                ),
                "High",
            ))
    return conflicts


def _source_reconciliation(
    documents: List[Dict[str, Any]], conflicts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Explain which artifacts were treated as authoritative and why."""
    def authority(document: Dict[str, Any]) -> Tuple[int, str]:
        if document.get("role") == "reference_report":
            return 20, "reference report; context only"
        if document.get("structured_kind") == "architecture":
            return 100, "structured architecture contract"
        if str(document.get("type") or "").lower() in {
            "tf", "hcl", "bicep", "yaml", "yml", "json",
        } and document.get("structured_kind") in {
            "kubernetes", "docker_compose", "cloudformation", "architecture",
        }:
            return 95, "machine-readable deployment definition"
        if document.get("role") == "source_design":
            return 80, "design source"
        return 60, "supporting context"

    decisions = []
    environments: Dict[str, List[str]] = {}
    for document in documents:
        score, reason = authority(document)
        environment = str(document.get("environment") or "unspecified")
        environments.setdefault(environment, []).append(document.get("filename", "source"))
        decisions.append({
            "filename": document.get("filename", "source"),
            "role": document.get("role", "source_design"),
            "authority_score": score,
            "reason": reason,
            "environment": environment,
            "deployment_version": document.get("deployment_version") or "unspecified",
            "document_version": document.get("document_version") or "unspecified",
            "last_updated": document.get("last_updated") or "unspecified",
            "extraction_quality": document.get("extraction_quality") or "unknown",
        })
    decisions.sort(key=lambda item: (-item["authority_score"], item["filename"].lower()))
    return {
        "status": "conflict" if conflicts else "compatible",
        "precedence": ["structured_architecture", "iac", "source_design", "user_context", "inference"],
        "conflicts": conflicts,
        "decisions": decisions,
        "environments": environments,
        "selected_authority": decisions[0]["filename"] if decisions else None,
    }


def _find_component_evidence(
    text: str, name: str, component_id: str, index: sources.SourceIndex,
) -> Tuple[int | None, str]:
    """Find the line of the design that names this component.

    Document headers, page markers and section separators are skipped. A
    component matched against a filename like `orders-service-design.docx` was
    never named by the design, and quoting the header as its evidence would put
    scaffolding in the report where a design statement belongs.
    """
    candidates = {
        name.lower(), component_id.lower().replace("_", " "),
    }
    for line_number, line in enumerate((text or "").splitlines(), 1):
        citation = index.cite(line_number)
        if citation is None or citation.line is None:
            continue
        lowered = line.lower()
        if any(candidate and re.search(r"(?<![a-z0-9])" + re.escape(candidate) + r"(?![a-z0-9])", lowered) for candidate in candidates):
            return line_number, line.strip()
    return None, ""


def _extract_actors_and_identities(text: str, architecture: SystemArchitecture) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    actor_terms = ("user", "customer", "admin", "administrator", "doctor", "nurse", "developer", "operator", "partner", "vendor", "attacker")
    actors = []
    lowered = (text or "").lower()
    for actor in actor_terms:
        if re.search(r"(?<![a-z])" + re.escape(actor) + r"s?(?![a-z])", lowered):
            actors.append({"id": actor, "name": actor.title(), "evidence_status": "explicit"})

    identities = []
    for component in architecture.components or []:
        props = component.properties or {}
        if component.type == "Identity Provider" or props.get("auth_type") not in {None, "", "none", "unknown"}:
            identities.append({
                "component_id": component.id,
                "provider": props.get("auth_type") or component.name,
                "mfa": props.get("mfa_enabled"),
                "authorization": "ABAC" if props.get("abac_enabled") else "RBAC" if props.get("rbac_enabled") else "unknown",
                "evidence_status": props.get("evidence_status", "inferred"),
            })
    return actors, identities


def _assertion_status(value: Any) -> str:
    state = presence(value)
    return "present" if state is True else "absent" if state is False else "unknown"


def _provenance(index: sources.SourceIndex, source_documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """List the sources the description was assembled from, with ingestion detail.

    The index knows what the text contains; ingestion knows extraction quality
    and page counts. Neither alone tells a reviewer whether a document was read
    completely.
    """
    by_name = {str(doc.get("filename") or ""): doc for doc in source_documents}
    records = []
    for source in index.sources:
        record = dict(source)
        record["filename"] = record.pop("document")
        record.update({
            key: value for key, value in (by_name.get(record["filename"]) or {}).items()
            if key not in record
        })
        records.append(record)
    return records or [{"filename": sources.NARRATIVE_DOCUMENT, "role": "source_design"}]


def _attribution(index: sources.SourceIndex, architecture: SystemArchitecture) -> Dict[str, Any]:
    """Count what each source contributed, and what nothing stated.

    With several documents the useful question is not how many components were
    modeled but which document is carrying the model, and how much of it rests on
    inference instead.
    """
    per_source: Dict[str, int] = {}
    uncited = 0
    for component in architecture.components or []:
        document = (component.properties or {}).get("source_document")
        if document:
            per_source[document] = per_source.get(document, 0) + 1
        else:
            uncited += 1
    return {
        "components_by_source": dict(sorted(per_source.items(), key=lambda item: (-item[1], item[0]))),
        "components_without_a_source": uncited,
        "sources": len(index.sources),
    }


def _evidence(
    source_type: str,
    statement: str,
    confidence: str,
    citation: Optional[sources.Citation] = None,
) -> Dict[str, Any]:
    """Build one evidence record, cited where the statement could be located.

    An inferred claim has no citation by definition: nothing stated it. Saying so
    is more useful than naming a document that happens to have been uploaded.
    """
    record = {
        "source_type": source_type,
        "source_ref": citation.document if citation else sources.NARRATIVE_DOCUMENT,
        "line": citation.line if citation else None,
        "statement": statement,
        "confidence": confidence,
    }
    if citation:
        record.update(citation.as_dict())
    return record


def _gap(gap_type: str, scope: str, message: str, severity: str) -> Dict[str, Any]:
    return {"type": gap_type, "scope": scope, "message": message, "severity": severity}


def _architecture_ir(
    architecture: SystemArchitecture,
    actors: List[Dict[str, Any]],
    identities: List[Dict[str, Any]],
    validation_issues: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return the evidence-backed intermediate representation manifest."""
    return {
        "version": "architecture-ir-1.0",
        "components": [{
            "id": item.id,
            "name": item.name,
            "type": item.type,
            "trust_level": item.trust_level,
            "confidence": item.confidence,
            "evidence": item.evidence,
            "control_assertions": (item.properties or {}).get("control_assertions", {}),
        } for item in architecture.components or []],
        "flows": [{
            "id": f"{item.source_id}->{item.target_id}",
            "source_id": item.source_id,
            "target_id": item.target_id,
            "protocol": item.protocol,
            "data_type": item.data_type,
            "claim_status": "inferred" if item.assumed else "explicit",
            "confidence": item.confidence,
            "evidence": item.evidence,
        } for item in architecture.flows or []],
        "boundaries": [item.model_dump() for item in architecture.trust_boundaries or []],
        "assets": [item.model_dump() for item in architecture.assets or []],
        "actors": actors,
        "identities": identities,
        "unresolved_claims": [
            item for item in validation_issues
            if item["type"] in {"invalid_flow", "invalid_boundary_membership", "contradictory_control"}
        ],
        "contract": "Every downstream engine consumes canonical IDs and provenance from this IR; inferred claims remain distinguishable from explicit source facts.",
    }
