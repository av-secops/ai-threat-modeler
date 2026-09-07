"""Turn unspecified controls into a short list of questions for the architect.

Most STRIDE cells in a real design review resolve to "the description does not
say". That is the honest answer and the most useful one, but there are typically
well over a hundred such cells, so listing them individually buries the report.

This module groups them by the control they are waiting on, so an analyst gets
roughly a dozen questions instead of a hundred and fifty rows, each naming every
element it would resolve and stating what evidence would close it. Answering one
question resolves many cells, which is what makes iteration worthwhile.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import graph

# Control families, in the order an analyst usually asks about them. Each maps
# the raw control names the coverage engine looks for onto one question.
CONTROL_FAMILIES: List[Dict[str, Any]] = [
    {
        "id": "AUTHN",
        "title": "Authentication strength",
        "controls": {"auth_type", "mfa_enabled", "mtls_enabled", "token_revocation"},
        "question": "How does each of these elements authenticate its callers, and is multi-factor or mutual TLS required?",
        "accepted_evidence": [
            "Identity provider configuration or policy showing the enforced method",
            "Gateway or service configuration showing which authenticator is required",
            "A statement that a caller is unauthenticated, which is itself an answer",
        ],
        "weight": 5,
    },
    {
        "id": "AUTHZ",
        "title": "Authorization model",
        "controls": {"authorization", "rbac_enabled", "abac_enabled", "tenant_isolation", "object_level_auth"},
        "question": "What authorization model governs these elements, and which roles or attributes are allowed to reach them?",
        "accepted_evidence": [
            "Role or policy definitions, including a dedicated role per sensitive service",
            "IAM or key policy showing who may use a key, queue, or bucket",
            "Confirmation that access is unrestricted once authenticated",
        ],
        "weight": 5,
    },
    {
        "id": "ENCRYPT-REST",
        "title": "Encryption at rest",
        "controls": {"encryption_at_rest"},
        "question": "Is stored data encrypted at rest, and who controls the keys?",
        "accepted_evidence": [
            "Storage configuration showing encryption enabled and the key source",
            "Key management policy naming the key owner and rotation period",
        ],
        "weight": 4,
    },
    {
        "id": "ENCRYPT-TRANSIT",
        "title": "Transport encryption",
        "controls": {"encryption_in_transit", "transport_encryption"},
        "question": "Which protocol carries each of these interactions, and is TLS terminated before or after this hop?",
        "accepted_evidence": [
            "Protocol and TLS version per interface, including internal hops",
            "Load balancer or service mesh configuration showing where TLS terminates",
        ],
        "weight": 4,
    },
    {
        "id": "AUDIT",
        "title": "Audit logging and accountability",
        "controls": {"audit_logging", "logging_enabled", "log_integrity"},
        "question": "What security-relevant events do these elements record, where do the logs go, and how long are they kept?",
        "accepted_evidence": [
            "Log destination, retention period, and whether the logs are tamper-evident",
            "A list of audited events for privileged actions",
        ],
        "weight": 3,
    },
    {
        "id": "INTEGRITY",
        "title": "Input and integrity validation",
        "controls": {"integrity_validation", "input_validation", "webhook_signature_validation", "container_image_provenance"},
        "question": "How is untrusted input validated, and are inbound payloads, artifacts, or images integrity-checked before use?",
        "accepted_evidence": [
            "Validation approach per interface, such as a schema or allow-list",
            "Signature or digest verification for webhooks, artifacts, and images",
        ],
        "weight": 4,
    },
    {
        "id": "AVAILABILITY",
        "title": "Rate limiting and resilience",
        "controls": {"rate_limiting", "waf_enabled", "resilience", "multi_region", "replication", "backup_enabled", "autoscaling", "request_size_limit", "query_depth_limiting", "concurrency_limits"},
        "question": "What quotas, rate limits, or redundancy protect these elements, and what recovery objective applies?",
        "accepted_evidence": [
            "Rate limit or quota per exposed interface",
            "Redundancy, backup, and tested recovery objectives",
        ],
        "weight": 3,
    },
    {
        "id": "DATA-PROTECTION",
        "title": "Sensitive data handling",
        "controls": {"dlp_enabled", "data_sensitivity", "tokenization", "masking"},
        "question": "What sensitive data do these elements hold or carry, and how is it classified, masked, or tokenized?",
        "accepted_evidence": [
            "Data classification per store and interface",
            "Masking, tokenization, or redaction applied before logging or export",
        ],
        "weight": 4,
    },
]

_FAMILY_BY_CONTROL: Dict[str, Dict[str, Any]] = {
    control: family for family in CONTROL_FAMILIES for control in family["controls"]
}

_UNRESOLVED_STATUSES = {"unknown", "potential"}

# A trust boundary implements no controls of its own; the question belongs on the
# components and flows that cross it, which are asked about in their own right.
_KINDS_WITHOUT_OWNERS = {"boundary"}

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def build_evidence_requests(coverage: Dict[str, Any], architecture=None) -> Dict[str, Any]:
    """Group every unresolved coverage cell into prioritized evidence requests."""
    all_unresolved = [cell for cell in coverage.get("cells", []) if cell.get("status") in _UNRESOLVED_STATUSES or cell.get("unresolved_controls")]
    cells = [cell for cell in all_unresolved if cell.get("element_kind") not in _KINDS_WITHOUT_OWNERS]
    boundary_cells = len(all_unresolved) - len(cells)
    elements_by_id = {element["id"]: element for element in coverage.get("elements", [])}
    gatekeepers = _elements_upstream_of_sensitive_data(architecture)

    grouped: Dict[str, Dict[str, Any]] = {}
    unmapped_cells = 0
    for cell in cells:
        family = _family_for(cell)
        if family is None:
            unmapped_cells += 1
            continue
        bucket = grouped.setdefault(family["id"], {"family": family, "cells": []})
        bucket["cells"].append(cell)

    requests = [
        _request(bucket["family"], bucket["cells"], elements_by_id, gatekeepers)
        for bucket in grouped.values()
    ]
    requests.sort(key=lambda request: (
        PRIORITY_ORDER[request["priority"]],
        -request["priority_score"],
        -request["resolves_cells"],
        request["title"],
    ))
    for position, request in enumerate(requests, start=1):
        request["rank"] = position

    resolved_by_requests = sum(request["resolves_cells"] for request in requests)
    return {
        "version": "evidence-requests-1.0",
        "requests": requests,
        "unresolved_cells": len(cells),
        "cells_addressed": resolved_by_requests,
        "cells_without_request": unmapped_cells,
        "boundary_cells_excluded": boundary_cells,
        "summary": _summary(requests, len(cells)),
    }


def _family_for(cell: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pick the family for a cell, preferring the most specific control named."""
    controls = cell.get("unresolved_controls") or cell.get("expected_controls") or cell.get("controls") or []
    for control in controls:
        family = _FAMILY_BY_CONTROL.get(control)
        if family is not None:
            return family
    return None


def _elements_upstream_of_sensitive_data(architecture) -> Set[str]:
    """Components from which regulated or credential-like data is reachable.

    An unanswered question about one of these is worth more than the same
    question elsewhere, because the answer decides how exposed the data behind it
    is, not just the element itself.
    """
    if architecture is None:
        return set()
    flows = list(getattr(architecture, "flows", None) or [])
    components = {component.id: component for component in getattr(architecture, "components", None) or []}
    sensitive = {
        component_id for component_id, component in components.items()
        if _is_sensitive(component.properties or {})
    }
    return {
        component_id for component_id in components
        if graph.downstream(component_id, flows) & sensitive
    }


def _request(
    family: Dict[str, Any],
    cells: List[Dict[str, Any]],
    elements_by_id: Dict[str, Dict[str, Any]],
    gatekeepers: Set[str],
) -> Dict[str, Any]:
    by_element: Dict[str, Dict[str, Any]] = {}
    for cell in cells:
        element_id = cell["element_id"]
        entry = by_element.setdefault(element_id, {
            "id": element_id,
            "name": cell.get("element_name") or element_id,
            "type": cell.get("element_type"),
            "kind": cell.get("element_kind"),
            # A component and the asset it holds can share a name, so the label
            # carries the type that tells them apart.
            "label": _label(cell),
            "stride_categories": [],
            "exposure": _exposure(elements_by_id.get(element_id)),
            "guards_sensitive_data": element_id in gatekeepers,
        })
        if cell["category"] not in entry["stride_categories"]:
            entry["stride_categories"].append(cell["category"])

    elements = sorted(by_element.values(), key=lambda entry: (-len(entry["stride_categories"]), entry["name"]))
    for entry in elements:
        entry["stride_categories"].sort()

    categories = sorted({cell["category"] for cell in cells})
    score = _score(family, elements)
    return {
        "id": f"EVR-{family['id']}",
        "family": family["id"],
        "title": family["title"],
        "question": family["question"],
        "priority": _priority(score),
        "priority_score": score,
        "stride_categories": categories,
        "resolves_cells": len(cells),
        "elements": elements,
        "accepted_evidence": list(family["accepted_evidence"]),
        "why_it_matters": _why(family, categories, elements),
        "asked_of": "architecture owner",
        "state": "open",
    }


def _label(cell: Dict[str, Any]) -> str:
    name = cell.get("element_name") or cell.get("element_id")
    kind = cell.get("element_kind")
    element_type = cell.get("element_type")
    if kind == "flow":
        return f"{name} (data flow)"
    if kind == "asset":
        return f"{name} (asset)"
    if kind == "actor":
        return f"{name} (actor)"
    return f"{name} ({element_type})" if element_type else str(name)


def _exposure(element: Optional[Dict[str, Any]]) -> str:
    """How exposed the element is, which drives how urgently the gap matters."""
    if not element:
        return "unknown"
    properties = element.get("properties") or {}
    trust = element.get("trust_level")
    if trust in {"public", "internet", "external"}:
        return "internet_reachable"
    if properties.get("crosses_trust_boundary"):
        return "crosses_trust_boundary"
    if _is_sensitive(properties):
        return "holds_sensitive_data"
    return "internal"


def _is_sensitive(properties: Dict[str, Any]) -> bool:
    sensitive_values = {"pii", "phi", "financial", "credentials", "secrets", "restricted", "confidential"}
    for key in ("data_sensitivity", "sensitivity", "data_type", "data_classification"):
        if str(properties.get(key) or "").lower() in sensitive_values:
            return True
    return False


EXPOSURE_WEIGHT = {
    "internet_reachable": 4,
    "crosses_trust_boundary": 3,
    "holds_sensitive_data": 3,
    "internal": 1,
    "unknown": 1,
}


def _score(family: Dict[str, Any], elements: List[Dict[str, Any]]) -> int:
    """Rank by the control's importance against its most exposed element.

    Deliberately driven by the worst element rather than the sum of them, so a
    large architecture does not push every question to Critical. An element that
    stands in front of sensitive data counts one level more exposed than the same
    element with nothing behind it, since the answer settles what the data behind
    it is exposed to as well.
    """
    worst = max(
        min(
            EXPOSURE_WEIGHT["internet_reachable"],
            EXPOSURE_WEIGHT[entry["exposure"]] + int(bool(entry.get("guards_sensitive_data"))),
        )
        for entry in elements
    )
    return family["weight"] * worst


def _priority(score: int) -> str:
    # Weights run 3 to 5 and exposure 1 to 4, so the scale is 3 to 20.
    if score >= 16:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def _why(family: Dict[str, Any], categories: List[str], elements: List[Dict[str, Any]]) -> str:
    exposed = [entry["label"] for entry in elements if entry["exposure"] == "internet_reachable"]
    sensitive = [entry["label"] for entry in elements if entry["exposure"] in {"holds_sensitive_data", "crosses_trust_boundary"}]
    reasons = [
        f"{len(elements)} element(s) cannot be assessed for {', '.join(categories)} until this is answered."
    ]
    if exposed:
        reasons.append(f"Internet-reachable: {_join(exposed)}.")
    if sensitive:
        reasons.append(f"Handles sensitive data or crosses a trust boundary: {_join(sensitive)}.")
    reasons.append(
        "Unanswered, these remain unresolved rather than confirmed, so the report neither "
        "credits a control that may not exist nor reports a vulnerability that may not exist."
    )
    return " ".join(reasons)


def _join(names: List[str], limit: int = 4) -> str:
    if len(names) <= limit:
        return ", ".join(names)
    return ", ".join(names[:limit]) + f", and {len(names) - limit} more"


def _summary(requests: List[Dict[str, Any]], unresolved_cells: int) -> str:
    if not requests:
        return "Every applicable STRIDE cell resolved to a finding or a stated control. No further evidence is required."
    top = requests[0]
    return (
        f"{unresolved_cells} STRIDE cells are unresolved because the design does not state the relevant control. "
        f"They collapse into {len(requests)} question(s). Answering '{top['title']}' alone resolves "
        f"{top['resolves_cells']} of them."
    )
