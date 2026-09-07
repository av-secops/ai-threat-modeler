from typing import Dict, List


def detect_missing_elements(system_model) -> List[Dict[str, str]]:
    gaps: List[Dict[str, str]] = []
    components = system_model.components or []
    flows = system_model.flows or []
    metadata = system_model.metadata or {}
    unresolved = metadata.get('unresolved_references') or []
    if unresolved:
        gaps.append({'type': 'unresolved_iac_values', 'message': f'{len(unresolved)} IaC properties are unresolved. Supply resolved plan values; missing values were not treated as secure or insecure.'})
    for limitation in metadata.get('analysis_limits') or []:
        gaps.append({'type': 'input_analysis_limit', 'message': str(limitation)})

    if components and not flows:
        gaps.append({
            "type": "missing_data_flows",
            "message": "No data flows are modeled. Supply explicit communication paths; resource dependencies alone are not data flows.",
        })
    elif any(getattr(flow, "assumed", False) for flow in flows):
        gaps.append({
            "type": "missing_data_flows",
            "message": "Some data flows were missing and had to be inferred. Validate source, destination, and protocol details.",
        })

    auth_components = [component for component in components if component.type in {"API", "Service", "API Gateway", "Identity Provider"}]
    if auth_components and any((component.properties or {}).get("auth_type") in {None, "", "none"} for component in auth_components):
        gaps.append({
            "type": "missing_auth_model",
            "message": "One or more exposed application components do not have a defined authentication or authorization model.",
        })

    storage_types = {"Database", "Object Storage", "Data Warehouse", "Secrets Manager"}
    if not any(component.type in storage_types for component in components):
        gaps.append({
            "type": "missing_storage_layer",
            "message": "No storage layer was identified. Confirm where application data, logs, and secrets are stored.",
        })

    # Threats live on the edges. A component nothing reaches is assessed almost
    # not at all, and after someone amends a model to add the component they
    # forgot, this is the difference between the analysis changing and the
    # analysis appearing to ignore them.
    if flows:
        connected = {flow.source_id for flow in flows} | {flow.target_id for flow in flows}
        isolated = [component for component in components if component.id not in connected]
        if isolated:
            names = ", ".join(component.name for component in isolated[:5])
            remainder = len(isolated) - 5
            gaps.append({
                "type": "unconnected_components",
                "message": (
                    f"Nothing is recorded as talking to {names}"
                    f"{f' and {remainder} others' if remainder > 0 else ''}. "
                    "Most risk arises on the paths between components, so add the flows "
                    "that reach them to have them assessed."
                ),
            })

    external_components = [
        component for component in components
        if (component.properties or {}).get("external") or component.trust_level == "external"
    ]
    if external_components and not any(
        flow.target_id in {component.id for component in external_components} or flow.source_id in {component.id for component in external_components}
        for flow in flows
    ):
        gaps.append({
            "type": "undefined_external_integrations",
            "message": "External integrations were referenced but the specific interaction flows are undefined.",
        })

    return gaps
