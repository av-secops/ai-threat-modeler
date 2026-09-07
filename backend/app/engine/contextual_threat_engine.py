from typing import Dict, List, Optional

from ..models import Threat
from .impact_mapper import map_business_impact
from .mitigation_generator import generate_mitigation
from .risk_scoring import calculate_risk


THREAT_LIBRARY = {
    "missing_authentication": {
        "id": "CTX-API-001",
        "category": "Spoofing",
        "title": "Unauthenticated or weakly authenticated exposed interface",
        "description": "An exposed application entry point accepts requests without a strong identity check.",
        "root_cause": "Authentication is missing or downgraded on an internet-reachable interface.",
        "owasp_top_10": ["API1:2023 Broken Object Level Authorization", "API2:2023 Broken Authentication"],
        "cwe": ["CWE-306", "CWE-287"],
        "mitre_attack": ["T1078"],
        "nist_800_53": ["IA-2", "AC-3"],
    },
    "bola": {
        "id": "CTX-API-002",
        "category": "Elevation of Privilege",
        "title": "Object-level authorization gap on data access path",
        "description": "The architecture suggests API-driven access to sensitive records without clear object-level authorization controls.",
        "root_cause": "The design defines data access but not record ownership or tenant-scoped authorization checks.",
        "owasp_top_10": ["API1:2023 Broken Object Level Authorization"],
        "cwe": ["CWE-639", "CWE-862"],
        "mitre_attack": ["T1098"],
        "nist_800_53": ["AC-6", "AC-3"],
    },
    "cleartext_flow": {
        "id": "CTX-FLOW-001",
        "category": "Information Disclosure",
        "title": "Sensitive flow crosses a boundary without transport protection",
        "description": "A data flow carrying potentially sensitive information uses plaintext or undefined transport security.",
        "root_cause": "The architecture does not enforce encrypted transport across the affected boundary.",
        "owasp_top_10": ["A02:2021 Cryptographic Failures"],
        "cwe": ["CWE-319"],
        "mitre_attack": ["T1040"],
        "nist_800_53": ["SC-8"],
    },
    "unencrypted_storage": {
        "id": "CTX-DATA-001",
        "category": "Information Disclosure",
        "title": "Sensitive data store lacks explicit encryption-at-rest controls",
        "description": "A storage component appears to hold regulated or credential-like data without explicit encryption-at-rest protection.",
        "root_cause": "Storage security controls are absent or undefined for a sensitive asset.",
        "owasp_top_10": ["A02:2021 Cryptographic Failures"],
        "cwe": ["CWE-311"],
        "mitre_attack": ["T1005"],
        "nist_800_53": ["SC-28"],
        # The component property this pattern is a judgement about. Naming it
        # lets the analyzer see that a knowledge-base rule on the same property
        # and the same component is the same problem, rather than reporting one
        # weakness twice under two titles.
        "controls": ["encryption_at_rest"],
    },
    "secrets_exposure": {
        "id": "CTX-SEC-001",
        "category": "Information Disclosure",
        "title": "Secrets handling path is weak or undefined",
        "description": "The design references credentials, tokens, or integrations without a dedicated secrets isolation mechanism.",
        "root_cause": "Secrets lifecycle and storage controls are not clearly separated from application code or configuration.",
        "owasp_top_10": ["A05:2021 Security Misconfiguration"],
        "cwe": ["CWE-798", "CWE-522"],
        "mitre_attack": ["T1552"],
        "nist_800_53": ["IA-5", "SC-12"],
    },
    "supply_chain": {
        "id": "CTX-SC-001",
        "category": "Tampering",
        "title": "Software supply chain integrity controls are not evident",
        "description": "The architecture relies on packages, images, or third-party services without visible provenance or dependency governance controls.",
        "root_cause": "Build, dependency, or artifact validation controls are missing from the design.",
        "owasp_top_10": ["A06:2021 Vulnerable and Outdated Components"],
        "cwe": ["CWE-494", "CWE-1104"],
        "mitre_attack": ["T1195"],
        "nist_800_53": ["SI-7", "CM-14"],
    },
    "iam_misconfig": {
        "id": "CTX-INFRA-001",
        "category": "Elevation of Privilege",
        "title": "Cloud workload permissions may be broader than necessary",
        "description": "A cloud-connected workload accesses storage or integrations without evidence of least-privilege identity scoping.",
        "root_cause": "IAM or workload identity boundaries are undefined for the component.",
        "owasp_top_10": ["A05:2021 Security Misconfiguration"],
        "cwe": ["CWE-269", "CWE-732"],
        "mitre_attack": ["T1098", "T1078.004"],
        "nist_800_53": ["AC-6", "AC-2"],
    },
    "llm_prompt_injection": {
        "id": "CTX-AI-001",
        "category": "Tampering",
        "title": "LLM retrieval or tool chain is vulnerable to prompt injection",
        "description": "The architecture contains model or retrieval components that process untrusted content without a clear isolation or tool-authorization boundary.",
        "root_cause": "Untrusted prompts or retrieved data can influence model behavior or tool execution directly.",
        "owasp_top_10": [],
        "cwe": ["CWE-74"],
        "mitre_attack": ["T1059"],
        "mitre_atlas": ["AML.T0051", "AML.T0054"],
        "nist_800_53": ["SI-10", "AC-6"],
    },
    "external_data_exposure": {
        "id": "CTX-DATA-002",
        "category": "Information Disclosure",
        "title": "Sensitive data leaves the trust boundary without minimization",
        "description": "A sensitive data flow terminates in an external service or third-party integration without explicit egress restrictions.",
        "root_cause": "Data classification and outbound sharing controls are not defined on the integration flow.",
        "owasp_top_10": ["A01:2021 Broken Access Control"],
        "cwe": ["CWE-200", "CWE-201"],
        "mitre_attack": ["T1537"],
        "nist_800_53": ["AC-4", "SC-7"],
    },
    "missing_waf": {
        "id": "CTX-API-003",
        "category": "Denial of Service",
        "title": "Missing Web Application Firewall on public entry point",
        "description": "A public API or gateway is exposed without an explicit WAF or edge filtering layer.",
        "root_cause": "Internet-facing request handling lacks a dedicated application-layer filtering control.",
        "owasp_top_10": ["A05:2021 Security Misconfiguration"],
        "cwe": ["CWE-693"],
        "mitre_attack": ["T1190"],
        "nist_800_53": ["SC-7", "SI-4"],
    },
    "missing_input_validation": {
        "id": "CTX-API-004",
        "category": "Tampering",
        "title": "Missing input validation on request handling path",
        "description": "The design identifies request handling without clear validation or sanitization controls.",
        "root_cause": "User-controlled input can reach business logic without a defined validation boundary.",
        "owasp_top_10": ["A03:2021 Injection", "API8:2023 Security Misconfiguration"],
        "cwe": ["CWE-20", "CWE-74"],
        "mitre_attack": ["T1190"],
        "nist_800_53": ["SI-10"],
    },
    "redis_missing_auth": {
        "id": "CTX-DATA-003",
        "category": "Spoofing",
        "title": "Redis session store permits unauthenticated session access",
        "description": "A Redis-backed session store explicitly lacks authentication, allowing session injection or impersonation if its network boundary is reached.",
        "root_cause": "Redis authentication is explicitly absent from a session security boundary.",
        "owasp_top_10": ["A07:2021 Identification and Authentication Failures"],
        "cwe": ["CWE-306", "CWE-384"],
        "mitre_attack": ["T1078"],
        "nist_800_53": ["AC-3", "IA-2"],
    },
    "redis_session_auth_unknown": {
        "id": "CTX-SESSION-001",
        "category": "Spoofing",
        "title": "Redis session-store authentication requires validation",
        "description": "Redis stores application sessions, but its authentication, TLS, and network-isolation controls are not defined at the component boundary.",
        "root_cause": "The architecture identifies a security-critical session store without documenting how workloads authenticate to it.",
        "owasp_top_10": ["A07:2021 Identification and Authentication Failures"],
        "cwe": ["CWE-306", "CWE-384"],
        "mitre_attack": ["T1078"],
        "nist_800_53": ["IA-2", "SC-8", "SC-7"],
    },
    "fhir_partner_authentication": {
        "id": "CTX-FHIR-001",
        "category": "Spoofing",
        "title": "FHIR partner authentication boundary requires validation",
        "description": "The FHIR interoperability service is modeled without component-specific partner authentication controls.",
        "root_cause": "OAuth client identity, audience validation, and mutual TLS are not defined for the FHIR partner boundary.",
        "owasp_top_10": ["API2:2023 Broken Authentication"],
        "cwe": ["CWE-287", "CWE-306"],
        "mitre_attack": ["T1078"],
        "nist_800_53": ["IA-2", "IA-5", "SC-8"],
    },
    "oauth_token_lifecycle_unknown": {
        "id": "CTX-OAUTH-001",
        "category": "Spoofing",
        "title": "OAuth token replay and revocation controls require validation",
        "description": "OAuth or Azure AD is present, but token lifetime, refresh-token rotation, revocation, and replay controls are not specified.",
        "root_cause": "The identity design names an OAuth provider without defining the token lifecycle and invalidation contract.",
        "owasp_top_10": ["A07:2021 Identification and Authentication Failures", "API2:2023 Broken Authentication"],
        "cwe": ["CWE-294", "CWE-613"],
        "mitre_attack": ["T1528", "T1078"],
        "nist_800_53": ["IA-5", "AC-12"],
    },
}


class ContextualThreatEngine:
    def __init__(self, knowledge_base=None):
        self.knowledge_base = knowledge_base

    def analyze(self, system_model) -> List[Threat]:
        components = {component.id: component for component in system_model.components or []}
        threats: List[Threat] = []
        generated_keys = set()

        for component in system_model.components or []:
            threats.extend(self._analyze_component(component, generated_keys, system_model))

        for flow in system_model.flows or []:
            source = components.get(flow.source_id)
            target = components.get(flow.target_id)
            asset = self._match_asset_for_flow(system_model, flow)
            threats.extend(self._analyze_threat(source, flow, asset, target, generated_keys))

        return threats

    def analyze_threat(self, component, data_flow, asset):
        target = component
        return self._analyze_threat(component, data_flow, asset, target, set())

    def _analyze_component(self, component, generated_keys, system_model) -> List[Threat]:
        findings: List[Threat] = []
        props = component.properties or {}
        explicit_negations = set(props.get('explicit_negations') or [])
        architecture_text = ((system_model.metadata or {}).get('architecture_text') or '').lower()
        asset = self._match_asset_for_component(component, system_model)
        component_line = next(
            (line.strip() for line in architecture_text.splitlines() if component.name.lower() in line.lower()),
            '',
        )

        if component.type in {"API", "API Gateway", "Service", "ML Service"} and (
            component.trust_level in {"public", "external"} or props.get("public_access")
        ) and props.get("auth_type") in {None, "", "none", "basic", "api_key"}:
            findings.append(self._build_threat(
                "missing_authentication",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker interacts directly with {component.name} from an untrusted boundary and bypasses identity checks to execute privileged application actions.",
                exposure="public",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="low",
                privilege_required="none",
            ))

        if component.type in {"API", "API Gateway", "WebClient", "Service"} and (
            component.trust_level in {"public", "external"} or props.get("public_access")
        ) and props.get("waf_enabled") is False:
            findings.append(self._build_threat(
                "missing_waf",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker sends malicious HTTP traffic directly to {component.name}; without WAF filtering, common exploit and abuse traffic reaches application handlers.",
                exposure="public",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="low",
                privilege_required="none",
            ))

        if component.type in {"API", "API Gateway", "Service", "WebClient"} and props.get("input_validation") is False and "input_validation" in explicit_negations:
            findings.append(self._build_threat(
                "missing_input_validation",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker submits crafted input to {component.name}; without a validation boundary the payload can alter queries, workflow state, or downstream service behavior.",
                exposure="public" if component.trust_level in {"public", "external"} else "internal",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="low",
                privilege_required="none",
            ))

        if component.type == "Database" and props.get("db_type") == "redis" and props.get("auth_type") == "none":
            findings.append(self._build_threat(
                "redis_missing_auth",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker who reaches {component.name} can read session or cache data and tamper with cached authorization state because Redis authentication is not enforced.",
                exposure="internal",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="low",
                privilege_required="low",
            ))
        elif component.type == "Database" and props.get("db_type") == "redis" and props.get("auth_type") in {None, "", "unknown"} and 'session' in component_line:
            findings.append(self._build_threat(
                "redis_session_auth_unknown",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"If an attacker or compromised workload can reach {component.name}, weak Redis client authentication could permit session injection, fixation, or theft.",
                exposure="internal",
                data_sensitivity="credentials",
                exploit_complexity="medium",
                privilege_required="low",
                confidence_override="Medium",
                finding_type="control_gap",
                evidence_override=[f"Architecture input: {component_line}", "Redis AUTH/ACL and component-specific TLS are not specified."],
            ))

        is_fhir = 'fhir' in component.id.lower() or 'hl7' in component.id.lower() or props.get('healthcare_integration')
        if is_fhir and props.get('auth_type') in {None, "", "unknown", "none"}:
            explicit_missing = props.get('auth_type') == 'none'
            findings.append(self._build_threat(
                "fhir_partner_authentication",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"A system presenting a stolen or untrusted partner identity calls {component.name} and attempts to query or modify PHI through the interoperability API.",
                exposure="external" if props.get('external') else "internal",
                data_sensitivity="phi",
                exploit_complexity="low" if explicit_missing else "medium",
                privilege_required="none" if explicit_missing else "low",
                confidence_override="High" if explicit_missing else "Medium",
                finding_type="control_gap",
                evidence_override=[f"Architecture input: {component_line}", "FHIR-specific OAuth client credentials, audience validation, and mTLS are not specified."],
            ))

        has_token_lifecycle = any(token in architecture_text for token in ('token revocation', 'refresh token rotation', 'refresh-token rotation', 'token rotation', 'session revocation'))
        if component.type == 'Identity Provider' and props.get('auth_type') in {'oauth2', 'azure_ad'} and not has_token_lifecycle:
            findings.append(self._build_threat(
                "oauth_token_lifecycle_unknown",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker replays a stolen access or refresh token accepted through {component.name} after the legitimate user expects the session to be invalidated.",
                exposure="external",
                data_sensitivity="credentials",
                exploit_complexity="medium",
                privilege_required="none",
                confidence_override="Medium",
                finding_type="control_gap",
                evidence_override=[f"Architecture input: {component_line}", "Token lifetime, refresh-token rotation, replay detection, and revocation are not specified."],
            ))

        if component.type in {"Database", "Object Storage", "Data Warehouse"} and props.get("data_sensitivity") in {"pii", "financial", "credentials", "phi", "secrets"} and props.get("encryption_at_rest") is False and "encryption_at_rest" in explicit_negations:
            findings.append(self._build_threat(
                "unencrypted_storage",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"If {component.name} is accessed through backup compromise, host compromise, or cloud snapshot exposure, regulated records could be read in plaintext.",
                exposure="internal",
                data_sensitivity=props.get("data_sensitivity"),
                exploit_complexity="medium",
                privilege_required="low",
            ))

        if component.type in {"Service", "API", "ML Service"} and (
            props.get("third_party_integration") or props.get("has_webhooks") or props.get("external")
        ) and props.get("secrets_manager") is False and props.get("idp_integration") is False:
            findings.append(self._build_threat(
                "secrets_exposure",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"Credentials used by {component.name} could be recovered from deployment config, logs, or image layers and then reused against dependent systems.",
                exposure="internal",
                data_sensitivity="secrets",
                exploit_complexity="medium",
                privilege_required="low",
            ))

        if props.get("cloud_provider") and component.type in {"Service", "API", "ML Service"} and props.get("rbac_enabled") is False:
            findings.append(self._build_threat(
                "iam_misconfig",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"After compromising {component.name}, an attacker abuses over-broad cloud permissions to enumerate or modify adjacent services.",
                exposure="internal",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="medium",
                privilege_required="low",
            ))

        if (props.get("containerized") or props.get("deployment") == "k8s") and props.get("container_image_provenance") is False:
            findings.append(self._build_threat(
                "supply_chain",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"A malicious dependency or container image propagates into {component.name}, granting code execution inside the runtime environment.",
                exposure="internal",
                data_sensitivity=props.get("data_sensitivity") or "internal",
                exploit_complexity="medium",
                privilege_required="low",
            ))

        if (component.type == "ML Service" or props.get("ml_pipeline")) and (
            props.get("untrusted_retrieval") is True
            or props.get("tool_authorization") is False
            or props.get("prompt_sanitization") is False
            or props.get("output_validation") is False
        ):
            findings.append(self._build_threat(
                "llm_prompt_injection",
                component=component,
                asset=asset,
                flow_ref=None,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker feeds crafted content into {component.name}; the model treats it as instruction-bearing context and triggers unsafe retrieval, tool usage, or data disclosure.",
                exposure="public" if component.trust_level == "public" else "internal",
                data_sensitivity=props.get("data_sensitivity") or "sensitive",
                exploit_complexity="low",
                privilege_required="none",
            ))

        return [finding for finding in findings if finding]

    def _analyze_threat(self, source, data_flow, asset, target, generated_keys) -> List[Threat]:
        findings: List[Threat] = []
        if not source or not target:
            return findings

        flow_ref = f"{data_flow.source_id}->{data_flow.target_id}"
        source_props = source.properties or {}
        target_props = target.properties or {}
        combined_sensitivity = (
            (asset.sensitivity if asset else None)
            or data_flow.data_type
            or source_props.get("data_sensitivity")
            or target_props.get("data_sensitivity")
            or "internal"
        )

        if data_flow.protocol.lower() in {"http", "ws"} and not data_flow.assumed and (
            source.trust_level != target.trust_level or combined_sensitivity not in {"application_data", "internal"}
        ):
            findings.append(self._build_threat(
                "cleartext_flow",
                component=target,
                asset=asset,
                flow_ref=flow_ref,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"An attacker monitoring the path between {source.name} and {target.name} intercepts or alters the {combined_sensitivity} payload carried over {data_flow.protocol}.",
                exposure="public" if source.trust_level in {"public", "external"} else "internal",
                data_sensitivity=combined_sensitivity,
                exploit_complexity="low",
                privilege_required="none",
            ))

        if source.type in {"API", "Service"} and target.type in {"Database", "Object Storage"} and combined_sensitivity in {"pii", "financial", "credentials", "phi", "secrets"}:
            target_auth = target_props.get("auth_type") or source_props.get("auth_type")
            if target_auth in {None, "", "none"}:
                findings.append(self._build_threat(
                    "bola",
                    component=source,
                    asset=asset,
                    flow_ref=flow_ref,
                    generated_keys=generated_keys,
                    realistic_attack_scenario=f"A caller abuses the {source.name} to enumerate identifiers and access records in {target.name} that belong to another tenant or user.",
                    exposure="public" if source.trust_level == "public" else "internal",
                    data_sensitivity=combined_sensitivity,
                    exploit_complexity="low",
                    privilege_required="low",
                ))

        if (
            target.trust_level == "external"
            and target.type != "Identity Provider"
            and not data_flow.assumed
            and combined_sensitivity in {"pii", "financial", "credentials", "phi", "secrets"}
        ):
            findings.append(self._build_threat(
                "external_data_exposure",
                component=source,
                asset=asset,
                flow_ref=flow_ref,
                generated_keys=generated_keys,
                realistic_attack_scenario=f"{source.name} transmits sensitive {combined_sensitivity} data to external integration {target.name}; over-sharing or partner compromise exposes that dataset.",
                exposure="public" if source.trust_level == "public" else "internal",
                data_sensitivity=combined_sensitivity,
                exploit_complexity="medium",
                privilege_required="low",
            ))

        return [finding for finding in findings if finding]

    def _match_asset_for_flow(self, system_model, flow) -> Optional[object]:
        flow_ref = f"{flow.source_id}->{flow.target_id}"
        for asset in system_model.assets or []:
            if flow_ref in (asset.related_data_flows or []):
                return asset
            if asset.related_component_id in {flow.source_id, flow.target_id}:
                return asset
        return None

    @staticmethod
    def _match_asset_for_component(component, system_model) -> Optional[object]:
        if not component or not system_model:
            return None
        for asset in system_model.assets or []:
            if asset.related_component_id == component.id:
                return asset
        return None

    def _build_threat(
        self,
        pattern: str,
        component,
        asset,
        flow_ref: Optional[str],
        generated_keys,
        realistic_attack_scenario: str,
        exposure: str,
        data_sensitivity: str,
        exploit_complexity: str,
        privilege_required: str,
        confidence_override: Optional[str] = None,
        finding_type: str = "architecture",
        evidence_override: Optional[List[str]] = None,
    ) -> Optional[Threat]:
        library_entry = THREAT_LIBRARY[pattern]
        component_id = component.id if component else None
        dedupe_key = (library_entry["id"], component_id, flow_ref)
        if dedupe_key in generated_keys:
            return None
        generated_keys.add(dedupe_key)

        confidence = confidence_override or ("High" if not flow_ref or not flow_ref.endswith("assumed") else "Medium")
        risk = calculate_risk({
            "category": library_entry["category"],
            "exposure": exposure,
            "data_sensitivity": data_sensitivity,
            "asset_sensitivity": asset.sensitivity if asset else data_sensitivity,
            "exploit_complexity": exploit_complexity,
            "privilege_required": privilege_required,
            "evidence_confidence": confidence,
        })
        mitigation = generate_mitigation({"pattern": pattern})

        affected_components = [component_id] if component_id else []
        affected_flows = [flow_ref.replace("->", " → ")] if flow_ref else []

        return Threat(
            id=library_entry["id"],
            category=library_entry["category"],
            title=library_entry["title"],
            description=library_entry["description"],
            severity=risk["severity"],
            likelihood=risk["likelihood"],
            impact=risk["impact"],
            risk_score=risk["risk_score"],
            confidence=confidence,
            finding_type=finding_type,
            risk_factors=risk["risk_factors"],
            mitigation=mitigation["mitigation"],
            component=component_id,
            data_flow=flow_ref,
            asset=asset.name if asset else None,
            affected_component=component_id,
            related_data_flow=flow_ref,
            root_cause=library_entry["root_cause"],
            realistic_attack_scenario=realistic_attack_scenario,
            attack_scenario=realistic_attack_scenario,
            business_impact=map_business_impact({
                "title": library_entry["title"],
                "root_cause": library_entry["root_cause"],
                "asset": asset.name if asset else None,
                "asset_sensitivity": asset.sensitivity if asset else data_sensitivity,
                "data_sensitivity": data_sensitivity,
            }),
            specific_control=mitigation["specific_control"],
            implementation_detail=mitigation["implementation_detail"],
            optional_config_example=mitigation["optional_config_example"],
            exposure=exposure,
            data_sensitivity=data_sensitivity,
            exploit_complexity=exploit_complexity.title(),
            privilege_required=privilege_required.title(),
            evidence=evidence_override or [
                f"Affected component: {component.name}" if component else "Component context inferred",
                f"Related flow: {flow_ref}" if flow_ref else "Component-local weakness",
                f"Related asset: {asset.name}" if asset else f"Data sensitivity: {data_sensitivity}",
            ],
            affected_components=affected_components,
            affected_data_flows=affected_flows,
            affected_assets=[asset.name] if asset else [],
            component_id=component_id,
            flow_source=flow_ref.split("->")[0] if flow_ref else None,
            flow_target=flow_ref.split("->")[1] if flow_ref else None,
            status="Identified",
            owasp_top_10=library_entry.get("owasp_top_10", []),
            cwe=library_entry.get("cwe", []),
            mitre_attack=library_entry.get("mitre_attack", []),
            mitre_atlas=library_entry.get("mitre_atlas", []),
            nist_800_53=library_entry.get("nist_800_53", []),
            explanation={
                "why_flagged": library_entry["root_cause"],
                "component": component.name if component else None,
                "flow": flow_ref,
                "asset": asset.name if asset else None,
                "matched_controls": list(library_entry.get("controls", [])),
            },
        )
