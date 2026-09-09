"""
Comprehensive Threat Knowledge Base Loader

This module loads and manages the comprehensive threat knowledge base
from multiple modular JSON files covering cloud platforms, frameworks,
and attack patterns.
"""

import json
import re
from pathlib import Path
from typing import Any, List, Dict, Optional
import logging

from .contracts import CanonicalThreatRule
from .frameworks import registry, resolve_mappings, rule_mappings
from ..engine.control_statements import CONTROL_TERMS
from ..engine.control_contracts import CONTROL_ALIASES

logger = logging.getLogger(__name__)


TAXONOMY_FALLBACKS = {
    "Spoofing": {"cwe": ["CWE-287"], "owasp_top_10": ["A07:2021"], "nist_800_53": ["IA-2"]},
    "Tampering": {"cwe": ["CWE-345"], "owasp_top_10": ["A08:2021"], "nist_800_53": ["SI-7"]},
    "Repudiation": {"cwe": ["CWE-778"], "owasp_top_10": ["A09:2021"], "nist_800_53": ["AU-3"]},
    "Information Disclosure": {"cwe": ["CWE-200"], "owasp_top_10": ["A02:2021"], "nist_800_53": ["SC-28"]},
    "Denial of Service": {"cwe": ["CWE-400"], "owasp_top_10": ["A04:2021"], "nist_800_53": ["SC-5"]},
    "Elevation of Privilege": {"cwe": ["CWE-269"], "owasp_top_10": ["A01:2021"], "nist_800_53": ["AC-6"]},
}

# Fields with an authoritative producer in the architecture parser, canonical
# model, flow model, or IaC parser. Unsupported predicates remain searchable but
# cannot present themselves as deterministic checks that silently never fire.
ENGINE_EVALUABLE_FIELDS = {
    "absolute_timeout", "admin_separation", "audit_logging", "auth_checks",
    "auth_type", "authenticated", "compliance_frameworks", "containerized",
    "content_type_validation", "cors_wildcard", "csv_import", "csv_sanitization",
    "data_anonymization", "data_sensitivity", "deployment", "detailed_errors",
    "encryption_at_rest", "environment", "file_upload", "framework", "has_graphql",
    "has_jwt", "has_webhooks", "healthcare_integration", "html_sanitization",
    "input_validation", "is_iot_device", "jwt_validation", "least_privilege",
    "logging_enabled", "mfa_enabled", "ml_pipeline", "mobile_app", "mtls_enabled",
    "multi_region", "object_level_auth", "offline_capability", "ota_updates",
    "pagination", "privileged_container", "prompt_sanitization", "protocol",
    "public_access", "query_depth_limiting", "rate_limiting", "secrets_in_env",
    "session_timeout_type", "signed_urls", "third_party_integration", "trust_boundary",
    "trust_boundary_crossing", "type", "user_html_input", "webhook_signature_validation",
}
ENGINE_EVALUABLE_FIELDS |= set(CONTROL_TERMS)
from ..engine.literal_security import FIELDS as LITERAL_SECURITY_FIELDS
ENGINE_EVALUABLE_FIELDS |= set(LITERAL_SECURITY_FIELDS)
ENGINE_EVALUABLE_FIELDS |= {alias for alias, canonical in CONTROL_ALIASES.items() if canonical in ENGINE_EVALUABLE_FIELDS}

EXCLUDED_KB_FILES = {
    'enhanced_schema.json',
    'iac_security_rules.json',
    'schema.json',
}


class ThreatKnowledgeBase:
    """Loads and manages comprehensive threat knowledge base"""
    
    def __init__(self):
        self.kb_dir = Path(__file__).parent
        self.threats: List[Dict] = []
        self.threats_by_id: Dict[str, Dict] = {}
        self.threats_by_component: Dict[str, List[Dict]] = {}
        self.threats_by_cloud: Dict[str, List[Dict]] = {}
        self.validation_issues: List[Dict[str, str]] = []
        self.loaded_modules: List[str] = []
        self.typed_rules: List[CanonicalThreatRule] = []
        self.load_all()
    
    def load_all(self):
        """Load all threat modules"""
        self.threats = []
        self.threats_by_id = {}
        self.threats_by_component = {}
        self.threats_by_cloud = {}
        self.validation_issues = []
        self.loaded_modules = []
        self.typed_rules = []

        modules = self._discover_modules()
        
        raw_threats = []
        for module in modules:
            raw_threats.extend(self.load_module(module))

        self.threats = self._normalize_and_merge(raw_threats)
        for rule in self.threats:
            rule["framework_mappings"], issues = resolve_mappings(rule)
            rule["framework_mapping_issues"] = issues
            self.validation_issues.extend({"module": rule["source_module"], "issue": f"{rule['id']}: {issue}"} for issue in issues)
        self.typed_rules = [CanonicalThreatRule.model_validate(item) for item in self.threats]
        
        # Build indexes
        self._build_indexes()
        
        logger.info(
            "Loaded %s normalized threats from %s modules (%s validation issues)",
            len(self.threats), len(modules), len(self.validation_issues),
        )

    def _discover_modules(self) -> List[str]:
        """Auto-discover knowledge base modules so new packs load without code changes."""
        priority_order = [
            'cloud_aws_threats.json',
            'cloud_azure_threats.json',
            'cloud_gcp_threats.json',
            'owasp_web_top10.json',
            'owasp_api_top10.json',
            'container_k8s_threats.json',
            'auth_authz_threats.json',
            'infrastructure_threats.json',
            'database_threats.json',
            'supply_chain_threats.json',
            'emerging_threats.json',
            'custom_ai_llm_threats.json',
            'domain_threats.json',
            'threats.json',
        ]

        discovered = []
        for path in self.kb_dir.glob('*.json'):
            if path.name in EXCLUDED_KB_FILES:
                continue
            discovered.append(path.name)

        seen = set()
        ordered = []
        for module in priority_order:
            if module in discovered and module not in seen:
                ordered.append(module)
                seen.add(module)

        for module in sorted(discovered):
            if module not in seen:
                ordered.append(module)
                seen.add(module)

        return ordered
    
    def load_module(self, filename: str):
        """Load a single threat module"""
        filepath = self.kb_dir / filename
        
        if not filepath.exists():
            logger.warning(f"Threat module not found: {filename}")
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Handle both array and object formats
                if isinstance(data, list):
                    threats = data
                elif isinstance(data, dict) and 'threats' in data:
                    threats = data['threats']
                else:
                    logger.warning(f"Invalid format in {filename}")
                    self.validation_issues.append({"module": filename, "issue": "Expected a rule array or threats array"})
                    return []
                
                self.loaded_modules.append(filename)
                for threat in threats:
                    threat["_source_module"] = filename
                logger.debug(f"Loaded {len(threats)} threats from {filename}")
                return threats
                
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing {filename}: {e}")
            self.validation_issues.append({"module": filename, "issue": f"Invalid JSON: {e}"})
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
            self.validation_issues.append({"module": filename, "issue": str(e)})
        return []

    def _normalize_and_merge(self, raw_threats: List[Dict]) -> List[Dict]:
        merged: Dict[str, Dict] = {}
        for index, raw in enumerate(raw_threats, 1):
            normalized = self._normalize_threat(raw, index)
            if normalized["stride_category"] not in STRIDE_CATEGORIES:
                self.validation_issues.append({
                    "module": normalized["source_module"],
                    "issue": f"Threat {normalized['id']} has an unsupported STRIDE category and was rejected.",
                })
                continue
            schema_errors = self._canonical_validation_errors(normalized)
            if schema_errors:
                self.validation_issues.extend({
                    "module": normalized["source_module"],
                    "issue": f"Threat {normalized['id']}: {message}",
                } for message in schema_errors)
                continue
            threat_id = normalized["id"]
            if threat_id in merged:
                self.validation_issues.append({
                    "module": normalized["source_module"],
                    "issue": f"Duplicate threat ID {threat_id} rejected; canonical record already loaded.",
                })
                continue
            else:
                merged[threat_id] = normalized
        return list(merged.values())

    @staticmethod
    def _canonical_validation_errors(threat: Dict[str, Any]) -> List[str]:
        errors = []
        if not threat.get("id") or not threat.get("title") or not threat.get("description"):
            errors.append("id, title, and description are required")
        if threat.get("severity") not in {"Critical", "High", "Medium", "Low"}:
            errors.append("severity is invalid")
        if not isinstance(threat.get("components"), list) or not threat.get("components"):
            errors.append("at least one affected component type is required")
        detection = threat.get("detection") or {}
        if detection.get("auto_detectable") and not isinstance(detection.get("logic"), dict):
            errors.append("auto-detectable threats require structured detection logic")
        return errors

    def _normalize_threat(self, raw: Dict, index: int) -> Dict:
        from ..engine.knowledge_threat_engine import supports_detection_logic

        nested_threat = raw.get("threat") if isinstance(raw.get("threat"), dict) else {}
        risk = raw.get("risk") if isinstance(raw.get("risk"), dict) else {}
        mapped = raw.get("mapped_controls") if isinstance(raw.get("mapped_controls"), dict) else {}
        references = raw.get("references") if isinstance(raw.get("references"), dict) else {}
        mitigation = raw.get("mitigation")
        mitigations = raw.get("mitigations") or []
        threat_id = str(raw.get("threat_id") or raw.get("id") or f"KB-AUTO-{index:04d}")
        title = str(raw.get("threat_name") or raw.get("title") or nested_threat.get("title") or threat_id)
        description = str(
            raw.get("description") or nested_threat.get("description") or raw.get("attack_vector") or title
        )
        category = _normalize_stride(raw.get("stride_category") or raw.get("category"))
        components = _as_list(next(
            (raw[key] for key in ("component", "resource_type", "components") if key in raw), "Any",
        ))
        severity = _normalize_severity(
            raw.get("severity") or risk.get("severity") or raw.get("impact")
        )
        mitigation_text = _mitigation_text(mitigation, mitigations)
        preconditions = _as_list(raw.get("preconditions") or raw.get("prerequisites"))
        explicit_taxonomies = {
            "cwe": _as_list(raw.get("cwe") or mapped.get("cwe") or references.get("cwe")),
            "owasp_top_10": _as_list(raw.get("owasp_top_10") or mapped.get("owasp_top_10") or references.get("owasp_top_10")),
            "nist_800_53": _as_list(raw.get("nist_800_53") or mapped.get("nist_800_53") or references.get("nist_800_53")),
        }
        fallback = TAXONOMY_FALLBACKS.get(category, {})
        cwe = explicit_taxonomies["cwe"] or list(fallback.get("cwe") or [])
        owasp_top_10 = explicit_taxonomies["owasp_top_10"] or list(fallback.get("owasp_top_10") or [])
        nist_800_53 = explicit_taxonomies["nist_800_53"] or list(fallback.get("nist_800_53") or [])
        taxonomy_mapping_quality = {
            key: "curated" if values else "stride_category_fallback"
            for key, values in explicit_taxonomies.items()
        }
        detection = raw.get("detection") if isinstance(raw.get("detection"), dict) else {}
        auto_detectable = bool(detection.get("auto_detectable") and detection.get("logic"))
        unsupported_fields = sorted(_logic_fields(detection.get("logic")) - ENGINE_EVALUABLE_FIELDS)
        unsupported_reasons = []
        if unsupported_fields:
            unsupported_reasons.append(f"no authoritative parser producer: {', '.join(unsupported_fields)}")
        if auto_detectable and not supports_detection_logic(detection.get("logic")):
            unsupported_reasons.append("unsupported predicate syntax")
        if auto_detectable and unsupported_reasons:
            auto_detectable = False
            self.validation_issues.append({
                "module": str(raw.get("_source_module") or "unknown"),
                "issue": (
                    f"Threat {threat_id} was demoted to candidate-only because its predicate "
                    f"is not executable: {'; '.join(unsupported_reasons)}."
                ),
            })
        applicability_raw = raw.get("applicability") if isinstance(raw.get("applicability"), dict) else {}
        applicability = {
            "element_types": _as_list(applicability_raw.get("element_types") or components),
            "cloud_platforms": _as_list(applicability_raw.get("cloud_platforms") or raw.get("cloud_platform")),
            "cloud_services": _as_list(applicability_raw.get("cloud_services") or raw.get("cloud_services")),
            "required_signals": _as_list(applicability_raw.get("required_signals") or preconditions),
            "excluded_signals": _as_list(applicability_raw.get("excluded_signals")),
        }
        normalized_detection = {
            **detection,
            "auto_detectable": auto_detectable,
            "logic": detection.get("logic") if auto_detectable else {},
            "evidence_requirement": (
                str(detection.get("evidence_requirement") or "explicit")
                if auto_detectable else "candidate_only"
            ),
        }
        return {
            "id": threat_id,
            "threat_id": threat_id,
            "title": title,
            "threat_name": title,
            "description": description,
            # Compatibility envelope for pre-v2 consumers. Canonical engine
            # code uses the flat title and description fields above.
            "threat": {"title": title, "description": description},
            "attack_vector": str(raw.get("attack_vector") or description),
            "stride_category": category,
            "category": category,
            "components": components,
            "component": components,
            "cloud_platform": _as_list(raw.get("cloud_platform")),
            "cloud_services": _as_list(raw.get("cloud_services")),
            "severity": severity,
            "impact": severity,
            "likelihood": _normalize_level(raw.get("likelihood") or risk.get("likelihood")),
            "mitigation": mitigation_text,
            "preconditions": preconditions,
            "cwe": cwe,
            "owasp_top_10": owasp_top_10,
            "nist_800_53": nist_800_53,
            "mitre_attack": _as_list(raw.get("mitre_attack") or references.get("mitre_attack")),
            "mitre_atlas": _as_list(raw.get("mitre_atlas") or references.get("mitre_atlas")),
            "tags": _as_list(raw.get("tags")),
            "detection": normalized_detection,
            "applicability": applicability,
            "negating_controls": _as_list(raw.get("negating_controls")),
            "controls": {
                "negating_controls": _as_list(raw.get("negating_controls")),
                "remediation": mitigation_text or "Validate and implement an architecture-specific security control.",
            },
            "taxonomies": {
                "cwe": cwe,
                "owasp_top_10": owasp_top_10,
                "nist_800_53": nist_800_53,
                "mitre_attack": _as_list(raw.get("mitre_attack") or references.get("mitre_attack")),
                "mitre_atlas": _as_list(raw.get("mitre_atlas") or references.get("mitre_atlas")),
            },
            "rule_kind": "deterministic" if auto_detectable else "candidate",
            "source_module": str(raw.get("_source_module") or "unknown"),
            "source": str(raw.get("source") or raw.get("_source_module") or "unknown"),
            "version": str(raw.get("version") or raw.get("rule_version") or "1.0"),
            "taxonomy_mapping_quality": taxonomy_mapping_quality,
            "framework_mappings": raw.get("framework_mappings") or [],
            "verification": str(raw.get("verification") or ""),
            "review_status": str(raw.get("review_status") or "legacy_unreviewed"),
            "last_reviewed": raw.get("last_reviewed"),
            "predicate_support": {
                "status": "supported" if auto_detectable else "candidate_only",
                "element_kind": "flow" if components and all(re.sub(r'[\s_-]+', '', item.lower()) == 'dataflow' for item in components) else "component",
                "unsupported_fields": unsupported_fields,
                "unsupported_reasons": unsupported_reasons,
            },
            "references": _as_list(references.get("external_links")) if references else _as_list(raw.get("references")),
            "raw": raw,
        }

    @staticmethod
    def _merge_canonical(left: Dict, right: Dict) -> Dict:
        result = dict(left)
        for key in (
            "components", "component", "cloud_platform", "cloud_services", "preconditions",
            "cwe", "owasp_top_10", "nist_800_53", "mitre_attack", "mitre_atlas",
            "tags", "negating_controls", "references",
        ):
            result[key] = list(dict.fromkeys([*(left.get(key) or []), *(right.get(key) or [])]))
        if len(right.get("description", "")) > len(left.get("description", "")):
            result["description"] = right["description"]
            result["attack_vector"] = right["attack_vector"]
        if not result.get("detection") and right.get("detection"):
            result["detection"] = right["detection"]
        if not result.get("mitigation") and right.get("mitigation"):
            result["mitigation"] = right["mitigation"]
        return result
    
    def _build_indexes(self):
        """Build lookup indexes for fast querying"""
        for threat in self.threats:
            # Index by ID
            threat_id = threat.get('threat_id') or threat.get('id')
            if threat_id:
                self.threats_by_id[threat_id] = threat
            
            # Index by component
            component = threat.get('component')
            components = component if isinstance(component, list) else [component]
            for component_name in components:
                if not component_name:
                    continue
                if component_name not in self.threats_by_component:
                    self.threats_by_component[component_name] = []
                self.threats_by_component[component_name].append(threat)
            
            # Index by cloud platform
            cloud_platforms = threat.get('cloud_platform', [])
            if isinstance(cloud_platforms, str):
                cloud_platforms = [cloud_platforms]
            
            for platform in cloud_platforms:
                if platform not in self.threats_by_cloud:
                    self.threats_by_cloud[platform] = []
                self.threats_by_cloud[platform].append(threat)
    
    def get_all_threats(self) -> List[Dict]:
        """Get all threats"""
        return self.threats

    def get_typed_rules(self) -> List[CanonicalThreatRule]:
        return self.typed_rules
    
    def get_by_id(self, threat_id: str) -> Optional[Dict]:
        """Get threat by ID"""
        return self.threats_by_id.get(threat_id)
    
    def get_by_component(self, component: str) -> List[Dict]:
        """Get threats for a specific component"""
        exact = self.threats_by_component.get(component, [])
        return exact or self.threats_by_component.get(component.lower(), [])
    
    def get_by_cloud_platform(self, platform: str) -> List[Dict]:
        """Get threats for a specific cloud platform"""
        return self.threats_by_cloud.get(platform, [])
    
    def get_by_stride_category(self, category: str) -> List[Dict]:
        """Get threats by STRIDE category"""
        return [t for t in self.threats 
                if (t.get('stride_category') or t.get('category')) == category]
    
    def get_by_severity(self, min_severity: str = "Medium") -> List[Dict]:
        """Get threats above a certain severity"""
        severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        min_level = severity_order.get(min_severity, 2)
        
        return [t for t in self.threats 
                if severity_order.get(t.get('impact', 'Low'), 1) >= min_level]
    
    def search(self, query: str) -> List[Dict]:
        """Search threats by keyword"""
        query_lower = query.lower()
        results = []
        
        for threat in self.threats:
            # Search in name, description, attack vector
            searchable = [
                threat.get('threat_name', ''),
                threat.get('description', ''),
                threat.get('attack_vector', ''),
                ' '.join(threat.get('tags', []))
            ]
            
            if any(query_lower in field.lower() for field in searchable):
                results.append(threat)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get knowledge base statistics"""
        return {
            'total_threats': len(self.threats),
            'schema_version': 'canonical-kb-3.0',
            'modules': len(self.loaded_modules),
            'validation_issues': self.validation_issues,
            'by_component': {k: len(v) for k, v in self.threats_by_component.items()},
            'by_cloud': {k: len(v) for k, v in self.threats_by_cloud.items()},
            'by_stride': {
                category: len(self.get_by_stride_category(category))
                for category in ["Spoofing", "Tampering", "Repudiation", 
                               "Information Disclosure", "Denial of Service", 
                               "Elevation of Privilege"]
            }
        }


STRIDE_CATEGORIES = {
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
}


def _normalize_stride(value: Any) -> str:
    text = str(value or "").strip()
    if text in STRIDE_CATEGORIES:
        return text
    return {
        "Authentication": "Spoofing",
        "Injection": "Tampering",
        "Eavesdropping": "Information Disclosure",
        "Data Breach": "Information Disclosure",
        "Lateral Movement": "Elevation of Privilege",
        "Authorization": "Elevation of Privilege",
        "Combined": "Tampering",
    }.get(text, "Unknown")


def _logic_fields(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        field = value.get("field")
        if field:
            fields.add(str(field).split(".", 1)[0])
        for child in value.values():
            fields.update(_logic_fields(child))
    elif isinstance(value, list):
        for child in value:
            fields.update(_logic_fields(child))
    return fields


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, tuple):
        items = list(value)
    else:
        items = [value]
    output = []
    for item in items:
        if isinstance(item, dict):
            text = str(item.get("description") or item.get("name") or "").strip()
        else:
            text = str(item).strip()
        if text and text not in output:
            output.append(text)
    return output


def _normalize_severity(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("severity")
    text = str(value or "Medium").title()
    return text if text in {"Critical", "High", "Medium", "Low"} else "Medium"


def _normalize_level(value: Any) -> str:
    text = str(value or "Medium").title()
    return text if text in {"High", "Medium", "Low"} else "Medium"


def _mitigation_text(value: Any, mitigations: List[Any]) -> str:
    if isinstance(value, dict):
        text = value.get("primary") or value.get("description")
        if text:
            return str(text)
    elif value:
        return str(value)
    for item in mitigations:
        if isinstance(item, dict) and item.get("description"):
            return str(item["description"])
        if isinstance(item, str):
            return item
    return "Validate applicability and implement the control defined by the threat pattern."


# Global instance
_kb_instance: Optional[ThreatKnowledgeBase] = None


def get_knowledge_base() -> ThreatKnowledgeBase:
    """Get or create global knowledge base instance"""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = ThreatKnowledgeBase()
    return _kb_instance


def reload_knowledge_base() -> ThreatKnowledgeBase:
    """Reload the knowledge base from disk."""
    global _kb_instance
    registry.cache_clear()
    rule_mappings.cache_clear()
    _kb_instance = ThreatKnowledgeBase()
    return _kb_instance
