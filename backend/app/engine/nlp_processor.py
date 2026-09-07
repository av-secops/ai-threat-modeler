"""
Hybrid NLP processor for architecture descriptions.

This module intentionally avoids a hard dependency on spaCy and instead uses:
- blingfire for fast sentence splitting when available
- regex and domain dictionaries as the primary extraction engine
- optional transformers pipeline for targeted NER enrichment

The public API is kept compatible with the previous NLPProcessor so the rest of
the analyzer can use the same methods without change.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

from . import control_statements, model_policy, technology_catalog

logger = logging.getLogger(__name__)

try:
    from blingfire import text_to_sentences

    BLINGFIRE_AVAILABLE = True
except Exception:
    BLINGFIRE_AVAILABLE = False
    logger.warning("blingfire not available. Falling back to regex sentence splitting.")

try:
    from transformers import pipeline

    TRANSFORMERS_AVAILABLE = True
except Exception:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers not available. Named-entity enrichment will be disabled.")


NER_MODEL = os.getenv("AEGIS_THREAT_NER_MODEL", "dslim/bert-base-NER")

# The vendor catalog is data, not code. Kept under its historical name because
# several passes import it directly; new code should prefer the catalog's own
# helpers, which match the longest term rather than the first one listed.
TECH_COMPONENT_MAP = technology_catalog.TECHNOLOGY_TYPES

FLOW_VERBS = {
    "send",
    "sends",
    "sent",
    "transmit",
    "transmits",
    "forward",
    "forwards",
    "connect",
    "connects",
    "connected",
    "communicate",
    "communicates",
    "query",
    "queries",
    "queried",
    "read",
    "reads",
    "write",
    "writes",
    "call",
    "calls",
    "invoke",
    "invokes",
    "fetch",
    "fetches",
    "push",
    "pushes",
    "pull",
    "pulls",
    "store",
    "stores",
    "stored",
    "route",
    "routes",
    "routed",
    "redirect",
    "redirects",
    "authenticate",
    "authenticates",
    "authorize",
    "authorizes",
    "publish",
    "publishes",
    "subscribe",
    "subscribes",
    "consume",
    "consumes",
    "upload",
    "uploads",
    "download",
    "downloads",
    "stream",
    "streams",
    "proxy",
    "proxies",
    "cache",
    "caches",
    "replicate",
    "replicates",
}

PROTOCOL_INDICATORS = {
    "https": "HTTPS",
    "http": "HTTP",
    "grpc": "gRPC",
    "graphql": "GraphQL",
    "websocket": "WebSocket",
    "ws": "WebSocket",
    "wss": "WebSocket",
    "tcp": "TCP",
    "tls": "HTTPS",
    "ssl": "HTTPS",
    "mqtt": "MQTT",
    "amqp": "AMQP",
    "rest": "HTTPS",
    "ssh": "SSH",
    "sftp": "SFTP",
}

SERVICE_NAME_PATTERNS = [
    r"(?:^|\n)[ \t]*(?:\d+\.|-|\*)[ \t]+([A-Z][A-Za-z0-9/&\- \t]+?(?:Service|API|Gateway|Worker|Job|Handler|Manager|Controller|Processor|Engine|Store|Database|Cache|Agent|Pipeline))[ \t]*(?:\(([^)\r\n]+)\))?",
    r"(?:^|\n)[ \t]*([A-Z][A-Za-z0-9/&\- \t]+?(?:Service|API|Gateway|Worker|Job|Handler|Manager|Controller|Processor|Engine|Store|Database|Cache|Agent|Pipeline))[ \t]*:[ \t]*([^\r\n]+)",
]


class NLPProcessor:
    """Hybrid NLP processor for architecture descriptions."""

    def __init__(self):
        self.sentence_splitter = text_to_sentences if BLINGFIRE_AVAILABLE else None
        self.ner_pipeline = None
        self.ready = True
        self._load_optional_models()

    def _load_optional_models(self) -> None:
        if not TRANSFORMERS_AVAILABLE:
            return

        if os.getenv("AEGIS_THREAT_ENABLE_TRANSFORMERS", "").lower() not in {"1", "true", "yes"}:
            return

        try:
            self.ner_pipeline = pipeline(
                "token-classification",
                model=NER_MODEL,
                aggregation_strategy="simple",
                **model_policy.transformers_kwargs(NER_MODEL),
            )
            logger.info("Transformers NER pipeline initialized.")
            model_policy.note_model(NER_MODEL, "named_entity_recognition", loaded=True)
        except Exception as exc:
            logger.info("Transformers NER pipeline unavailable: %s", exc)
            self.ner_pipeline = None
            model_policy.note_model(
                NER_MODEL, "named_entity_recognition", loaded=False, error=str(exc),
                fallback="rule_based_extraction",
            )

    def _split_sentences(self, text: str) -> List[str]:
        if not text:
            return []
        if self.sentence_splitter:
            try:
                return [line.strip() for line in self.sentence_splitter(text).splitlines() if line.strip()]
            except Exception:
                pass
        chunks = re.split(r"(?<=[.!?])\s+|\n+", text)
        return [chunk.strip() for chunk in chunks if chunk.strip()]

    def _normalize_component_name(self, text: str) -> str:
        normalized = re.sub(r"[^a-z0-9\s/-]", " ", text.lower())
        normalized = re.sub(r"\b(?:the|a|an)\b", " ", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    def extract_entities(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }

        result = self._merge_entities(result, self._extract_with_regex(text))
        if self.ner_pipeline:
            result = self._merge_entities(result, self._extract_with_transformers(text))
        return result

    def _extract_with_transformers(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }
        try:
            entities = self.ner_pipeline(text)
        except Exception as exc:
            logger.info("Transformers NER extraction skipped: %s", exc)
            return result

        for ent in entities:
            label = ent.get("entity_group", "")
            value = ent.get("word", "").strip()
            normalized = self._normalize_component_name(value)
            if not normalized or len(normalized) < 3:
                continue

            if normalized in TECH_COMPONENT_MAP:
                result["technologies"].append(
                    {
                        "text": value,
                        "label": "TECH",
                        "component_type": TECH_COMPONENT_MAP[normalized],
                        "source": "transformers",
                    }
                )
            elif label in {"ORG", "MISC", "PRODUCT"} and re.search(
                r"(service|api|gateway|worker|engine|pipeline|database|cache)$",
                value,
                re.IGNORECASE,
            ):
                result["services"].append(
                    {
                        "text": value,
                        "label": "SERVICE",
                        "component_type": self.classify_component_type(value),
                        "source": "transformers",
                    }
                )

        return result

    def _extract_with_regex(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }
        text_lower = text.lower()
        seen = set()

        for tech in technology_catalog.terms_longest_first():
            comp_type = TECH_COMPONENT_MAP[tech]
            # Technologies are terms, not arbitrary substrings. Without token
            # boundaries, "gin" matched words such as "logging".
            if technology_catalog.mentions(text_lower, tech) and tech not in seen:
                seen.add(tech)
                result["technologies"].append(
                    {
                        "text": tech,
                        "label": "TECH",
                        "component_type": comp_type,
                        "source": "regex",
                    }
                )

        for service_pattern in SERVICE_NAME_PATTERNS:
            for match in re.finditer(service_pattern, text, re.MULTILINE):
                name = match.group(1).strip()
                tech_stack = (match.group(2) or "").strip()
                normalized_name = self._normalize_component_name(name)
                if not normalized_name or normalized_name in seen:
                    continue
                seen.add(normalized_name)
                result["services"].append(
                    {
                        "text": name,
                        "tech_stack": tech_stack,
                        "label": "SERVICE",
                        "component_type": self.classify_component_type(f"{name} {tech_stack}".strip()),
                        "source": "regex",
                    }
                )

        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text_lower and proto_key not in seen:
                seen.add(proto_key)
                result["protocols"].append({"text": proto_name, "label": "PROTOCOL", "source": "regex"})

        security_patterns = {
            "oauth2": ("OAuth2", "authentication"),
            "jwt": ("JWT", "authentication"),
            "mfa": ("MFA", "authentication"),
            "multi-factor": ("MFA", "authentication"),
            "rbac": ("RBAC", "authorization"),
            "role-based": ("RBAC", "authorization"),
            "encryption at rest": ("Encryption at Rest", "encryption"),
            "tls": ("TLS", "encryption"),
            "mtls": ("mTLS", "encryption"),
            "waf": ("WAF", "defense"),
            "rate limit": ("Rate Limiting", "defense"),
            "input validation": ("Input Validation", "defense"),
            "api key": ("API Key", "authentication"),
            "certificate pinning": ("Certificate Pinning", "encryption"),
            "cors": ("CORS", "defense"),
            "csp": ("CSP", "defense"),
            "service mesh": ("Service Mesh", "defense"),
            "zero trust": ("Zero Trust", "defense"),
        }

        for keyword, (name, category) in security_patterns.items():
            if keyword in text_lower and keyword not in seen:
                seen.add(keyword)
                result["security_controls"].append(
                    {
                        "text": name,
                        "category": category,
                        "label": "SECURITY",
                        "source": "regex",
                    }
                )

        return result

    def extract_data_flows(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        flows = []
        component_names = self._build_component_name_map(components)
        existing_pairs = set()

        for sentence in self._split_sentences(text):
            sentence_lower = sentence.lower()
            if not any(verb in sentence_lower for verb in FLOW_VERBS):
                continue

            sentence_flows = self._extract_sentence_flows(sentence, component_names)
            for flow in sentence_flows:
                pair = (flow["source"], flow["target"])
                if pair in existing_pairs:
                    continue
                existing_pairs.add(pair)
                flows.append(flow)

        return flows

    def _extract_sentence_flows(self, sentence: str, component_names: Dict[str, str]) -> List[Dict]:
        sentence_lower = sentence.lower()
        protocol = self._infer_protocol(sentence_lower)
        matches = []

        patterns = [
            r"(\b[\w\s/.-]+?)\s+(?:calls?|invokes?|proxies?\s+to|routes?\s+(?:requests?\s+)?to)\s+(\b[\w\s/.-]+)",
            r"(\b[\w\s/-]+?)\s+(?:sends?|forwards?|pushes?|transmits?|routes?)\s+(?:[\w\s/-]+?\s+)?(?:to|into)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:connects?|communicates?|integrates?|interfaces?)\s+(?:with|to)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:queries|reads?\s+from|writes?\s+to|stores?\s+(?:data\s+)?in|fetches?\s+from|pulls?\s+from)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s*(?:->|=>)\s*(\b[\w\s/-]+)",
            r"(?:data|traffic|requests?)\s+(?:flows?|goes?|moves?|travels?)\s+from\s+(\b[\w\s/-]+?)\s+to\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:receives?|consumes?|ingests?)\s+(?:[\w\s/-]+?\s+)?from\s+(\b[\w\s/-]+)",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, sentence_lower):
                source_text = self._normalize_component_name(match.group(1).strip())
                target_text = self._normalize_component_name(match.group(2).strip())
                source_id = self._match_component(source_text, component_names)
                target_id = self._match_component(target_text, component_names)
                if source_id and target_id and source_id != target_id:
                    matches.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "protocol": protocol,
                            "evidence": sentence.strip(),
                            "method": "hybrid_regex",
                        }
                    )
        return matches

    def _build_component_name_map(self, components: Dict[str, Any]) -> Dict[str, str]:
        component_names = {}
        for cid, comp in components.items():
            name = comp.name if hasattr(comp, "name") else comp.get("name", "")
            normalized_name = self._normalize_component_name(name)
            if not normalized_name:
                continue
            component_names[normalized_name] = cid
            for word in normalized_name.split():
                if len(word) > 3:
                    component_names[word] = cid
        return component_names

    def _match_component(self, text: str, component_names: Dict[str, str]) -> Optional[str]:
        text = self._normalize_component_name(text)
        if text in component_names:
            return component_names[text]
        for name, cid in component_names.items():
            if name in text or text in name:
                return cid
        for tech in technology_catalog.terms_longest_first():
            if tech in text:
                for name, cid in component_names.items():
                    if tech in name:
                        return cid
        return None

    def _infer_protocol(self, text: str) -> str:
        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text:
                return proto_name
        return "HTTPS"

    def _merge_entities(self, base: Dict, overlay: Dict) -> Dict:
        merged = {}
        for key in base:
            seen_texts = {entity["text"].lower() for entity in base.get(key, [])}
            merged[key] = list(base.get(key, []))
            for entity in overlay.get(key, []):
                if entity["text"].lower() not in seen_texts:
                    merged[key].append(entity)
                    seen_texts.add(entity["text"].lower())
        return merged

    def classify_component_type(self, text: str) -> str:
        text_lower = text.lower()
        # Most specific term wins: an "Azure OpenAI gateway" is classified by
        # the phrase the design used, not by whichever fragment of it the
        # catalog happened to list first.
        catalogued = technology_catalog.classify(text_lower)
        if catalogued:
            return catalogued
        if any(word in text_lower for word in ["database", "db", "sql", "store"]):
            return "Database"
        if any(word in text_lower for word in ["api", "endpoint", "rest", "backend"]):
            return "API"
        if any(word in text_lower for word in ["frontend", "ui", "client", "browser", "app"]):
            return "WebClient"
        if any(word in text_lower for word in ["queue", "message", "broker", "event"]):
            return "Queue"
        if any(word in text_lower for word in ["storage", "bucket", "file", "blob"]):
            return "Object Storage"
        if any(word in text_lower for word in ["gateway", "proxy", "ingress"]):
            return "API Gateway"
        if any(word in text_lower for word in ["load balancer", "balancer", "lb"]):
            return "Load Balancer"
        if any(word in text_lower for word in ["llm", "rag", "model", "embedding"]):
            return "ML Service"
        return "Service"

    def extract_security_properties(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        props = {
            "auth_type": "unknown",
            "encryption_at_rest": None,
            "logging_enabled": None,
            "input_validation": None,
            "rate_limiting": None,
            "public_access": None,
            "compliance_frameworks": [],
            "trust_boundary": "internal",
        }

        auth_checks = [
            ("cognito", "cognito"),
            ("auth0", "auth0"),
            ("okta", "okta"),
            ("keycloak", "keycloak"),
            ("azure ad", "azure_ad"),
            ("google identity", "google_identity"),
            ("firebase auth", "firebase"),
            ("oauth", "oauth2"),
            ("oidc", "oauth2"),
            ("jwt", "jwt"),
            ("json web token", "jwt"),
            ("api key", "api_key"),
            ("basic auth", "basic"),
            ("no auth", "none"),
            ("unauthenticated", "none"),
        ]
        for keyword, auth_type in auth_checks:
            if keyword in text_lower:
                props["auth_type"] = auth_type
                break

        # One vocabulary decides both whether a control is named and whether the
        # sentence claimed it or denied it, so "no MFA" cannot arrive here as
        # evidence that MFA is enforced.
        reading = control_statements.read(text)
        for control in control_statements.CONTROL_TERMS:
            stated = reading.value(control)
            if stated is not None:
                props[control] = stated

        if any(word in text_lower for word in ["hipaa", "phi"]):
            props["compliance_frameworks"].append("HIPAA")
        if "gdpr" in text_lower:
            props["compliance_frameworks"].append("GDPR")
        if "pci" in text_lower:
            props["compliance_frameworks"].append("PCI DSS")
        if "soc 2" in text_lower:
            props["compliance_frameworks"].append("SOC 2")

        if any(word in text_lower for word in ["pii", "personal", "phi"]):
            props["data_sensitivity"] = "pii"
        if any(word in text_lower for word in ["payment", "credit card", "financial"]):
            props["data_sensitivity"] = "financial"
        if any(word in text_lower for word in ["secret", "credential", "token", "password", "api key"]):
            props["credential_sensitivity"] = True

        if any(word in text_lower for word in ["kubernetes", "k8s"]):
            props["deployment"] = "k8s"
        if any(word in text_lower for word in ["docker", "container"]):
            props["containerized"] = True
        if any(
            re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text_lower)
            for term in ("llm", "rag", "embedding model", "vector database", "model serving")
        ):
            props["ml_pipeline"] = True

        if any(word in text_lower for word in ["internet-facing", "public-facing", "public endpoint", "external users"]):
            props["public_access"] = True
            props["trust_boundary"] = "internet"
        elif any(word in text_lower for word in ["third-party", "external api", "partner api", "vendor api"]):
            props["trust_boundary"] = "external"
        elif any(word in text_lower for word in ["internal only", "private network", "backoffice only"]):
            props["trust_boundary"] = "internal"

        self._apply_negation_signals(text_lower, props)
        return props

    def _apply_negation_signals(self, text_lower: str, props: Dict[str, Any]) -> None:
        """Denials the control vocabulary does not model as a property of its own."""
        if re.search(
            r"(does not|do not|doesn't|no|without).{0,40}(validate|validation).{0,20}(jwt|token)",
            text_lower,
        ):
            props["jwt_validation"] = False


_nlp_instance: Optional[NLPProcessor] = None


def get_nlp_processor() -> NLPProcessor:
    global _nlp_instance
    if _nlp_instance is None:
        _nlp_instance = NLPProcessor()
    return _nlp_instance


def nlp_runtime_ready() -> bool:
    try:
        processor = get_nlp_processor()
        return processor.ready
    except Exception:
        return False
