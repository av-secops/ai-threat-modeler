import hashlib
import json
import logging
import re
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime
from threading import RLock
from typing import Any, Dict, List, Optional, Set, Tuple

from .analysis_gaps import detect_missing_elements
from .architecture_intelligence import ArchitectureIntelligence
from .attack_path_engine import generate_attack_paths
from .contextual_threat_engine import ContextualThreatEngine
from .canonical_model import canonicalize_architecture
from .deduplication_engine import deduplicate_threats
from .disagreement_engine import DisagreementEngine
from .evidence_requests import build_evidence_requests
from . import graph as reachability
from .graph_builder import GraphBuilder
from .impact_mapper import map_business_impact
from .mermaid_generator import diagram_coverage, generate_mermaid
from .model_policy import model_status
from .architecture_document import render as render_architecture_document
from .output_model import build_system_model, group_findings, normalize_finding_output, risk_methodology
from .owasp_mapping import owasp_for
from .known_issue_taxonomy import CONTROL_PROPERTIES, GENERIC_WEAKNESS_RULES_BY_ID
from .knowledge_threat_engine import KnowledgeThreatEngine
from .local_intelligence import LocalIntelligence
from .parser import ArchitectureParser
from .progress import ProgressReporter, ProgressSink
from .reporter import ReportGenerator
from .risk_scoring import calculate_risk, score_for
from . import source_index
from .confidence_calibration import ConfidenceCalibrator
from .retrieval_quality import audit_knowledge_rules, rule_provenance
from ..knowledge_base.frameworks import resolve_mappings
from .stride_coverage_engine import StrideCoverageEngine
from .specialist_router import SpecialistRouter
from .specialist_orchestrator import SpecialistOrchestrator
from ..knowledge_base.loader import get_knowledge_base, reload_knowledge_base
from ..services.untrusted_input import scan as scan_untrusted
from ..models import AnalysisResult, SystemArchitecture, Threat

logger = logging.getLogger(__name__)

TITLE_LENGTH = 120


def _merge(left: Optional[List[Any]], right: Optional[List[Any]]) -> List[Any]:
    """Both lists, in order, without repeats."""
    merged: List[Any] = []
    for item in [*(left or []), *(right or [])]:
        if item and item not in merged:
            merged.append(item)
    return merged


def _summarize(text: str, limit: int = TITLE_LENGTH) -> str:
    """Shorten text for a finding title without cutting a word in half."""
    cleaned = ' '.join(str(text or '').split()).rstrip('.')
    if len(cleaned) <= limit:
        return cleaned
    clipped = cleaned[:limit]
    boundary = clipped.rfind(' ')
    return f"{clipped[:boundary] if boundary > limit // 2 else clipped}..."


DOMAIN_PLAYBOOK = {
    "general": {
        "label": "General software system",
        "headline": "Prioritize exposed interfaces, sensitive stores, and trust-boundary crossings first.",
        "priority_controls": ["authentication", "authorization", "encryption", "logging"],
        "high_risk_areas": ["public entry points", "sensitive storage", "external integrations"],
    },
    "saas": {
        "label": "Multi-tenant SaaS",
        "headline": "Tenant isolation, admin workflows, and identity federation should dominate review order.",
        "priority_controls": ["tenant isolation", "RBAC", "audit trails", "API authorization"],
        "high_risk_areas": ["cross-tenant access", "admin tooling", "identity providers"],
    },
    "fintech": {
        "label": "Fintech or payments",
        "headline": "Payment flows, secrets handling, and transaction integrity need the strongest controls.",
        "priority_controls": ["strong auth", "key management", "transaction integrity", "egress controls"],
        "high_risk_areas": ["payment APIs", "credential stores", "third-party payment links"],
    },
    "healthcare": {
        "label": "Healthcare or PHI system",
        "headline": "PHI storage, long-lived sessions, and auditability drive the highest impact risk.",
        "priority_controls": ["least privilege", "audit logging", "DLP", "session controls"],
        "high_risk_areas": ["record access", "download paths", "clinical integrations"],
    },
    "ai": {
        "label": "AI or LLM application",
        "headline": "Prompt injection, retrieval leakage, and tool authorization should be reviewed as first-order architecture risks.",
        "priority_controls": ["retrieval isolation", "tool-call authorization", "data minimization", "artifact integrity"],
        "high_risk_areas": ["prompt inputs", "vector stores", "tool execution", "model outputs"],
    },
    "platform": {
        "label": "Cloud platform or Kubernetes stack",
        "headline": "Workload identity, segmentation, and platform control-plane access are the dominant design concerns.",
        "priority_controls": ["least-privilege IAM", "network policy", "secret isolation", "supply-chain integrity"],
        "high_risk_areas": ["control plane", "shared infrastructure", "cluster ingress", "build pipeline"],
    },
}

STRIDE_MAPPING = {
    "Authentication": "Spoofing",
    "Authorization": "Elevation of Privilege",
    "Data Breach": "Information Disclosure",
    "Injection": "Tampering",
    "Lateral Movement": "Elevation of Privilege",
}


class ThreatAnalyzer:
    def __init__(self):
        self.knowledge_base = get_knowledge_base()
        self.contextual_engine = ContextualThreatEngine(self.knowledge_base)
        self.knowledge_engine = KnowledgeThreatEngine(self.knowledge_base)
        self.stride_coverage_engine = StrideCoverageEngine()
        self.specialist_router = SpecialistRouter()
        self.specialist_orchestrator = SpecialistOrchestrator(self.knowledge_base)
        self.local_intelligence = LocalIntelligence(self.knowledge_base)
        self.confidence_calibrator = ConfidenceCalibrator()
        self.disagreement_engine = DisagreementEngine()
        self.knowledge_quality_audit = audit_knowledge_rules(self.knowledge_base.get_all_threats())
        self._cache_lock = RLock()
        self._parsed_arch_cache: OrderedDict[str, SystemArchitecture] = OrderedDict()
        self._graph_cache: OrderedDict[str, object] = OrderedDict()

    def _cache_get(self, cache: OrderedDict, key: str):
        with self._cache_lock:
            if key in cache:
                cache.move_to_end(key)
                return cache[key]
        return None

    def _cache_set(self, cache: OrderedDict, key: str, value, max_size: int):
        with self._cache_lock:
            cache[key] = value
            cache.move_to_end(key)
            while len(cache) > max_size:
                cache.popitem(last=False)

    @staticmethod
    def _stable_hash(payload) -> str:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _architecture_signature(self, architecture: SystemArchitecture) -> str:
        payload = architecture.model_dump() if hasattr(architecture, "model_dump") else architecture.dict()
        return self._stable_hash(payload)

    def _get_cached_graph(self, architecture: SystemArchitecture):
        signature = self._architecture_signature(architecture)
        cached_graph = self._cache_get(self._graph_cache, signature)
        if cached_graph is not None:
            return cached_graph
        graph = GraphBuilder(architecture).get_graph()
        self._cache_set(self._graph_cache, signature, graph, max_size=32)
        return graph

    def _generate_report_markdown(self, result: AnalysisResult) -> str:
        # Rendering is cheap; IDs and scores cannot key changing evidence,
        # remediations, review decisions, and publication status correctly.
        return ReportGenerator.generate_markdown(result)

    def reload_local_intelligence(self) -> Dict[str, object]:
        from .embedding_service import reset_embedding_service, reset_vector_store
        from .semantic_matcher import reset_semantic_matcher
        from .stride_classifier import reset_stride_classifier

        reset_semantic_matcher()
        reset_vector_store()
        reset_embedding_service()
        reset_stride_classifier()
        self.knowledge_base = reload_knowledge_base()
        self.contextual_engine = ContextualThreatEngine(self.knowledge_base)
        self.knowledge_engine = KnowledgeThreatEngine(self.knowledge_base)
        self.specialist_orchestrator = SpecialistOrchestrator(self.knowledge_base)
        self.local_intelligence = LocalIntelligence(self.knowledge_base)
        self.confidence_calibrator = ConfidenceCalibrator()
        self.disagreement_engine = DisagreementEngine()
        self.knowledge_quality_audit = audit_knowledge_rules(self.knowledge_base.get_all_threats())
        with self._cache_lock:
            self._parsed_arch_cache.clear()
            self._graph_cache.clear()
        return {
            "knowledge_base_threats": len(self.knowledge_base.get_all_threats()),
            "cached_architectures_cleared": True,
            "cached_graphs_cleared": True,
        }

    def _normalize_analysis_mode(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> str:
        if analysis_mode not in {"fast", "standard", "deep"}:
            return "standard"
        if analysis_mode == "fast" and not use_local_slm:
            return "fast"
        return analysis_mode

    def _analysis_flags(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> Dict[str, bool]:
        mode = self._normalize_analysis_mode(analysis_mode, use_local_slm)
        return {
            "mode": mode,
            "architecture_intelligence": mode in {"standard", "deep"},
            "attack_chains": mode in {"standard", "deep"},
            "deep_context": mode == "deep",
            "local_intelligence": use_local_slm,
        }

    def analyze_from_text(
        self,
        description: str,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general",
        source_documents: Optional[List[Dict[str, Any]]] = None,
        progress: Optional[ProgressSink] = None,
    ) -> AnalysisResult:
        reporter = ProgressReporter(progress)
        reporter.phase("parsing")
        cache_key = self._stable_hash({"description": description, "source_documents": source_documents or []})
        system_architecture = self._cache_get(self._parsed_arch_cache, cache_key)
        parse_cache_hit = system_architecture is not None
        if system_architecture is None:
            parser = ArchitectureParser()
            system_architecture = parser.parse(description)
            if source_documents:
                metadata = system_architecture.metadata or {}
                metadata["source_documents"] = deepcopy(source_documents)
                system_architecture.metadata = metadata
            self._cache_set(self._parsed_arch_cache, cache_key, system_architecture, max_size=32)
        parsing_performance = reporter.finish()
        result = self.analyze(
            system_architecture,
            project_name,
            use_local_slm=use_local_slm,
            analysis_mode=analysis_mode,
            domain_profile=domain_profile,
            progress=progress,
        )
        performance = result.engine_status["performance"]
        performance["phase_ms"] = {**parsing_performance["phase_ms"], **performance["phase_ms"]}
        performance["total_ms"] = round(performance["total_ms"] + parsing_performance["total_ms"], 3)
        performance["parse_cache_hit"] = parse_cache_hit
        return result

    def analyze(
        self,
        architecture: SystemArchitecture,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general",
        progress: Optional[ProgressSink] = None,
    ) -> AnalysisResult:
        reporter = ProgressReporter(progress)
        analysis_flags = self._analysis_flags(analysis_mode, use_local_slm)
        reporter.phase("canonical_model")
        # Engines enrich their working model. Neither callers nor the parse
        # cache should acquire those mutations or share them across requests.
        architecture = architecture.model_copy(deep=True)
        architecture, architecture_validation = canonicalize_architecture(architecture)
        graph = self._get_cached_graph(architecture)

        reporter.phase("knowledge", {"components": len(architecture.components)})
        threats, specialist_diagnostics = self.specialist_orchestrator.analyze(architecture)
        specialist_route = specialist_diagnostics
        kb_diagnostics = specialist_diagnostics["knowledge_diagnostics"]
        from .workflow_checks import analyze_workflows
        workflow_threats, workflow_assessments = analyze_workflows(architecture)
        threats.extend(workflow_threats)
        reporter.phase("declared_issues", {"findings": len(threats)})
        threats = self._process_known_issues(architecture, threats)
        threats = self._process_stated_weaknesses(architecture, threats)
        threats = self._flag_untrusted_instructions(architecture, threats)
        threats = self._normalize_stride(threats)
        threats = self._ensure_architecture_links(threats, architecture)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = deduplicate_threats(threats)
        reporter.phase("stride_coverage", {"findings": len(threats)})
        coverage_candidates, _ = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=True,
        )
        threats.extend(coverage_candidates)
        threats = self._normalize_stride(threats)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = deduplicate_threats(threats)
        reporter.phase("local_intelligence")
        threats, local_diagnostics = self.local_intelligence.enrich(
            architecture, threats, enabled=analysis_flags["local_intelligence"],
        )
        disagreement_diagnostics = self.disagreement_engine.assess(threats, local_diagnostics)
        reporter.phase("calibration", {"findings": len(threats)})
        threats, confidence_diagnostics = self.confidence_calibrator.calibrate(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = self._classify_tiers(threats)
        from .finding_assurance import validate_evidence
        threats = validate_evidence(threats, architecture)
        threats = self._suppress_potentials_superseded_by_known_issues(threats)
        threats = self._collapse_findings_on_the_same_control(threats)
        _, stride_coverage = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=False,
        )
        reporter.phase("attack_paths")
        attack_paths = generate_attack_paths(architecture, threats)
        threats = self._attach_attack_paths(threats, attack_paths)
        threats = self._enrich_threat_explanations(threats, architecture)
        threats = self._cite_evidence_sources(threats, architecture)
        architecture_insights = []
        if analysis_flags["architecture_intelligence"]:
            try:
                architecture_insights = [item.to_dict() for item in ArchitectureIntelligence().analyze(graph, architecture)]
            except Exception as exc:
                logger.warning("Architecture intelligence failed: %s", exc)

        missing_information = detect_missing_elements(architecture)
        evidence_requests = build_evidence_requests(stride_coverage, architecture)
        reporter.phase("scoring")
        score = self._calculate_score(threats)
        reporter.phase("reporting")
        from .canonical_diagram import diagram_views
        views = diagram_views(architecture, threats)
        diagram = views[0]['diagram']
        diagram_stats = views[0]['coverage']

        confirmed = [threat for threat in threats if threat.tier == "Confirmed"]
        potential = [threat for threat in threats if threat.tier == "Potential"]

        result = AnalysisResult(
            project_name=project_name,
            summary=(
                f"Context-aware analysis complete. "
                f"{len(confirmed)} confirmed risks, {len(potential)} assumption-sensitive risks, "
                f"and {len(attack_paths)} modeled attack paths."
            ),
            threats=threats,
            architecture=architecture,
            score=score,
            mermaid_diagram=diagram,
            diagram=diagram,
            timestamp=datetime.now().isoformat(),
        )

        result.attack_chains = {
            "paths": attack_paths,
            "count": len(attack_paths),
        }
        result.system_model = build_system_model(architecture)
        result.architecture_document = render_architecture_document(architecture)
        result.stride_coverage = stride_coverage
        result.architecture_validation = architecture_validation
        result.engine_status = {
            "canonical_model": {"status": "active", "version": architecture_validation["version"]},
            "rule_engine": {"status": "active", "findings": len(threats)},
            "knowledge_base": {
                "status": "active",
                "schema_version": "canonical-kb-3.0",
                "threats": len(self.knowledge_base.get_all_threats()),
                "typed_rules": len(self.knowledge_base.get_typed_rules()),
                "deterministic_rules": sum(
                    item.rule_kind == "deterministic" for item in self.knowledge_base.get_typed_rules()
                ),
                "candidate_only_rules": sum(
                    item.rule_kind == "candidate" for item in self.knowledge_base.get_typed_rules()
                ),
                "validation_issues": len(self.knowledge_base.validation_issues),
                "validation_issue_details": self.knowledge_base.validation_issues[:50],
                "quality_audit": self.knowledge_quality_audit,
                **kb_diagnostics,
            },
            "specialist_router": specialist_route,
            "local_models": model_status(),
            "local_intelligence": local_diagnostics,
            "disagreements": disagreement_diagnostics,
            "confidence_calibration": confidence_diagnostics,
            "stride_coverage": {
                "status": "active", "version": stride_coverage["version"],
                "applicable_cells": stride_coverage["applicable_cells"],
                "unknown_cells": stride_coverage["unknown_cells"],
            },
            "diagram_coverage": diagram_stats,
            "diagram_views": views,
            "workflow_assessments": workflow_assessments,
            "evidence_requests": {
                "status": "active",
                "requests": len(evidence_requests["requests"]),
                "unresolved_cells": evidence_requests["unresolved_cells"],
                "cells_addressed": evidence_requests["cells_addressed"],
            },
            "quality_gate": self._runtime_quality_gate(
                architecture_validation, threats, stride_coverage, local_diagnostics,
                disagreement_diagnostics, architecture, attack_paths,
            ),
        }
        result.finding_groups = group_findings(threats)
        result.risk_methodology = risk_methodology()
        result.risk_methodology["score_breakdown"] = {
            **self._score_breakdown(threats),
            "determined_control_ratio": (result.engine_status or {}).get("quality_gate", {}).get(
                "determined_control_ratio", 0.0
            ),
        }
        result.architecture_insights = architecture_insights
        result.ml_enhanced = {
            "analysis_mode": analysis_flags["mode"],
            "local_intelligence": local_diagnostics["status"],
            "semantic_matching": local_diagnostics["semantic_retrieval"],
            "stride_classifier": local_diagnostics["stride_classifier"],
            "architecture_modeled": True,
            "attack_paths": True,
            "attack_chains": True,
            "contextual_threat_engine": True,
        }
        result.coverage = self._build_coverage(architecture, threats, analysis_flags, missing_information)
        result.follow_up_questions = self._build_follow_up_questions(
            architecture, threats, missing_information, stride_coverage, disagreement_diagnostics,
        )
        result.evidence_requests = evidence_requests
        result.review_summary = self._build_review_summary(threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, threats)
        result.ai_security_lens = self._build_ai_security_lens(architecture, threats)
        result.priority_actions = self._build_priority_actions(threats)
        from .finding_assurance import attach_assurance
        attach_assurance(result)
        result.report_markdown = self._generate_report_markdown(result)
        result.engine_status["performance"] = reporter.finish()
        return result

    # Extraction states that mean the whole document reached the model. Anything
    # else left content behind: an image-only PDF page, or an embedded diagram.
    _COMPLETE_EXTRACTION = frozenset({
        "text_complete", "semantic_text_complete", "structured_complete", "structured_text_complete",
    })

    @staticmethod
    def _unread_document_content(
        architecture: Optional[SystemArchitecture],
    ) -> List[Dict[str, Any]]:
        """List uploaded documents whose content did not fully reach the model.

        Ingestion already records this per document and nothing read it, so a
        design whose diagram pages were images was analysed as though those pages
        did not exist and published as ready.
        """
        documents = ((architecture.metadata if architecture else None) or {}).get("source_documents") or []
        unread = []
        for document in documents:
            quality = str(document.get("extraction_quality") or "")
            if not quality or quality in ThreatAnalyzer._COMPLETE_EXTRACTION:
                continue
            pages = [page for page in str(document.get("image_only_pages") or "").split(",") if page]
            images = str(document.get("embedded_images") or "")
            unread.append({
                "document": document.get("filename") or "uploaded document",
                "extraction_quality": quality,
                "unread_pages": pages,
                "embedded_images": images,
                "detail": str(document.get("warning") or "").strip()
                or "Part of this document could not be extracted.",
            })
        return unread

    @staticmethod
    def _describe_unread_content(unread: List[Dict[str, Any]]) -> str:
        """State which documents were read incompletely, and where."""
        if not unread:
            return ""

        def one(record: Dict[str, Any]) -> str:
            pages = record.get("unread_pages") or []
            if pages:
                label = "page" if len(pages) == 1 else "pages"
                return f"{record['document']} ({label} {', '.join(pages)} not read)"
            return f"{record['document']} ({record['detail'].rstrip('.').lower()})"

        named = [one(record) for record in unread[:3]]
        if len(unread) > 3:
            named.append(f"and {len(unread) - 3} more")
        return (
            "Part of an uploaded document was not read, so the model may be missing "
            "design it describes: " + "; ".join(named) + "."
        )

    @staticmethod
    def _runtime_quality_gate(
        architecture_validation: Dict[str, Any],
        threats: List[Threat],
        stride_coverage: Dict[str, Any],
        local_diagnostics: Optional[Dict[str, Any]] = None,
        disagreement_diagnostics: Optional[Dict[str, Any]] = None,
        architecture: Optional[SystemArchitecture] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Decide whether this report can be published as it stands.

        Two different questions were previously answered by one verdict. Whether
        the report contradicts itself is an integrity question and blocks
        publication. Whether the model captured everything in the input is a
        completeness question and calls for review instead, because one missed
        component is not a reason to withhold every finding.
        """
        def scoped(threat: Threat) -> bool:
            return bool(
                threat.affected_components or threat.affected_data_flows or threat.affected_assets
            )

        confirmed_without_evidence = sum(
            threat.tier == "Confirmed" and not threat.evidence_details for threat in threats
        )
        unmapped = sum(not scoped(threat) for threat in threats)
        def declared(threat: Threat) -> bool:
            explanation = threat.explanation or {}
            return (
                explanation.get("origin") == "declared_known_issue"
                or explanation.get("scope_resolution") == "unresolved_explicit_statement"
            )

        # An issue the input states but the model cannot place is still worth
        # reporting. Dropping it would lose the user's own evidence, and blocking
        # the report would withhold every other finding over one unplaced item,
        # so it is carried as a review item instead.
        confirmed_unmapped = sum(
            threat.tier == "Confirmed" and not scoped(threat) and not declared(threat)
            for threat in threats
        )
        unscoped_declared = sum(
            not scoped(threat) and declared(threat) for threat in threats
        )
        challenger = ((local_diagnostics or {}).get("challenger") or {})
        omitted_components = int(challenger.get("omitted_component_count") or 0)
        duplicate_aliases = int(challenger.get("duplicate_alias_count") or 0)
        unclassified_known_issues = sum(
            threat.tier == "Confirmed" and str(threat.id).startswith("UNCLASSIFIED-KNOWN-ISSUE")
            for threat in threats
        )
        unresolved_disagreements = int((disagreement_diagnostics or {}).get("unresolved_count") or 0)
        unknown_cells = int(stride_coverage.get("unknown_cells") or 0)
        applicable_cells = int(stride_coverage.get("applicable_cells") or 0)
        determined_ratio = (
            round((applicable_cells - unknown_cells) / applicable_cells, 3) if applicable_cells else 0.0
        )

        unread_documents = ThreatAnalyzer._unread_document_content(architecture)
        declared_known_issues = len(((architecture.metadata if architecture else None) or {}).get("known_issues") or [])
        modeled_known_issues = sum(
            (threat.explanation or {}).get("origin") == "declared_known_issue" for threat in threats
        )
        dropped_known_issues = max(0, declared_known_issues - modeled_known_issues)
        invalid_attack_paths = sum(
            not path.get("entry_point")
            or not (path.get("target") or path.get("target_component_id"))
            or not path.get("hops")
            or any(
                not hop.get("source") or not hop.get("target") or not hop.get("evidence_status")
                for hop in path.get("hops") or []
            )
            for path in attack_paths or []
        )

        integrity_violations = [
            check for check in (
                ("invalid_topology", 0 if architecture_validation.get("valid", False) else 1,
                 "The component and flow graph does not validate."),
                ("confirmed_without_evidence", confirmed_without_evidence,
                 "A confirmed finding cites no evidence."),
                ("confirmed_without_scope", confirmed_unmapped,
                 "A confirmed finding names no affected element."),
                ("declared_known_issue_not_reported", dropped_known_issues,
                 "An issue stated in the input is missing from the findings."),
                ("invalid_attack_paths", invalid_attack_paths,
                 "An attack path lacks an entry, target, or evidence-backed graph hop."),
            ) if check[1]
        ]
        completeness_warnings = [
            check for check in (
                ("omitted_named_components", omitted_components,
                 "A component named in the input is absent from the model."),
                ("duplicate_component_aliases", duplicate_aliases,
                 "One component appears more than once under different names."),
                ("unclassified_known_issues", unclassified_known_issues,
                 "A stated issue has no taxonomy classification."),
                ("unscoped_declared_issues", unscoped_declared,
                 "An issue stated in the input could not be placed on an element."),
                ("unscoped_findings", unmapped - confirmed_unmapped,
                 "A potential finding names no affected element."),
                ("unresolved_engine_disagreements", unresolved_disagreements,
                 "Engines disagree and the conflict is unresolved."),
                ("low_determined_control_coverage", 1 if applicable_cells and determined_ratio < 0.5 else 0,
                 "Fewer than half of applicable control states are determined from evidence."),
                # A diagram that was uploaded as an image contributes nothing to
                # the model. Reporting "ready" over an unread page would present
                # a model of part of the design as a model of the design.
                ("unread_document_content", len(unread_documents),
                 ThreatAnalyzer._describe_unread_content(unread_documents)),
            ) if check[1]
        ]

        def as_items(checks) -> List[Dict[str, Any]]:
            return [{"check": name, "count": count, "detail": detail} for name, count, detail in checks]

        status = (
            "blocked" if integrity_violations
            else "review" if completeness_warnings
            else "ready"
        )
        return {
            "status": status,
            # Retained under its original name for API and report consumers.
            "publication_status": status,
            "model_integrity": "valid" if not integrity_violations else "violated",
            "integrity_violations": as_items(integrity_violations),
            "completeness_warnings": as_items(completeness_warnings),
            "architecture_valid": architecture_validation.get("valid", False),
            "confirmed_without_evidence": confirmed_without_evidence,
            "unmapped_findings": unmapped,
            "confirmed_unmapped_findings": confirmed_unmapped,
            "omitted_named_components": omitted_components,
            "duplicate_component_aliases": duplicate_aliases,
            "unclassified_known_issues": unclassified_known_issues,
            "unscoped_declared_issues": unscoped_declared,
            "declared_known_issues": declared_known_issues,
            "reported_known_issues": modeled_known_issues,
            "invalid_attack_paths": invalid_attack_paths,
            "unknown_stride_cells": unknown_cells,
            "applicable_stride_cells": applicable_cells,
            # Unknown control state is expected in prose models, but very low
            # determination means the report needs reviewer validation.
            "determined_control_ratio": determined_ratio,
            "unresolved_engine_disagreements": unresolved_disagreements,
            "unread_document_content": unread_documents,
            "policy": (
                "Publication is blocked only where the report would contradict itself: an "
                "invalid topology, a confirmed finding without evidence or scope, or an issue "
                "stated in the input that no finding reports. Invalid attack paths also block "
                "publication. Extraction gaps, an issue that "
                "could not be placed on an element, and unresolved engine disagreements mark "
                "the report for review. Fewer than half of applicable controls determined from "
                "evidence also requires review; unknown states remain visible as questions."
            ),
        }

    @staticmethod
    def _suppress_potentials_superseded_by_known_issues(threats: List[Threat]) -> List[Threat]:
        """Suppress only a question about the same control and complete scope."""
        def scope(threat):
            components = set(threat.affected_components or [])
            components.update(filter(None, [threat.component, threat.affected_component]))
            flows = set(threat.affected_data_flows or [])
            flows.update(filter(None, [threat.data_flow, threat.related_data_flow]))
            return frozenset(components), frozenset(flows)

        confirmed_claims = []
        for threat in threats:
            source_refs = {
                str(item.get("source_ref") or "") for item in (threat.evidence_details or [])
            }
            if threat.tier != "Confirmed" or not any(re.fullmatch(r"K\d+", ref) for ref in source_refs):
                continue
            controls = set((threat.explanation or {}).get("matched_controls") or [])
            if controls:
                confirmed_claims.append((scope(threat), controls, threat.stride_category or threat.category, (threat.cwe or [None])[0]))

        filtered = []
        for threat in threats:
            category = threat.stride_category or threat.category
            controls = set((threat.explanation or {}).get("matched_controls") or [])
            superseded = threat.tier == "Potential" and bool(controls) and any(
                scope(threat) == known_scope and category == known_category and controls <= known_controls
                and bool(threat.cwe) and threat.cwe[0] == known_cwe
                for known_scope, known_controls, known_category, known_cwe in confirmed_claims
            )
            if not superseded:
                filtered.append(threat)
        return filtered

    #: How authoritative a finding about a control is, most authoritative last.
    #: A knowledge-base rule names the weakness and carries a written mitigation;
    #: a contextual pattern describes the same absence in general terms; the
    #: taxonomy restates the analyst's own sentence. Where several describe one
    #: control on one component, the reviewer should read the most specific.
    _CONTROL_FINDING_PRECEDENCE = ("GENERIC-", "CTX-", "KB-", "IAC-", "CODE-")

    @classmethod
    def _collapse_findings_on_the_same_control(cls, threats: List[Threat]) -> List[Threat]:
        """Merge the same weakness, control and complete scope across producers.

        Different passes reach the same conclusion from the same property: a rule
        predicate, a contextual pattern and the plain sentence all report that a
        store is unencrypted. Reporting each bills the analyst three times for one
        problem, so the most specific is kept and the others' framework mappings
        and evidence are folded into it.
        """
        def authority(threat: Threat) -> float:
            if (threat.explanation or {}).get('origin') == 'declared_known_issue':
                # Preserve the owner's stable issue identifier when correlation
                # also enables a KB predicate for the same control and scope.
                return 3.5
            for rank, prefix in enumerate(cls._CONTROL_FINDING_PRECEDENCE, start=1):
                if str(threat.id or "").startswith(prefix):
                    return rank
            return 0

        def scope(threat):
            return (
                tuple(sorted(set(filter(None, [threat.component, threat.affected_component,
                    threat.component_id, *(threat.affected_components or [])])))),
                tuple(sorted(set(filter(None, [threat.data_flow, threat.related_data_flow,
                    *(threat.affected_data_flows or [])])))),
                (threat.stride_category or threat.category),
                (threat.cwe or [None])[0],
            )

        claims = {}
        for threat in threats:
            if threat.tier != "Confirmed":
                continue
            controls = (threat.explanation or {}).get("matched_controls") or []
            component = threat.component or threat.affected_component
            for control in controls:
                if component and threat.cwe:
                    claims.setdefault((scope(threat), control), []).append(threat)

        signature_claims = {}
        for threat in threats:
            if threat.tier != "Confirmed":
                continue
            component = threat.component or threat.affected_component
            signature = cls._root_signature(threat)
            if component and signature:
                signature_claims.setdefault((scope(threat), signature), []).append(threat)
        for (finding_scope, signature), duplicates in signature_claims.items():
            if len(duplicates) > 1:
                claims[(finding_scope, f"root:{signature}")] = duplicates

        superseded: Dict[int, Threat] = {}
        for duplicates in claims.values():
            if len(duplicates) < 2:
                continue
            keeper = max(duplicates, key=authority)
            for threat in duplicates:
                if threat is not keeper:
                    superseded[id(threat)] = keeper

        for threat in threats:
            keeper = superseded.get(id(threat))
            if keeper is None:
                continue
            while id(keeper) in superseded:
                keeper = superseded[id(keeper)]
            keeper.cwe = _merge(keeper.cwe, threat.cwe)
            keeper.owasp_top_10 = _merge(keeper.owasp_top_10, threat.owasp_top_10)
            keeper.mitre_attack = _merge(keeper.mitre_attack, threat.mitre_attack)
            keeper.nist_800_53 = _merge(keeper.nist_800_53, threat.nist_800_53)
            keeper.evidence = _merge(keeper.evidence, threat.evidence)
            keeper.evidence_details = _merge(keeper.evidence_details, threat.evidence_details)
            keeper.explanation = {
                **(threat.explanation or {}),
                **(keeper.explanation or {}),
                "merged_finding_ids": _merge(
                    (keeper.explanation or {}).get("merged_finding_ids") or [keeper.id],
                    (threat.explanation or {}).get("merged_finding_ids") or [threat.id],
                ),
            }
        return [threat for threat in threats if id(threat) not in superseded]

    @staticmethod
    def _root_signature(threat: Threat) -> str:
        stop = {
            "a", "an", "as", "at", "configured", "configuration", "container",
            "for", "is", "kubernetes", "missing", "not", "requires", "running",
            "runs", "run", "the", "to", "validation", "workload",
        }
        tokens = {
            token[:-1] if token.endswith("s") and len(token) > 4 else token
            for token in re.findall(r"[a-z0-9]+", str(threat.title or "").lower())
            if token not in stop and len(token) > 2
        }
        return " ".join(sorted(tokens)) if 0 < len(tokens) <= 6 else ""

    def refresh_result_artifacts(
        self,
        result: AnalysisResult,
        domain_profile: str = "general",
        analysis_mode: str = "standard",
        use_local_slm: bool = True,
    ) -> AnalysisResult:
        """Rebuild report fields after threats have been externally updated."""
        analysis_flags = self._analysis_flags(analysis_mode, use_local_slm)
        architecture = result.architecture
        threats = self._normalize_stride(result.threats)
        threats = self._ensure_architecture_links(threats, architecture)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats, local_diagnostics = self.local_intelligence.enrich(
            architecture, threats, enabled=analysis_flags["local_intelligence"],
        )
        disagreement_diagnostics = self.disagreement_engine.assess(threats, local_diagnostics)
        threats, confidence_diagnostics = self.confidence_calibrator.calibrate(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = self._classify_tiers(threats)
        from .finding_assurance import validate_evidence, attach_assurance
        threats = validate_evidence(threats, architecture)
        threats = self._suppress_potentials_superseded_by_known_issues(threats)
        threats = self._collapse_findings_on_the_same_control(threats)
        _, stride_coverage = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=False,
        )
        attack_paths = generate_attack_paths(architecture, threats)
        threats = self._attach_attack_paths(threats, attack_paths)
        result.attack_chains = {"paths": attack_paths, "count": len(attack_paths)}
        from .canonical_diagram import diagram_views
        views = diagram_views(architecture, threats)
        result.mermaid_diagram = views[0]['diagram']
        result.diagram = result.mermaid_diagram
        threats = self._enrich_threat_explanations(threats, architecture)
        threats = self._cite_evidence_sources(threats, architecture)
        result.threats = threats

        missing_information = detect_missing_elements(architecture)
        confirmed = [threat for threat in threats if threat.tier == "Confirmed"]
        potential = [threat for threat in threats if threat.tier == "Potential"]

        result.score = self._calculate_score(threats)
        result.summary = (
            f"Context-aware analysis complete. "
            f"{len(confirmed)} confirmed risks, {len(potential)} assumption-sensitive risks, "
            f"and {len((result.attack_chains or {}).get('paths', []))} modeled attack paths."
        )
        evidence_requests = build_evidence_requests(stride_coverage, architecture)
        result.coverage = self._build_coverage(architecture, threats, analysis_flags, missing_information)
        result.follow_up_questions = self._build_follow_up_questions(
            architecture, threats, missing_information, stride_coverage, disagreement_diagnostics,
        )
        result.evidence_requests = evidence_requests
        result.review_summary = self._build_review_summary(threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, threats)
        result.ai_security_lens = self._build_ai_security_lens(architecture, threats)
        result.priority_actions = self._build_priority_actions(threats)
        result.system_model = build_system_model(architecture)
        result.architecture_document = render_architecture_document(architecture)
        result.stride_coverage = stride_coverage
        result.engine_status = {
            **(result.engine_status or {}),
            "diagram_coverage": views[0]['coverage'],
            "diagram_views": views,
            "local_intelligence": local_diagnostics,
            "disagreements": disagreement_diagnostics,
            "confidence_calibration": confidence_diagnostics,
            "stride_coverage": {
                "status": "active", "version": stride_coverage["version"],
                "applicable_cells": stride_coverage["applicable_cells"],
                "unknown_cells": stride_coverage["unknown_cells"],
            },
            "evidence_requests": {
                "status": "active",
                "requests": len(evidence_requests["requests"]),
                "unresolved_cells": evidence_requests["unresolved_cells"],
                "cells_addressed": evidence_requests["cells_addressed"],
            },
            "quality_gate": self._runtime_quality_gate(
                result.architecture_validation or {"valid": True}, threats, stride_coverage, local_diagnostics,
                disagreement_diagnostics, result.architecture,
                ((result.attack_chains or {}).get("paths") or []),
            ),
        }
        result.finding_groups = group_findings(threats)
        result.risk_methodology = risk_methodology()
        result.risk_methodology["score_breakdown"] = {
            **self._score_breakdown(threats),
            "determined_control_ratio": (result.engine_status or {}).get("quality_gate", {}).get(
                "determined_control_ratio", 0.0
            ),
        }
        attach_assurance(result)
        result.report_markdown = self._generate_report_markdown(result)
        return result

    @staticmethod
    def _attach_stated_evidence(threat: Threat, statement: str, rule: Dict[str, Any]) -> None:
        """Record on an existing finding that the description states this outright.

        A finding inferred from a control property and a sentence asserting the
        same weakness are one problem. Merging keeps the named title while the
        sentence remains visible as the reason, and promotes the finding to a
        stated fact rather than a deduction.
        """
        evidence = f"Stated in the architecture description: {statement}"
        if evidence in (threat.evidence or []):
            return
        threat.evidence = [*(threat.evidence or []), evidence]
        threat.evidence_details = [*(threat.evidence_details or []), {
            "source_type": "architecture_input",
            "source_ref": threat.component,
            "line": None,
            "statement": statement,
            "confidence": "High",
        }]
        threat.tier = "Confirmed"
        threat.confidence = "High"
        threat.cwe = list(threat.cwe or []) or list(rule['cwe'])
        threat.owasp_top_10 = list(threat.owasp_top_10 or []) or list(rule['owasp'])

    def _process_stated_weaknesses(
        self, architecture: SystemArchitecture, threats: List[Threat]
    ) -> List[Threat]:
        """Report weaknesses the description states about a specific component.

        These are stated facts rather than inferences, so they are reported at
        the same confidence as an entry under a "Known issues" heading. Where a
        finding already covers the same weakness on the same component - a rule
        that fired on the control property the sentence set, for instance - the
        sentence is attached to that finding as evidence instead of being
        reported again, so the analyst gets one finding that still says where
        the knowledge came from.
        """
        def covering(component_id: str, rule: Dict[str, Any]) -> Optional[Threat]:
            # Same rule, the same primary weakness reached by another route such
            # as a "Known issues" entry using a legacy rule id, or a finding that
            # already fired on the control property this weakness sets.
            properties = set(CONTROL_PROPERTIES.get(rule['control'], ()))
            for threat in threats:
                if threat.component != component_id:
                    continue
                controls = set((threat.explanation or {}).get('matched_controls') or ())
                if (
                    str(threat.id).startswith(rule['id'])
                    or (
                        rule['category'] == (threat.stride_category or threat.category)
                        and rule['cwe'][0] == (threat.cwe or [None])[0]
                        and (not controls or bool(properties & controls))
                    )
                ):
                    return threat
            return None

        for component in architecture.components or []:
            for weakness in (component.properties or {}).get('stated_weaknesses') or []:
                rule = GENERIC_WEAKNESS_RULES_BY_ID.get(weakness['rule_id'])
                if not rule:
                    continue
                covered = covering(component.id, rule)
                if covered is not None:
                    self._attach_stated_evidence(covered, weakness['statement'], rule)
                    continue
                rule_id = rule['id']
                statement = weakness['statement']
                severity = rule['severity'].title()
                threats.append(Threat(
                    id=f"{rule_id}-{component.id}",
                    category=rule['category'],
                    stride_category=rule['category'],
                    affected_stride_categories=list(rule['stride']),
                    title=f"Stated weakness: {_summarize(statement)}",
                    description=statement,
                    severity=severity,
                    severity_source="rule",
                    likelihood="High",
                    impact="High" if severity in {"Critical", "High"} else "Medium",
                    risk_score=90 if severity == "Critical" else 75 if severity == "High" else 55,
                    confidence="High",
                    mitigation=rule['mitigation'],
                    component=component.id,
                    affected_component=component.id,
                    component_id=component.id,
                    root_cause=f"The description states this weakness directly about {component.name}.",
                    realistic_attack_scenario=(
                        f"An attacker targets {component.name} at the weakness the description "
                        f"already states is present: {statement}"
                    ),
                    attack_scenario=(
                        f"An attacker targets {component.name} at the weakness the description "
                        f"already states is present: {statement}"
                    ),
                    business_impact=map_business_impact({"title": statement, "severity": severity}),
                    evidence=[f"Stated in the architecture description: {statement}"],
                    evidence_details=[{
                        "source_type": "architecture_input",
                        "source_ref": component.id,
                        "line": None,
                        "statement": statement,
                        "confidence": "High",
                    }],
                    affected_components=[component.id],
                    affected_data_flows=[],
                    affected_assets=[],
                    tier="Confirmed",
                    status="Identified",
                    finding_type="control_gap",
                    owasp_top_10=list(rule['owasp']),
                    cwe=list(rule['cwe']),
                    explanation={
                        "scope_resolution": "literal_component_sentence",
                        "scope_warning": None,
                        "matched_controls": list(CONTROL_PROPERTIES.get(rule['control'], ())),
                    },
                ))

        for index, weakness in enumerate(
            (architecture.metadata or {}).get('unscoped_stated_weaknesses') or [], 1
        ):
            rule = GENERIC_WEAKNESS_RULES_BY_ID.get(weakness['rule_id'])
            if not rule:
                continue
            statement = weakness['statement']
            covered = next(
                (
                    threat for threat in threats
                    if str(threat.id).startswith(rule['id'])
                    and statement in " ".join(threat.evidence or [])
                ),
                None,
            )
            if covered is not None:
                continue
            severity = rule['severity'].title()
            threats.append(Threat(
                id=f"{rule['id']}-UNSCOPED-{index:02d}",
                category=rule['category'],
                stride_category=rule['category'],
                affected_stride_categories=list(rule['stride']),
                title=f"Stated weakness requiring component mapping: {_summarize(statement)}",
                description=statement,
                severity=severity,
                severity_source="rule",
                likelihood="High",
                impact="High" if severity in {"Critical", "High"} else "Medium",
                risk_score=90 if severity == "Critical" else 75 if severity == "High" else 55,
                confidence="High",
                mitigation=rule['mitigation'],
                root_cause="The description states this weakness directly, but its component was not resolved.",
                realistic_attack_scenario=(
                    "An attacker exploits the stated weakness after the unresolved architecture "
                    f"scope is confirmed: {statement}"
                ),
                attack_scenario=(
                    "An attacker exploits the stated weakness after the unresolved architecture "
                    f"scope is confirmed: {statement}"
                ),
                business_impact=map_business_impact({"title": statement, "severity": severity}),
                evidence=[f"Stated in the architecture description: {statement}"],
                evidence_details=[{
                    "source_type": "architecture_input",
                    "source_ref": "unresolved_component",
                    "line": None,
                    "statement": statement,
                    "confidence": "High",
                }],
                affected_components=[],
                affected_data_flows=[],
                affected_assets=[],
                tier="Confirmed",
                status="Identified",
                finding_type="control_gap",
                owasp_top_10=list(rule['owasp']),
                cwe=list(rule['cwe']),
                explanation={
                    "scope_resolution": "unresolved_explicit_statement",
                    "scope_warning": "Confirmed source weakness; affected component requires analyst mapping.",
                    "matched_controls": list(CONTROL_PROPERTIES.get(rule['control'], ())),
                },
            ))
        return threats

    def _flag_untrusted_instructions(
        self, architecture: SystemArchitecture, threats: List[Threat]
    ) -> List[Threat]:
        """Report material under review that tries to direct the analysis itself.

        Reported whether or not an LLM is enabled, because the finding is about
        the document rather than about any one engine's behaviour.
        """
        metadata = architecture.metadata or {}
        text = str(metadata.get("architecture_text") or "")
        detections = scan_untrusted(text, source="architecture input")
        if not detections:
            return threats

        summaries = "; ".join(detection["description"] for detection in detections)
        threats.append(Threat(
            id="UNTRUSTED-INPUT-INSTRUCTION-001",
            category="Tampering",
            stride_category="Tampering",
            affected_stride_categories=["Tampering", "Repudiation"],
            title="Submitted material contains text that addresses the analysis tool",
            description=(
                "The design material contains text written to direct an automated reviewer rather "
                f"than to describe the system: {summaries}. Assisted review of this material cannot "
                "be treated as independent until the text is explained or removed."
            ),
            severity="Medium",
            likelihood="High",
            impact="Medium",
            risk_score=60,
            confidence="High",
            mitigation=(
                "Confirm with the document's author why the text is present. Re-run the analysis on "
                "material without it, and treat any prior assisted review of this document as unreliable. "
                "Language model output in this run was accepted only where it resolved to a modeled "
                "component and quoted the source, so the text could suppress findings but not invent them."
            ),
            root_cause="Material under review carries instruction-shaped text.",
            realistic_attack_scenario=(
                "Someone submitting a design for review embeds instructions telling an assisted "
                "reviewer to report nothing, so a weakness passes review unrecorded."
            ),
            attack_scenario=(
                "Someone submitting a design for review embeds instructions telling an assisted "
                "reviewer to report nothing, so a weakness passes review unrecorded."
            ),
            business_impact=map_business_impact({"title": "Manipulated security review", "severity": "Medium"}),
            evidence=[detection["quote"] for detection in detections],
            evidence_details=[{
                "source_type": "architecture_input",
                "source_ref": detection["source"],
                "line": detection["line"],
                "statement": detection["quote"],
                "confidence": "High",
            } for detection in detections],
            affected_components=[],
            affected_data_flows=[],
            affected_assets=[],
            tier="Confirmed",
            status="Identified",
            finding_type="process",
            owasp_top_10=["A03:2021-Injection"],
            cwe=["CWE-77"],
            explanation={
                "origin": "untrusted_input_scan",
                "scope": "submitted_material",
                "detections": [detection["id"] for detection in detections],
            },
        ))
        return threats

    def _process_known_issues(self, architecture: SystemArchitecture, threats: List[Threat]) -> List[Threat]:
        metadata = architecture.metadata or {}
        known_issues = metadata.get("known_issues", [])
        component_ids = {component.id for component in architecture.components or []}
        for issue_index, issue in enumerate(known_issues, 1):
            description = issue.get("description", "Known security issue identified in source material.")
            severity = issue.get("severity", "medium").title()
            threat_id = issue.get("suggested_threat_id") or "KNOWN"
            source_record_id = issue.get("source_record_id")
            # Preserve every known issue even where multiple instances map to a
            # single taxonomy rule. Deduplication must never drop source facts.
            threat_id = f"{threat_id}-{source_record_id or f'{issue_index:02d}'}"
            category = issue.get("category", "Tampering")
            affected_components = [
                component_id for component_id in issue.get("component_hints", [])
                if component_id in component_ids
            ]
            primary_component = affected_components[0] if affected_components else None
            threat = Threat(
                id=threat_id,
                category=category,
                stride_category=category,
                affected_stride_categories=issue.get("affected_stride_categories") or [category],
                title=f"Known issue: {_summarize(description)}",
                description=description,
                severity=severity,
                severity_source="rule",
                likelihood="High",
                impact="High" if severity in {"Critical", "High"} else "Medium",
                risk_score=90 if severity == "Critical" else 75 if severity == "High" else 55,
                confidence="High",
                mitigation=issue.get("mitigation") or f"Resolve the explicitly documented issue: {description}",
                component=primary_component,
                data_flow=None,
                asset=None,
                affected_component=primary_component,
                component_id=primary_component,
                root_cause="The design input explicitly lists this weakness as already present.",
                realistic_attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                business_impact=map_business_impact({"title": description, "root_cause": description}),
                evidence=[f"Known issue from design input: {description}"],
                evidence_details=[{
                    "source_type": "architecture_input",
                    "source_ref": source_record_id or f"K{issue_index}",
                    "line": None,
                    "statement": description,
                    "confidence": "High",
                }],
                affected_components=affected_components,
                affected_data_flows=[],
                affected_assets=[],
                tier="Confirmed",
                status="Identified",
                finding_type="control_gap",
                owasp_top_10=issue.get("owasp_top_10", []),
                cwe=issue.get("cwe", []),
                explanation={
                    "origin": "declared_known_issue",
                    "scope_resolution": issue.get("component_resolution", "unresolved"),
                    "scope_warning": None if primary_component else "Confirmed source issue; affected component requires analyst mapping.",
                    "matched_controls": list(CONTROL_PROPERTIES.get(issue.get("control"), ())),
                },
            )
            threats.append(threat)

        # Static findings are explicit source or configuration evidence, not
        # assumptions. Keep them separate from generic architecture rules.
        source_findings = (
            [("iac", item) for item in metadata.get("iac_findings", [])]
            + [("code", item) for item in metadata.get("security_findings", [])]
        )
        for source_kind, finding in source_findings:
            evidence_kind = finding.get("evidence_kind", "explicit")
            evidence_source = f"{source_kind}_absence" if evidence_kind == "absence" else source_kind
            severity = str(finding.get("severity", "Medium")).title()
            severity_score = {"Critical": 95, "High": 80, "Medium": 55, "Low": 30}.get(severity, 55)
            finding_text = f"{finding.get('rule_id', '')} {finding.get('title', '')}".upper()
            exposure = finding.get("exposure") or ("public" if any(token in finding_text for token in ("PUBLIC", "OPEN", "INTERNET")) else "internal")
            resource_id = finding.get("resource_id")
            component_id = resource_id if resource_id in component_ids else (
                "source" if source_kind == "code" and "source" in component_ids else None
            )
            if component_id is None and source_kind == "iac" and "terraform.configuration" in component_ids:
                component_id = "terraform.configuration"
            evidence = finding.get("evidence", []) or [finding.get("description", "Static analysis rule matched.")]
            threats.append(Threat(
                id=finding.get("id") or f"IAC-{len(threats) + 1}",
                category=finding.get("category", "Tampering"),
                title=finding.get("title", "Security finding"),
                description=finding.get("description", "An insecure source or configuration pattern was detected."),
                severity=severity,
                severity_source="rule",
                likelihood="High" if severity in {"Critical", "High"} else "Medium",
                impact="Critical" if severity == "Critical" else "High" if severity == "High" else "Medium",
                risk_score=severity_score,
                confidence="High",
                mitigation=finding.get("mitigation", "Correct the insecure source or configuration pattern."),
                component_id=component_id,
                component=component_id,
                root_cause=f"Security rule {finding.get('rule_id', 'unknown')} matched {finding.get('resource_id', 'unknown')}.",
                realistic_attack_scenario=finding.get("description", "An attacker exploits the insecure source or infrastructure configuration."),
                attack_scenario=finding.get("description", "An attacker exploits the insecure source or infrastructure configuration."),
                business_impact=map_business_impact({"title": finding.get("title", "Security finding"), "severity": severity}),
                evidence=evidence,
                evidence_details=[{
                    "source_type": evidence_source,
                    "source_ref": str(resource_id or finding.get("rule_id") or "source"),
                    "line": finding.get("line"),
                    "document": finding.get("source_file"),
                    "locator": finding.get("locator"),
                    "statement": item,
                    "confidence": "High",
                } for item in evidence],
                cwe=finding.get("cwe", []),
                owasp_top_10=finding.get("owasp_top_10", []) or owasp_for(finding.get("cwe", []), finding.get("category")),
                nist_800_53=finding.get("nist_800_53", []),
                exposure=exposure,
                data_sensitivity="sensitive",
                # Complexity is left unstated on purpose. Deriving it from the
                # rule's severity fed severity back into the calculation that
                # produces severity, and a pattern scanner has no independent
                # reading of how hard a match is to exploit. The direct-evidence
                # floor below already keeps a confirmed finding from being demoted.
                privilege_required="None" if exposure == "public" else "Low",
                affected_components=[component_id] if component_id else [],
                tier="Confirmed",
                status="Identified",
                finding_type=f"{source_kind}_candidate" if evidence_kind == "absence" else source_kind,
                explanation={
                    "origin": f"{source_kind}_rule",
                    "rule_id": finding.get("rule_id"),
                    "rule_metadata": finding.get("rule_metadata", {}),
                    "references": finding.get("references", []),
                    "verification": finding.get("verification"),
                    "exposure_evidence": exposure,
                    "control_state": "unknown" if evidence_kind == "absence" else "missing",
                },
            ))
        return threats

    def _normalize_stride(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            threat.stride_category = STRIDE_MAPPING.get(threat.category, threat.category)
            # Knowledge base and coverage findings carry a CWE but often no
            # OWASP entry. A report used for compliance evidence needs the
            # mapping on every finding, not only on the ones authored with it.
            if not threat.owasp_top_10:
                threat.owasp_top_10 = owasp_for(threat.cwe, threat.category)
        return threats

    def _classify_tiers(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            if threat.confidence_score is not None:
                direct = bool((threat.explanation or {}).get("confidence_calibration", {}).get("direct_evidence"))
                threat.tier = "Confirmed" if direct and threat.confidence_score >= 0.8 else "Potential"
            elif threat.finding_type in {"code", "iac"} and threat.evidence_details:
                threat.tier = "Confirmed"
            elif threat.finding_type in {"architecture", "control_gap"} and threat.confidence in {"Low", "Medium"}:
                threat.tier = "Potential"
            elif threat.confidence == "High" and threat.evidence_details:
                threat.tier = "Confirmed"
            elif threat.related_data_flow or threat.affected_component:
                threat.tier = "Confirmed" if len(threat.evidence) >= 2 else "Potential"
            else:
                threat.tier = "Potential"
        return threats

    def _apply_risk_model(self, threats: List[Threat], architecture: Optional[SystemArchitecture] = None) -> List[Threat]:
        """Apply one transparent technical risk calculation to every finding."""
        severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        components = {item.id: item for item in (architecture.components if architecture else [])}
        flow_list = list(architecture.flows if architecture else [])
        flows = {f"{item.source_id}->{item.target_id}": item for item in flow_list}
        for threat in threats:
            # An authored severity is a floor; a computed one is not. This used to
            # key off evidence_details being populated, which meant the floor
            # applied to nearly every finding once architecture evidence started
            # carrying citations, so auto-generated coverage questions kept the
            # Medium their producer guessed and never fell to Low.
            authored = threat.severity_source == "rule"
            component_id = threat.component or threat.affected_component or threat.component_id or ""
            component = components.get(component_id)
            flow_ref = (threat.data_flow or threat.related_data_flow or "").replace(" → ", "->")
            flow = flows.get(flow_ref)
            control_assertions = (component.properties or {}).get("control_assertions", {}) if component else {}
            present_controls = sum(value == "present" for value in control_assertions.values())
            # A flow-scoped finding is anchored by the two components it runs
            # between. Without them such findings entered the risk model with no
            # blast radius and no classification, so every question about a path
            # scored as though it concerned nothing.
            anchors = {reference for reference in (threat.affected_components or []) if reference}
            if component_id:
                anchors.add(component_id)
            if flow is not None:
                anchors.update({flow.source_id, flow.target_id})
            risk = calculate_risk({
                "category": threat.category,
                "exposure": threat.exposure,
                "data_sensitivity": threat.data_sensitivity or self._classification(anchors, components, flow),
                "exploit_complexity": threat.exploit_complexity,
                "privilege_required": threat.privilege_required,
                "evidence_confidence": threat.confidence,
                "compensating_controls": present_controls,
                "control_state": self._control_state(threat, component),
                "crosses_trust_boundary": self._sits_on_a_boundary(anchors, flow, flow_list),
                "blast_radius": self._blast_radius(anchors, flow_list),
                "architecture_size": len(components),
            })
            # This runs once per refinement of the architecture, so the result has
            # to be free to fall as well as rise. Comparing against the current
            # severity, and taking the greater score, made every pass a ratchet:
            # a value computed before controls or classifications were known could
            # never come back down, and the outcome depended on how many passes
            # ran. The producing rule's own claim is kept once so the
            # direct-evidence floor still measures against what was reported.
            if threat.reported_severity is None:
                threat.reported_severity = threat.severity
            calculated_severity = risk["severity"]
            if authored and severity_rank.get(threat.reported_severity, 1) > severity_rank.get(calculated_severity, 1):
                calculated_severity = threat.reported_severity
            threat.severity = calculated_severity
            threat.likelihood = risk["likelihood"]
            threat.impact = risk["impact"]
            threat.risk_score = (
                risk["risk_score"] if calculated_severity == risk["severity"]
                else score_for(calculated_severity, risk["risk_factors"])
            )
            threat.risk_factors = risk["risk_factors"]
        return threats

    @staticmethod
    def _blast_radius(anchors: Set[str], flows: List[Any]) -> int:
        """How much else is reachable once these components are held.

        Counting the components a finding names measures how the finding was
        written, not what it costs: nearly every finding names one component, so
        the blast radius term in the risk model never contributed anything. What
        an attacker gains is the component plus everything it can reach, which is
        a question about the graph.
        """
        reachable = set()
        for start in anchors:
            reachable |= reachability.downstream(start, flows)
        return len(anchors | reachable)

    @staticmethod
    def _control_state(threat: Threat, component: Optional[Any]) -> str:
        """Whether the control this finding concerns is absent, present or unstated.

        Confirmed tier is the fallback because a finding only reaches it on direct
        evidence of the weakness, which establishes the gap even when the rule did
        not name the control it was about. That is a reading of the architecture,
        not of our confidence in it: tier says the weakness exists, while
        confidence grades how good the evidence is, and only the former belongs in
        likelihood.
        """
        assertions = (component.properties or {}).get("control_assertions", {}) if component else {}
        controls = (threat.explanation or {}).get("matched_controls") or []
        states = {assertions.get(name, "unknown") for name in controls}
        if "absent" in states or threat.tier == "Confirmed":
            return "absent"
        if states == {"present"}:
            return "present"
        return "unknown"

    @staticmethod
    def _sits_on_a_boundary(anchors: Set[str], flow: Optional[Any], flows: List[Any]) -> bool:
        """Whether this finding sits where trust changes hands.

        A flow-scoped finding answers this from its own flow. For a
        component-scoped finding only inbound crossings count: something arriving
        from another trust zone is attack surface, whereas a call out to a less
        trusted place is an exfiltration concern that impact already covers.
        Accepting either direction made this true for 94% of findings, so it added
        a constant point and separated nothing.
        """
        if flow is not None:
            return bool((flow.properties or {}).get("crosses_trust_boundary"))
        return any(
            (item.properties or {}).get("crosses_trust_boundary") and item.target_id == component_id
            for component_id in anchors
            for item in reachability.touching(component_id, flows)
        )

    @staticmethod
    def _classification(anchors: Set[str], components: Dict[str, Any], flow: Optional[Any]) -> Optional[str]:
        """The most sensitive data the finding's elements are known to handle."""
        return reachability.most_sensitive(
            *(
                (components[component_id].properties or {}).get("data_sensitivity")
                for component_id in anchors if component_id in components
            ),
            getattr(flow, "data_type", None) if flow is not None else None,
        )

    def _ensure_architecture_links(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        component_to_assets: Dict[str, List[str]] = {}
        for asset in architecture.assets:
            if asset.related_component_id:
                component_to_assets.setdefault(asset.related_component_id, []).append(asset.name)

        for threat in threats:
            threat.component = threat.component or threat.affected_component or threat.component_id
            if threat.component and not threat.affected_components:
                threat.affected_components = [threat.component]

            if threat.data_flow and threat.data_flow.replace("->", " → ") not in threat.affected_data_flows:
                threat.affected_data_flows.append(threat.data_flow.replace("->", " → "))

            if not threat.asset:
                candidate_assets = component_to_assets.get(threat.component or "", [])
                if candidate_assets:
                    threat.asset = candidate_assets[0]
            if threat.asset and threat.asset not in threat.affected_assets:
                threat.affected_assets.append(threat.asset)

        return threats

    @staticmethod
    def _flows_by_component(architecture: SystemArchitecture) -> Dict[str, List[Dict[str, str]]]:
        """Index the flows that touch each component, in reading order.

        A component-scoped finding still lives somewhere in the diagram, and the
        paths in and out of that component are what tell a reviewer how the
        weakness is reached and what it can reach. The architecture already
        holds that; it just was never carried onto the finding.
        """
        names = {component.id: component.name or component.id for component in architecture.components or []}
        index: Dict[str, List[Dict[str, str]]] = {}
        for flow in architecture.flows or []:
            properties = flow.properties or {}
            described = {
                'label': f"{names.get(flow.source_id, flow.source_id)} → "
                         f"{names.get(flow.target_id, flow.target_id)}",
                'reference': f"{flow.source_id}->{flow.target_id}",
                'protocol': (flow.protocol or '').upper(),
                'boundary': str(properties.get('trust_boundary') or 'unknown'),
                'crosses_trust_boundary': bool(properties.get('crosses_trust_boundary')),
                'assumed': bool(flow.assumed),
            }
            for component_id, direction in ((flow.source_id, 'outbound'), (flow.target_id, 'inbound')):
                index.setdefault(component_id, []).append({**described, 'direction': direction})
        return index

    @staticmethod
    def _describe_flow_context(
        threat: Threat,
        architecture: SystemArchitecture,
        incident_flows: Dict[str, List[Dict[str, str]]],
    ) -> None:
        """Say which flows relate to this finding, and why none do when that is so.

        The flows a finding is *about* stay in ``affected_data_flows``, because
        claiming a component-scoped rule examined a particular path would
        overstate the evidence. The flows merely touching the component go into
        the explanation as context, and where there are none the reason is
        recorded, since "no flow-specific impact" reads identically whether the
        finding is component-local or the architecture has no flows at all.
        """
        explanation = dict(threat.explanation or {})
        related: List[Dict[str, str]] = []
        seen: set = set()
        for component_id in threat.affected_components or []:
            for flow in incident_flows.get(component_id, []):
                key = (flow['reference'], flow['direction'])
                if key not in seen:
                    seen.add(key)
                    related.append(flow)
        if related:
            explanation['component_flows'] = related

        if threat.affected_data_flows:
            explanation['flow_context'] = 'flow_scoped'
        elif related:
            explanation['flow_context'] = 'component_flows'
        elif not (architecture.flows or []):
            explanation['flow_context'] = 'no_flows_modeled'
        else:
            explanation['flow_context'] = 'component_isolated'
        threat.explanation = explanation

    def _attach_attack_paths(self, threats: List[Threat], attack_paths: List[Dict[str, Any]]) -> List[Threat]:
        paths_by_finding = {path.get("related_threat_id"): path for path in attack_paths}
        for threat in threats:
            threat.attack_path = paths_by_finding.get(threat.id)
            if threat.attack_path:
                explanation = dict(threat.explanation or {})
                explanation.pop("attack_path_reason", None)
                explanation["attack_path_status"] = threat.attack_path.get("path_status")
                threat.explanation = explanation
                if threat.attack_path.get("steps"):
                    threat.attack_scenario = threat.attack_scenario or " ".join(threat.attack_path["steps"])
        return threats

    def _enrich_threat_explanations(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        component_map = {component.id: component for component in architecture.components}
        incident_flows = self._flows_by_component(architecture)
        local_models = model_status()
        for threat in threats:
            component = component_map.get(threat.affected_component or threat.component_id or "")
            explanation = dict(threat.explanation or {})
            if component:
                controls = set(explanation.get('matched_controls') or [])
                explanation['correlated_evidence'] = [fact for fact in component.properties.get('correlation_evidence', [])
                    if not controls or fact.get('control') in controls]
                explanation['correlated_controls'] = {key: value for key, value in component.properties.get('correlated_controls', {}).items()
                    if not controls or key in controls}
            rule = self._rule_for_finding(threat.id)
            if rule:
                explanation["framework_mappings"] = rule.get("framework_mappings") or []
                explanation["framework_mapping_issues"] = rule.get("framework_mapping_issues") or []
            else:
                mappings, issues = resolve_mappings({"cwe": threat.cwe, "mitre_attack": threat.mitre_attack, "mitre_atlas": threat.mitre_atlas})
                explanation["framework_mappings"] = mappings
                explanation["framework_mapping_issues"] = issues
            explanation.update({
                "component_name": component.name if component else None,
                "trust_level": component.trust_level if component else None,
                "asset_sensitivity": threat.data_sensitivity,
                "root_cause": threat.root_cause,
                "provenance": {
                    "finding_id": threat.id,
                    "producer": threat.finding_type or "architecture",
                    "evidence_sources": sorted({
                        str(item.get("source_type") or "unknown")
                        for item in (threat.evidence_details or [])
                    }),
                    "knowledge_rule": rule_provenance(rule) if rule else None,
                    "models": [
                        {key: item.get(key) for key in ("role", "model", "revision", "loaded", "fallback")}
                        for item in local_models.get("models") or []
                    ],
                    "engine_version": "2.3.2",
                },
            })
            threat.explanation = explanation
            self._describe_flow_context(threat, architecture, incident_flows)
        return threats

    def _rule_for_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        normalized = re.sub(r"^KB-", "", str(finding_id or ""))
        for rule in self.knowledge_base.get_all_threats():
            rule_id = str(rule.get("id") or "")
            if normalized == rule_id or normalized.startswith(f"{rule_id}-"):
                return rule
        return None

    @staticmethod
    def _cite_evidence_sources(threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        """Name the document, page and line behind each piece of evidence.

        Producers record the statement they matched but not where it sat, and with
        several uploads the statement alone does not say which file to go and
        read. Resolving it centrally means every producer gains citations without
        each one needing to carry the source text around.

        Evidence that quotes no source keeps its element reference: a finding
        derived from the component graph was not stated anywhere.
        """
        metadata = architecture.metadata or {}
        text = str(metadata.get("source_text") or metadata.get("architecture_text") or "")
        if not text:
            return threats

        index = source_index.build(text)
        resolved: Dict[str, Optional[Dict[str, Any]]] = {}
        for threat in threats:
            for record in threat.evidence_details or []:
                statement = str(record.get("statement") or "").strip()
                if not statement or record.get("cite"):
                    continue
                if statement not in resolved:
                    citation = index.find(statement)
                    resolved[statement] = citation.as_dict() if citation else None
                if resolved[statement]:
                    record.update(resolved[statement])
        return threats

    def _build_coverage(
        self,
        architecture: SystemArchitecture,
        threats: List[Threat],
        analysis_flags: Dict[str, bool],
        missing_information: List[Dict[str, str]],
    ) -> Dict[str, object]:
        assumptions = architecture.metadata.get("assumptions", [])
        assumed_flows = sum(1 for flow in architecture.flows if flow.assumed)
        return {
            "analysis_mode": analysis_flags["mode"],
            "components_analyzed": len(architecture.components),
            "flows_analyzed": len(architecture.flows),
            "trust_boundaries_modeled": len(architecture.trust_boundaries),
            "assets_classified": len(architecture.assets),
            "assumption_count": len(assumptions),
            "assumed_flows": assumed_flows,
            "threats_identified": len(threats),
            "document_driven_analysis": False,
            "missing_information": missing_information,
            "assumptions": assumptions,
        }

    def _build_follow_up_questions(
        self,
        architecture: SystemArchitecture,
        threats: List[Threat],
        missing_information: List[Dict[str, str]],
        stride_coverage: Optional[Dict[str, Any]] = None,
        disagreement_diagnostics: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        prompts = []
        for index, gap in enumerate(missing_information[:8], start=1):
            prompts.append({
                "id": f"gap-{index}",
                "scope": gap["type"],
                "type": gap["type"],
                "priority": "high" if "auth" in gap["type"] or "data_flows" in gap["type"] else "medium",
                "question": gap["message"],
                "rationale": "Clarifying this item will tighten contextual threat accuracy and reduce assumed paths.",
                "related_components": [],
                "related_threat_count": len([threat for threat in threats if threat.tier == "Potential"]),
            })
        represented = {(item["scope"], item["type"]) for item in prompts}
        for cell in (stride_coverage or {}).get("cells", []):
            if cell.get("status") != "unknown" or len(prompts) >= 12:
                continue
            key = (cell["element_id"], cell["category"])
            if key in represented:
                continue
            prompts.append({
                "id": f"stride-gap-{len(prompts) + 1}",
                "scope": cell["element_id"],
                "type": cell["category"],
                "priority": "high" if cell["category"] in {"Spoofing", "Information Disclosure", "Elevation of Privilege"} else "medium",
                "question": f"What verified controls address {cell['category']} for {cell['element_name']}?",
                "rationale": cell["rationale"],
                "related_components": [cell["element_id"]] if cell["element_kind"] == "component" else [],
                "related_threat_count": 0,
            })
            represented.add(key)
        for item in (disagreement_diagnostics or {}).get("items", []):
            if len(prompts) >= 16:
                break
            prompts.append({
                "id": item["id"],
                "scope": item.get("element_id") or item.get("finding_id") or "analysis",
                "type": "engine_disagreement",
                "priority": "high" if item.get("status") == "review_required" else "medium",
                "question": item.get("question"),
                "rationale": item.get("resolution"),
                "related_components": [item["element_id"]] if item.get("element_id") else [],
                "related_threat_count": 1 if item.get("finding_id") else 0,
            })
        return prompts

    def _build_review_summary(self, threats: List[Threat]) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {}
        by_tier: Dict[str, int] = {}
        for threat in threats:
            by_severity[threat.severity] = by_severity.get(threat.severity, 0) + 1
            by_tier[threat.tier] = by_tier.get(threat.tier, 0) + 1
        return {
            "total": len(threats),
            "by_severity": by_severity,
            "by_tier": by_tier,
        }

    def _build_domain_context(self, domain_profile: str, architecture: SystemArchitecture, threats: List[Threat]) -> Dict[str, Any]:
        playbook = DOMAIN_PLAYBOOK.get(domain_profile, DOMAIN_PLAYBOOK["general"])
        top_risks = [threat.title for threat in sorted(threats, key=lambda item: item.risk_score or 0, reverse=True)[:3]]
        return {
            "profile": domain_profile,
            "label": playbook["label"],
            "headline": playbook["headline"],
            "priority_controls": playbook["priority_controls"],
            "high_risk_areas": playbook["high_risk_areas"],
            "top_contextual_risks": top_risks,
        }

    def _build_ai_security_lens(self, architecture: SystemArchitecture, threats: List[Threat]) -> Dict[str, Any]:
        ai_threats = [threat for threat in threats if threat.mitre_atlas or "LLM" in threat.title or "prompt" in (threat.realistic_attack_scenario or "").lower()]
        return {
            "enabled": any((component.properties or {}).get("ml_pipeline") or component.type == "ML Service" for component in architecture.components),
            "overview": f"{len(ai_threats)} AI-contextual threats identified." if ai_threats else "No strong AI-native threat chain was detected from the current model.",
            "items": [
                {
                    "id": threat.id,
                    "label": threat.title,
                    "level": threat.severity.lower(),
                    "count": 1,
                    "summary": threat.realistic_attack_scenario,
                }
                for threat in ai_threats[:5]
            ],
        }

    def _build_priority_actions(self, threats: List[Threat]) -> List[Dict[str, Any]]:
        actions = []
        for threat in sorted(threats, key=lambda item: item.risk_score or 0, reverse=True)[:3]:
            actions.append({
                "title": threat.title,
                "priority": threat.severity,
                "why_now": threat.root_cause or threat.description,
                "action": threat.mitigation,
                "focus_area": [threat.affected_component] if threat.affected_component else [],
            })
        return actions

    def _calculate_score(self, threats: List[Threat]) -> int:
        return self._score_breakdown(threats)["overall_score"]

    @classmethod
    def _score_breakdown(cls, threats: List[Threat]) -> Dict[str, Any]:
        if not threats:
            return {
                "overall_score": 100, "confirmed_risk_score": 100,
                "uncertainty_penalty": 0, "unique_risk_groups": 0,
                "formula": "No modeled findings.",
            }

        # Count one root control once. Repeated framework mappings and producers
        # should not make a system look less secure than the underlying defects.
        unique: Dict[Tuple[str, str, str], Threat] = {}
        for threat in threats:
            component = threat.component or threat.affected_component or "unmapped"
            controls = (threat.explanation or {}).get("matched_controls") or []
            root = str(controls[0]) if controls else cls._root_signature(threat) or threat.id
            key = (component, threat.stride_category or threat.category, root)
            if key not in unique or (threat.risk_score or 0) > (unique[key].risk_score or 0):
                unique[key] = threat

        confirmed_burden = sum(
            ((threat.risk_score or 0) / 100) ** 1.35
            for threat in unique.values() if threat.tier == "Confirmed"
        )
        potential_burden = sum(
            ((threat.risk_score or 0) / 100) ** 1.35 * 0.2
            for threat in unique.values() if threat.tier != "Confirmed"
        )
        confirmed_score = round(100 / (1 + confirmed_burden / 3.0))
        uncertainty_penalty = min(15, round(potential_burden * 2.5))
        overall = max(5 if confirmed_burden else 20, confirmed_score - uncertainty_penalty)
        return {
            "overall_score": min(100, overall),
            "confirmed_risk_score": min(100, confirmed_score),
            "uncertainty_penalty": uncertainty_penalty,
            "unique_risk_groups": len(unique),
            "confirmed_burden": round(confirmed_burden, 3),
            "potential_burden": round(potential_burden, 3),
            "formula": (
                "Deduplicated root risks use diminishing impact; potential findings contribute "
                "one fifth of confirmed risk and are shown as a separate uncertainty penalty."
            ),
        }
