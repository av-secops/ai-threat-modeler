"""Constrained local architecture and coverage challenger."""

from __future__ import annotations

from typing import Any, Dict, List

from . import technology_catalog
from .component_roles import already_represented, find_named_roles
from .stride_coverage_engine import StrideCoverageEngine


class LocalChallenger:
    """Produces structured review candidates, never ungrounded findings."""

    def challenge(self, architecture, findings, retrieved_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        _, coverage = StrideCoverageEngine().assess(
            architecture, findings, generate_candidates=False,
        )
        unknown = {
            (cell["element_id"], cell["category"]): cell
            for cell in coverage["cells"] if cell["status"] == "unknown"
        }
        review_candidates = []
        components = {item.id: item for item in architecture.components or []}
        thresholds = {
            "Spoofing": 0.68, "Tampering": 0.68, "Repudiation": 0.72,
            "Information Disclosure": 0.7, "Denial of Service": 0.72,
            "Elevation of Privilege": 0.7,
        }
        for rule in retrieved_rules:
            category = rule.get("stride_category") or rule.get("category")
            for scope in rule.get("retrieved_for") or []:
                score = float(
                    (rule.get("retrieval_scores_by_scope") or {}).get(
                        scope, rule.get("retrieval_score") or 0,
                    )
                )
                threshold = thresholds.get(category, 0.7)
                if score < threshold:
                    continue
                element_id, separator, retrieved_category = scope.rpartition(":")
                if not separator or retrieved_category != category:
                    continue
                cell = unknown.get((element_id, category))
                if not cell:
                    continue
                component = components.get(element_id)
                if component and not self._rule_applies(rule, component):
                    continue
                required = (rule.get("applicability") or {}).get("required_signals", [])
                if not required and score < 0.8:
                    continue
                review_candidates.append({
                    "candidate_rule_id": rule["id"],
                    "element_id": element_id,
                    "element_name": cell["element_name"],
                    "stride_category": category,
                    "retrieval_score": round(score, 4),
                    "status": "information_required",
                    "required_evidence": required,
                    "negating_controls": rule.get("negating_controls") or [],
                    "question": f"Is {rule['title']} applicable to {cell['element_name']}, and what source or configuration evidence proves or negates it?",
                })
        review_candidates.sort(key=lambda item: item["retrieval_score"], reverse=True)

        omitted = self._omitted_literal_components(architecture)
        duplicates = self._duplicate_component_aliases(architecture)
        return {
            "version": "local-challenger-1.0",
            "mode": "constrained_semantic_challenger",
            "review_candidates": review_candidates[:30],
            "review_candidate_count": len(review_candidates),
            "omitted_literal_components": omitted,
            "omitted_component_count": len(omitted),
            "duplicate_component_aliases": duplicates,
            "duplicate_alias_count": len(duplicates),
            "unknown_stride_cells_reviewed": len(unknown),
            "finding_authority": False,
            "contract": "The local model can rank candidates and detect extraction omissions; only evidence predicates can create findings.",
        }

    @staticmethod
    def _rule_applies(rule: Dict[str, Any], component) -> bool:
        allowed = {
            str(item).lower().replace("_", " ")
            for item in (
                (rule.get("applicability") or {}).get("element_types")
                or rule.get("components") or []
            )
        }
        actual = str(component.type or "").lower().replace("_", " ")
        generic = {"any", "component", "system"}
        if allowed and not (allowed & generic) and actual not in allowed:
            aliases = {
                "service": {"api", "microservice", "serverless", "worker"},
                "container": {"container platform", "kubernetes workload"},
                "database": {"db", "data warehouse"},
            }
            if not any(actual in aliases.get(item, set()) or item in aliases.get(actual, set()) for item in allowed):
                return False
        expected_clouds = {
            str(item).lower() for item in (rule.get("cloud_platform") or []) if item
        }
        actual_cloud = str((component.properties or {}).get("cloud_provider") or "").lower()
        return not expected_clouds or not actual_cloud or actual_cloud in expected_clouds

    @staticmethod
    def _omitted_literal_components(architecture) -> List[Dict[str, str]]:
        if (architecture.metadata or {}).get("authoritative_model"):
            return []
        source = str((architecture.metadata or {}).get("architecture_text") or "").lower()
        # A name resolved to something other than a component of its own is
        # accounted for, not omitted: the system's own name is not a data store
        # just because a vendor sells one under that name.
        resolved = " ".join(
            str(entry.get("removed") or "")
            for entry in (architecture.metadata or {}).get("resolved_names") or []
        )
        represented = " ".join(
            [resolved] + [
                f"{item.id} {item.name} {item.type} {(item.properties or {}).get('technology', '')}"
                for item in architecture.components or []
            ]
        ).lower()
        omitted = []
        represented_types = frozenset(item.type for item in architecture.components or [])
        # Prefer longest aliases so "azure openai" is not reduced to "openai".
        for technology in technology_catalog.terms_longest_first():
            if len(technology) < 3:
                continue
            if not technology_catalog.mentions(source, technology):
                continue
            if technology_catalog.mentions(represented, technology):
                continue
            if technology_catalog.covered_by(technology, represented_types):
                continue
            if any(item["technology"] in technology or technology in item["technology"] for item in omitted):
                continue
            omitted.append({
                "technology": technology,
                "expected_type": technology_catalog.TECHNOLOGY_TYPES[technology],
                "source_evidence": technology,
                "status": "extraction_review_required",
            })
        for term, expected_type in technology_catalog.LOGICAL_TERMS.items():
            if term in source and term not in represented and not any(
                item["technology"] in term or term in item["technology"] for item in omitted
            ):
                omitted.append({
                    "technology": term,
                    "expected_type": expected_type,
                    "source_evidence": term,
                    "status": "extraction_review_required",
                })

        # Registries only cover known technologies and fixed phrases. Named
        # components such as "Settlement Worker" are the omissions that
        # previously went unreported, so review them by role vocabulary too.
        for candidate in find_named_roles(source):
            phrase = str(candidate.get("phrase") or "").strip()
            words = phrase.split()
            if (
                not phrase or len(words) > 5
                or words[0] in {"and", "or", "from", "for", "to", "with", "without"}
                or any(word in {"call", "calls", "reach", "reaches", "use", "uses", "may", "can"} for word in words)
            ):
                continue
            if already_represented(candidate, architecture.components or []):
                continue
            if any(
                item["technology"] in phrase or phrase in item["technology"]
                for item in omitted
            ):
                continue
            omitted.append({
                "technology": phrase,
                "expected_type": candidate["type"],
                "source_evidence": phrase,
                "status": "extraction_review_required",
            })
        return omitted

    @staticmethod
    def _duplicate_component_aliases(architecture) -> List[Dict[str, str]]:
        component_ids = {item.id for item in architecture.components or []}
        duplicates = []
        for aliases in technology_catalog.ALIAS_GROUPS:
            present = sorted(component_ids & aliases)
            if len(present) > 1:
                duplicates.append({"aliases": ", ".join(present), "status": "merge_required"})
        return duplicates
