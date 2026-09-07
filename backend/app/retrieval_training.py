"""Build governed security-retrieval triples from the canonical knowledge base."""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .engine.retrieval_quality import rule_provenance, security_domains_for_text
from .engine.evaluation_governance import audit_splits


DATASET_SCHEMA = "security-retrieval-training-1.0"


def build_security_retrieval_dataset(
    rules: List[Dict[str, Any]], feedback: Iterable[Dict[str, Any]] = (), seed: int = 231,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Create positive/hard-negative triples and a rule-held-out evaluation set."""
    rng = random.Random(seed)
    rule_by_id = {item["id"]: item for item in rules}
    equivalents = _equivalent_rule_ids(rules)
    train, evaluation = [], []
    for rule in rules:
        negatives = _hard_negatives(
            rule, rules, limit=5, excluded_ids=equivalents[rule["id"]],
        )
        if not negatives:
            continue
        document = retrieval_document(rule)
        queries = _queries_for_rule(rule)
        for template_index, query in enumerate(queries):
            negative = negatives[template_index % len(negatives)]
            train.append({
                "schema_version": DATASET_SCHEMA, "example_id": f"{rule['id']}:{template_index}",
                "query": query, "positive_id": rule["id"], "positive": document,
                "negative_id": negative["id"], "negative": retrieval_document(negative),
                "hard_negative_reason": _negative_reason(rule, negative),
                "stride_category": rule.get("stride_category"),
                "security_domains": security_domains_for_text(document),
                "source": "validated_canonical_knowledge_base", "provenance": rule_provenance(rule),
                "rule_family": min(equivalents[rule['id']]),
                "split": _split_for_rule(min(equivalents[rule["id"]])),
            })
        for query_index, query in enumerate(queries):
            evaluation.append({
                "id": f"rule_{_slug(rule['id'])}_{query_index}", "query": query,
                "source": "rule_generated", "review_status": "automated_contract_review",
                "evaluation_purpose": "catalog_lookup_regression",
                "component_type": (rule.get("components") or [None])[0],
                "stride_category": rule.get("stride_category"),
                "cloud_provider": (rule.get("cloud_platform") or [None])[0],
                "security_domains": security_domains_for_text(document), "top_k": 10,
                "expected_ids": [rule["id"]],
                "acceptable_ids": sorted(equivalents[rule["id"]] - {rule["id"]}),
                "forbidden_ids": [item["id"] for item in negatives[:3]],
            })

    approved_feedback = list(feedback)
    for item in approved_feedback:
        finding = item.get("finding") or {}
        rule_id = finding.get("rule_id") or finding.get("id")
        rule = rule_by_id.get(rule_id)
        query = item.get("query") or item.get("architecture_context")
        if not rule or not query:
            continue
        if item.get("decision") in {"accepted", "reclassified"}:
            negatives = _hard_negatives(
                rule, rules, limit=1, excluded_ids=equivalents[rule["id"]],
            )
            if negatives:
                train.append({
                    "schema_version": DATASET_SCHEMA, "example_id": f"feedback:{item.get('feedback_id')}",
                    "query": query, "positive_id": rule_id, "positive": retrieval_document(rule),
                    "negative_id": negatives[0]["id"], "negative": retrieval_document(negatives[0]),
                    "hard_negative_reason": "approved_reviewer_feedback",
                    "stride_category": finding.get("stride_category") or rule.get("stride_category"),
                    "security_domains": item.get("security_domains") or security_domains_for_text(query),
                    "source": "approved_reviewer_feedback", "feedback_id": item.get("feedback_id"),
                    "provenance": rule_provenance(rule),
                    "rule_family": min(equivalents[rule_id]),
                    "split": _split_for_rule(min(equivalents[rule_id])),
                })
    rng.shuffle(train)
    manifest = validate_security_dataset(train, evaluation, rules)
    manifest['split_audit'] = audit_splits(train)
    if not manifest['split_audit']['valid']:
        raise ValueError('Training data contains cross-split queries or equivalent rule families.')
    manifest['independent_accuracy_benchmark'] = False
    manifest["equivalent_rule_clusters"] = len({
        tuple(sorted(group)) for group in equivalents.values() if len(group) > 1
    })
    manifest["approved_feedback_examples"] = len([item for item in train if item["source"] == "approved_reviewer_feedback"])
    return train, evaluation, manifest


def validate_security_dataset(
    train: List[Dict[str, Any]], evaluation: List[Dict[str, Any]], rules: List[Dict[str, Any]],
) -> Dict[str, Any]:
    covered = {item["positive_id"] for item in train}
    expected = {item["id"] for item in rules}
    categories = Counter(item.get("stride_category") for item in train)
    domains = Counter(domain for item in train for domain in item.get("security_domains") or [])
    sources = Counter((item.get("provenance") or {}).get("source_module") for item in train)
    missing = sorted(expected - covered)
    if missing:
        raise ValueError(f"retrieval training data misses {len(missing)} knowledge rules")
    if any(not item.get("negative_id") or item["negative_id"] == item["positive_id"] for item in train):
        raise ValueError("every training example requires a distinct hard negative")
    return {
        "schema_version": DATASET_SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(),
        "training_examples": len(train), "evaluation_scenarios": len(evaluation),
        "knowledge_rules": len(rules), "covered_rules": len(covered), "missing_rule_ids": missing,
        "training_split_examples": sum(item.get("split") == "train" for item in train),
        "validation_split_examples": sum(item.get("split") == "validation" for item in train),
        "stride_coverage": dict(sorted(categories.items())), "domain_coverage": dict(sorted(domains.items())),
        "module_coverage": dict(sorted(sources.items())),
        "review_basis": "Rules passed CanonicalThreatRule validation; reviewer feedback is included only after admin approval.",
    }


def write_dataset(
    train: List[Dict[str, Any]], evaluation: List[Dict[str, Any]], manifest: Dict[str, Any], output_dir: str | Path,
) -> Dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    train_path = output / "security_retrieval_train.jsonl"
    eval_path = output / "security_retrieval_eval.json"
    manifest_path = output / "manifest.json"
    rendered = "\n".join(json.dumps(item, sort_keys=True, ensure_ascii=True) for item in train) + "\n"
    train_path.write_text(rendered, encoding="utf-8")
    eval_path.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    complete = {
        **manifest, "train_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "evaluation_sha256": hashlib.sha256(eval_path.read_bytes()).hexdigest(),
        "train_path": str(train_path), "evaluation_path": str(eval_path),
    }
    manifest_path.write_text(json.dumps(complete, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return complete


def retrieval_document(rule: Dict[str, Any]) -> str:
    applicability = rule.get("applicability") or {}
    taxonomies = rule.get("taxonomies") or {}
    return " ".join(filter(None, [
        f"Rule {rule.get('id')}", str(rule.get("title") or ""), str(rule.get("description") or ""),
        str(rule.get("attack_vector") or ""), f"STRIDE {rule.get('stride_category')}",
        f"Severity {rule.get('severity')}", f"Components {' '.join(rule.get('components') or [])}",
        f"Cloud {' '.join([*(rule.get('cloud_platform') or []), *(rule.get('cloud_services') or [])])}",
        f"Required signals {' '.join(applicability.get('required_signals') or [])}",
        f"Excluded signals {' '.join(applicability.get('excluded_signals') or [])}",
        f"Controls {' '.join(rule.get('negating_controls') or [])}",
        f"Taxonomy {' '.join(sum((list(value or []) for value in taxonomies.values()), []))}",
        f"Tags {' '.join(rule.get('tags') or [])}",
    ]))


def _queries_for_rule(rule: Dict[str, Any]) -> List[str]:
    components = ", ".join(rule.get("components") or ["system component"])
    signals = ", ".join((rule.get("applicability") or {}).get("required_signals") or rule.get("preconditions") or [])
    cloud = ", ".join([*(rule.get("cloud_platform") or []), *(rule.get("cloud_services") or [])])
    return [
        f"Threat model {components}: {rule.get('title')}",
        " ".join(filter(None, [f"Architecture uses {components}.", f"Context: {cloud}." if cloud else "", f"Observed weakness: {signals}." if signals else "", str(rule.get("attack_vector") or rule.get("description") or "")])),
        f"Which {rule.get('stride_category')} risk applies to {components} when {signals or rule.get('description')}?",
    ]


def _hard_negatives(
    rule: Dict[str, Any], rules: List[Dict[str, Any]], limit: int,
    excluded_ids: Iterable[str] = (),
) -> List[Dict[str, Any]]:
    source_tokens = _tokens(retrieval_document(rule))
    source_components = set(map(str.lower, rule.get("components") or []))
    excluded = set(excluded_ids) | {rule["id"]}
    ranked = []
    for candidate in rules:
        if candidate["id"] in excluded:
            continue
        candidate_components = set(map(str.lower, candidate.get("components") or []))
        same_scope = bool(source_components & candidate_components) or "any" in source_components | candidate_components
        same_stride = candidate.get("stride_category") == rule.get("stride_category")
        similarity = _jaccard(source_tokens, _tokens(retrieval_document(candidate)))
        score = similarity + (0.35 if same_scope else 0) + (0.25 if same_stride else 0)
        ranked.append((score, candidate))
    ranked.sort(key=lambda item: (-item[0], item[1]["id"]))
    return [item[1] for item in ranked[:limit]]


def _equivalent_rule_ids(rules: List[Dict[str, Any]]) -> Dict[str, set[str]]:
    """Cluster duplicate rules so they never become false hard negatives."""
    parents = {item["id"]: item["id"] for item in rules}

    def find(rule_id: str) -> str:
        while parents[rule_id] != rule_id:
            parents[rule_id] = parents[parents[rule_id]]
            rule_id = parents[rule_id]
        return rule_id

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for index, left in enumerate(rules):
        left_components = {item.lower() for item in left.get("components") or []}
        left_tokens = _tokens(retrieval_document(left))
        for right in rules[index + 1:]:
            if left.get("stride_category") != right.get("stride_category"):
                continue
            right_components = {item.lower() for item in right.get("components") or []}
            if left_components and right_components and not left_components & right_components:
                continue
            similarity = _jaccard(left_tokens, _tokens(retrieval_document(right)))
            title_similarity = _jaccard(
                _tokens(str(left.get("title") or "")),
                _tokens(str(right.get("title") or "")),
            )
            shared_cwe = set(left.get("cwe") or []) & set(right.get("cwe") or [])
            same_title = _normalized_title(left.get("title")) == _normalized_title(right.get("title"))
            if (
                same_title or similarity >= 0.82
                or (shared_cwe and similarity >= 0.45)
                or (title_similarity >= 0.5 and similarity >= 0.3)
            ):
                union(left["id"], right["id"])

    groups: Dict[str, set[str]] = {}
    for rule_id in parents:
        groups.setdefault(find(rule_id), set()).add(rule_id)
    return {rule_id: groups[find(rule_id)] for rule_id in parents}


def _negative_reason(positive: Dict[str, Any], negative: Dict[str, Any]) -> str:
    same_stride = positive.get("stride_category") == negative.get("stride_category")
    same_component = bool(set(positive.get("components") or []) & set(negative.get("components") or []))
    return "same_stride_and_component_but_different_control" if same_stride and same_component else "semantically_close_non_applicable_rule"


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9:_-]{3,}", value.lower()))


def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left or right else 0.0


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _normalized_title(value: Any) -> str:
    without_alias = re.sub(r"\s*\([^)]{2,12}\)\s*$", "", str(value or ""))
    return _slug(without_alias)


def _split_for_rule(rule_id: str) -> str:
    return "validation" if int(hashlib.sha256(rule_id.encode()).hexdigest()[:8], 16) % 10 == 0 else "train"
