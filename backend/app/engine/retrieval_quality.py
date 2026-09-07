"""Quality controls around security retrieval, feedback, and observability."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


RETRIEVAL_QUALITY_VERSION = "retrieval-quality-1.0"
DATA_DIR = Path(__file__).resolve().parents[1] / "data"
FEEDBACK_FILE = DATA_DIR / "retrieval_feedback.jsonl"
CALIBRATION_FILE = DATA_DIR / "retrieval_calibration.json"
TRAINABLE_DECISIONS = {"accepted", "false_positive", "reclassified"}


@dataclass(frozen=True)
class RetrievalRequest:
    request_id: str
    query: str
    component_type: Optional[str]
    stride_category: Optional[str]
    cloud_provider: Optional[str]
    security_domains: List[str]
    scope: Dict[str, Any]
    top_k: int = 5


def architecture_retrieval_requests(architecture, stride_categories: Iterable[str]) -> List[RetrievalRequest]:
    """Create evidence-rich component and flow queries with graph context."""
    components = {item.id: item for item in architecture.components or []}
    assets_by_component: Dict[str, List[str]] = defaultdict(list)
    for asset in architecture.assets or []:
        if asset.related_component_id:
            assets_by_component[asset.related_component_id].append(
                f"{asset.name}:{asset.sensitivity}:{asset.asset_type}"
            )
    boundaries_by_component: Dict[str, List[str]] = defaultdict(list)
    for boundary in architecture.trust_boundaries or []:
        for component_id in boundary.components or []:
            boundaries_by_component[component_id].append(
                f"{boundary.name}:{boundary.boundary_type}"
            )
    incident: Dict[str, List[str]] = defaultdict(list)
    for flow in architecture.flows or []:
        source = components.get(flow.source_id)
        target = components.get(flow.target_id)
        description = (
            f"{source.name if source else flow.source_id} -> "
            f"{target.name if target else flow.target_id} over {flow.protocol} "
            f"carrying {flow.data_type}; assumed={bool(flow.assumed)}"
        )
        incident[flow.source_id].append(description)
        incident[flow.target_id].append(description)
    attack_routes = _attack_routes(architecture, components)

    requests: List[RetrievalRequest] = []
    for component in architecture.components or []:
        properties = component.properties or {}
        property_text = "; ".join(
            f"{key}={properties[key]}" for key in sorted(properties)
            if properties[key] not in (None, "", [], {})
        )
        graph_context = " | ".join(incident.get(component.id, [])[:8])
        base = " ".join(filter(None, [
            f"Component {component.name}", f"type {component.type}",
            f"trust {component.trust_level}", component.description,
            f"properties {property_text}" if property_text else "",
            f"assets {'; '.join(assets_by_component.get(component.id, []))}" if assets_by_component.get(component.id) else "",
            f"boundaries {'; '.join(boundaries_by_component.get(component.id, []))}" if boundaries_by_component.get(component.id) else "",
            f"graph paths {graph_context}" if graph_context else "",
            f"reachable attack routes {'; '.join(attack_routes.get(component.id, []))}" if attack_routes.get(component.id) else "",
        ]))
        cloud = str(properties.get("cloud_provider") or _cloud_from_text(base) or "") or None
        domains = security_domains_for_text(base)
        requests.append(RetrievalRequest(
            request_id=component.id,
            query=f"{base} Assess applicable STRIDE risks: {', '.join(stride_categories)}.",
            component_type=component.type, stride_category=None,
            cloud_provider=cloud, security_domains=domains,
            scope={"kind": "component", "component_id": component.id}, top_k=30,
        ))

    for flow in architecture.flows or []:
        source = components.get(flow.source_id)
        target = components.get(flow.target_id)
        properties = flow.properties or {}
        base = " ".join(filter(None, [
            f"Data flow from {source.name if source else flow.source_id}",
            f"to {target.name if target else flow.target_id}",
            f"protocol {flow.protocol}", f"data {flow.data_type}",
            f"source type {source.type}" if source else "",
            f"target type {target.type}" if target else "",
            f"boundary {properties.get('trust_boundary')}" if properties.get("trust_boundary") else "",
            f"assumed {bool(flow.assumed)}",
        ]))
        requests.append(RetrievalRequest(
            request_id=f"flow:{flow.source_id}->{flow.target_id}",
            query=f"{base} Assess applicable STRIDE risks: {', '.join(stride_categories)}.",
            component_type="Data Flow", stride_category=None,
            cloud_provider=_cloud_from_text(base), security_domains=security_domains_for_text(base),
            scope={"kind": "flow", "source_id": flow.source_id, "target_id": flow.target_id},
            top_k=18,
        ))
    return requests


def hierarchical_chunks(text: str, max_chars: int = 1800, overlap_sentences: int = 2) -> List[Dict[str, Any]]:
    """Chunk long design documents without cutting sentences or losing headings."""
    lines = [line.strip() for line in str(text or "").splitlines()]
    sections: List[tuple[str, List[str]]] = []
    heading = "Architecture"
    body: List[str] = []
    for line in lines:
        if not line:
            continue
        if re.match(r"^(#{1,6}\s+|[A-Z][A-Z0-9 /_-]{4,}:?$)", line):
            if body:
                sections.append((heading, body))
            heading, body = line.lstrip("# ").rstrip(":"), []
        else:
            body.append(line)
    if body or not sections:
        sections.append((heading, body or [str(text or "")]))

    chunks: List[Dict[str, Any]] = []
    for section_index, (title, paragraphs) in enumerate(sections):
        sentences = [
            item.strip() for item in re.split(r"(?<=[.!?])\s+|\n+", " ".join(paragraphs))
            if item.strip()
        ]
        current: List[str] = []
        for sentence in sentences:
            rendered = f"Section: {title}\n" + " ".join([*current, sentence])
            if current and len(rendered) > max_chars:
                chunks.append(_chunk_record(title, section_index, len(chunks), current))
                current = current[-overlap_sentences:] if overlap_sentences else []
            current.append(sentence)
        if current:
            chunks.append(_chunk_record(title, section_index, len(chunks), current))
    return chunks or [_chunk_record("Architecture", 0, 0, [""])]


def security_domains_for_text(text: str) -> List[str]:
    lowered = text.lower()
    mappings = {
        "aws": ("aws", "s3", "lambda", "kms", "iam", "ec2", "eks", "dynamodb"),
        "azure": ("azure", "entra", "key vault", "aks", "blob"),
        "gcp": ("gcp", "google cloud", "gke", "bigquery", "vertex"),
        "web_api": (
            "api", "api gateway", "web", "webclient", "web application",
            "graphql", "browser", "frontend", "rest",
        ),
        "identity": ("identity", "oauth", "oidc", "jwt", "session", "keycloak", "authentication"),
        "data": ("database", "storage", "postgres", "mongo", "redis", "warehouse"),
        "payments": ("payment", "stripe", "cardholder", "webhook", "pci"),
        "ai_llm": (
            "llm", "large language model", "foundation model", "generative ai",
            "rag", "vector store", "prompt injection", "model inference",
        ),
        "agent_mcp": ("agent", "mcp", "tool call", "tool server"),
        "container": ("kubernetes", "k8s", "container", "pod", "docker", "eks", "aks", "gke"),
        "serverless": ("lambda", "serverless", "cloud function", "eventbridge"),
        "supply_chain": ("ci/cd", "pipeline", "dependency", "artifact", "registry", "github actions"),
        "infrastructure": ("network", "vpc", "subnet", "dns", "load balancer", "compute", "ec2"),
    }
    return sorted(
        domain for domain, terms in mappings.items()
        if any(_contains_phrase(lowered, term) for term in terms)
    ) or ["general"]


def rule_provenance(rule: Dict[str, Any]) -> Dict[str, Any]:
    canonical = {
        key: rule.get(key) for key in (
            "id", "title", "description", "stride_category", "severity",
            "components", "cloud_platform", "tags", "source_module", "references",
            "version", "taxonomy_mapping_quality", "detection", "applicability",
            "controls", "negating_controls", "mitigation", "verification",
            "cwe", "owasp_top_10", "mitre_attack", "mitre_atlas", "framework_mappings",
        )
    }
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    return {
        "rule_id": rule.get("id"),
        "rule_version": rule.get("version") or digest[:16],
        "content_digest": digest[:16],
        "source_module": rule.get("source_module"),
        "source": rule.get("source") or rule.get("source_module"),
        "references": rule.get("references") or [],
        "taxonomy_mapping_quality": rule.get("taxonomy_mapping_quality") or {},
        "framework_mappings": rule.get("framework_mappings") or [],
        "knowledge_schema": "canonical-kb-3.0",
    }


def audit_knowledge_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Surface near duplicates and logically conflicting applicability signals."""
    duplicates, contradictions = [], []
    tokenized = [_tokens(f"{item.get('title', '')} {item.get('description', '')}") for item in rules]
    for left_index, left in enumerate(rules):
        left_components = set(map(str.lower, left.get("components") or []))
        for right_index in range(left_index + 1, len(rules)):
            right = rules[right_index]
            if (left.get("stride_category") or left.get("category")) != (right.get("stride_category") or right.get("category")):
                continue
            right_components = set(map(str.lower, right.get("components") or []))
            if left_components and right_components and not left_components & right_components and "any" not in left_components | right_components:
                continue
            similarity = _jaccard(tokenized[left_index], tokenized[right_index])
            title_similarity = _jaccard(
                _tokens(str(left.get("title") or "")),
                _tokens(str(right.get("title") or "")),
            )
            shared_cwe = set(left.get("cwe") or []) & set(right.get("cwe") or [])
            if (
                similarity >= 0.82 or (shared_cwe and similarity >= 0.45)
                or (title_similarity >= 0.5 and similarity >= 0.3)
            ):
                duplicates.append({"rule_ids": [left.get("id"), right.get("id")], "lexical_similarity": round(similarity, 3)})
            left_required = set(map(str.lower, (left.get("applicability") or {}).get("required_signals") or []))
            right_excluded = set(map(str.lower, (right.get("applicability") or {}).get("excluded_signals") or []))
            right_required = set(map(str.lower, (right.get("applicability") or {}).get("required_signals") or []))
            left_excluded = set(map(str.lower, (left.get("applicability") or {}).get("excluded_signals") or []))
            conflict = (left_required & right_excluded) | (right_required & left_excluded)
            if conflict:
                contradictions.append({"rule_ids": [left.get("id"), right.get("id")], "signals": sorted(conflict)})
    return {
        "version": RETRIEVAL_QUALITY_VERSION, "rules_audited": len(rules),
        "near_duplicate_count": len(duplicates), "near_duplicates": duplicates[:100],
        "contradiction_count": len(contradictions), "contradictions": contradictions[:100],
    }


class RetrievalFeedbackStore:
    """Append-only feedback ledger; raw UI feedback is never auto-approved."""

    def __init__(self, path: Path = FEEDBACK_FILE):
        self.path = path
        self._lock = threading.Lock()

    def record(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        decision = str(payload.get("decision") or "").lower()
        if decision not in {"accepted", "false_positive", "mitigated", "reclassified"}:
            raise ValueError("decision must be accepted, false_positive, mitigated, or reclassified")
        event = {
            "schema_version": "retrieval-feedback-1.0", "event": "decision",
            "feedback_id": str(uuid.uuid4()), "recorded_at": _now(),
            "approved_for_training": False, **payload, "decision": decision,
        }
        self._append(event)
        return event

    def approve(self, feedback_id: str, approved_by: str) -> Dict[str, Any]:
        decisions = {item.get("feedback_id"): item for item in self.events() if item.get("event") == "decision"}
        decision = decisions.get(feedback_id)
        if not decision:
            raise KeyError(feedback_id)
        if decision.get("decision") not in TRAINABLE_DECISIONS:
            raise ValueError("this review state is not eligible for training")
        event = {
            "schema_version": "retrieval-feedback-1.0", "event": "approval",
            "feedback_id": feedback_id, "approved_by": approved_by,
            "approved_at": _now(),
        }
        self._append(event)
        return event

    def approved_training_records(self) -> List[Dict[str, Any]]:
        events = self.events()
        approvals = {item.get("feedback_id") for item in events if item.get("event") == "approval"}
        return [
            item for item in events
            if item.get("event") == "decision" and item.get("feedback_id") in approvals
        ]

    def summary(self) -> Dict[str, Any]:
        decisions = Counter(
            item.get("decision") for item in self.events() if item.get("event") == "decision"
        )
        reviewed = decisions.get("accepted", 0) + decisions.get("false_positive", 0) + decisions.get("reclassified", 0)
        return {
            "decisions": dict(decisions), "reviewed_for_accuracy": reviewed,
            "observed_false_positive_rate": round(decisions.get("false_positive", 0) / max(1, reviewed), 4),
            "approved_training_records": len(self.approved_training_records()),
        }

    def events(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        output = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                output.append(json.loads(line))
            except ValueError:
                continue
        return output

    def _append(self, event: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n")


class RetrievalCalibrator:
    def __init__(self, path: Path = CALIBRATION_FILE):
        self.path = path
        self.data = self._load()

    def threshold(self, domains: Iterable[str], stride_category: Optional[str]) -> float:
        candidates = []
        for domain in domains:
            candidates.append((self.data.get("thresholds") or {}).get(f"domain:{domain}"))
        if stride_category:
            candidates.append((self.data.get("thresholds") or {}).get(f"stride:{stride_category}"))
        values = [float(value) for value in candidates if value is not None]
        return max(values) if values else float(self.data.get("default_threshold", 0.3))

    def fit(self, records: List[Dict[str, Any]], minimum_examples: int = 20) -> Dict[str, Any]:
        groups: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: {"positive": [], "negative": []})
        for item in records:
            score = float(item.get("retrieval_score") or 0)
            label = "negative" if item.get("decision") == "false_positive" else "positive"
            for domain in item.get("security_domains") or ["general"]:
                groups[f"domain:{domain}"][label].append(score)
            if item.get("stride_category"):
                groups[f"stride:{item['stride_category']}"][label].append(score)
        thresholds = {}
        diagnostics = {}
        for key, values in groups.items():
            if len(values["positive"]) + len(values["negative"]) < minimum_examples:
                continue
            if not values["positive"] or not values["negative"]:
                continue
            threshold, metrics = _optimal_threshold(values["positive"], values["negative"])
            thresholds[key] = threshold
            diagnostics[key] = metrics
        candidate = {
            "version": "retrieval-calibration-2.0", "updated_at": _now(),
            "default_threshold": 0.3, "thresholds": thresholds,
            "diagnostics": diagnostics,
            "approved_examples": len(records), "minimum_examples": minimum_examples,
            "status": "candidate_only", "promotion_required": "Independent reviewed holdout evaluation; training fit is not validation.",
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.with_suffix('.candidate.json').write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return candidate

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"version": "retrieval-calibration-1.0", "default_threshold": 0.3, "thresholds": {}}


class RetrievalMonitor:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = Counter()
        self._latency_ms: List[float] = []

    def record(self, *, latency_ms: float, results: int, fallback: bool, cache: str) -> None:
        with self._lock:
            self._counters["queries"] += 1
            self._counters["results"] += results
            self._counters["fallback_queries"] += int(fallback)
            self._counters[f"cache:{cache}"] += 1
            self._latency_ms.append(float(latency_ms))
            if len(self._latency_ms) > 5000:
                self._latency_ms = self._latency_ms[-5000:]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            latencies = sorted(self._latency_ms)
            counters = dict(self._counters)
        return {
            "version": "retrieval-monitor-1.0", **counters,
            "fallback_rate": round(counters.get("fallback_queries", 0) / max(1, counters.get("queries", 0)), 4),
            "latency_ms": {
                "p50": round(_percentile(latencies, 0.5), 2),
                "p95": round(_percentile(latencies, 0.95), 2),
                "max": round(max(latencies), 2) if latencies else 0.0,
            },
        }


retrieval_monitor = RetrievalMonitor()


def _optimal_threshold(positive: List[float], negative: List[float]) -> tuple[float, Dict[str, Any]]:
    """Select a reviewed threshold by F1, then precision and false-positive rate."""
    candidates = sorted(set([0.2, 0.85, *positive, *negative]))
    best = None
    for threshold in candidates:
        true_positive = sum(score >= threshold for score in positive)
        false_negative = len(positive) - true_positive
        false_positive = sum(score >= threshold for score in negative)
        true_negative = len(negative) - false_positive
        precision = true_positive / max(1, true_positive + false_positive)
        recall = true_positive / max(1, true_positive + false_negative)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        false_positive_rate = false_positive / max(1, false_positive + true_negative)
        candidate = (
            round(f1, 6), round(precision, 6), -round(false_positive_rate, 6),
            -abs(threshold - 0.3), threshold,
            {
                "precision": round(precision, 4), "recall": round(recall, 4),
                "f1": round(f1, 4), "false_positive_rate": round(false_positive_rate, 4),
                "positive_examples": len(positive), "negative_examples": len(negative),
            },
        )
        if best is None or candidate[:5] > best[:5]:
            best = candidate
    selected = min(0.85, max(0.2, float(best[4])))
    return round(selected, 4), best[5]


def timed_retrieval():
    return time.perf_counter()


def _chunk_record(title: str, section_index: int, chunk_index: int, sentences: List[str]) -> Dict[str, Any]:
    content = f"Section: {title}\n" + " ".join(sentences)
    return {
        "id": f"section-{section_index}-chunk-{chunk_index}", "section": title,
        "section_index": section_index, "chunk_index": chunk_index,
        "text": content, "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def _tokens(value: str) -> set[str]:
    return {item for item in re.findall(r"[a-z0-9:_-]+", value.lower()) if len(item) > 2}


def _contains_phrase(text: str, phrase: str) -> bool:
    return bool(re.search(
        r"(?<![a-z0-9])" + re.escape(phrase.lower()) + r"(?![a-z0-9])",
        text,
    ))


def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left or right else 0.0


def _cloud_from_text(text: str) -> Optional[str]:
    lowered = text.lower()
    if any(item in lowered for item in ("aws", "amazon", "s3", "lambda", "ec2", "eks", "kms")):
        return "aws"
    if any(item in lowered for item in ("azure", "entra", "aks", "key vault")):
        return "azure"
    if any(item in lowered for item in ("gcp", "google cloud", "gke", "bigquery")):
        return "gcp"
    return None


def _attack_routes(architecture, components: Dict[str, Any]) -> Dict[str, List[str]]:
    """Enumerate short stated routes from public entry points to internal nodes."""
    adjacency: Dict[str, List[str]] = defaultdict(list)
    for flow in architecture.flows or []:
        if not flow.assumed:
            adjacency[flow.source_id].append(flow.target_id)
    origins = [
        item.id for item in components.values()
        if str(item.trust_level).lower() in {"public", "external", "internet", "untrusted"}
        or (item.properties or {}).get("public_access") is True
    ]
    routes: Dict[str, List[str]] = defaultdict(list)
    for origin in origins:
        stack = [(origin, [origin])]
        while stack:
            node, path = stack.pop()
            if len(path) > 1:
                rendered = " -> ".join(components[item].name if item in components else item for item in path)
                if rendered not in routes[node]:
                    routes[node].append(rendered)
            if len(path) >= 5:
                continue
            for target in adjacency.get(node, []):
                if target not in path:
                    stack.append((target, [*path, target]))
    return routes


def _percentile(values: List[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(quantile * len(ordered)) - 1))
    return float(ordered[index])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
