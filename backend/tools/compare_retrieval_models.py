"""Compare candidate embedding models and block unsafe default promotion."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine.embedding_service import reset_embedding_service  # noqa: E402
from app.engine.semantic_matcher import SemanticThreatMatcher  # noqa: E402
from app.evaluation import evaluate_retrieval_corpus, load_retrieval_corpus  # noqa: E402
from app.knowledge_base.loader import ThreatKnowledgeBase  # noqa: E402
from app.engine.evaluation_governance import holdout_gate  # noqa: E402


MODELS = {
    "bge-base": "BAAI/bge-base-en-v1.5",
    "bge-large": "BAAI/bge-large-en-v1.5",
    "mpnet": "all-mpnet-base-v2",
    "nomic": "nomic-ai/nomic-embed-text-v1.5",
}
LOCAL_SECURITY_MODEL = ROOT / "models" / "aegis-bge-security-v1"
if LOCAL_SECURITY_MODEL.exists():
    MODELS["aegis-security"] = str(LOCAL_SECURITY_MODEL.resolve())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="training/retrieval/security_retrieval_eval.json")
    parser.add_argument("--models", nargs="*", choices=sorted(MODELS), default=list(MODELS))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--training-dataset", help="JSONL training records, required to audit promotion eligibility")
    parser.add_argument("--allow-downloads", action="store_true")
    parser.add_argument("--output", default="training/retrieval/model_comparison.json")
    args = parser.parse_args()
    os.environ["AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD"] = "1" if args.allow_downloads else "0"
    os.environ["AEGIS_THREAT_RERANKER_MODEL"] = "disabled"
    corpus = load_retrieval_corpus(args.corpus)
    if args.limit:
        corpus = corpus[:args.limit]
    knowledge = ThreatKnowledgeBase()
    training = [json.loads(line) for line in Path(args.training_dataset).read_text(encoding="utf-8").splitlines() if line.strip()] if args.training_dataset else []
    independence = holdout_gate(corpus, training)
    if not args.training_dataset:
        independence["eligible"] = False
        independence["reasons"].append("Supply --training-dataset to audit train/holdout overlap before promotion.")
    reports = []
    for name in args.models:
        os.environ["AEGIS_THREAT_EMBEDDING_MODEL"] = MODELS[name]
        reset_embedding_service()
        started = time.perf_counter()
        matcher = SemanticThreatMatcher()
        diagnostics = matcher.diagnostics()
        if diagnostics["embedding_backend"] != "sentence_transformer":
            reports.append({
                "name": name,
                "model": MODELS[name],
                "diagnostics": diagnostics,
                "metrics": None,
                "seconds": round(time.perf_counter() - started, 2),
                "promotion_eligible": False,
                "availability": "unavailable",
                "failed_scenarios": [],
            })
            continue
        report = evaluate_retrieval_corpus(corpus, matcher=matcher, knowledge_base=knowledge)
        diagnostics = matcher.diagnostics()
        metrics = report["metrics"]
        eligible = bool(
            independence['eligible']
            and
            diagnostics["embedding_backend"] == "sentence_transformer"
            and metrics["recall_at_k"] >= 0.98
            and metrics["mean_reciprocal_rank"] >= 0.9
            and metrics["hard_negative_outrank_rate"] == 0
        )
        reports.append({
            "name": name, "model": MODELS[name], "diagnostics": diagnostics,
            "metrics": metrics, "seconds": round(time.perf_counter() - started, 2),
            "promotion_eligible": eligible,
            "availability": "available",
            "failed_scenarios": [
                item["id"] for item in report["scenarios"]
                if item["missing_expected_ids"] or item["outranking_forbidden_ids"]
            ],
        })
    eligible = [item for item in reports if item["promotion_eligible"]]
    winner = max(
        eligible,
        key=lambda item: (
            item["metrics"]["mean_ndcg_at_k"], item["metrics"]["mean_reciprocal_rank"], -item["seconds"],
        ),
        default=None,
    )
    output = {
        "schema_version": "retrieval-model-comparison-1.0",
        "corpus": args.corpus, "scenarios": len(corpus), "reports": reports,
        "recommended_model": winner["model"] if winner else None,
        "holdout_governance": independence,
        "promotion_gate": {
            "recall_at_k": ">= 0.98", "mean_reciprocal_rank": ">= 0.90",
            "hard_negative_outrank_rate": "== 0", "real_embedding_required": True,
        },
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
