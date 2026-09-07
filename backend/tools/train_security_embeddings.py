"""Fine-tune a local sentence embedding model on governed security triples."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine import model_policy  # noqa: E402
from app.engine.evaluation_governance import audit_splits  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-model", default="BAAI/bge-base-en-v1.5")
    parser.add_argument("--dataset", default="training/retrieval/security_retrieval_train.jsonl")
    parser.add_argument("--output", default="models/aegis-bge-security-candidate")
    parser.add_argument("--report", default="training/retrieval/fine_tune_report.json")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=12)
    parser.add_argument("--max-seq-length", type=int, default=384)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    if Path(args.output).exists():
        raise SystemExit('Choose a new candidate output directory; existing or active model weights are not overwritten.')

    import torch
    from torch.utils.data import DataLoader
    from sentence_transformers import InputExample, SentenceTransformer, losses
    from sentence_transformers.evaluation import TripletEvaluator

    records = [json.loads(line) for line in Path(args.dataset).read_text(encoding="utf-8").splitlines() if line]
    if args.limit:
        records = records[:args.limit]
    if len(records) < 100:
        raise SystemExit("Refusing to train on fewer than 100 governed triples")
    audit = audit_splits(records)
    if not audit['valid']:
        raise SystemExit('Cross-split query or family leakage detected; training refused.')
    training = [item for item in records if item.get("split") == "train"]
    validation = [item for item in records if item.get("split") == "validation"]
    if not validation:
        raise SystemExit("Dataset has no rule-held-out validation split")
    examples = [InputExample(texts=[item["query"], item["positive"], item["negative"]]) for item in training]
    model = SentenceTransformer(
        args.base_model,
        **model_policy.sentence_transformer_kwargs(args.base_model),
    )
    model.max_seq_length = args.max_seq_length
    loader = DataLoader(examples, shuffle=True, batch_size=args.batch_size)
    loss = losses.TripletLoss(model=model, triplet_margin=0.25)
    evaluator = TripletEvaluator(
        anchors=[item["query"] for item in validation],
        positives=[item["positive"] for item in validation],
        negatives=[item["negative"] for item in validation],
        name="security-holdout",
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.fit(
        train_objectives=[(loader, loss)], epochs=args.epochs,
        warmup_steps=max(1, math.ceil(len(loader) * args.epochs * 0.1)),
        evaluator=evaluator, evaluation_steps=max(20, len(loader) // 2),
        output_path=str(output), save_best_model=True, show_progress_bar=True,
        use_amp=torch.cuda.is_available(),
    )
    metrics = evaluator(model, output_path=str(output))
    report = {
        "schema_version": "security-embedding-training-1.0", "base_model": args.base_model,
        "output": str(output), "training_examples": len(training), "validation_examples": len(validation),
        "epochs": args.epochs, "batch_size": args.batch_size,
        "device": "cuda" if torch.cuda.is_available() else "cpu", "metrics": metrics,
        "split_audit": audit, "promotion_status": "requires_independent_holdout",
    }
    (output / "aegis_training_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
