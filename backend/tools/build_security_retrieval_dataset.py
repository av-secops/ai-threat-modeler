"""Generate versioned retrieval training triples and exhaustive KB evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.knowledge_base.loader import ThreatKnowledgeBase  # noqa: E402
from app.retrieval_training import build_security_retrieval_dataset, write_dataset  # noqa: E402
from app.engine.retrieval_quality import RetrievalFeedbackStore  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "training" / "retrieval"))
    args = parser.parse_args()
    knowledge = ThreatKnowledgeBase()
    feedback = RetrievalFeedbackStore().approved_training_records()
    train, evaluation, manifest = build_security_retrieval_dataset(
        knowledge.get_all_threats(), feedback=feedback,
    )
    print(json.dumps(write_dataset(train, evaluation, manifest, args.output), indent=2))


if __name__ == "__main__":
    main()
