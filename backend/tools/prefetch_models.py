"""Fetch the local models an analysis needs, then record their revisions.

Analysis is offline by design, so this is the one place allowed to use the
network. Run it once per environment, ideally while building an image:

    AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1 python tools/prefetch_models.py --write-lock

Without --write-lock it only reports what is present, which is useful as a
pre-demo check on a machine you do not want to change.
"""

import argparse
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.engine import model_policy  # noqa: E402
from app.engine.nlp_processor import NER_MODEL  # noqa: E402
from app.engine.retrieval_config import configured_embedding_model, configured_reranker_model  # noqa: E402

# Roles the product describes. Optional roles stay unconfigured on most
# installs; the report says so rather than implying they ran.
ROLES = [
    {
        "role": "embeddings",
        "model": configured_embedding_model(),
        "kind": "sentence-transformer",
        "required": True,
    },
    {
        "role": "reranker",
        "model": configured_reranker_model() or "",
        "kind": "cross-encoder",
        "required": False,
    },
    {
        "role": "stride_classifier_embeddings",
        "model": os.getenv("AEGIS_THREAT_CLASSIFIER_EMBEDDING_MODEL", "all-MiniLM-L6-v2").strip(),
        "kind": "sentence-transformer",
        "required": True,
    },
    {
        "role": "named_entity_recognition",
        "model": NER_MODEL if os.getenv("AEGIS_THREAT_ENABLE_TRANSFORMERS", "").lower() in {"1", "true", "yes"} else "",
        "kind": "transformers",
        "required": False,
    },
    {
        "role": "local_slm",
        "model": os.getenv("AEGIS_THREAT_LOCAL_SLM_MODEL", "").strip(),
        "kind": "transformers",
        "required": False,
    },
]


def resolve(entry: dict) -> dict:
    """Load one model and report the outcome, including its resolved revision."""
    model_id = entry["model"]
    if not model_id:
        return {**entry, "status": "not_configured", "revision": None}

    try:
        if entry["kind"] == "sentence-transformer":
            from sentence_transformers import SentenceTransformer

            SentenceTransformer(model_id, **model_policy.sentence_transformer_kwargs(model_id))
            revision = _revision_of(model_id)
        elif entry["kind"] == "cross-encoder":
            from sentence_transformers import CrossEncoder

            CrossEncoder(model_id, **model_policy.sentence_transformer_kwargs(model_id))
            revision = _revision_of(model_id)
        else:
            from transformers import AutoConfig

            config = AutoConfig.from_pretrained(model_id, **model_policy.transformers_kwargs(model_id))
            revision = getattr(config, "_commit_hash", None) or _revision_of(model_id)
    except Exception as exc:
        return {**entry, "status": "unavailable", "revision": None, "error": str(exc).splitlines()[0][:200]}

    # A pin is what the load actually enforced, so report it in preference to
    # whatever else the cache happens to hold.
    return {**entry, "status": "available", "revision": model_policy.locked_revision(model_id) or revision}


def _revision_of(model_id: str) -> str | None:
    """Read the commit hash the local cache resolved for this model."""
    try:
        from huggingface_hub import constants, scan_cache_dir
    except ImportError:
        return None
    cache = model_policy.cache_dir() or constants.HF_HUB_CACHE
    try:
        report = scan_cache_dir(cache)
    except Exception:
        return None
    wanted = model_id if "/" in model_id else f"sentence-transformers/{model_id}"
    for repo in report.repos:
        if repo.repo_id != wanted:
            continue
        newest = max(repo.revisions, key=lambda revision: revision.last_modified, default=None)
        if newest:
            return newest.commit_hash
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-lock", action="store_true", help="record resolved revisions in model_locks.json")
    args = parser.parse_args()

    if args.write_lock and not model_policy.downloads_allowed():
        print("Refusing to write a lock file without AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1,")
        print("because an offline resolve can only confirm what is already on disk.")
        return 2

    results = [resolve(entry) for entry in ROLES]

    print(f"Offline enforced: {not model_policy.downloads_allowed()}")
    print(f"Cache directory:  {model_policy.cache_dir() or '(library default)'}\n")
    for item in results:
        revision = (item["revision"] or "unpinned")[:12]
        print(f"{item['role']:<26} {item['status']:<15} {revision:<14} {item['model'] or '-'}")
        if item.get("error"):
            print(f"{'':<26} {item['error']}")

    missing_required = [item for item in results if item["required"] and item["status"] != "available"]

    if args.write_lock:
        try:
            existing = json.loads(model_policy.LOCK_FILE.read_text(encoding="utf-8")).get("models", {})
        except (OSError, ValueError):
            existing = {}
        models = dict(existing)
        models.update({
            item["model"]: {
                "role": item["role"], "revision": item["revision"],
                "source": item["model"], "required": item["required"],
            }
            for item in results
            if item["status"] == "available" and item["revision"]
        })
        payload = {
            "comment": (
                "Revisions this deployment is pinned to. Loads are offline and refuse a "
                "different revision. Regenerate with: AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1 "
                "python tools/prefetch_models.py --write-lock"
            ),
            "models": models,
        }
        model_policy.LOCK_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {len(models)} pinned revision(s) to {model_policy.LOCK_FILE}")

    if missing_required:
        roles = ", ".join(item["role"] for item in missing_required)
        print(f"\nRequired model(s) unavailable: {roles}")
        print("Analysis will still run on BM25 plus local hashing, with reduced semantic quality.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
