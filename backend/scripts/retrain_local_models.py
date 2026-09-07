"""
Rebuild local knowledge-driven intelligence for AI Threat Modeler.

This refreshes:
- knowledge base loading
- semantic vector index
- local STRIDE classifier
- analyzer caches
"""

from pathlib import Path
import json
import sys


def main():
    backend_dir = Path(__file__).resolve().parent.parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    from app.engine.analyzer import ThreatAnalyzer

    analyzer = ThreatAnalyzer()
    stats = analyzer.reload_local_intelligence()
    # The request path initializes models lazily; this maintenance command must
    # actually refresh derived artifacts before reporting completion.
    local = analyzer.local_intelligence
    local._ensure_initialized()
    stats["retrieval"] = local.matcher.diagnostics() if local.matcher else {"status": "unavailable"}
    stats["stride_classifier_ready"] = bool(local.classifier and local.classifier.is_trained)
    stats["initialization_errors"] = list(local.initialization_errors)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
