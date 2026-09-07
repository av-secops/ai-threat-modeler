"""Print versioned KB coverage and diagnostics; no model downloads or inference."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.knowledge_base.frameworks import coverage_report
from app.knowledge_base.loader import ThreatKnowledgeBase


def main():
    kb = ThreatKnowledgeBase()
    report = coverage_report(kb.threats)
    report["validation_issues"] = kb.validation_issues
    report["scope"] = "Architecture KB mappings; IaC checks have their own catalog. Unmapped IDs are not proof of a product vulnerability."
    print(json.dumps(report, indent=2))
    if any(rule.get("framework_mapping_issues") for rule in kb.threats):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
