"""Aegis model-as-code commands; offline except explicit discover-aws.

Exit codes: 0 success, 2 invalid input, 3 policy/coverage failure, 4 runtime or
missing dependency. No server, model downloads, shell commands, or AI required.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.model_interchange import (ModelError, digest, export_model, import_model,
                                          load_document, validate_model)
from app.services.cloud_drift import compare_drift, discover_aws, snapshot_to_model

EXIT_INVALID, EXIT_POLICY, EXIT_RUNTIME = 2, 3, 4
SEVERITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def gate_model(document, *, fail_severity="High", tier="all", allow_review=False):
    model = validate_model(document)
    if fail_severity not in SEVERITY or tier not in {"all", "Confirmed", "Potential"}:
        raise ModelError("Unknown gate severity or tier")
    status = model.get("engine_status") or {}
    quality = status.get("quality_gate") or {}
    knowledge = status.get("knowledge_base") or {}
    if not isinstance(knowledge, dict):
        raise ModelError("engine_status.knowledge_base must be an object")
    failures = []
    if not isinstance(quality, dict) or quality.get("status") not in {"ready", "review", "blocked"}:
        failures.append({"check": "missing_quality_gate", "message": "A model alone is not an analyzed report."})
        quality = {}
    if quality.get("status") == "blocked" or quality.get("integrity_violations") or quality.get("model_integrity") == "violated" or quality.get("architecture_valid") is False:
        failures.append({"check": "analysis_integrity", "message": "The analysis quality gate is blocked."})
    if (quality.get("status") == "review" or quality.get("completeness_warnings")) and not allow_review:
        failures.append({"check": "review_required", "message": "Unresolved review requirements block this CI policy."})
    if not knowledge.get("content_digest"):
        failures.append({"check": "missing_knowledge_provenance", "message": "Knowledge content digest is required."})
    for threat in model["threats"]:
        severity = threat.get("severity")
        evidence = threat.get("evidence_details") or threat.get("evidence")
        if threat.get("tier") == "Confirmed" and not evidence:
            failures.append({"check": "confirmed_without_evidence", "finding_id": threat["id"]})
        if severity not in SEVERITY:
            failures.append({"check": "unknown_severity", "finding_id": threat["id"]})
            continue
        if tier != "all" and threat.get("tier", "Potential") != tier:
            continue
        # Imported status and a generic 'closed' label do not verify a fix.
        if SEVERITY[severity] >= SEVERITY[fail_severity]:
            failures.append({"check": "severity_threshold", "finding_id": threat["id"], "severity": severity})
    return {"schema_version": "aegis-ci-gate/1", "passed": not failures, "model_id": model["model_id"],
        "model_sha256": digest(model), "failures": failures,
        "policy": {"fail_severity": fail_severity, "tier": tier, "allow_review": allow_review},
        "notice": "This evaluates a supplied report, not deployed security. Protect report provenance and CI artifacts from tampering."}


def _write_output(value, path, force, inputs):
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n"
    if not path:
        sys.stdout.write(text)
        return
    target = Path(path).resolve()
    if target in {Path(p).resolve() for p in inputs if p}:
        raise ModelError("Output must not overwrite an input file")
    if target.exists() and not force:
        raise ModelError("Output exists; choose a new path or explicitly use --force")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=target.parent,
                                         prefix=".aegis-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, target)
        else:
            # Same-directory link gives atomic publication without a check/write race.
            os.link(temporary, target)
        print(json.dumps({"output": str(target), "sha256": digest(value)}, sort_keys=True))
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("validate", "import", "export"):
        command = sub.add_parser(name)
        command.add_argument("input")
        command.add_argument("--format", choices=("aegis", "otm", "threat-dragon"), default="aegis")
        if name != "export":
            command.add_argument("--diagram-id", type=int)
        command.add_argument("--fail-on-loss", action="store_true")
    compare = sub.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--mappings", help="JSON object mapping old component IDs to new IDs")
    compare.add_argument("--fail-on-change", action="store_true")
    gate = sub.add_parser("gate")
    gate.add_argument("input")
    gate.add_argument("--fail-severity", choices=tuple(SEVERITY), default="High")
    gate.add_argument("--tier", choices=("all", "Confirmed", "Potential"), default="all")
    gate.add_argument("--allow-review", action="store_true")
    drift = sub.add_parser("drift")
    drift.add_argument("baseline")
    drift.add_argument("observed")
    drift.add_argument("--fail-on-change", action="store_true")
    snapshot = sub.add_parser("snapshot-model")
    snapshot.add_argument("input")
    discover = sub.add_parser("discover-aws")
    discover.add_argument("--allow-network", action="store_true", help="Required explicit opt-in; other commands are offline")
    discover.add_argument("--account-id", required=True)
    discover.add_argument("--region", required=True)
    discover.add_argument("--services", nargs="+", choices=("ec2", "rds", "lambda", "s3"), required=True)
    discover.add_argument("--profile")
    discover.add_argument("--max-resources", type=int, default=500)
    discover.add_argument("--max-requests", type=int, default=20)
    discover.add_argument("--timeout-seconds", type=int, default=60)
    for command in sub.choices.values():
        command.add_argument("--out")
        command.add_argument("--force", action="store_true")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    warnings, code = [], 0
    try:
        if args.command in {"validate", "import"}:
            result = import_model(load_document(args.input), args.format, diagram_id=args.diagram_id)
            warnings = result["warnings"]
            output = result["model"] if args.command == "import" else {
                "valid": True, "format": args.format, "model_id": result["model"]["model_id"],
                "sha256": digest(result["model"]), "warnings": warnings}
        elif args.command == "export":
            result = export_model(load_document(args.input), args.format)
            output, warnings = result["document"], result["warnings"]
        elif args.command == "compare":
            # Import only on demand: validation/interchange do not load graph or ML engines.
            from app.services.comparison_engine import compare_reports
            before, after = validate_model(load_document(args.before)), validate_model(load_document(args.after))
            mappings = load_document(args.mappings) if args.mappings else None
            if mappings and any(not isinstance(v, str) for v in mappings.values()):
                raise ModelError("Component mappings must map string IDs to string IDs")
            output = compare_reports(before, after, component_mappings=mappings)
            output["input_provenance"] = {"before": {"model_id": before["model_id"], "sha256": digest(before)},
                                          "after": {"model_id": after["model_id"], "sha256": digest(after)}}
            if args.fail_on_change and any(c["status"] != "unchanged" for c in output["changes"]):
                code = EXIT_POLICY
        elif args.command == "gate":
            output = gate_model(load_document(args.input), fail_severity=args.fail_severity,
                                tier=args.tier, allow_review=args.allow_review)
            code = 0 if output["passed"] else EXIT_POLICY
        elif args.command == "drift":
            output = compare_drift(load_document(args.baseline), load_document(args.observed))
            incomplete = any(v["status"] == "partial" for v in output["coverage"].values())
            changed = any(r["status"] != "unchanged" for r in output["changes"])
            code = EXIT_POLICY if incomplete or (args.fail_on_change and changed) else 0
        elif args.command == "snapshot-model":
            output = snapshot_to_model(load_document(args.input))
        else:
            if not args.allow_network:
                raise ModelError("discover-aws requires --allow-network and a separately authorized read-only AWS profile")
            output = discover_aws(account_id=args.account_id, region=args.region, services=args.services,
                profile=args.profile, max_resources=args.max_resources, max_requests=args.max_requests,
                timeout_seconds=args.timeout_seconds)
            if any(v["status"] == "partial" for v in output["coverage"].values()):
                code = EXIT_POLICY
        if warnings:
            print(json.dumps({"warnings": warnings}, sort_keys=True), file=sys.stderr)
        if getattr(args, "fail_on_loss", False) and warnings:
            # Do not publish a conversion when the caller disallows its warnings.
            print(json.dumps({"error": "conversion_requires_review", "warnings": warnings}), file=sys.stderr)
            return EXIT_POLICY
        inputs = [getattr(args, key, None) for key in ("input", "before", "after", "baseline", "observed", "mappings")]
        _write_output(output, args.out, args.force, inputs)
        return code
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        print(json.dumps({"error": "invalid_input", "detail": str(exc)}), file=sys.stderr)
        return EXIT_INVALID
    except (OSError, RuntimeError, ImportError) as exc:
        print(json.dumps({"error": "runtime_error", "detail": str(exc)}), file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    raise SystemExit(main())
