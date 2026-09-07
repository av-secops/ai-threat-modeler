"""Offline, version-aware framework references, independent of risk scoring."""

from collections import Counter
from functools import lru_cache
import json
from pathlib import Path


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data/security_frameworks.json"
RULE_MAPPINGS_PATH = REGISTRY_PATH.with_name("framework_rule_mappings.json")


@lru_cache(maxsize=1)
def registry():
    with REGISTRY_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != "1.0" or not data.get("frameworks"):
        raise ValueError("Invalid security framework registry; refresh and validate the snapshot")
    return data


@lru_cache(maxsize=1)
def rule_mappings():
    with RULE_MAPPINGS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)["rules"]


def resolve_mappings(rule):
    """Resolve exact IDs; never infer a newer category from an older number.

    CWE membership denotes taxonomy alignment, not applicability or compliance.
    Invalid references remain visible as diagnostics without discarding a valid
    security check or treating an invented technique as an official reference.
    """
    frameworks = registry()["frameworks"]
    mappings, issues = {}, []

    def add(framework, identifier, version=None, basis="curated_rule_mapping", cwes=None):
        if not isinstance(framework, str) or not isinstance(identifier, str):
            issues.append("Framework identifiers must be strings")
            return
        catalog = frameworks.get(framework, {})
        entry = catalog.get("entries", {}).get(identifier)
        if not entry or (version is not None and str(version) != catalog.get("version")):
            issues.append(f"Unresolved framework mapping {framework}/{version or 'unspecified'}/{identifier}")
            return
        key = (framework, identifier)
        mappings[key] = {"framework": framework, "framework_name": catalog["name"],
                         "version": catalog["version"], "id": identifier, "name": entry["name"],
                         "url": entry["url"], "basis": basis}
        if cwes:
            mappings[key]["matched_cwes"] = sorted(cwes)
        if entry.get("rank"):
            mappings[key]["rank"] = entry["rank"]

    for item in [*(rule.get("framework_mappings") or []), *rule_mappings().get(rule.get("id"), [])]:
        if not isinstance(item, dict) or not item.get("version"):
            issues.append("Framework mappings require a framework, version and identifier")
            continue
        add(item.get("framework"), item.get("id"), item["version"])
    for framework in ("mitre_attack", "mitre_atlas"):
        for identifier in rule.get(framework) or []:
            add(framework, identifier, basis="existing_rule_reference")
    # STRIDE fallback CWEs are not curated mappings and cannot establish coverage.
    if (rule.get("taxonomy_mapping_quality") or {}).get("cwe") in (None, "curated"):
        cwes = set(rule.get("cwe") or [])
        for identifier, entry in frameworks["owasp_web"]["entries"].items():
            matched = cwes & set(entry.get("cwes") or [])
            if matched:
                add("owasp_web", identifier, basis="official_cwe_membership", cwes=matched)
        for identifier in sorted(cwes & frameworks["cwe_top25"]["entries"].keys()):
            add("cwe_top25", identifier, basis="exact_cwe_membership", cwes=[identifier])
    return [mappings[key] for key in sorted(mappings)], sorted(set(issues))


def coverage_report(rules):
    """Report catalog coverage, not whether any particular product is secure."""
    data = registry()
    mapped = {key: {"deterministic": set(), "candidate": set()} for key in data["frameworks"]}
    for rule in rules:
        for item in rule.get("framework_mappings") or []:
            mapped[item["framework"]][rule["rule_kind"]].add(item["id"])
    return {
        "registry_verified_on": data["verified_on"],
        "notice": data["notice"],
        "rules": dict(Counter(rule["rule_kind"] for rule in rules)),
        "stride": dict(Counter(rule["stride_category"] for rule in rules)),
        "frameworks": {key: {"version": value["version"], "reference_entries": len(value["entries"]),
            "deterministic_mapped_ids": sorted(mapped[key]["deterministic"]),
            "candidate_mapped_ids": sorted(mapped[key]["candidate"]),
            "unmapped_ids": sorted(value["entries"].keys() - mapped[key]["deterministic"] - mapped[key]["candidate"])}
            for key, value in data["frameworks"].items()},
    }
