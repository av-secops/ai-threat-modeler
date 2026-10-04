"""Offline, versioned architecture interchange. Imports are claims, not verification.

Vendored upstream schemas are pinned, hash checked and never fetched at runtime.
External validation uses jsonschema from the base requirements.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Any

from ..models import Asset, Component, DataFlow, SystemArchitecture, Threat, TrustBoundary

MODEL_VERSION = "aegis-model/1"
MAX_BYTES = 8 * 1024 * 1024
MAX_ELEMENTS = 5000
MAX_DEPTH = 50
EXTERNAL_FORMATS = frozenset({"otm", "threat-dragon"})
SCHEMA_DIRECTORY = Path(__file__).resolve().parent / "schemas"


def _assert_local_schema_refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                    not isinstance(item, str) or not item.startswith("#")):
                raise RuntimeError("Vendored schemas must contain only local fragment references")
            _assert_local_schema_refs(item)
    elif isinstance(value, list):
        for item in value:
            _assert_local_schema_refs(item)


@lru_cache(maxsize=1)
def _schema_bundle():
    """Read the checked-in manifest and verify bytes before using any schema."""
    try:
        manifest = json.loads((SCHEMA_DIRECTORY / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "aegis-interchange-schemas/1":
            raise ValueError("unsupported schema manifest")
        entries = manifest["schemas"]
        if set(entries) != EXTERNAL_FORMATS:
            raise ValueError("incomplete schema manifest")
        schemas = {}
        for name, entry in entries.items():
            filename = entry["file"]
            if not isinstance(filename, str) or Path(filename).name != filename:
                raise ValueError("schema path must be a plain filename")
            data = (SCHEMA_DIRECTORY / filename).read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise RuntimeError(f"Vendored {name} schema checksum mismatch")
            schema = json.loads(data)
            _assert_local_schema_refs(schema)
            schemas[name] = schema
        return entries, schemas
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise RuntimeError("Vendored interchange schema files or manifest are unavailable or invalid") from exc


def _schema_source(format_name):
    return _schema_bundle()[0][format_name]["source_url"]


class ModelError(ValueError):
    """Invalid, unsupported, or ambiguous model; never silently repaired."""


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


def bounded(value: Any) -> None:
    """Reject cyclic/deep YAML aliases and non-JSON data before processing."""
    count = 0

    def visit(item, depth, ancestors):
        nonlocal count
        count += 1
        if depth > MAX_DEPTH or count > 250000:
            raise ModelError("Document exceeds depth or expanded value limit")
        if isinstance(item, (dict, list)):
            if id(item) in ancestors:
                raise ModelError("Cyclic document references are not supported")
            ancestors = ancestors | {id(item)}
            if isinstance(item, dict) and any(not isinstance(k, str) for k in item):
                raise ModelError("All object keys must be strings")
            for child in (item.values() if isinstance(item, dict) else item):
                visit(child, depth + 1, ancestors)

    visit(value, 0, set())
    try:
        size = len(stable_json(value).encode())
    except (TypeError, ValueError, RecursionError) as exc:
        raise ModelError("Document must contain finite JSON values") from exc
    if size > MAX_BYTES:
        raise ModelError("Document exceeds 8 MiB expanded size limit")


def load_document(path: str | Path) -> dict:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ModelError("Document exceeds 8 MiB size limit")

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ModelError(f"Duplicate object key: {key}")
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8-sig")
        if str(path).lower().endswith((".yaml", ".yml")):
            import yaml

            class UniqueLoader(yaml.SafeLoader):
                # Model-as-code deliberately excludes YAML aliases and merges:
                # expansion could consume memory before post-parse bounds run.
                def compose_node(self, parent, index):
                    if self.check_event(yaml.AliasEvent):
                        raise ModelError("YAML aliases/merge references are unsupported; use explicit values")
                    return super().compose_node(parent, index)

            def mapping(loader, node):
                loader.flatten_mapping(node)
                return pairs([(loader.construct_object(k), loader.construct_object(v)) for k, v in node.value])

            UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
            try:
                value = yaml.load(text, Loader=UniqueLoader)
            except yaml.YAMLError as exc:
                raise ModelError("Invalid or unsupported YAML; only safe explicit JSON-compatible values are supported") from exc
        else:
            value = json.loads(text, object_pairs_hook=pairs)
        bounded(value)
    except (UnicodeError, RecursionError) as exc:
        raise ModelError("Invalid encoding or excessively nested document") from exc
    if not isinstance(value, dict):
        raise ModelError("The document root must be an object")
    return value


def _ids(rows, kind):
    found = set()
    if len(rows) > MAX_ELEMENTS:
        raise ModelError(f"Too many {kind}; limit {MAX_ELEMENTS}")
    for row in rows:
        if not isinstance(row, dict):
            raise ModelError(f"Each {kind} must be an object")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in found:
            raise ModelError(f"Empty or duplicate {kind} id: {identifier}")
        found.add(identifier)
    return found


def validate_model(document: dict) -> dict:
    """Validate without running extraction, AI, or canonical evidence inference."""
    bounded(document)
    if not isinstance(document, dict):
        raise ModelError("Model must be an object")
    value = deepcopy(document)
    if "schema_version" in value and value["schema_version"] != MODEL_VERSION:
        raise ModelError("Unsupported Aegis model schema version")
    if "architecture" not in value:
        value = {"architecture": value}
    for key in ("engine_status", "extensions", "provenance"):
        if key in value and value[key] is not None and not isinstance(value[key], dict):
            raise ModelError(f"{key} must be an object")
    arch = value.get("architecture")
    if not isinstance(arch, dict):
        raise ModelError("architecture must be an object")
    unknown = set(arch) - set(SystemArchitecture.model_fields)
    if unknown:
        raise ModelError(f"Unsupported architecture fields: {sorted(unknown)}; use metadata")
    for collection, cls in (("components", Component), ("flows", DataFlow),
                            ("trust_boundaries", TrustBoundary), ("assets", Asset)):
        rows = arch.get(collection, [])
        if not isinstance(rows, list) or len(rows) > MAX_ELEMENTS:
            raise ModelError(f"Invalid or oversized {collection}")
        for row in rows:
            if not isinstance(row, dict) or set(row) - set(cls.model_fields):
                raise ModelError(f"Invalid or unsupported fields in {collection}; use properties/metadata")
        if collection in {"flows", "trust_boundaries"}:
            for row in rows:
                if not row.get("id"):
                    row["id"] = collection + "-" + digest(row)[:24]
    try:
        arch = SystemArchitecture.model_validate(arch, strict=True).model_dump(mode="json")
    except ValueError as exc:
        raise ModelError(f"Invalid architecture: {exc}") from exc
    components = _ids(arch["components"], "component")
    flows = _ids(arch["flows"], "flow")
    boundaries = _ids(arch["trust_boundaries"], "boundary")
    if not components:
        raise ModelError("At least one component is required")
    numbers = set()
    for flow in arch["flows"]:
        if flow["source_id"] not in components or flow["target_id"] not in components:
            raise ModelError(f"Flow {flow['id']} references an unknown component")
        if flow["flow_number"]:
            if flow["flow_number"] in numbers:
                raise ModelError("Duplicate flow number")
            numbers.add(flow["flow_number"])
    next_number = 1
    for flow in sorted(arch["flows"], key=lambda r: r["id"]):
        if not flow["flow_number"]:
            while f"F-{next_number:03d}" in numbers:
                next_number += 1
            flow["flow_number"] = f"F-{next_number:03d}"
            numbers.add(flow["flow_number"])
    by_boundary = {b["id"]: b for b in arch["trust_boundaries"]}
    for boundary in arch["trust_boundaries"]:
        if set(boundary["components"]) - components:
            raise ModelError("Boundary references an unknown component")
        if boundary["parent_id"] and boundary["parent_id"] not in boundaries:
            raise ModelError("Boundary references an unknown parent")
        current, seen = boundary, set()
        while current:
            if current["id"] in seen:
                raise ModelError("Boundary parent cycle")
            seen.add(current["id"])
            current = by_boundary.get(current["parent_id"])
    component_aliases, flow_aliases = {}, {}
    for comp in arch["components"]:
        component_aliases.setdefault(comp["name"], set()).add(comp["id"])
    names = {c["id"]: c["name"] for c in arch["components"]}
    for flow in arch["flows"]:
        for left, right in ((flow["source_id"], flow["target_id"]), (names[flow["source_id"]], names[flow["target_id"]])):
            for arrow in ("->", chr(0x2192)):
                for separator in (arrow, " " + arrow + " "):
                    flow_aliases.setdefault(left + separator + right, set()).add(flow["id"])
        flow_aliases.setdefault(flow["flow_number"], set()).add(flow["id"])

    def resolve_refs(refs, identities, aliases, label):
        resolved = []
        for ref in refs:
            if ref in identities:
                resolved.append(ref)
                continue
            matches = aliases.get(ref, set())
            if len(matches) != 1:
                raise ModelError(f"{label} reference {ref!r} is unknown or ambiguous; use explicit IDs")
            resolved.extend(matches)
        return sorted(set(resolved))

    for asset in arch["assets"]:
        component_ref = asset["related_component_id"]
        mapped_component = resolve_refs([component_ref], components, component_aliases, "Asset component")[0] if component_ref else None
        mapped_flows = resolve_refs(asset["related_data_flows"], flows, flow_aliases, "Asset flow")
        if mapped_component != component_ref or mapped_flows != asset["related_data_flows"]:
            asset["evidence"].append({"source_type": "interchange_reference_resolution",
                "original_component": component_ref, "original_flows": asset["related_data_flows"]})
        asset["related_component_id"], asset["related_data_flows"] = mapped_component, mapped_flows

    threats = value.get("threats", [])
    if not isinstance(threats, list):
        raise ModelError("threats must be a list")
    _ids(threats, "finding")
    for threat in threats:
        try:
            Threat.model_validate(threat, strict=True)
        except ValueError as exc:
            raise ModelError(f"Invalid finding: {exc}") from exc
        refs = threat.get("affected_components", [])
        flow_refs = threat.get("affected_data_flows", [])
        mapped_refs = resolve_refs(refs, components, component_aliases, "component")
        mapped_flows = resolve_refs(flow_refs, flows, flow_aliases, "flow")
        if mapped_refs != refs or mapped_flows != flow_refs:
            explanation = threat.setdefault("explanation", {}) or {}
            explanation.setdefault("interchange_original_references", {"components": refs, "flows": flow_refs})
            threat["explanation"] = explanation
        threat["affected_components"], threat["affected_data_flows"] = mapped_refs, mapped_flows
    for key in ("components", "flows", "trust_boundaries"):
        arch[key].sort(key=lambda row: row["id"])
    value["architecture"] = arch
    value["schema_version"] = MODEL_VERSION
    value.setdefault("model_id", (arch.get("metadata") or {}).get("model_id") or "model-" + digest(arch)[:24])
    if not isinstance(value["model_id"], str) or not value["model_id"].strip():
        raise ModelError("model_id must be a nonempty string")
    value.setdefault("project_name", "Imported model")
    if not isinstance(value["project_name"], str) or not value["project_name"].strip():
        raise ModelError("project_name must be a nonempty string")
    value["threats"] = sorted(threats, key=lambda row: row["id"])
    return value


def validate_external(document: dict, format_name: str) -> None:
    bounded(document)
    if format_name not in EXTERNAL_FORMATS:
        raise ModelError("Unsupported external format")
    try:
        from jsonschema import Draft7Validator, validators
    except ImportError as exc:
        raise RuntimeError("External interchange requires jsonschema>=4.23,<5") from exc
    # Schema data is bundled and only has local refs; input $schema is never resolved.
    validator = Draft7Validator
    if format_name == "threat-dragon":
        # Upstream's v2 schema annotates nullable style fields with the OpenAPI
        # keyword; official example files use null there. No other types relax.
        def nullable_type(checker, types, instance, schema):
            if instance is None and schema.get("nullable") is True:
                return
            yield from Draft7Validator.VALIDATORS["type"](checker, types, instance, schema)
        validator = validators.extend(Draft7Validator, {"type": nullable_type})
    errors = sorted(validator(_schema_bundle()[1][format_name]).iter_errors(document),
                    key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        raise ModelError(f"{format_name} schema at {list(error.path)}: {error.message}")
    version = document.get("otmVersion") if format_name == "otm" else document.get("version", "")
    if (format_name == "otm" and version != "0.2.0") or (format_name == "threat-dragon" and not version.startswith("2.")):
        raise ModelError(f"Unsupported {format_name} version {version}")


def _warning(code, message, element=None):
    return {"code": code, "message": message, **({"element": element} if element else {})}


def _import_result(document, format_name, architecture, threats, model_id, title, warnings):
    source_hash = digest(document)
    provenance = {"format": format_name, "schema": _schema_source(format_name),
                  "schema_sha256": _schema_bundle()[0][format_name]["sha256"],
                  "schema_dialect": "draft7+upstream-nullable" if format_name == "threat-dragon" else "draft7",
                  "source_sha256": source_hash, "verification": "imported_unverified"}
    for kind in ("components", "flows", "trust_boundaries"):
        for row in architecture.get(kind, []):
            row.setdefault("evidence", []).append({"source_type": "model_interchange",
                "source_sha256": source_hash, "element_id": row["id"], "evidence_basis": "source_design"})
    result = validate_model({"schema_version": MODEL_VERSION, "model_id": str(model_id),
        "project_name": title, "architecture": architecture, "threats": threats,
        "provenance": provenance,
        "extensions": {"interchange_source": deepcopy(document), "conversion_warnings": warnings}})
    return {"model": result, "warnings": warnings, "provenance": provenance}


def _import_threat(raw, identifier, components=None, flows=None):
    # A source's mitigated/accepted/confirmed label cannot certify Aegis closure.
    return {"id": identifier, "title": raw.get("title") or raw.get("name") or identifier,
        "description": raw.get("description") or "", "mitigation": raw.get("mitigation") or "",
        "category": raw.get("type") or ", ".join(raw.get("categories") or []) or "Unclassified",
        "severity": raw.get("severity") or "Unknown", "tier": "Potential", "review_status": "pending_review",
        "affected_components": components or [], "affected_data_flows": flows or [],
        "explanation": {"origin": "external_interchange", "source_record": deepcopy(raw),
                        "verification": "imported_unverified"}}


def import_model(document: dict, format_name: str, *, diagram_id: int | None = None) -> dict:
    if format_name == "aegis":
        return {"model": validate_model(document), "warnings": []}
    validate_external(document, format_name)
    if format_name == "otm":
        return _import_otm(document)
    return _import_dragon(document, diagram_id)


def _import_otm(doc):
    warnings = [_warning("source_preserved", "Original OTM retained in extensions; layout, asset risk ratings, numeric risk, mitigation states and custom attributes are not executable Aegis controls.")]
    comps, zones, flows = doc.get("components") or [], doc.get("trustZones") or [], doc.get("dataflows") or []
    cids, bids, fids = _ids(comps, "component"), _ids(zones, "trust zone"), _ids(flows, "flow")
    if cids & bids or cids & fids or bids & fids:
        raise ModelError("OTM element IDs must be globally unique for this interchange profile")
    by_comp = {r["id"]: r for r in comps}

    def parent_zone(row):
        current, seen = row, set()
        while current:
            if current["id"] in seen:
                raise ModelError("OTM component parent is missing or cyclic")
            seen.add(current["id"])
            parent = current.get("parent") or {}
            if "trustZone" in parent:
                if parent["trustZone"] not in bids:
                    raise ModelError("OTM parent trust zone does not exist")
                return parent["trustZone"]
            if "component" in parent:
                if parent["component"] not in cids:
                    raise ModelError("OTM component parent is missing or cyclic")
                current = by_comp[parent["component"]]
            else:
                return None

    architecture = {"components": [], "flows": [], "trust_boundaries": [], "metadata": {}}
    for comp in comps:
        parent_zone(comp)
        architecture["components"].append({"id": comp["id"], "name": comp["name"], "type": comp["type"],
            "trust_level": "unknown", "description": comp.get("description") or "",
            "properties": {"interchange_parent": comp["parent"], "interchange_attributes": comp.get("attributes") or {}}})
    for zone in zones:
        architecture["trust_boundaries"].append({"id": zone["id"], "name": zone["name"],
            "boundary_type": zone.get("type") or "unspecified", "parent_id": parent_zone(zone),
            "components": [c["id"] for c in comps if parent_zone(c) == zone["id"]]})
    if any("component" in c["parent"] for c in comps):
        warnings.append(_warning("component_containment", "Component containment is preserved as metadata; only zone membership maps to Aegis trust boundaries."))
    reverse_ids = {}
    for flow in flows:
        row = {"id": flow["id"], "source_id": flow["source"], "target_id": flow["destination"],
               "protocol": "unknown", "description": flow.get("description") or flow["name"]}
        architecture["flows"].append(row)
        if flow.get("bidirectional"):
            rid = flow["id"] + ":reverse"
            if rid in cids | bids | fids:
                raise ModelError("Generated reverse flow ID conflicts with a source element")
            reverse_ids[flow["id"]] = rid
            architecture["flows"].append({**row, "id": rid, "source_id": row["target_id"], "target_id": row["source_id"]})
    asset_ids = _ids(doc.get("assets") or [], "asset")
    for row in comps:
        asset_refs = row.get("assets") or {}
        if set((asset_refs.get("processed") or []) + (asset_refs.get("stored") or [])) - asset_ids:
            raise ModelError("OTM component references an unknown asset")
    if any(set(f.get("assets") or []) - asset_ids for f in flows):
        raise ModelError("OTM flow references an unknown asset")
    threat_rows = doc.get("threats") or []
    tids = _ids(threat_rows, "threat")
    mitigation_ids = _ids(doc.get("mitigations") or [], "mitigation")
    scopes = {tid: {"components": [], "flows": []} for tid in tids}
    for rows, scope in ((comps, "components"), (flows, "flows")):
        for row in rows:
            for ref in row.get("threats") or []:
                if ref["threat"] not in tids:
                    raise ModelError("OTM references an unknown threat")
                for mitigation in ref.get("mitigations") or []:
                    if mitigation and mitigation.get("mitigation") not in mitigation_ids:
                        raise ModelError("OTM references an unknown mitigation")
                scopes[ref["threat"]][scope].append(row["id"])
                if scope == "flows" and row["id"] in reverse_ids:
                    scopes[ref["threat"]][scope].append(reverse_ids[row["id"]])
    threats = [_import_threat(r, r["id"], **scopes[r["id"]]) for r in threat_rows]
    if threats:
        warnings.append(_warning("risk_scale", "OTM numeric likelihood/impact have no approved severity mapping; imported severity stays Unknown, requiring review."))
    project = doc["project"]
    return _import_result(doc, "otm", architecture, threats, project["id"], project["name"], warnings)


def _import_dragon(doc, diagram_id):
    warnings = [_warning("source_preserved", "Original Threat Dragon document retained; layout and source statuses do not establish Aegis control verification or risk closure.")]
    diagrams = doc["detail"]["diagrams"]
    if len({d["id"] for d in diagrams}) != len(diagrams):
        raise ModelError("Duplicate Threat Dragon diagram IDs")
    if diagram_id is None and len(diagrams) != 1:
        raise ModelError("Select --diagram-id for a multi-diagram document; diagrams are not silently merged")
    matches = [d for d in diagrams if diagram_id is None or d["id"] == diagram_id]
    if len(matches) != 1:
        raise ModelError("Selected diagram does not exist")
    diagram = matches[0]
    if not diagram["version"].startswith("2."):
        raise ModelError("Only Threat Dragon 2.x diagrams are supported")
    cells = diagram.get("cells") or []
    _ids(cells, "cell")
    nodes = {c["id"] for c in cells if c["shape"] in {"process", "store", "actor"}}
    boundary_ids = {c["id"] for c in cells if c["shape"] in {"trust-boundary-box", "trust-boundary-curve"}}
    architecture = {"components": [], "flows": [], "trust_boundaries": [], "metadata": {"source_diagram_id": diagram["id"]}}
    threats = []
    for cell in cells:
        data = cell.get("data") or {}
        name = data.get("name") or (cell.get("attrs") or {}).get("text", {}).get("text") or cell["id"]
        kind = cell["shape"]
        props = {"source_diagram_id": diagram["id"], "source_controls": deepcopy(data)}
        if kind in {"actor", "process", "store"}:
            if cell.get("parent") and cell["parent"] not in boundary_ids:
                raise ModelError("Threat Dragon node references an unknown boundary parent")
            architecture["components"].append({"id": cell["id"], "name": name,
                "type": {"actor": "External Entity", "process": "Service", "store": "Data Store"}[kind],
                "trust_level": "unknown", "description": data.get("description") or "", "properties": props})
        elif kind == "flow":
            source, target = (cell.get("source") or {}).get("cell"), (cell.get("target") or {}).get("cell")
            if source not in nodes or target not in nodes:
                raise ModelError("Threat Dragon flow must reference two existing nodes; coordinate-only endpoints are unsupported")
            row = {"id": cell["id"], "source_id": source, "target_id": target,
                "protocol": data.get("protocol") or "unknown", "description": data.get("description") or name, "properties": props}
            architecture["flows"].append(row)
            if data.get("isBidirectional"):
                if any(c["id"] == cell["id"] + ":reverse" for c in cells):
                    raise ModelError("Generated reverse flow ID conflicts with a source element")
                architecture["flows"].append({**row, "id": cell["id"] + ":reverse", "source_id": target, "target_id": source})
        elif kind in {"trust-boundary-box", "trust-boundary-curve"}:
            children = cell.get("children", [])
            if not isinstance(children, list) or any(not isinstance(cid, str) for cid in children):
                raise ModelError("Invalid Threat Dragon boundary children")
            if set(children) - {c["id"] for c in cells}:
                raise ModelError("Threat Dragon boundary references an unknown child")
            parent = cell.get("parent")
            if parent and not any(c["id"] == parent and c["shape"] in {"trust-boundary-box", "trust-boundary-curve"} for c in cells):
                raise ModelError("Threat Dragon boundary references an unknown parent")
            members = sorted(set(cid for cid in children if cid in nodes) |
                             {c["id"] for c in cells if c["id"] in nodes and c.get("parent") == cell["id"]})
            architecture["trust_boundaries"].append({"id": cell["id"], "name": name,
                "boundary_type": "trust", "parent_id": parent, "components": members})
            warnings.append(_warning("boundary_geometry", "Only explicit children map to membership; visual containment and crossing curves require review.", cell["id"]))
        else:
            raise ModelError(f"Unsupported Threat Dragon shape {kind}; source must be reviewed before import")
        source_threats = data.get("threats", cell.get("threats", []))
        if "threats" in data and "threats" in cell and data["threats"] != cell["threats"]:
            raise ModelError("Conflicting cell and data threat lists")
        if not isinstance(source_threats, list):
            raise ModelError("Threat list must be an array")
        for index, raw in enumerate(source_threats):
            if not isinstance(raw, dict) or any(not isinstance(raw.get(k), str) for k in
                    ("title", "description", "mitigation", "severity", "status", "type")):
                raise ModelError("Invalid Threat Dragon data.threats entry")
            identifier = f"{diagram['id']}:{cell['id']}:{raw.get('id') or raw.get('threatId') or index}"
            flow_refs = [cell["id"]] if kind == "flow" else []
            if kind == "flow" and data.get("isBidirectional"):
                flow_refs.append(cell["id"] + ":reverse")
            threats.append(_import_threat(raw, identifier,
                [cell["id"]] if kind in {"actor", "process", "store"} else [], flow_refs))
    if len(diagrams) > 1:
        warnings.append(_warning("selected_diagram_only", "Only the selected diagram is modeled; other diagrams remain in extensions."))
    summary = doc["summary"]
    return _import_result(doc, "threat-dragon", architecture, threats,
        str(summary.get("id") or "td-" + digest(summary)[:24]) + f":diagram:{diagram['id']}", summary["title"], warnings)


def export_model(document: dict, format_name: str) -> dict:
    model = validate_model(document)
    if format_name == "aegis":
        return {"document": model, "warnings": []}
    if format_name not in EXTERNAL_FORMATS:
        raise ModelError("Unsupported export format")
    arch = model["architecture"]
    identities = [r["id"] for key in ("components", "flows", "trust_boundaries") for r in arch[key]]
    if len(identities) != len(set(identities)):
        raise ModelError("External interchange requires globally unique component/flow/boundary IDs")
    warnings = [_warning("aegis_extension", "Full Aegis model is preserved in a namespaced extension; other tools may discard it. Standard fields do not express all controls, provenance, risk scope or review states.")]
    if format_name == "otm":
        # OTM requires a numeric rating even for an unrated trust zone. Mark the
        # required placeholder explicitly, warn, and let strict callers refuse it.
        root_id = "aegis-unrated-" + digest(model["model_id"])[:16]
        if any(r["id"] == root_id for k in ("components", "flows", "trust_boundaries") for r in arch[k]):
            raise ModelError("Synthetic OTM root collides with a model element")
        zones = [{"id": root_id, "name": "Unrated model scope", "risk": {"trustRating": 0},
                  "attributes": {"aegis": {"synthetic": True, "trust_rating_unknown": True}}}]
        for boundary in arch["trust_boundaries"]:
            zones.append({"id": boundary["id"], "name": boundary["name"], "type": boundary["boundary_type"],
                "parent": {"trustZone": boundary["parent_id"] or root_id}, "risk": {"trustRating": 0},
                "attributes": {"aegis": {"trust_rating_unknown": True}}})
        parents = {}
        for comp in arch["components"]:
            membership = [b["id"] for b in arch["trust_boundaries"] if comp["id"] in b["components"]]
            if len(membership) > 1:
                warnings.append(_warning("overlapping_boundaries", "OTM supports one parent. Overlapping memberships remain only in the Aegis extension; standard parent is unrated scope.", comp["id"]))
            parents[comp["id"]] = membership[0] if len(membership) == 1 else root_id
        warnings.append(_warning("otm_unrated_scope", "OTM requires numeric zone ratings: placeholder 0 is NOT a measured trust rating. Native findings/assets remain in project.attributes.aegis; no numeric risk is invented."))
        out = {"otmVersion": "0.2.0", "project": {"id": model["model_id"], "name": model["project_name"],
            "attributes": {"aegis": model}}, "trustZones": zones,
            "components": [{"id": c["id"], "name": c["name"], "type": c["type"],
                            "description": c["description"], "parent": {"trustZone": parents[c["id"]]}}
                           for c in arch["components"]],
            "dataflows": [{"id": f["id"], "name": f["description"] or f["flow_number"],
                           "source": f["source_id"], "destination": f["target_id"],
                           "attributes": {"aegis_protocol": f["protocol"], "aegis_flow_number": f["flow_number"]}}
                          for f in arch["flows"]]}
    else:
        out = _export_dragon(model, warnings)
    validate_external(out, format_name)
    return {"document": out, "warnings": warnings, "schema": _schema_source(format_name),
            "schema_sha256": _schema_bundle()[0][format_name]["sha256"]}


def _export_dragon(model, warnings):
    arch = model["architecture"]
    # Prefix only short IDs (upstream requires >=2 characters); retain a mapping.
    all_ids = [r["id"] for k in ("components", "flows", "trust_boundaries") for r in arch[k]]
    if len(set(all_ids)) != len(all_ids):
        raise ModelError("Threat Dragon requires globally unique element IDs")
    idmap = {v: "aegis-" + digest([model["model_id"], v])[:24] for v in all_ids}
    cells = []
    for index, comp in enumerate(arch["components"]):
        shape = "actor" if comp["type"] in {"External Entity", "User", "Actor"} else "store" if comp["type"] in {"Database", "Storage", "Data Store", "Cache"} else "process"
        threats = []
        for threat in model["threats"]:
            if comp["id"] in threat.get("affected_components", []):
                threats.append({"id": threat["id"], "title": threat["title"], "description": threat["description"],
                    "mitigation": threat["mitigation"], "severity": threat["severity"], "status": "Open",
                    "type": threat.get("stride_category") or threat["category"], "modelType": "STRIDE"})
        cells.append({"id": idmap[comp["id"]], "shape": shape, "zIndex": index + 1,
            "position": {"x": (index % 4) * 220 + 40, "y": (index // 4) * 180 + 40},
            "size": {"width": 160, "height": 100}, "attrs": {"text": {"text": comp["name"]}},
            "data": {"type": "tm." + shape.title(), "name": comp["name"], "description": comp["description"] or "",
                     "hasOpenThreats": bool(threats), "threats": threats}})
    for flow in arch["flows"]:
        threats = [{"id": t["id"], "title": t["title"], "description": t["description"],
                    "mitigation": t["mitigation"], "severity": t["severity"], "status": "Open",
                    "type": t.get("stride_category") or t["category"], "modelType": "STRIDE"}
                   for t in model["threats"] if flow["id"] in t.get("affected_data_flows", [])]
        cells.append({"id": idmap[flow["id"]], "shape": "flow", "zIndex": len(cells) + 1,
            "source": {"cell": idmap[flow["source_id"]]}, "target": {"cell": idmap[flow["target_id"]]},
            "attrs": {"line": {"targetMarker": {"name": "block"}}},
            "data": {"type": "tm.Flow", "name": flow["flow_number"], "protocol": flow["protocol"],
                     "description": flow["description"], "hasOpenThreats": bool(threats), "threats": threats}})
    if arch["trust_boundaries"]:
        warnings.append(_warning("boundary_layout", "Trust boundaries are retained in the Aegis extension; no visual containment is fabricated by the generated grid layout."))
    if any(not t.get("affected_data_flows") and not t.get("affected_components") for t in model["threats"]):
        warnings.append(_warning("finding_scope", "Unscoped findings remain in the Aegis extension; imported status requires fresh review."))
    return {"version": "2.5.0", "summary": {"title": model["project_name"], "id": model["model_id"]},
        "detail": {"contributors": [], "reviewer": "", "diagramTop": 1, "threatTop": len(model["threats"]),
            "diagrams": [{"id": 0, "version": "2.5.0", "title": model["project_name"], "diagramType": "STRIDE", "thumbnail": "", "cells": cells}]},
        "aegis": {"model": model, "element_ids": idmap}}


