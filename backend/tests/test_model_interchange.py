from copy import deepcopy
import hashlib
import json

import pytest

from app.services.model_interchange import (
    ModelError, bounded, export_model, import_model, load_document, validate_external, validate_model,
)
from app.services import model_interchange as interchange


def model():
    return {"model_id": "checkout", "project_name": "Checkout", "architecture": {
        "components": [{"id": "client", "name": "Client", "type": "External Entity"},
                       {"id": "api", "name": "Orders", "type": "API"}],
        "flows": [{"id": "request", "source_id": "client", "target_id": "api", "protocol": "HTTPS"}],
        "trust_boundaries": [{"id": "app", "name": "Application", "boundary_type": "network", "components": ["api"]}]},
        "threats": [{"id": "risk-1", "title": "Order authorization", "category": "Elevation of Privilege",
                     "description": "Validate tenant checks", "severity": "High", "mitigation": "Enforce tenant authorization",
                     "affected_components": ["api"], "affected_data_flows": ["request"]}]}


def otm():
    return {"otmVersion": "0.2.0", "project": {"id": "shop", "name": "Shop"},
        "trustZones": [{"id": "zone", "name": "Application", "risk": {"trustRating": 20}}],
        "components": [{"id": "web", "name": "Web", "type": "Service", "parent": {"trustZone": "zone"}},
                       {"id": "db", "name": "Orders", "type": "Database", "parent": {"component": "web"}}],
        "dataflows": [{"id": "sql", "name": "Queries", "source": "web", "destination": "db", "bidirectional": True,
                       "threats": [{"threat": "tamper", "state": "Mitigated"}]}],
        "threats": [{"id": "tamper", "name": "Tampering", "risk": {"likelihood": 60, "impact": 80}}]}


def dragon():
    return {"version": "2.5.0", "summary": {"title": "Checkout", "id": "checkout"},
        "detail": {"contributors": [], "reviewer": "", "diagramTop": 1, "threatTop": 0,
            "diagrams": [{"id": 0, "title": "Data flows", "version": "2.5.0", "diagramType": "STRIDE", "thumbnail": "",
                "cells": [{"id": "web", "shape": "process", "zIndex": 1, "data": {"type": "tm.Process", "name": "Web", "hasOpenThreats": False}},
                          {"id": "db", "shape": "store", "zIndex": 2, "data": {"type": "tm.Store", "name": "DB", "hasOpenThreats": False}},
                          {"id": "sql", "shape": "flow", "zIndex": 3, "source": {"cell": "web"}, "target": {"cell": "db"},
                           "data": {"type": "tm.Flow", "hasOpenThreats": False, "protocol": "TLS", "isBidirectional": True}}]}]}}


def test_native_normalization_is_stable_idempotent_and_nonmutating():
    original = model()
    saved = deepcopy(original)
    first = validate_model(original)
    assert original == saved
    assert validate_model(first) == first
    assert first["architecture"]["flows"][0]["flow_number"] == "F-001"
    reordered = deepcopy(original)
    reordered["architecture"]["components"].reverse()
    assert validate_model(reordered) == first


@pytest.mark.parametrize("change", [
    lambda m: m["architecture"]["components"].append(deepcopy(m["architecture"]["components"][0])),
    lambda m: m["architecture"]["flows"][0].update(target_id="missing"),
    lambda m: m["architecture"]["trust_boundaries"][0].update(parent_id="app"),
    lambda m: m["architecture"]["trust_boundaries"][0].update(components=["missing"]),
    lambda m: m["architecture"]["flows"][0].update(assumed="false"),
    lambda m: m["architecture"]["components"][0].update(extra_field=True),
    lambda m: m["threats"][0].update(affected_components=["missing"]),
    lambda m: m.update(schema_version="aegis-model/99"),
])
def test_native_invalid_graphs_and_types_are_rejected(change):
    value = model()
    change(value)
    with pytest.raises(ModelError):
        validate_model(value)


def test_generated_flow_ids_do_not_merge_parallel_flows():
    value = model()
    flow = value["architecture"]["flows"][0]
    flow.pop("id")
    value["threats"] = []
    value["architecture"]["flows"].append(deepcopy(flow))
    with pytest.raises(ModelError, match="duplicate"):
        validate_model(value)


@pytest.mark.parametrize("format_name", ["otm", "threat-dragon"])
def test_exports_pass_pinned_schema_and_are_deterministic(format_name):
    result = export_model(model(), format_name)
    validate_external(result["document"], format_name)
    assert result == export_model(model(), format_name)
    assert result["warnings"]
    imported = import_model(result["document"], format_name)
    assert len(imported["model"]["architecture"]["components"]) == 2
    assert len(imported["model"]["architecture"]["flows"]) == 1
    assert imported["model"]["extensions"]["interchange_source"] == result["document"]


def test_otm_import_preserves_scoped_threats_unknown_severity_and_source():
    source = otm()
    result = import_model(source, "otm")
    arch = result["model"]["architecture"]
    assert len(arch["flows"]) == 2
    assert arch["trust_boundaries"][0]["components"] == ["web", "db"]
    threat = result["model"]["threats"][0]
    assert threat["severity"] == "Unknown"
    assert threat["tier"] == "Potential"
    assert threat["review_status"] == "pending_review"
    assert threat["affected_data_flows"] == ["sql", "sql:reverse"]
    assert all(c["trust_level"] == "unknown" for c in arch["components"])
    assert result["model"]["extensions"]["interchange_source"] == source


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(otmVersion="0.3.0"),
    lambda d: d["project"].pop("id"),
    lambda d: d["components"][0].update(parent={"trustZone": "missing"}),
    lambda d: d["components"][0].update(parent={"component": "db"}),
    lambda d: d["dataflows"][0].update(destination="missing"),
    lambda d: d["dataflows"][0].update(threats=[{"threat": "missing", "state": "Open"}]),
    lambda d: d["dataflows"][0].update(assets=["missing"]),
])
def test_otm_negative_schema_and_references(mutate):
    value = otm()
    mutate(value)
    with pytest.raises(ModelError):
        import_model(value, "otm")


def test_dragon_multiple_diagrams_require_selection_and_no_silent_merge():
    value = dragon()
    second = deepcopy(value["detail"]["diagrams"][0])
    second["id"] = 1
    value["detail"]["diagrams"].append(second)
    with pytest.raises(ModelError, match="diagram-id"):
        import_model(value, "threat-dragon")
    result = import_model(value, "threat-dragon", diagram_id=1)
    assert result["model"]["model_id"] == "checkout:diagram:1"
    assert len(result["model"]["architecture"]["components"]) == 2
    assert len(result["model"]["architecture"]["flows"]) == 2
    assert any(w["code"] == "selected_diagram_only" for w in result["warnings"])


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version="1.0.0"),
    lambda d: d["detail"].pop("reviewer"),
    lambda d: d["detail"]["diagrams"][0]["cells"][0].update(shape="unknown-node"),
    lambda d: d["detail"]["diagrams"][0]["cells"][2].update(source={"x": 0, "y": 0}),
    lambda d: d["detail"]["diagrams"][0]["cells"][0]["data"].update(threats=[{"title": "Malformed"}]),
])
def test_dragon_rejects_incomplete_and_unsupported_shapes(mutate):
    value = dragon()
    mutate(value)
    with pytest.raises(ModelError):
        import_model(value, "threat-dragon")


def test_dragon_mitigated_source_status_does_not_close_imported_finding():
    value = dragon()
    value["detail"]["diagrams"][0]["cells"][0]["data"]["threats"] = [{
        "id": "risk-id", "title": "Injection", "description": "Input handling", "mitigation": "Parameters",
        "severity": "High", "status": "Mitigated", "type": "Tampering"}]
    risk = import_model(value, "threat-dragon")["model"]["threats"][0]
    assert risk["review_status"] == "pending_review"
    assert risk["explanation"]["source_record"]["status"] == "Mitigated"


@pytest.mark.parametrize("name,text", [
    ("bad.json", '{"components": [], "components": []}'),
    ("bad.yml", "components: []\ncomponents: []\n"),
    ("bad.yml", "danger: !!python/object/apply:os.system ['echo unsafe']"),
    ("bad.json", '{"n": NaN}'),
])
def test_loader_rejects_duplicate_keys_unsafe_yaml_and_nonfinite_values(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    with pytest.raises((ModelError, ValueError)):
        load_document(path)


def test_yaml_loads_safely_and_cycles_are_bounded(tmp_path):
    path = tmp_path / "model.yml"
    path.write_text("components:\n  - id: api\n    name: API\n    type: Service\nflows: []\n")
    assert validate_model(load_document(path))["architecture"]["components"][0]["id"] == "api"
    cyclic = {}
    cyclic["x"] = cyclic
    with pytest.raises(ModelError, match="Cyclic"):
        bounded(cyclic)


def test_external_document_never_fetches_input_schema(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("Network attempted"))
    value = otm()
    value["$schema"] = "https://invalid.example/schema.json"
    assert import_model(value, "otm")["model"]["model_id"] == "shop"


def test_dragon_official_nullable_style_annotation_is_supported_not_arbitrary_null():
    value = dragon()
    value["detail"]["diagrams"][0]["cells"][0]["attrs"] = {
        "body": {"stroke": "black", "strokeWidth": 1, "strokeDasharray": None}}
    assert import_model(value, "threat-dragon")["provenance"]["schema_dialect"] == "draft7+upstream-nullable"
    value["detail"]["diagrams"][0]["cells"][0]["data"]["hasOpenThreats"] = None
    with pytest.raises(ModelError):
        import_model(value, "threat-dragon")


def test_legacy_flow_labels_resolve_only_when_unambiguous():
    value = model()
    value["threats"][0]["affected_data_flows"] = ["Client -> Orders"]
    assert validate_model(value)["threats"][0]["affected_data_flows"] == ["request"]
    parallel = deepcopy(value["architecture"]["flows"][0])
    parallel["id"] = "parallel"
    value["architecture"]["flows"].append(parallel)
    with pytest.raises(ModelError, match="ambiguous"):
        validate_model(value)


def test_yaml_alias_expansion_is_rejected_before_construction(tmp_path):
    path = tmp_path / "aliases.yaml"
    path.write_text("a: &a [1,2]\nb: [*a, *a]\n")
    with pytest.raises(ModelError, match="aliases"):
        load_document(path)


def test_legacy_asset_flow_labels_resolve_and_preserve_source_references():
    value = model()
    value["architecture"]["assets"] = [{"name": "Orders", "sensitivity": "financial", "location": "API",
        "related_component_id": "api", "related_data_flows": ["client " + chr(0x2192) + " api"]}]
    normalized = validate_model(value)
    asset = normalized["architecture"]["assets"][0]
    assert asset["related_data_flows"] == ["request"]
    assert asset["evidence"][0]["source_type"] == "interchange_reference_resolution"
    assert validate_model(normalized) == normalized


def test_vendored_schemas_have_pinned_license_manifest_and_hashes(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('Schema attempted network'))
    interchange._schema_bundle.cache_clear()
    entries, schemas = interchange._schema_bundle()
    assert set(entries) == set(schemas) == {'otm', 'threat-dragon'}
    assert interchange.SCHEMA_DIRECTORY.name == 'schemas'
    for name, record in entries.items():
        data = (interchange.SCHEMA_DIRECTORY / record['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['sha256']
        assert record['license'] == 'Apache-2.0' and record['attribution']
        assert 'Apache License' in (interchange.SCHEMA_DIRECTORY / record['license_file']).read_text(encoding='utf-8')
        assert len(record['upstream_commit']) == 40
        assert record['upstream_commit'] in record['source_url']
        assert json.loads(data) == schemas[name]
    assert import_model(otm(), 'otm')['provenance']['schema_sha256'] == entries['otm']['sha256']


@pytest.mark.parametrize('failure', ['checksum', 'remote_ref', 'missing_file', 'path_escape'])
def test_vendored_schema_failures_are_closed_and_never_fetched(tmp_path, monkeypatch, failure):
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('Schema attempted network'))
    folder = interchange.SCHEMA_DIRECTORY
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    for entry in manifest['schemas'].values():
        (tmp_path / entry['file']).write_bytes((folder / entry['file']).read_bytes())
    entry = manifest['schemas']['otm']
    if failure == 'checksum':
        (tmp_path / entry['file']).write_text('{}')
    elif failure == 'remote_ref':
        raw = json.dumps({'$ref': 'https://untrusted.invalid/schema.json'}).encode()
        (tmp_path / entry['file']).write_bytes(raw)
        entry['sha256'] = hashlib.sha256(raw).hexdigest()
    elif failure == 'missing_file':
        (tmp_path / entry['file']).unlink()
    else:
        entry['file'] = '../outside.json'
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    monkeypatch.setattr(interchange, 'SCHEMA_DIRECTORY', tmp_path)
    interchange._schema_bundle.cache_clear()
    try:
        with pytest.raises(RuntimeError):
            validate_external(otm(), 'otm')
        # Native validation remains available without external schema assets.
        assert validate_model(model())['model_id'] == 'checkout'
    finally:
        interchange._schema_bundle.cache_clear()
