"""Exercise the upload transport through extraction, analysis and report output."""

from pathlib import Path
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app


FIXTURES = Path(__file__).parent / "fixtures" / "professional_holdout"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as value:
        yield value


def upload(client, filename, payload, mime):
    response = client.post("/analyze-documents", data={
        "project_name": f"Engine upload regression {filename}",
        "use_local_slm": "false", "analysis_mode": "standard",
    }, files=[("files", (filename, payload, mime))])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["report_markdown"]
    assert result["engine_status"]["quality_gate"]["model_integrity"] == "valid"
    return result


def test_pdf_upload_preserves_missing_control_and_source(client):
    import pymupdf

    with pymupdf.open() as document:
        page = document.new_page()
        for index, line in enumerate([
            "Claims architecture design",
            "React calls a Node.js REST API over HTTPS.",
            "The API writes patient records to PostgreSQL over TLS.",
            "PostgreSQL is not encrypted at rest.",
        ]):
            page.insert_text((40, 40 + index * 20), line)
        payload = document.tobytes()
    result = upload(client, "claims-design.pdf", payload, "application/pdf")
    findings = [t for t in result["threats"] if t["tier"] == "Confirmed" and "CWE-311" in t["cwe"]]
    assert findings
    assert all(t["component"] == "postgresql" for t in findings)
    assert any("claims-design.pdf" in str(e) for t in findings for e in t["evidence_details"])


def test_yaml_upload_preserves_explicit_topology_and_tenant_issue(client):
    result = upload(client, "claims-design.yml", (FIXTURES / "structured_architecture.yml").read_bytes(), "application/yaml")
    assert {c["id"] for c in result["architecture"]["components"]} == {"portal", "gateway", "claims", "database"}
    assert {(f["source_id"], f["target_id"]) for f in result["architecture"]["flows"]} == {
        ("portal", "gateway"), ("gateway", "claims"), ("claims", "database"),
    }
    assert all(not f["assumed"] for f in result["architecture"]["flows"])
    assert any(t["tier"] == "Confirmed" and t["id"].startswith("API-BOLA-TENANT-CONTROL") for t in result["threats"])


def test_terraform_project_upload_retains_direct_misconfigurations(client):
    response = client.post("/analyze-iac-project", data={
        "project_name": "Engine multicloud upload regression", "analysis_mode": "standard",
    }, files=[("files", ("multicloud.tf", (FIXTURES / "multi_cloud.tf").read_bytes(), "text/plain"))])
    assert response.status_code == 200, response.text
    result = response.json()
    ids = {t["id"] for t in result["threats"] if t["tier"] == "Confirmed"}
    for prefix in ("IAC-AWS-S3-PUBLIC-ACL", "IAC-AWS-LAMBDA-HARDCODED-SECRET", "IAC-GCP-SQL-PUBLIC"):
        assert any(identifier.startswith(prefix) for identifier in ids), (prefix, ids)
    assert result["report_markdown"]


def test_plan_document_upload_preserves_unknown_values_and_diagnostics(client):
    plan = {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": [{
            "address": "aws_db_instance.claims", "type": "aws_db_instance", "name": "claims",
            "values": {"storage_encrypted": False, "publicly_accessible": None},
        }]}},
        "resource_changes": [{"address": "aws_db_instance.claims", "change": {
            "after_unknown": {"publicly_accessible": True},
        }}],
    }
    result = upload(client, "claims-plan.json", json.dumps(plan).encode(), "application/json")
    assert any(t["id"].startswith("IAC-AWS-RDS-NO-ENCRYPTION") for t in result["threats"])
    assert not any(t["id"].startswith("IAC-AWS-RDS-PUBLIC") for t in result["threats"])
    assert result["architecture"]["metadata"]["unresolved_references"]
    assert result["architecture"]["metadata"]["analysis_limits"]
    assert not result["architecture"]["flows"]


def test_busy_analysis_is_not_rewritten_to_internal_error(client, monkeypatch):
    from fastapi import HTTPException

    async def busy(*args, **kwargs):
        raise HTTPException(503, "Analysis capacity is busy", headers={"Retry-After": "5"})

    monkeypatch.setattr("app.main._run_analysis", busy)
    response = client.post("/analyze", json={"project_name": "Busy regression", "description": "React calls the Node.js API over HTTPS.", "use_local_slm": False})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
