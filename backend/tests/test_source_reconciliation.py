from app.engine.canonical_model import canonicalize_architecture
from app.models import Component, SystemArchitecture
from app.services.document_ingestion import _extract_text_from_bytes


def test_conflicting_declared_systems_block_canonical_validation():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")],
        flows=[],
        metadata={
            "source_text": "An API.",
            "source_documents": [
                {"filename": "claims.yml", "role": "source_design", "system_name": "Claims SaaS"},
                {"filename": "inventory.yml", "role": "source_design", "system_name": "Inventory Platform"},
            ],
        },
    )

    canonical, validation = canonicalize_architecture(architecture)

    assert validation["valid"] is False
    assert any(item["type"] == "source_conflict" for item in validation["issues"])
    assert canonical.metadata["source_reconciliation"]["status"] == "conflict"


def test_terraform_is_accepted_as_an_uploadable_text_artifact():
    text, extension, metadata = _extract_text_from_bytes(
        "main.tf", b'resource "aws_s3_bucket" "evidence" {}',
    )

    assert extension == ".tf"
    assert "aws_s3_bucket" in text
    assert metadata["extraction_quality"] == "text_complete"


def test_reconciliation_records_authority_environment_and_version_conflicts():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")],
        flows=[],
        metadata={
            "source_text": "System: Claims SaaS\nAPI service.",
            "source_documents": [
                {
                    "filename": "claims-v1.yml", "role": "source_design",
                    "system_name": "Claims SaaS", "environment": "prod",
                    "deployment_version": "1.0", "structured_kind": "architecture",
                    "extraction_quality": "structured_complete",
                },
                {
                    "filename": "claims-v2.yml", "role": "source_design",
                    "system_name": "Claims SaaS", "environment": "prod",
                    "deployment_version": "2.0", "structured_kind": "architecture",
                    "extraction_quality": "structured_complete",
                },
            ],
        },
    )

    canonical, validation = canonicalize_architecture(architecture)
    reconciliation = canonical.metadata["source_reconciliation"]

    assert validation["valid"] is False
    assert reconciliation["status"] == "conflict"
    assert reconciliation["selected_authority"] == "claims-v1.yml"
    assert reconciliation["environments"]["prod"] == ["claims-v1.yml", "claims-v2.yml"]
    assert all(item["authority_score"] == 100 for item in reconciliation["decisions"])
