"""Every fact should cite the document that stated it, not the first one uploaded."""

from app.engine import source_index
from app.engine.analyzer import ThreatAnalyzer
from app.engine.parser import ArchitectureParser


def _assembled(*sections: str, context: str = "") -> str:
    """Reproduce what /analyze-documents hands the parser."""
    body = "\n\n---\n\n".join(sections)
    return f"User Context:\n{context}\n\n---\n\n{body}" if context else body


def _document(filename: str, kind: str, content: str, role: str = "source_design") -> str:
    return f"Document: {filename}\nType: {kind}\nRole: {role}\nContent:\n{content}"


def test_a_line_is_attributed_to_the_document_that_contains_it():
    text = _assembled(
        _document("edge.md", "md", "The React portal calls the orders API over TLS."),
        _document("data.md", "md", "The orders API writes patient records to the records database."),
    )
    index = source_index.build(text)

    portal = index.find("React portal calls")
    records = index.find("writes patient records")

    assert portal is not None and records is not None
    assert portal.document == "edge.md"
    assert records.document == "data.md"
    assert portal.source_id != records.source_id


def test_pages_and_tables_locate_a_statement_inside_its_document():
    text = _document(
        "design.pdf", "pdf",
        "[Page 1]\nOverview of the estate.\n\n[Page 7]\nThe ingestion bucket is not encrypted at rest.",
    )
    index = source_index.build(text)

    bucket = index.find("ingestion bucket is not encrypted")

    assert bucket is not None
    assert bucket.locator == "page 7"
    assert bucket.display().startswith("design.pdf, page 7, line")


def test_a_table_row_is_located_by_table_number():
    text = _document(
        "records.docx", "docx",
        "[Table 2]\nRow 1: Component | Type\nRow 2: Orders API | API",
    )
    index = source_index.build(text)

    row = index.find("Orders API")

    assert row is not None
    assert row.locator == "table 2"


def test_a_horizontal_rule_inside_a_document_does_not_end_it():
    text = _assembled(
        _document(
            "design.md", "md",
            "The portal is public.\n\n---\n\nThe records database holds patient records.",
        ),
        _document("ops.md", "md", "Backups run nightly."),
    )
    index = source_index.build(text)

    # A Markdown rule looks exactly like the joiner between documents. Treating
    # it as a boundary would hand the rest of design.md to no source at all.
    after_rule = index.find("records database holds patient records")

    assert after_rule is not None
    assert after_rule.document == "design.md"
    assert [record["document"] for record in index.sources] == ["design.md", "ops.md"]


def test_the_typed_description_is_a_source_of_its_own():
    text = _assembled(
        _document("design.md", "md", "The database stores orders."),
        context="A React portal calls the orders API.",
    )
    index = source_index.build(text)

    typed = index.find("React portal calls the orders API")
    uploaded = index.find("database stores orders")

    assert typed is not None and typed.document == source_index.NARRATIVE_DOCUMENT
    assert typed.role == "user_context"
    assert uploaded is not None and uploaded.document == "design.md"


def test_a_plain_description_with_no_documents_is_still_cited():
    index = source_index.build("A React portal calls a Node.js API.")

    citation = index.find("React portal")

    assert citation is not None
    assert citation.document == source_index.NARRATIVE_DOCUMENT
    assert citation.line == 1
    assert not index.multi_source


def test_document_headers_are_never_reported_as_design_statements():
    text = _document("orders-service-design.docx", "docx", "The portal is public.")
    index = source_index.build(text)

    # The filename contains a role noun. Anything matched here came from the
    # header, and the locator has to say so rather than implying a design line.
    header = index.cite(1)

    assert header is not None
    assert header.locator == source_index.HEADER_LOCATOR
    assert header.line is None


def test_known_issues_stop_at_the_next_uploaded_document_and_iac_is_not_prose():
    text = _assembled(
        _document(
            "docker-compose.yml", "yml",
            """# Health Check configuration
services:
  aitm:
    build: .
    ports: [\"8000:8000\"]
    environment:
      - ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-*}

[Structured paths]
$.services.aitm.ports[0] = '8000:8000'""",
        ),
        context="""A React client calls a FastAPI service.
KNOWN ISSUES:
- CORS allows wildcard origins.
- Internal service calls have no rate limiting.""",
    )

    architecture = ArchitectureParser().parse(text)
    issues = architecture.metadata["known_issues"]
    component_ids = {component.id for component in architecture.components}
    iac_rules = {finding["rule_id"] for finding in architecture.metadata["iac_findings"]}

    assert len(issues) == 2
    assert not any(issue["description"].startswith(("Document:", "Type:", "Role:")) for issue in issues)
    assert "aitm" in component_ids
    assert "health_service" not in component_ids
    assert "IAC-COMPOSE-CORS-WILDCARD" in iac_rules


def test_service_extraction_never_builds_a_component_name_across_bullets():
    architecture = ArchitectureParser().parse("""
- React SPA frontend hosted on CloudFront CDN
- API Gateway with OAuth2 via Auth0
- Python FastAPI microservices:
  1. Auth Service: Handles user management
  2. Billing Service: Integrates with Stripe
""")

    names = {component.name for component in architecture.components}
    assert "Auth Service" in names
    assert "Billing Service" in names
    assert not any("React SPA frontend hosted" in name and "Service" in name for name in names)


def test_evidence_quotes_the_design_rather_than_a_filename():
    # "user" appears in the User Context header and in the design. A component
    # named for the actor must be evidenced by the sentence, not the scaffolding.
    text = _assembled(
        _document("portal-service-design.docx", "docx", "Users sign in to the clinician portal."),
        context="Users access the system from the internet.",
    )
    result = ThreatAnalyzer().analyze_from_text(
        text, project_name="Header Evidence",
        source_documents=[{
            "filename": "portal-service-design.docx", "type": "docx",
            "role": "source_design", "characters": "40",
        }],
    )

    for component in result.architecture.components:
        for record in component.evidence or []:
            assert not str(record.get("statement", "")).startswith("Document:"), record
            assert not str(record.get("statement", "")).startswith("User Context:"), record
            assert record.get("locator") != source_index.HEADER_LOCATOR, record


def test_component_evidence_cites_the_document_that_named_the_component():
    text = _assembled(
        _document("edge.md", "md", "A React portal serves customers over the internet."),
        _document("data.md", "md", "A PostgreSQL orders database stores customer orders."),
    )
    result = ThreatAnalyzer().analyze_from_text(
        text, project_name="Provenance",
        source_documents=[
            {"filename": "edge.md", "type": "md", "role": "source_design", "characters": "60"},
            {"filename": "data.md", "type": "md", "role": "source_design", "characters": "60"},
        ],
    )

    cited = {
        component.name: (component.evidence or [{}])[0].get("document")
        for component in result.architecture.components
    }

    # The bug this replaces attributed every component to edge.md, the first
    # document uploaded, whatever the design actually said.
    assert any(document == "data.md" for document in cited.values()), cited
    assert any(document == "edge.md" for document in cited.values()), cited


def test_provenance_records_every_source_not_only_the_first():
    text = _assembled(
        _document("edge.md", "md", "A React portal serves customers."),
        _document("data.md", "md", "A PostgreSQL database stores orders."),
        context="The system handles retail orders.",
    )
    result = ThreatAnalyzer().analyze_from_text(
        text, project_name="Provenance Sources",
        source_documents=[
            {"filename": "edge.md", "type": "md", "role": "source_design", "characters": "40"},
            {"filename": "data.md", "type": "md", "role": "source_design", "characters": "40"},
        ],
    )
    provenance = (result.architecture.metadata or {}).get("source_provenance") or []
    names = [record.get("filename") for record in provenance]

    assert source_index.NARRATIVE_DOCUMENT in names
    assert "edge.md" in names and "data.md" in names

    attribution = (result.architecture.metadata or {}).get("source_attribution") or {}
    assert attribution.get("sources") == 3
    assert attribution.get("components_by_source")


def test_a_finding_cites_the_document_that_stated_its_weakness():
    text = _assembled(
        _document("edge.md", "md", "A React portal serves customers over the internet."),
        _document(
            "storage.md", "md",
            "[Page 4]\nThe S3 receipts bucket is not encrypted at rest.",
        ),
    )
    result = ThreatAnalyzer().analyze_from_text(
        text, project_name="Finding Citations",
        source_documents=[
            {"filename": "edge.md", "type": "md", "role": "source_design", "characters": "50"},
            {"filename": "storage.md", "type": "md", "role": "source_design", "characters": "60"},
        ],
    )

    cited = [
        record
        for threat in result.threats
        for record in threat.evidence_details or []
        if record.get("document") == "storage.md"
    ]

    assert cited, [
        (threat.id, [item.get("statement") for item in threat.evidence_details or []])
        for threat in result.threats
    ]
    assert any(record.get("locator") == "page 4" for record in cited), cited
    assert all(record.get("cite", "").startswith("storage.md") for record in cited), cited


def test_an_inferred_component_cites_nothing_rather_than_a_document():
    text = _document("edge.md", "md", "A React portal serves customers over the internet.")
    result = ThreatAnalyzer().analyze_from_text(
        text, project_name="Inference",
        source_documents=[{"filename": "edge.md", "type": "md", "role": "source_design", "characters": "50"}],
    )

    for component in result.architecture.components:
        evidence = (component.evidence or [{}])[0]
        if evidence.get("source_type") == "inference":
            assert evidence.get("document") is None, evidence
            assert evidence.get("line") is None, evidence
