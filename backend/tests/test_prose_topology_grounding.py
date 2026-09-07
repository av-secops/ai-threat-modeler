import pytest

from app.engine.flow_extraction import extract_stated_flows
from app.engine.parser import ArchitectureParser
from app.engine.prose import architecture_assertions
from app.models import Component


@pytest.mark.parametrize("exclusion", [
    "No LLM or AWS services are used.",
    "LLM and AWS services are not deployed.",
    "We do not use LLM or AWS services.",
])
def test_inline_exclusions_do_not_create_technologies(exclusion):
    architecture = ArchitectureParser().parse(
        "React calls a Node.js REST API. PostgreSQL stores records. " + exclusion
    )
    assert {c.type for c in architecture.components} >= {"WebClient", "API", "Database"}
    names = " ".join(c.name.lower() for c in architecture.components)
    assert "llm" not in names
    assert "aws" not in names


def test_absent_controls_do_not_erase_their_component():
    architecture = ArchitectureParser().parse("Redis has no authentication. The API has no input validation.")
    assert any(c.id == "redis" and c.properties.get("auth_type") == "none" for c in architecture.components)


@pytest.mark.parametrize("text", [
    "MFA is not used on the API.", "The API does not use authentication.",
    "PostgreSQL encryption at rest is not used.",
])
def test_exclusion_filter_preserves_missing_control_statements(text):
    assert architecture_assertions(text) == text


def test_rest_api_and_interoperability_api_are_distinct():
    architecture = ArchitectureParser().parse(
        "React calls a REST API over HTTPS. The REST API calls an HL7 FHIR API over mTLS."
    )
    apis = [c for c in architecture.components if c.type == "API"]
    assert len(apis) == 2
    pairs = {(f.source_id, f.target_id): f for f in architecture.flows}
    assert ("react", "rest_api") in pairs
    assert ("rest_api", "hl7_fhir_api") in pairs
    assert ("react", "hl7_fhir_api") not in pairs
    assert pairs[("rest_api", "hl7_fhir_api")].protocol.upper() == "MTLS"


def test_logging_verb_does_not_become_an_api_component():
    architecture = ArchitectureParser().parse("CloudTrail logs API calls. React calls a Node.js API.")
    assert not any("logs api" in c.name.lower() for c in architecture.components)
    assert any(c.type in {"Monitoring", "Threat Detection"} and "cloudtrail" in c.name.lower() for c in architecture.components)


def test_logging_api_calls_does_not_declare_a_generic_application_api():
    architecture = ArchitectureParser().parse("AWS API Gateway routes to Lambda. CloudTrail logs API calls.")
    assert not any(c.type == "API" for c in architecture.components)


def test_exchanges_and_consumes_are_explicit_relationships():
    flows = extract_stated_flows("API exchanges records with PostgreSQL. Lambda consumes SQS.", components())
    assert {(f["source_id"], f["target_id"]) for f in flows} == {("API", "PostgreSQL"), ("SQS", "Lambda")}


def components():
    return {name: Component(id=name, name=name, type=kind) for name, kind in [
        ("Lambda", "Service"), ("S3", "Object Storage"), ("DynamoDB", "Database"), ("SQS", "Queue"),
        ("React", "WebClient"), ("API", "API"), ("PostgreSQL", "Database"),
    ]}


def test_shared_subject_survives_read_and_publish_verbs():
    flows = extract_stated_flows("Lambda reads S3 and DynamoDB and publishes messages to SQS.", components())
    assert {(f["source_id"], f["target_id"]) for f in flows} == {
        ("S3", "Lambda"), ("DynamoDB", "Lambda"), ("Lambda", "SQS"),
    }


@pytest.mark.parametrize("protocol", ["TLS", "MTLS", "GRPCS", "WSS", "WS"])
def test_explicit_transport_is_preserved(protocol):
    flows = extract_stated_flows(f"API writes records to PostgreSQL over {protocol}.", components())
    assert len(flows) == 1
    assert flows[0]["protocol"] == protocol


def test_protocol_is_scoped_to_its_hop():
    flows = extract_stated_flows("React calls API over HTTPS which writes records to PostgreSQL over HTTP.", components())
    assert {(f["source_id"], f["target_id"]): f["protocol"] for f in flows} == {
        ("React", "API"): "HTTPS", ("API", "PostgreSQL"): "HTTP",
    }


def test_negated_flow_is_not_reported_as_a_connection():
    flows = extract_stated_flows("React does not call PostgreSQL. React calls API.", components())
    assert {(f["source_id"], f["target_id"]) for f in flows} == {("React", "API")}
