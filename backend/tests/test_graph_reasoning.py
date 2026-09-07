"""What the architecture graph is asked, and what it is allowed to answer.

These cover the passes that read the graph rather than the text: which flows a
description states, which the tool supplies, how far a weakness reaches, and
which data a component turns out to handle.
"""

import pytest

from app.engine import graph, prose
from app.engine.analyzer import ThreatAnalyzer
from app.engine.parser import ArchitectureParser
from app.models import Component, DataFlow


HEALTHCARE = (
    "A public React web portal calls a Node.js REST API over HTTPS. "
    "The API authenticates staff against Azure AD, stores patient records in a "
    "PostgreSQL database, and uploads scanned documents to an S3 ingestion bucket. "
    "The API also sends results to a laboratory partner. "
    "The portal has no MFA and the ingestion bucket is not encrypted at rest."
)


@pytest.fixture(scope="module")
def healthcare():
    return ArchitectureParser().parse(HEALTHCARE)


@pytest.fixture(scope="module")
def healthcare_flows(healthcare):
    return {(flow.source_id, flow.target_id): flow for flow in healthcare.flows}


def test_a_list_of_verbs_keeps_the_subject_it_was_given(healthcare_flows):
    """"The API authenticates against X, stores in Y, and uploads to Z".

    Each verb belongs to the API. Splitting the list at ", and" left the last
    verb without a subject, and the middle one took the previous object as its
    subject, so the model claimed the identity provider wrote to the database.
    """
    assert ("node_js", "azure_ad") in healthcare_flows
    assert ("node_js", "postgresql") in healthcare_flows
    assert ("node_js", "s3") in healthcare_flows
    assert ("azure_ad", "postgresql") not in healthcare_flows


def test_a_role_noun_refers_to_the_only_component_that_can_answer_it(healthcare_flows):
    """The description says "a Node.js REST API" once and "the API" after."""
    assert ("node_js", "laboratory_partner") in healthcare_flows


def test_every_flow_the_description_states_is_stated_not_guessed(healthcare_flows):
    assert all(
        flow.properties.get("origin") == "stated" and flow.assumed is False
        for flow in healthcare_flows.values()
    )


def test_a_weakness_attaches_to_the_component_the_sentence_names(healthcare):
    """"The portal has no MFA and the ingestion bucket is not encrypted at rest".

    Two claims about two components, joined without a comma. Read as one clause
    both attached to the portal, and the bucket's missing encryption was filed
    against a browser.
    """
    components = {component.id: component for component in healthcare.components}

    assert components["s3"].properties.get("encryption_at_rest") is False
    assert components["react"].properties.get("mfa_enabled") is False
    assert components["react"].properties.get("encryption_at_rest") is not False


def test_a_classification_travels_with_the_data(healthcare):
    """Patient records are named once; every component handling them is PHI."""
    components = {component.id: component for component in healthcare.components}

    assert components["postgresql"].properties["data_sensitivity"] == "phi"
    assert components["node_js"].properties["data_sensitivity"] == "phi"
    assert components["node_js"].properties["data_sensitivity_basis"] == "propagated"
    assert "carried from" in components["node_js"].properties["data_sensitivity_reason"]


def test_a_stated_classification_is_not_overruled_by_a_deduction():
    architecture = ArchitectureParser().parse(
        "A billing service reads payment records from a ledger database and writes "
        "to an audit log."
    )
    components = {component.id: component for component in architecture.components}

    assert components["ledger_database"].properties["data_sensitivity_basis"] == "stated"


def test_a_compute_tier_is_connected_like_any_other_backend():
    """"a website with ec2 on backend and s3 for images and an rds db".

    Nothing here says what talks to what, and the type templates keyed off names
    that this description never uses, so the tool produced no data flows at all.
    """
    architecture = ArchitectureParser().parse(
        "a website with ec2 on backend and s3 bucket for image store and a aws rds db"
    )
    flows = {(flow.source_id, flow.target_id) for flow in architecture.flows}

    assert ("web_application", "ec2") in flows
    assert ("ec2", "rds") in flows
    assert ("ec2", "s3") in flows
    assert all(flow.assumed for flow in architecture.flows), "a guess must read as a guess"


def test_blast_radius_is_what_the_graph_reaches():
    flows = [
        DataFlow(source_id="a", target_id="b", protocol="https"),
        DataFlow(source_id="b", target_id="c", protocol="https"),
        DataFlow(source_id="c", target_id="d", protocol="https"),
    ]

    assert graph.downstream("a", flows) == {"b", "c", "d"}
    assert graph.downstream("d", flows) == set()


def test_a_cycle_does_not_trap_the_walk():
    flows = [
        DataFlow(source_id="a", target_id="b", protocol="https"),
        DataFlow(source_id="b", target_id="a", protocol="https"),
    ]

    assert graph.downstream("a", flows) == {"b"}


def test_the_most_sensitive_claim_decides():
    assert graph.most_sensitive("application_data", "phi", "pii") == "phi"
    assert graph.most_sensitive(None, None) is None


def test_reading_from_a_store_means_handling_what_it_holds():
    components = {
        "service": Component(id="service", name="Service", type="Service"),
        "store": Component(
            id="store", name="Store", type="Database",
            properties={"data_sensitivity": "financial"},
        ),
    }
    reasons = graph.propagate_sensitivity(
        components, [DataFlow(source_id="service", target_id="store", protocol="tcp")],
    )

    assert reasons["service"][0] == "financial"


def test_a_coordinated_object_is_not_a_second_claim():
    """"sends records to the database and the bucket" names one action."""
    assert prose.clauses("The API sends records to the database and the bucket.") == (
        "The API sends records to the database and the bucket.",
    )


def test_a_finding_is_reached_through_the_architecture_not_at_itself():
    """The bucket is not an entry point, so its path runs in from the portal."""
    result = ThreatAnalyzer().analyze_from_text(HEALTHCARE, use_local_slm=False)
    encryption = next(
        threat for threat in result.threats
        if threat.component == "s3" and "ncrypt" in threat.title
    )

    assert encryption.attack_path["hops"], "a finding two hops in must show the hops"
    assert encryption.attack_path["entry_component_id"] == "react"
    assert encryption.attack_path["path_status"] == "explicit"


def test_a_path_names_the_data_it_opens_up():
    result = ThreatAnalyzer().analyze_from_text(HEALTHCARE, use_local_slm=False)
    reached = next(threat for threat in result.threats if threat.attack_path)

    assert reached.attack_path["hops"]
    assert reached.attack_path["sensitive_data_reached"]


def test_one_control_absent_on_one_component_is_one_finding():
    result = ThreatAnalyzer().analyze_from_text(
        "A records service stores patient data in a ledger database. "
        "The ledger database is not encrypted at rest.",
        use_local_slm=False,
    )
    encryption = [
        threat for threat in result.threats
        if threat.component == "ledger_database" and "ncrypt" in threat.title
    ]

    assert len(encryption) == 1
    assert encryption[0].id.startswith("KB-"), "the named rule outranks the general pattern"
    assert "CWE-311" in encryption[0].cwe, "the general pattern's mapping is kept"
