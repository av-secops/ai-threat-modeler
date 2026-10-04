from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools.aegis_cli import gate_model, main

CLI = Path(__file__).resolve().parents[1] / "tools" / "aegis_cli.py"


def report():
    return {"model_id": "shop", "project_name": "Shop", "architecture": {
        "components": [{"id": "api", "name": "API", "type": "Service"}], "flows": []}, "threats": [],
        "engine_status": {"quality_gate": {"status": "ready", "integrity_violations": [], "completeness_warnings": []},
                          "knowledge_base": {"content_digest": "fixture-not-human-validation"}}}


def write(tmp_path, value, name="model.json"):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def run(*args, seed="1"):
    return subprocess.run([sys.executable, str(CLI), *args], text=True, capture_output=True,
        timeout=30, env={**os.environ, "PYTHONHASHSEED": seed, "AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD": "0"})


def test_validate_returns_machine_readable_result_without_analysis(tmp_path):
    result = run("validate", write(tmp_path, report()))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["valid"] is True


def test_compare_deterministic_across_hash_seeds_and_does_not_claim_remediation(tmp_path):
    before, after = report(), report()
    before["threats"] = [{"id": "auth", "title": "Authorization", "category": "Elevation of Privilege", "severity": "High",
        "description": "Test authorization", "mitigation": "Enforce checks", "affected_components": ["api"]}]
    a, b = write(tmp_path, before, "before.json"), write(tmp_path, after, "after.json")
    first, second = run("compare", a, b, "--fail-on-change"), run("compare", a, b, "--fail-on-change", seed="57")
    assert first.returncode == second.returncode == 3, first.stderr
    assert first.stdout == second.stdout
    comparison = json.loads(first.stdout)
    assert comparison["findings"]["no_longer_reported"]
    assert "not verified remediation" in comparison["notice"]


def test_gate_zero_findings_does_not_pass_without_engine_gate(tmp_path):
    value = report()
    value.pop("engine_status")
    result = run("gate", write(tmp_path, value))
    assert result.returncode == 3
    assert "missing_quality_gate" in result.stdout


def test_gate_enforces_review_and_severity_policy():
    value = report()
    assert gate_model(value)["passed"]
    value["engine_status"]["quality_gate"]["status"] = "review"
    assert not gate_model(value)["passed"]
    assert gate_model(value, allow_review=True)["passed"]
    value["engine_status"]["quality_gate"]["status"] = "ready"
    value["threats"] = [{"id": "auth", "title": "Authorization", "category": "Elevation of Privilege", "severity": "High",
        "description": "Test authorization", "mitigation": "Enforce checks", "affected_components": ["api"],
        "tier": "Confirmed", "review_status": "verified_fixed"}]
    result = gate_model(value)
    assert {f["check"] for f in result["failures"]} == {"severity_threshold", "confirmed_without_evidence"}


def test_export_warnings_are_visible_and_strict_conversion_does_not_publish(tmp_path):
    source, output = write(tmp_path, report()), str(tmp_path / "external.json")
    strict = run("export", source, "--format", "otm", "--fail-on-loss", "--out", output)
    assert strict.returncode == 3
    assert not Path(output).exists()
    assert "conversion_requires_review" in strict.stderr
    accepted = run("export", source, "--format", "otm", "--out", output)
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(Path(output).read_text())["otmVersion"] == "0.2.0"
    assert "warnings" in accepted.stderr


def test_cli_never_overwrites_input_or_existing_output_implicitly(tmp_path):
    source, output = write(tmp_path, report()), str(tmp_path / "output.json")
    assert run("import", source, "--out", source, "--force").returncode == 2
    assert run("import", source, "--out", output).returncode == 0
    assert run("import", source, "--out", output).returncode == 2
    assert run("import", source, "--out", output, "--force").returncode == 0


@pytest.mark.parametrize("value", [{}, {"architecture": []}, {"architecture": {"components": [], "flows": []}}])
def test_invalid_input_returns_code_two_without_traceback(tmp_path, value):
    result = run("validate", write(tmp_path, value))
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "invalid_input"


def test_invalid_json_and_missing_file_exit_codes(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{bad")
    assert run("validate", str(bad)).returncode == 2
    assert run("validate", str(tmp_path / "missing.json")).returncode == 4


def test_discovery_requires_optin_before_optional_sdk_or_any_network():
    result = run("discover-aws", "--account-id", "123456789012", "--region", "us-east-1", "--services", "ec2")
    assert result.returncode == 2
    assert "--allow-network" in result.stderr


def test_offline_commands_do_not_connect_network(tmp_path, monkeypatch, capsys):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("Unexpected network"))
    source = write(tmp_path, report())
    assert main(["validate", source]) == 0
    assert main(["compare", source, source]) == 0
    assert main(["gate", source]) == 0
    assert main(["export", source, "--format", "threat-dragon"]) == 0


def test_partial_drift_fails_ci_even_without_fail_on_change(tmp_path):
    baseline = {"schema_version": "aegis-cloud-snapshot/1", "provider": "aws", "account_id": "123456789012",
        "region": "us-east-1", "observed_at": "2026-10-04T12:00:00Z", "resources": [], "coverage": {"ec2": {"status": "complete"}}}
    observed = deepcopy(baseline)
    observed["coverage"]["ec2"] = {"status": "partial", "reason": "AccessDenied"}
    a, b = write(tmp_path, baseline, "before.json"), write(tmp_path, observed, "after.json")
    result = run("drift", a, b)
    assert result.returncode == 3
    assert json.loads(result.stdout)["coverage"]["ec2"]["status"] == "partial"
