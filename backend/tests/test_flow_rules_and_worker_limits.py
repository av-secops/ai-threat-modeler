import asyncio
import threading

import pytest

from app.engine.knowledge_threat_engine import KnowledgeThreatEngine
from app.engine.iac_security import IaCSecurityAnalyzer
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Component, DataFlow, SystemArchitecture
from app.services.analysis_workers import AnalysisBusy, AnalysisWorkers


@pytest.fixture(scope="module")
def engine():
    return KnowledgeThreatEngine(ThreatKnowledgeBase())


@pytest.mark.parametrize("protocol,authenticated,assumed,expected", [
    ("HTTP", True, False, {"LAT-002"}),
    ("HTTPS", True, False, set()),
    ("TCP", True, False, set()),
    ("TLS", False, False, {"LAT-001"}),
    ("HTTP", False, True, set()),
    ("HTTPS", None, False, set()),
])
def test_explicit_flow_rules_do_not_invent_plaintext_or_missing_auth(engine, protocol, authenticated, assumed, expected):
    architecture = SystemArchitecture(components=[Component(id=name, name=name, type="API") for name in ("a", "b")], flows=[
        DataFlow(source_id="a", target_id="b", protocol=protocol, assumed=assumed,
                 properties={"trust_boundary": "internal", "authenticated": authenticated}),
    ])
    findings, _ = engine.analyze(architecture)
    actual = {f.id[3:10] for f in findings if f.id.startswith("KB-LAT-")}
    assert actual == expected


def test_timed_out_and_cancelled_workers_keep_their_slots():
    async def exercise():
        workers = AnalysisWorkers(1)
        release = threading.Event()
        started = threading.Event()

        def work():
            started.set()
            assert release.wait(5)

        task = asyncio.create_task(workers.run(work, timeout=0.05))
        while not started.is_set():
            await asyncio.sleep(0.001)
        with pytest.raises(asyncio.TimeoutError):
            await task
        try:
            with pytest.raises(AnalysisBusy):
                await workers.run(lambda: None)
        finally:
            release.set()
        for _ in range(100):
            try:
                assert await workers.run(lambda: 42) == 42
                break
            except AnalysisBusy:
                await asyncio.sleep(0.01)
        else:
            pytest.fail("Worker did not release its slot")
    asyncio.run(exercise())


def test_security_group_does_not_mix_egress_cidrs_and_ingress_ports():
    source = '''resource "aws_security_group" "app" {
      ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["10.0.0.0/8"] }
      egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
    }'''
    analyzer = IaCSecurityAnalyzer()
    assert not analyzer._analyze_security_group(source, "aws_security_group.app", 1)
    findings = analyzer._analyze_security_group(source.replace('"10.0.0.0/8"', '"0.0.0.0/0"'), "aws_security_group.app", 1)
    assert len(findings) == 1 and findings[0]["severity"] == "Critical"
    assert findings[0]["exposure"] != "public"


@pytest.mark.parametrize("host,expected", [("127.0.0.1", False), ("::1", False), ("0.0.0.0", True), ("::", True)])
def test_compose_long_port_syntax_respects_host_binding(host, expected):
    document = {"services": {"db": {"ports": [{"target": 5432, "published": "15432", "host_ip": host}]}}}
    findings = IaCSecurityAnalyzer()._analyze_compose(document, "db:")
    assert any(f["rule_id"] == "IAC-COMPOSE-PUBLIC-SENSITIVE-PORT" for f in findings) is expected
