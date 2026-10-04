"""Repeatable output/performance probes; not an independently reviewed benchmark."""

import argparse
import cProfile
import json
import os
import platform
import math
import statistics
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD", "0")

SCENARIOS = {
    "simple_web": "A website on Node.js with a React frontend. Keycloak manages authentication. The backend runs on AWS EC2 and stores product images in S3.",
    "secure_web": """React frontend calls a Node.js REST API over HTTPS. The API reads PostgreSQL over TLS.
The Node.js REST API validates input using schemas and uses parameterized SQL queries.
Keycloak uses OAuth2 with MFA, refresh-token rotation and short-lived tokens.
PostgreSQL has encryption at rest and is private. No LLM or AWS services are used.""",
    "saas": """A multi-tenant SaaS uses React, a Node.js GraphQL API, PostgreSQL, Redis sessions, Auth0 and Stripe.
React calls GraphQL over HTTPS. GraphQL reads PostgreSQL and Redis. Stripe sends webhooks to the Node.js API.
KNOWN ISSUES:
- The GraphQL endpoint has no query depth or cost limits.
- Session tokens remain valid after password changes.
- Tenant identifiers from requests are trusted without checking the authenticated tenant.
- Stripe webhook signatures are not verified.""",
    "aws": """AWS API Gateway routes to Lambda. Lambda reads S3 and DynamoDB and publishes messages to SQS.
EKS workers consume SQS messages and use KMS keys. CloudTrail logs API calls.
KNOWN ISSUES:
- The Lambda execution role grants s3:* on *.
- The S3 bucket is public and stores customer invoices.
- EC2 instances do not require IMDSv2.
- The KMS key policy allows all principals to decrypt.""",
    "healthcare": """Healthcare records management system with React, a .NET Core REST API, Azure AD,
PostgreSQL for PHI, Redis for sessions, Azure Blob Storage and an HL7 FHIR API.
The REST API uses OAuth2 and MFA. React calls the REST API over HTTPS.
The REST API reads PostgreSQL and Redis and exchanges records with the FHIR API.
KNOWN ISSUES:
- Session timeout is 8 hours for PHI access.
- Break-the-glass access is not audited separately.""",
    "payments": """React calls a Node.js payments API over HTTPS. The API creates Stripe PaymentIntents.
Stripe sends HTTPS webhooks to the API. The API writes orders to PostgreSQL over TLS.
Stripe webhook signatures are verified against the raw body. The API validates amount and currency server-side.
Idempotency keys and replay protection prevent duplicate payment processing. PostgreSQL is encrypted at rest.""",
    "ai_agents": """A multi-tenant support SaaS uses React, a Node.js REST API, Azure OpenAI, an OpenSearch vector database,
an autonomous agent and an MCP server. The agent queries OpenSearch and calls MCP tools for refunds through Stripe.
Tenant PDFs are ingested into the vector database. Entra ID authenticates staff. Redis caches conversations.
KNOWN ISSUES:
- Retrieval queries do not enforce tenant filters.
- The agent executes shell commands from untrusted tool descriptions.
- The MCP client forwards its broad GitHub token to every MCP server.
- Refund tool calls have no human approval.""",
    "hybrid": """React calls an AWS API Gateway over HTTPS. API Gateway routes to EKS services with PostgreSQL on RDS.
EKS sends events to SQS. A Lambda consumer copies documents to Azure Blob Storage over HTTPS.
An Azure AI agent retrieves documents and calls a private MCP server. GitHub Actions deploys to EKS using OIDC.
CloudTrail and Azure Monitor collect audit events. Stripe webhooks enter through a dedicated payments API.
KNOWN ISSUES:
- Kubernetes pods run privileged and mount the host filesystem.
- GitHub Actions accepts pull requests from forks with write permissions.
- The agent logs full customer prompts containing personal information.
- The payments API does not verify webhook signatures.""",
}

SCENARIOS.update({
    'mfa_present': 'The admin portal calls the management API over HTTPS. The admin portal enforces multi-factor authentication.',
    'mfa_absent': 'The admin portal calls the management API over HTTPS. The admin portal has no multi-factor authentication.',
    'rate_limit_present': 'React calls the Orders API over HTTPS. Orders API enforces rate limiting.',
    'rate_limit_absent': 'React calls the Orders API over HTTPS. Orders API has no rate limiting.',
    'endpoint_exception': 'React calls Orders API over HTTPS. Orders API enforces rate limiting. Orders API has no rate limiting on /export.',
    'document_control': 'Document: prompt.txt\nType: txt\nContent:\nReact calls Orders API over HTTPS.\n\n---\nDocument: controls.pdf\nType: pdf\nContent:\n[Page 2]\nOrders API enforces rate limiting and validates input.',
    'conflicting_controls': 'Orders API stores orders in PostgreSQL.\nKnown issues:\n- Orders API has no rate limiting.\nControls:\nOrders API enforces rate limiting.',
    'planned_controls': 'React calls Orders API over HTTPS. Orders API will implement rate limiting. PostgreSQL encryption at rest is planned.',
    'tenant_isolation': 'A multi-tenant SaaS uses an Orders API and PostgreSQL. Orders API enforces object-level authorization and tenant isolation. PostgreSQL uses row-level security.',
    'tenant_weakness': 'A multi-tenant SaaS uses an Orders API and PostgreSQL.\nKnown issues:\n- Orders API trusts tenant identifiers from requests without checking the authenticated tenant.',
    'control_verbs': 'React calls Orders API over HTTPS. Orders API stores records in PostgreSQL. KMS encrypts database storage. Rate limits protect API gateway.',
    'async_workflow': 'Orders API publishes billing events to Kafka over TLS. Billing worker consumes Kafka and stores invoices in PostgreSQL.\nKnown issues:\n- Billing worker does not validate tenant identifiers on consumed messages.',
})


def scale_scenario(size):
    components = '\n'.join(f'Row {i + 1}: C{i} | Service {i:03d} | Node.js API | Internal tenant record processing' for i in range(1, size + 1))
    flows = '\n'.join(f'Row {i + 1}: F{i} | C{i} -> C{i + 1} | HTTPS | Tenant records' for i in range(1, size))
    return (f'Document: scale-{size}.txt\nType: txt\nRole: source_design\nContent:\n'
        f'[Table 1]\nRow 1: ID | Component | Technology | Responsibility / Data\n{components}\n\n'
        f'[Table 2]\nRow 1: ID | Source and destination | Protocol | Data\n{flows}\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--local-ai", action="store_true")
    parser.add_argument("--repeats", type=int, default=1, help="1-50 runs per scenario; separates first-run and warm samples.")
    parser.add_argument("--scale", action="store_true", help="Also exercise explicit 10/50/200-component synthetic chain models.")
    parser.add_argument("--compare", type=Path, help="Earlier probe report from the same hardware and configuration.")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 50:
        parser.error('--repeats must be between 1 and 50')
    from app.engine.analyzer import ThreatAnalyzer

    profile = cProfile.Profile()
    if args.profile:
        profile.enable()
    started = perf_counter()
    analyzer = ThreatAnalyzer()
    initialization = perf_counter() - started
    outputs = []
    scenarios = dict(SCENARIOS)
    if args.scale:
        scenarios.update({f'scale_{size}': scale_scenario(size) for size in (10, 50, 200)})
    for name, description in scenarios.items():
        phases = []
        started = perf_counter()
        result = analyzer.analyze_from_text(
            description, name, use_local_slm=args.local_ai,
            progress=lambda event: phases.append((event["phase"], perf_counter())),
        )
        finished = perf_counter()
        endpoints = [*phases[1:], ("complete", finished)]
        phase_ms = {
            phase: round((end - begin) * 1000, 2)
            for (phase, begin), (_, end) in zip(phases, endpoints)
        }
        data = result.model_dump()
        warm_ms, digests = [], {result.engine_status.get('analysis_manifest', {}).get('semantic_output_digest')}
        for _ in range(args.repeats - 1):
            repeat_started = perf_counter()
            repeated = analyzer.analyze_from_text(description, name, use_local_slm=args.local_ai)
            warm_ms.append(round((perf_counter() - repeat_started) * 1000, 2))
            digests.add(repeated.engine_status.get('analysis_manifest', {}).get('semantic_output_digest'))
        outputs.append({"scenario": name, "input": description,
                        "review_status": "engineering_probe_not_independently_reviewed",
                        "elapsed_ms": round((finished - started) * 1000, 2),
                        "phase_ms": phase_ms, "result": data,
                        "warm_samples_ms": warm_ms,
                        "warm_p50_ms": statistics.median(warm_ms) if warm_ms else None,
                        "warm_p95_ms": sorted(warm_ms)[math.ceil(len(warm_ms) * .95) - 1] if warm_ms else None,
                        "repeated_semantics_stable": len(digests) == 1 if args.repeats > 1 else None})
        print(json.dumps({"scenario": name, "ms": outputs[-1]["elapsed_ms"],
                          "components": len(result.architecture.components),
                          "findings": len(result.threats),
                          "confirmed": sum(t.tier == "Confirmed" for t in result.threats),
                          "evidence_resolution": result.stride_coverage["evidence_resolution_percent"]}), flush=True)
    if args.profile:
        profile.disable()
        args.profile.parent.mkdir(parents=True, exist_ok=True)
        profile.dump_stats(str(args.profile))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    comparison = []
    if args.compare:
        previous = {row['scenario']: row for row in json.loads(args.compare.read_text(encoding='utf-8'))['scenarios']}
        for current in outputs:
            old = previous.get(current['scenario'])
            if not old or old.get('input') != current['input']:
                continue
            before = {t['id']: t for t in old['result']['threats']}
            after = {t['id']: t for t in current['result']['threats']}
            comparison.append({'scenario': current['scenario'], 'added': sorted(after.keys() - before.keys()),
                'removed': sorted(before.keys() - after.keys()),
                'changed': sorted(key for key in before.keys() & after.keys() if any(
                    before[key].get(field) != after[key].get(field) for field in ('severity', 'tier', 'affected_components', 'evidence_details'))),
                'latency_ratio': current['elapsed_ms'] / old['elapsed_ms'] if old.get('elapsed_ms') else None})
    args.output.write_text(json.dumps({
        "scope": "Development probes, not independent accuracy validation",
        "corpus_version": "analysis-quality-probes-1", "independent_acceptance": "pending_reviewed_corpus",
        "comparison": comparison,
        "local_ai_enabled": args.local_ai,
        "run_configuration": {"python": platform.python_version(), "platform": platform.platform(),
            "machine": platform.machine(), "logical_cpus": os.cpu_count(), "repeats": args.repeats,
            "timing_scope": "First call per scenario followed by shared-process warm runs; not isolated cold model-start benchmarks."},
        "initialization_ms": round(initialization * 1000, 2), "scenarios": outputs,
    }, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"Initialization: {initialization:.3f}s; report: {args.output}")


if __name__ == "__main__":
    main()
