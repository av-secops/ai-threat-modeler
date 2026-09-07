"""Repeatable output/performance probes; not an independently reviewed benchmark."""

import argparse
import cProfile
import json
import os
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--local-ai", action="store_true")
    args = parser.parse_args()
    from app.engine.analyzer import ThreatAnalyzer

    profile = cProfile.Profile()
    if args.profile:
        profile.enable()
    started = perf_counter()
    analyzer = ThreatAnalyzer()
    initialization = perf_counter() - started
    outputs = []
    for name, description in SCENARIOS.items():
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
        outputs.append({"scenario": name, "input": description,
                        "elapsed_ms": round((finished - started) * 1000, 2),
                        "phase_ms": phase_ms, "result": data})
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
    args.output.write_text(json.dumps({
        "scope": "Development probes, not independent accuracy validation",
        "local_ai_enabled": args.local_ai,
        "initialization_ms": round(initialization * 1000, 2), "scenarios": outputs,
    }, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"Initialization: {initialization:.3f}s; report: {args.output}")


if __name__ == "__main__":
    main()
