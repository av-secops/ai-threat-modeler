# Nexora Telecom BSS: Supporting Controls

Document revision: controls-1.
Environment: production.
Deployment release: 26.09.
This document describes the same fictional system as architecture-scenario.txt.
These are architecture-owner statements, not evidence of runtime verification.

## Public Edge and Login

Public Edge has AWS WAF implemented. Public Edge uses managed web-exploit rules
and IP-based rate limiting. Public Edge does not provide a substitute for service
authorization or parameterized database queries.

Application Ingress accepts application traffic only from the approved edge path.
The private microservices do not expose their own public load balancers. Customer
and operator sessions access the public edge; a service's internal trust level
does not mean its public-facing API functionality is unreachable through ingress.

Customer Identity uses OAuth2/OIDC authorization-code login with PKCE. Customer
Identity implements brute-force protection through failed-login controls and
account-recovery verification. Workforce Identity requires MFA for operator and
platform support users. Customer Identity does not require MFA for every ordinary
subscriber. Do not transfer workforce MFA to customer accounts.

Customer Account Service validates JWT signatures, issuer and audience.
Subscriber Profile Service validates JWT signatures, issuer and audience.
Order Orchestration Service validates JWT signatures, issuer and audience.
Customer Support Service validates workforce token signatures, issuer and audience.
These authentication statements do not resolve the tenant-binding or entitlement
revocation weaknesses declared in the architecture document.

## Service Controls

Customer Account Service enforces object-level authorization using a tenant ID
derived from the authenticated server-side identity context. Customer Account
Service uses parameterized queries and request schema validation.

Product Catalog Service uses parameterized queries for catalog reads and writes.
Product Catalog Service enforces request schema validation for product changes.

Offer Pricing Service uses parameterized queries only on /quotes. The separate
administrative offer-search endpoint remains subject to K02. Do not credit that
narrow control to every Offer Pricing Service query.

Usage Mediation Service enforces request size limits and schema validation on
uploaded usage batches. Collector client credentials are bound to an operator at
ingestion. Deduplication beyond the short replay cache still has the K05 weakness.

Balance Wallet Service requires an authenticated workload identity and checks
that an operator's wallet belongs to the requested tenant. This does not provide
the missing atomicity for concurrent debits described in K07.

Notification Service applies output encoding to customer values in email templates.
Notification Service uses tenant-scoped template identifiers and does not accept
arbitrary executable templates from message events.

Fraud Analytics Service executes a deterministic rule set maintained by the
platform team. It is not an AI agent, has no LLM integration, and cannot execute
instructions from customer usage records.

## Payment Controls and Their Exception

Payment Provider performs hosted card-data collection. The platform stores
provider payment references and tokens, not PAN or CVV. Subscriber contact details
and financial transaction metadata remain sensitive platform data.

Payment Collections Service verifies webhook signatures only on
/payments/webhooks/stripe. Payment Collections Service enforces idempotency on
/payments/webhooks/stripe using a persisted provider event ID. Those protections
do not apply to /payments/webhooks/legacy, which remains enabled in production.

Payment Collections Service derives payable amount, currency and billing-account
reference from server-side order state before creating a PaymentIntent. Browser
supplied success flags do not authorize a wallet credit. The legacy webhook
exception must be assessed separately rather than treating all callbacks as safe.

## Data, AWS and Kubernetes

Business Database has encryption at rest, TLS connections and automated backups.
Business Database is not publicly accessible. Application database roles are
restricted to service-owned schemas and approved reporting views.

Charging State Store has encryption at rest. Charging State Store permits access
through approved workload IAM roles. Encryption does not establish event uniqueness
or correct conditional writes in an application.

Session Cache has TLS and authentication enabled. Session Cache is in private
subnets and accepts connections only from approved workload security contexts.
Private authenticated Redis does not invalidate stale application entitlements.

Billing Documents has S3 Block Public Access enabled and uses KMS-backed encryption
at rest. Billing Documents requires encrypted transport. Its private configuration
does not revoke an already issued presigned URL or narrow the broad K13 role.

Product Assets contains only non-sensitive product graphics. Product Assets uses
CloudFront origin access rather than an anonymous S3 bucket policy. Product images
are public through the CDN by design; this is not public access to Billing Documents.

Service Secrets stores provider credentials and database secrets. Service Secrets
uses KMS-backed encryption and role-scoped secret retrieval. No static AWS access
keys are embedded in application container images.

Provisioning Queue has a dead-letter queue and a finite retry policy. Consumers
record processing failures. These controls do not validate an arbitrary outbound
URL or authorize a forged business transition.

EKS runs non-root application containers, uses read-only root filesystems where
supported, and restricts privileged workloads. Kubernetes RBAC separates routine
application deployment from cluster administration. Namespace NetworkPolicies
allow specified application dependencies; they do not validate MSK event contents.

## Logging, Build and Recovery

Application Logging receives application events and operational telemetry. The
support troubleshooting exception in K16 remains active and must not be hidden
by this general logging statement.

Security Audit sends CloudTrail management events to the separate security account.
Production application roles cannot delete the cross-account audit destination.
CloudTrail is not a complete substitute for application-level billing, refund,
settlement-approval or support-action audit events.

Build Pipeline uses GitHub OIDC federation for its AWS role. Its trust policy
restricts the repository and protected production environment. Container Registry
performs vulnerability scanning. Container signature enforcement is planned for
release 26.10; do not count it as implemented in production release 26.09.

Business Database backups and Billing Documents replicas are available in the
recovery region. Restore procedures exist. The evidence supplied here does not
establish whether the complete charging and settlement workflow has passed an
end-to-end recovery test; retain that as an open question.

## Scope and Review Notes

Source statements about an implemented control may complement the main prompt.
A narrow path-specific control does not contradict a weakness on another path.
A proposed future-release control does not remediate the current release.
Where this document does not establish a control, ask for evidence instead of
asserting an unverified configuration defect.
