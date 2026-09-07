# Nexora Telecom BSS: Chrome Run Review

Run: 7 September 2026, generated at 21:24:31 local time.
Analysis: Nexora Telecom BSS 26.09 - Chrome review, revision 1.
Method: submitted prompt.txt through Chrome, uploaded architecture-scenario.txt and supporting-controls.md, selected SaaS / Multi-tenant, and set model scope to production / 26.09. Local semantic analysis remained enabled. No architecture facts or answers were invented to clear the review warnings.

This is a review of one fictional scenario, not an assessment of Amdocs or a statistically representative benchmark. No application code was changed.

## Verdict

Not suitable for security sign-off. The component/flow inventory was preserved, but evidence interpretation, declared-issue recognition, diagram boundaries and reporting contain substantive errors. The displayed 50/100 score should not be treated as a reliable measure of this scenario's security.

## Observed Results

| Metric | Actual output |
| --- | --- |
| Included sources | Prompt plus both uploaded documents; both files reported text_complete |
| Model inventory | 42 components, including all 16 microservices; 74 explicit flows; 9 declared boundaries retained in the model |
| Findings | 20: 4 Confirmed, 4 other Potential findings, 12 validation questions |
| All findings by severity | 1 Critical, 9 High, 6 Medium, 4 Low |
| Confirmed severity subtotal | 0 Critical, 4 High; arithmetic matches the register |
| STRIDE distribution | S 4, T 3, R 2, I 6, D 1, E 4 |
| Reported attack paths | 4 |
| Publication | Blocked; final PDF disabled |
| Assessment versus evidence | 100% assessed, but only 11.4% evidence resolution; 599 of 676 applicable cells unresolved |
| Review questions | 889 initially; 855 after production/release scope; final report displays 20 follow-up questions |
| Unassigned control statements | 36 |
| Backend analysis duration | 39.52 seconds, including 35.06 seconds in local intelligence; excludes upload and preview preparation |
| Final drawing | 40/42 components and 60/74 flows visible |

## Check Against All 16 Declared Weaknesses

"Missing" below means the final register lacks a correctly scoped finding for that stated root cause. A generic question about the same component is not counted as successful detection. These are owner-declared weaknesses, not runtime-confirmed exploits.

| ID | Expected weakness | Final output review |
| --- | --- | --- |
| K01 | Subscriber Profile trusts X-Tenant-ID without tenant membership validation | Missing as a specific cross-tenant authorization finding. |
| K02 | Offer Pricing administrative search concatenates PostgreSQL query input | Missing SQL injection finding; /quotes protection must not cover administrative search. |
| K03 | Forged provisioning events can select unauthorized tenants/order transitions | Missing producer/tenant binding and state-transition finding. |
| K04 | Provisioning callback URL can target private/link-local destinations | Correctly detected as High outbound destination validation absent, with relevant remediation and source evidence. |
| K05 | Usage replay after the 15-minute cache can cause duplicate charges | Missing billing-window replay/idempotency finding. A generic flow-integrity question does not explain the duplicate charge. |
| K06 | One tenant's replay starves interactive prepaid charging | Missing tenant/workload isolation and charging availability finding. |
| K07 | Non-atomic wallet debit permits concurrent balance races | Missing transaction atomicity/race finding. Generic wallet authorization is a different issue. |
| K08 | 24-hour invoice URLs survive suspension/access revocation | Missing URL lifetime/revocation finding. |
| K09 | Legacy payment webhook skips signatures and replay checks | Missing endpoint-specific webhook finding. The correlation ledger actually contains the legacy route's absent signature claim, but the final register does not promote it. |
| K10 | Same employee adjusts settlement and approves payout | Missing separation-of-duties finding. |
| K11 | Support sessions and privileges survive password/account/role changes | Generic OAuth lifecycle question is placed on Workforce Identity, not the stated Customer Support session/entitlement defect. Not correctly reported. |
| K12 | CSV exports do not neutralize spreadsheet formula prefixes | Missing CSV formula injection finding. The confirmed export finding is about storage encryption, not CSV safety. |
| K13 | Export IAM role reads all tenant prefixes | Generic authorization question is present, but the explicitly broad S3 permissions and tenant-prefix scope are not reported as the stated weakness. |
| K14 | Shared Kafka principal has excessive producer topic ACLs | Missing event producer identity/topic authorization finding. |
| K15 | Mutable image tags and unenforced signing in release 26.09 | Missing build/deployment integrity finding. Planned 26.10 controls must remain future controls. |
| K16 | Support logs tokens/PII and can delete its own log group | Missing credential logging and application-audit tampering findings. Cross-account CloudTrail protection is a separate scope. |

Only K04 is clearly captured as its specific declared weakness. The other 15 are missing, too generic, or assigned to a different root cause. This is a scenario-specific result, not a general recall estimate.

## Incorrect or Misleading Findings

### Two Unsupported Confirmed Findings

1. **Invoice Billing auditability, High:** the engine treats "CloudTrail is not a complete substitute for application-level billing, refund, settlement-approval or support-action audit events" as evidence that invoice audit_logging is absent. This sentence explains a limitation; it does not state invoice audit logging is disabled or missing.
2. **Document Export disclosure, High:** the engine takes the explanatory sentence beginning "Neither WAF presence, encryption at rest nor valid JWT signatures proves tenant authorization" as absent encryption_at_rest and absent waf_enabled on Document Export Service. It then recommends storage encryption. That is not the stated CSV or IAM weakness, and the document already describes encrypted storage.

The other two confirmed findings have source support: provisioning SSRF and subscriber MFA not being mandatory. The MFA recommendation should still be scoped to subscriber risk and sensitive actions; its current remediation starts with administrative access even though workforce MFA is explicitly present.

### Controls and Context Lost

- Redis authentication/TLS/isolation are reported unspecified even though supporting-controls.md explicitly states TLS and authentication enabled, private subnets and restricted workload access. The correlated evidence retains TLS but does not establish the authentication property consumed by the finding.
- Public Product Assets is classified as **phi** even though it contains only non-sensitive product graphics. The report consequently elevates an object-storage validation question. No healthcare subsystem exists in this scenario.
- OAuth remediation mentions PHI access, and its description uses generic "OAuth or Azure AD" wording even though the architecture names a corporate OIDC provider, not Azure AD.
- The Customer Portal's intended hosted payment-provider checkout receives a Critical disclosure finding solely from external financial-data flow and unspecified restrictions. No unnecessary card-data disclosure is established; the scenario deliberately keeps PAN/CVV at the provider. Remaining sharing controls can be questions without asserting this exposure level.
- Flow questions require webhook_signature_validation for usage-to-DynamoDB and provisioning-to-Secrets Manager interactions. These are not webhook endpoints. Their control contracts need protocol/service-specific applicability.
- The asset inventory is empty despite subscriber identifiers, credentials, financial ledgers and invoice documents being described. Subscriber Profile remains unknown sensitivity while Product Assets becomes PHI.

## Why Final PDF Export Is Blocked

The underlying conflict is on Build Pipeline / logging_enabled. The exact same source sentence, "Build Pipeline does not send its own application logs to CloudTrail," produces one absent claim and one present claim.

The document says AWS collects CloudTrail management events, rather than GitHub transmitting application logs to CloudTrail. It does not contradict itself about the same logging control. The app labels this parser-generated disagreement invalid_topology and tells the user the component/flow graph does not validate.

Fix the contradictory claim extraction and diagnostic classification. Do not simply disable the publication gate. Genuine conflicting evidence should remain visible, but the message must identify the affected control, source and scope.

The gate also reports declared_known_issues=0 and reported_known_issues=0. All component stated_weaknesses lists and architecture.metadata.known_issues are empty. Therefore the missing-known-issue check cannot detect that the input contains K01-K16.

## Architecture and DFD Review

The saved canonical model retains all 9 named boundaries and all 74 flow endpoints. The drawing instead uses 4 generic zones and changes their semantics:

- Application Ingress is drawn in the Internet / Client Boundary despite being explicitly internal/private.
- Stripe, GitHub Actions, Messaging Provider, Operator OSS and Roaming Partner are drawn as application processes inside the Application Trust Boundary, despite their External Entity types and external ownership.
- The diagram omits Public Edge -> Application Ingress, Rating Charging -> Balance Wallet, Payment Collections -> Payment Provider, Payment Collections -> Balance Wallet and Service Provisioning -> Operator OSS, among other declared interactions. Simplification is disclosed, but it breaks the essential charging, payment and provisioning workflows.
- It reports 60 drawn flows out of 74, while the exported hidden-flow diagnostic says 13 rather than 14. The difference is not fully explained by that field.
- Boundary crossings are reported as 37. Counting directed flows between the scenario's declared logical boundary memberships gives 51. Equal trust-level labels do not mean two distinct logical boundaries are the same boundary.
- Text is very small and connections overlap at normal zoom. Zoom is available, but workflow-specific views and a context-level overview are needed; arbitrary truncation is not a suitable substitute.

## Attack Paths and Metrics

The attack paths include conditional-access caveats, which is useful. However, two paths are built on the unsupported confirmed audit/encryption findings above. The invoice path also jumps from usage mediation through the shared event-stream node to invoice billing, without demonstrating the topic/producer and rating-stage prerequisites. A broker-level connection is not proof that all of its event topics can be traversed interchangeably.

The confirmed severity arithmetic is correct, but classification quality is not. Likewise, all six STRIDE categories appear, but 100% assessed means the matrix was traversed, not that all threats were found. The 855 review questions versus 20 final questions need explicit total-versus-prioritized labels.

## Recommended Implementation Order

1. **Declared-issue extraction:** preserve multiline K01-K16 entries regardless of numbered heading style. Store source spans, service/endpoint scope and an explicit disposition for every issue. Make the quality gate compare against that independent inventory.
2. **Statement interpretation:** distinguish assertions from explanatory limitations, comparisons and future plans. Never interpret "X does not prove Y" as "X is absent." Do not emit opposite Boolean states from the same normalized claim without flagging a parser defect.
3. **Shared control contracts:** normalize authenticated/TLS/private language consistently across parser, correlation, contextual engines and STRIDE. Preserve endpoint exceptions and promote explicit absent endpoint controls into findings.
4. **Entity/data scope:** bind table rows and C identifiers exactly; avoid generic word matches assigning evidence to other services. Build explicit asset records and prevent healthcare labels from unrelated words or templates.
5. **Canonical DFD rendering:** render declared boundary membership and External Entity types. Preserve the principal business workflow in each view, expose hidden flows and reconcile diagram counts.
6. **Finding and attack-path applicability:** distinguish intended provider sharing from exfiltration, AWS API integrity from webhook signatures, broker connectivity from topic permission, and subscriber controls from workforce controls.
7. **Reporting integrity:** show precise control conflicts rather than invalid-topology messages, label confirmed as owner-declared/not deployment-verified, and separate prioritized questions from total unresolved assessments.
8. **Performance after correctness:** local intelligence consumed about 89% of this run's measured backend analysis time. Profile and batch/cache that stage, then measure detection retention and latency together. Do not trade missing findings for faster execution.

Regression acceptance should require all 16 stated weaknesses to have an explicit disposition; no PHI classification for Product Assets; no unsupported confirmed encryption/audit findings; Redis controls recognized; legacy webhook scope preserved; all declared logical boundaries preserved; and core workflows visible without broken edges.

## Evidence Artifact

The browser-generated workspace export contains the exact input, preview, correlation ledger, final result, engine diagnostics and generated Mermaid:

`Nexora_Telecom_BSS_26_09_-_Chrome_review_workspace.json` is retained locally and is not included in the public release. The input documents and this review are included so the scenario can be reproduced.

It can be used as a regression fixture after removing transient IDs/timestamps and keeping the source documents unchanged. The report remains open in Chrome; no findings were manually reclassified during this review.
