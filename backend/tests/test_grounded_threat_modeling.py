from app.engine.analyzer import ThreatAnalyzer
from app.engine.parser import ArchitectureParser
from app.knowledge_base.loader import ThreatKnowledgeBase


HEALTHCARE_TEMPLATE = '''
Healthcare records management system with:
- React frontend with role-based access (Doctor, Nurse, Admin)
- .NET Core REST API with OAuth2 + MFA authentication
- PostgreSQL for patient records (PHI/PII data)
- Redis for session management
- Azure Blob Storage for medical imaging (DICOM files)
- HL7 FHIR API for interoperability
- Azure AD for identity management
- Encryption at rest (AES-256) and in transit (TLS 1.3)
- Audit logging for all data access
- HIPAA-compliant infrastructure on Azure

KNOWN ISSUES:
- Break-the-glass access procedure not audited separately
- No data loss prevention (DLP) on file downloads
- Session timeout set to 8 hours (too long for PHI access)
'''


def test_exclusions_and_known_issues_do_not_create_components():
    architecture = ArchitectureParser().parse('''
Architecture:
- React frontend
- Node.js Express API
- PostgreSQL database

EXCLUSIONS:
- No LLM, RAG, Lambda, Gin, or vector database exists.

KNOWN ISSUES:
- Session tokens do not expire on password change.
''')

    component_ids = {component.id for component in architecture.components}
    assert 'gin' not in component_ids
    assert 'llm' not in component_ids
    assert 'lambda' not in component_ids
    assert 'ml_service' not in component_ids
    assert len(architecture.metadata['known_issues']) == 1


def test_known_issues_are_atomic_and_framework_aligned():
    description = '''
AWS application with Lambda, S3, Bedrock, an OpenSearch vector index, and an MCP server.

KNOWN ISSUES:
- A Terraform IAM policy grants s3:* on * to the CI deployment role.
- The statement-upload S3 bucket does not enforce bucket-owner-enforced object ownership.
- One Lambda function logs the full incoming event before redaction.
- Retrieval queries do not enforce a tenant filter before searching OpenSearch.
- Tool descriptions accept arbitrary shell command text for trigger_preview_deployment.
- Session tokens don't expire on password change.
'''
    result = ThreatAnalyzer().analyze_from_text(description, use_local_slm=False)
    findings = {finding.id.rsplit('-', 1)[0]: finding for finding in result.threats}

    assert len(result.architecture.metadata['known_issues']) == 6
    assert findings['AWS-IAM-WILDCARD-S3-001'].category == 'Elevation of Privilege'
    assert findings['AWS-S3-OBJECT-OWNERSHIP-001'].severity == 'High'
    assert findings['AWS-LAMBDA-SENSITIVE-LOGGING-001'].category == 'Information Disclosure'
    assert findings['AI-RAG-TENANT-ISOLATION-001'].severity == 'Critical'
    assert findings['MCP-TOOL-COMMAND-INJECTION-001'].severity == 'Critical'
    assert findings['AUTH-SESSION-REVOCATION-001'].category == 'Spoofing'
    expected_ids = {
        'AWS-IAM-WILDCARD-S3-001', 'AWS-S3-OBJECT-OWNERSHIP-001',
        'AWS-LAMBDA-SENSITIVE-LOGGING-001', 'AI-RAG-TENANT-ISOLATION-001',
        'MCP-TOOL-COMMAND-INJECTION-001', 'AUTH-SESSION-REVOCATION-001',
    }
    assert all(findings[threat_id].evidence_details[0]['source_type'] == 'architecture_input' for threat_id in expected_ids)


def test_professional_catalog_is_discovered():
    kb = ThreatKnowledgeBase()
    for threat_id in ('AWS-IAM-001', 'AI-RAG-001', 'MCP-002', 'PAY-001'):
        assert kb.get_by_id(threat_id) is not None


def test_known_issues_are_not_merged_when_they_share_cwes():
    result = ThreatAnalyzer().analyze_from_text('''
KNOWN ISSUES:
- Cursor rules instruct the model to read .env files when debugging.
- The MCP client forwards a broad GitHub token to every configured MCP server.
''', use_local_slm=False)

    finding_ids = {finding.id.rsplit('-', 1)[0] for finding in result.threats}
    assert 'AI-AGENT-LOCAL-SECRETS-001' in finding_ids
    assert 'MCP-CREDENTIAL-FORWARDING-001' in finding_ids


def test_healthcare_controls_are_scoped_to_the_declaring_component():
    architecture = ArchitectureParser().parse(HEALTHCARE_TEMPLATE)
    components = {component.id: component for component in architecture.components}

    assert 'frontend' not in components
    assert components['rest_api'].properties['auth_type'] == 'oauth2'
    assert components['postgresql'].properties.get('auth_type', 'unknown') == 'unknown'
    assert components['redis'].properties.get('auth_type', 'unknown') == 'unknown'
    assert components['hl7_fhir_api'].properties.get('auth_type', 'unknown') == 'unknown'
    assert components['redis'].properties.get('rbac_enabled') is not True


def test_healthcare_known_issues_cover_multiple_stride_categories():
    result = ThreatAnalyzer().analyze_from_text(HEALTHCARE_TEMPLATE, use_local_slm=False)
    findings = {finding.id.rsplit('-', 1)[0]: finding for finding in result.threats}

    assert findings['HEALTH-BTG-AUDIT-001'].category == 'Repudiation'
    assert findings['HEALTH-BTG-AUDIT-001'].severity == 'Critical'
    assert findings['HEALTH-PHI-DLP-001'].category == 'Information Disclosure'
    assert findings['HEALTH-PHI-DLP-001'].severity == 'Critical'
    assert findings['AUTH-LONG-LIVED-SESSION-001'].category == 'Spoofing'
    # Sessions that never expire, on components that handle PHI and sit either
    # side of a trust boundary, from which most of the architecture is reachable.
    # This read as High while blast radius counted the components a finding named
    # and PHI was recognised only where the word appeared, so the finding scored
    # as an internal weakness on one component.
    assert findings['AUTH-LONG-LIVED-SESSION-001'].severity == 'Critical'
    assert findings['HEALTH-BTG-AUDIT-001'].affected_components == ['rest_api', 'azure_ad', 'postgresql']
    assert findings['HEALTH-PHI-DLP-001'].affected_components == ['azure_blob', 'rest_api', 'react']
    assert findings['AUTH-LONG-LIVED-SESSION-001'].affected_components == ['redis', 'azure_ad', 'rest_api']


def test_healthcare_session_issue_does_not_hide_other_identity_controls():
    result = ThreatAnalyzer().analyze_from_text(HEALTHCARE_TEMPLATE, use_local_slm=False)
    findings = {finding.id: finding for finding in result.threats}

    assert findings['CTX-FHIR-001'].category == 'Spoofing'
    assert findings['CTX-FHIR-001'].tier == 'Potential'
    assert findings['CTX-FHIR-001'].confidence == 'Medium'
    # Token timeout does not answer Redis authentication or refresh-token
    # rotation. Sharing Spoofing is not enough to make these duplicates.
    assert findings['CTX-SESSION-001'].tier == 'Potential'
    assert findings['CTX-OAUTH-001'].tier == 'Potential'

    assert len(result.system_model['public_entry_points']) == 1
    assert len(result.system_model['boundary_crossings']) == 0
    assert len(result.system_model['inferred_boundary_crossings']) > 0
