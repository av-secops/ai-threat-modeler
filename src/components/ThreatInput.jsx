import React, { useState } from 'react';
import { Send, Cpu, ChevronDown, Upload, FileText } from 'lucide-react';
import { applicationTypes } from '../utils/assessmentCatalog';
import { enterprise } from '../services/enterprise';

const DOMAIN_OPTIONS = [
    { value: 'general', label: 'General Software' },
    { value: 'saas', label: 'SaaS / Multi-tenant' },
    { value: 'fintech', label: 'Fintech / Payments' },
    { value: 'healthcare', label: 'Healthcare / PHI' },
    { value: 'ai', label: 'AI / LLM App' },
    { value: 'platform', label: 'Platform / Kubernetes' },
];

const TEMPLATES = {
    'e-commerce': {
        name: 'E-Commerce Platform',
        description: `E-commerce platform with:
- React frontend (public-facing)
- API Gateway with WAF and rate limiting
- Node.js REST API with JWT authentication
- PostgreSQL database with encryption at rest for user/product data
- MongoDB for order storage
- Redis cluster for session management and caching
- S3 bucket for product images
- Stripe integration for payment processing
- SendGrid for transactional emails
- Deployed on Kubernetes with centralized logging

KNOWN ISSUES:
- No query depth limiting on product search GraphQL endpoint
- Session tokens don't expire on password change`
    },
    'saas': {
        name: 'SaaS Platform',
        description: `Multi-tenant SaaS platform with:
- React SPA frontend hosted on CloudFront CDN
- API Gateway with OAuth2/OIDC authentication via Auth0
- Python FastAPI microservices:
  1. Auth Service: Handles user management and RBAC
  2. Tenant Service: Multi-tenant data isolation
  3. Billing Service: Integrates with Stripe for subscriptions
  4. Notification Service: Email (SendGrid) and push notifications
- PostgreSQL with row-level security for tenant isolation
- Redis for rate limiting and caching
- Elasticsearch for full-text search and audit logs
- RabbitMQ for async job processing
- Deployed on AWS ECS with CloudWatch monitoring

KNOWN ISSUES:
- CORS allows wildcard origins in staging environment
- API rate limiting not enforced on internal service-to-service calls`
    },
    'iot': {
        name: 'IoT Platform',
        description: `IoT device management platform with:
- Angular dashboard for device management
- MQTT broker (Mosquitto) for device communication
- Node.js REST API for device provisioning
- AWS IoT Core for device registry and shadows
- DynamoDB for time-series telemetry data
- S3 for firmware storage and OTA updates
- Lambda functions for real-time data processing
- SNS for alerting and notifications
- X.509 certificate-based device authentication
- VPC with private subnets for backend services

KNOWN ISSUES:
- Firmware updates not signed
- No rate limiting on MQTT message publishing
- Device certificates don't have expiration dates`
    },
    'healthcare': {
        name: 'Healthcare System',
        description: `Healthcare records management system with:
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
- Session timeout set to 8 hours (too long for PHI access)`
    }
};

const ThreatInput = ({ onAnalyze, isAnalyzing, defaultProjectName }) => {
    const [description, setDescription] = useState('');
    const [projectName, setProjectName] = useState(defaultProjectName || 'My Security Audit');
    const [showTemplates, setShowTemplates] = useState(false);
    const [useLocalSlm, setUseLocalSlm] = useState(true);
    const [domainProfile, setDomainProfile] = useState('general');
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [diagramFiles, setDiagramFiles] = useState([]);
    const [selectedTypes, setSelectedTypes] = useState(['web']);
    const [otherType, setOtherType] = useState('');
    const [importUrl, setImportUrl] = useState('');
    const [importedSource, setImportedSource] = useState(null);
    const [importError, setImportError] = useState('');
    const [importing, setImporting] = useState(false);

    const canSubmit = (description.trim() || uploadedFiles.length > 0 || diagramFiles.length > 0 || importedSource) && selectedTypes.length && (!selectedTypes.includes('other') || otherType.trim());

    const handleSubmit = (e) => {
        e.preventDefault();
        if (canSubmit) {
            onAnalyze(description, projectName, useLocalSlm, {
                domainProfile,
                applicationTypes: selectedTypes, otherApplicationType: otherType, importedSource, diagramFiles,
                files: uploadedFiles,
                contextText: description,
            });
        }
    };

    const handleKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (canSubmit && !isAnalyzing) {
                onAnalyze(description, projectName, useLocalSlm, {
                    domainProfile,
                    applicationTypes: selectedTypes, otherApplicationType: otherType, importedSource, diagramFiles,
                    files: uploadedFiles,
                    contextText: description,
                });
            }
        }
    };

    const handleFileUpload = (e) => {
        const files = Array.from(e.target.files || []);
        setUploadedFiles(old => [...old, ...files]);
        e.target.value = '';
    };

    const applyTemplate = (key) => {
        const template = TEMPLATES[key];
        setProjectName(template.name);
        setDescription(template.description);
        setDomainProfile(key === 'saas' ? 'saas' : key === 'healthcare' ? 'healthcare' : 'general');
        setShowTemplates(false);
    };

    return (
        <div className="mx-auto mb-10 w-full max-w-6xl">
            <div className="glass-panel p-6">
                <div className="mb-6 flex flex-col gap-4 border-b border-brand-200 pb-5 dark:border-brand-700 md:flex-row md:items-start md:justify-between">
                    <div>
                        <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-brand-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-brand-primary">
                            Architecture Intake
                        </div>
                        <h2 className="flex items-center gap-2 text-2xl font-semibold text-brand-950 dark:text-white">
                            <Cpu className="h-5 w-5" />
                            System Architecture and Design Intake
                        </h2>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                            Paste architecture notes, or upload requirement docs, design specs, architecture writeups, Markdown, or PDFs. Keep the content focused on components, trust boundaries, data flows, and known issues.
                        </p>
                    </div>
                    <div className="relative">
                        <button
                            type="button"
                            onClick={() => setShowTemplates(!showTemplates)}
                            className="ui-button-secondary whitespace-nowrap"
                        >
                            Use Template
                            <ChevronDown className={`w-4 h-4 transition-transform ${showTemplates ? 'rotate-180' : ''}`} />
                        </button>
                        {showTemplates && (
                            <div className="absolute right-0 top-full z-20 mt-2 w-64 rounded-lg border border-brand-200 bg-white p-1 shadow-lg dark:border-brand-600 dark:bg-brand-800">
                                {Object.entries(TEMPLATES).map(([key, tmpl]) => (
                                    <button
                                        key={key}
                                        onClick={() => applyTemplate(key)}
                                        className="block w-full rounded-md px-4 py-3 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-300 dark:hover:bg-brand-700"
                                    >
                                        {tmpl.name}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="mb-5 grid gap-4 lg:grid-cols-[1.1fr_0.75fr_1fr]">
                    <div>
                    <label htmlFor="threat-model-name" className="ui-label">Threat model name</label>
                    <input
                        id="threat-model-name"
                        type="text"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Payment Gateway V2"
                    />
                    </div>
                    <div>
                        <label className="ui-label" htmlFor="application-type">Select Application Type</label>
                        <select
                            id="application-type"
                            value={selectedTypes[0] || ''}
                            onChange={(e) => setSelectedTypes([e.target.value])}
                            className="input-brand w-full font-mono"
                        >
                            {Object.entries(applicationTypes).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                        </select>
                        {selectedTypes.includes('other') && <input className="input-brand mt-2 w-full" aria-label="Other application type" value={otherType} maxLength={200} onChange={e => setOtherType(e.target.value)} placeholder="Application type" />}
                    </div>
                    <details className="py-2"><summary className="cursor-pointer text-sm">Additional scope</summary>
                        <label className="ui-label mt-3">Business domain<select value={domainProfile} onChange={e => setDomainProfile(e.target.value)} className="input-brand mt-1 w-full">{DOMAIN_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select></label>
                        <div className="mt-3 flex flex-wrap gap-3">{Object.entries(applicationTypes).map(([id, label]) => <label key={id} className="text-xs"><input type="checkbox" checked={selectedTypes.includes(id)} onChange={e => setSelectedTypes(e.target.checked ? [...selectedTypes, id] : selectedTypes.filter(v => v !== id))} /> {label}</label>)}</div>
                    </details>
                </div>
                <form onSubmit={handleSubmit} className="relative">
                    <div className="ui-subpanel mb-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-wide text-brand-500">Design Documents</p>
                                <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">
                                    Upload one or more `.txt`, `.md`, `.pdf`, `.docx`, `.json`, or `.yaml` files.
                                </p>
                            </div>
                            <label className="ui-button-secondary cursor-pointer">
                                <Upload className="h-4 w-4" />
                                Add Files
                                <input
                                    type="file"
                                    multiple
                                    className="hidden"
                                    onChange={handleFileUpload}
                                    disabled={isAnalyzing}
                                />
                            </label>
                        </div>
                        {uploadedFiles.length > 0 && (
                            <div className="mt-4 flex flex-wrap gap-2">
                                {uploadedFiles.map((file, index) => (
                                    <span
                                        key={`${file.name}-${file.size}-${index}`}
                                        className="ui-chip"
                                    >
                                        <FileText className="h-3.5 w-3.5" />
                                        {file.name}
                                    </span>
                                ))}
                            </div>
                        )}
                    </div>
                    <details className="mb-4 border-y border-brand-200 py-3 dark:border-brand-700"><summary className="cursor-pointer text-sm">Import documentation</summary>
                        <div className="mt-3 flex flex-wrap gap-2"><input aria-label="Documentation URL" type="url" className="input-brand min-w-0 flex-1 text-sm" value={importUrl} onChange={e => setImportUrl(e.target.value)} placeholder="https://approved-host/design.pdf" />
                            <button type="button" className="ui-button-secondary" disabled={importing || !importUrl.trim()} onClick={async () => { setImporting(true); setImportError(''); try { setImportedSource(await enterprise('/sources/import', 'POST', { url: importUrl })); } catch (error) { setImportError(error.message); } finally { setImporting(false); } }}><Upload size={16} />{importing ? 'Importing...' : 'Import'}</button></div>
                        {importedSource && <p className="mt-2 text-sm">{importedSource.name}</p>}{importError && <p role="alert" className="mt-2 text-sm text-red-700 dark:text-red-300">{importError}</p>}
                    </details>
                    <div className="mb-4 flex flex-wrap items-center gap-3"><label className="ui-button-secondary cursor-pointer"><Upload size={16} />Architecture diagram<input type="file" multiple aria-label="Upload architecture diagram" className="hidden" accept=".drawio,.xml,.mmd,.mermaid,.png,.jpg,.jpeg,.pdf" onChange={e => setDiagramFiles([...e.target.files])} disabled={isAnalyzing} /></label>{diagramFiles.map(file => <span className="text-xs" key={file.name}>{file.name}</span>)}</div>
                    <textarea
                        className="input-brand h-56 w-full resize-none font-mono text-sm leading-relaxed"
                        aria-label="Architecture description"
                        placeholder="Describe the system, its users, data and important workflows."
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        onKeyDown={handleKeyDown}
                        disabled={isAnalyzing}
                    />

                    {/* Local AI Engine Toggle */}
                    <div className="ui-subpanel mt-5 flex items-start gap-3">
                        <input
                            type="checkbox"
                            id="useLocalSlm"
                            checked={useLocalSlm}
                            onChange={(e) => setUseLocalSlm(e.target.checked)}
                            className="w-4 h-4 text-brand-primary bg-white border-brand-300 rounded focus:ring-brand-primary dark:focus:ring-brand-primary dark:ring-offset-brand-800 dark:bg-brand-700 dark:border-brand-600"
                        />
                        <div className="flex flex-col">
                            <label htmlFor="useLocalSlm" className="cursor-pointer text-sm font-semibold text-brand-800 dark:text-brand-200">
                                Enable Local Semantic AI Engine (Small LLM)
                            </label>
                            <span className="text-xs text-brand-500 dark:text-brand-400 mt-1 leading-5">
                                Uses on-device sentence embeddings to detect hidden architectural threats trained on the KB.
                            </span>
                        </div>
                    </div>

                    <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <span className="text-xs font-medium uppercase tracking-wide text-brand-400">Ctrl+Enter to submit</span>
                        <button
                            type="submit"
                            disabled={isAnalyzing || !canSubmit}
                            className="btn-brand gap-2"
                        >
                            {isAnalyzing ? (
                                <>Preparing model...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Review architecture
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ThreatInput;
