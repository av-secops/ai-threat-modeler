import asyncio
import os
import json
import time
import hashlib
import logging
import uuid
from contextlib import asynccontextmanager
from collections import OrderedDict
from typing import Callable, Dict, Optional, Tuple, TypeVar
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from .engine.analyzer import ThreatAnalyzer
from .models import AnalysisResult, Component, SystemArchitecture
from .services.document_ingestion import extract_documents
from .services.model_review import ModelReviewRequest, prepare_model
from .services.llm_analyzer import LLMAnalyzer
from .services.llm_providers import provider_public_info, supported_provider_ids
from .engine.retrieval_quality import (
    RetrievalCalibrator,
    RetrievalFeedbackStore,
    retrieval_monitor,
)

logger = logging.getLogger(__name__)

# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")

# Resource limits. An analysis is CPU-bound and holds its inputs in memory, so a
# single caller must not be able to exhaust the process.
MAX_UPLOAD_FILES = int(os.getenv("AEGIS_THREAT_MAX_UPLOAD_FILES", "20"))
MAX_UPLOAD_TOTAL_BYTES = int(os.getenv("AEGIS_THREAT_MAX_UPLOAD_TOTAL_BYTES", str(32 * 1024 * 1024)))
ANALYSIS_TIMEOUT_SECONDS = int(os.getenv("AEGIS_THREAT_ANALYSIS_TIMEOUT_SECONDS", "300"))
MAX_TRACKED_PROJECTS = int(os.getenv("AEGIS_THREAT_MAX_TRACKED_PROJECTS", "50"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm expensive analyzer dependencies once at startup."""
    app.state.threat_analyzer = ThreatAnalyzer()
    yield


app = FastAPI(
    title="Aegis Threat API", 
    version="2.3.1",
    description="Aegis Threat API for AI-assisted threat modeling and architecture risk analysis",
    lifespan=lifespan
)

if ENVIRONMENT == "production":
    if "*" in ALLOWED_ORIGINS:
        raise RuntimeError(
            "ALLOWED_ORIGINS must name the origins that may call this API. "
            "A wildcard with credentials would let any site read a threat model."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
else:
    # Development runs on a developer's machine and has no authentication, so a
    # wildcard is acceptable. Credentials are not: pairing the two is rejected by
    # browsers and would be a real flaw if this configuration ever shipped.
    logger.warning(
        "Running in development mode: CORS is open and no admin token is required. "
        "Set ENVIRONMENT=production and ALLOWED_ORIGINS before exposing this service."
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )


class AnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200, description="Name of the project")
    description: str = Field(..., min_length=10, max_length=10000, description="System architecture description")
    use_local_slm: bool = Field(default=True, description="Enable local semantic analysis")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    domain_profile: str = Field(default="general", description="Optional domain profile: general, saas, fintech, healthcare, ai, platform")
    
    @field_validator('project_name')
    @classmethod
    def sanitize_project_name(cls, v):
        # Remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[<>"\'\\/;]', '', v)
        return sanitized.strip()
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not v or len(v.strip()) < 10:
            raise ValueError('Description must be at least 10 characters')
        return v.strip()

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
        return v

    @field_validator('domain_profile')
    @classmethod
    def validate_domain_profile(cls, v):
        if v not in ['general', 'saas', 'fintech', 'healthcare', 'ai', 'platform']:
            return 'general'
        return v


class FindingFeedbackRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    finding_id: str = Field(..., min_length=1, max_length=200)
    decision: str = Field(..., pattern="^(accepted|false_positive|mitigated|reclassified)$")
    query: str = Field(default="", max_length=4000)
    retrieval_score: float = Field(default=0.0, ge=0.0, le=1.0)
    stride_category: Optional[str] = Field(default=None, max_length=80)
    security_domains: list[str] = Field(default_factory=list, max_length=20)
    finding: Dict = Field(default_factory=dict)
    corrected_rule_id: Optional[str] = Field(default=None, max_length=200)
    reviewer_note: str = Field(default="", max_length=2000)


class FeedbackApprovalRequest(BaseModel):
    feedback_id: str = Field(..., min_length=1, max_length=100)
    approved_by: str = Field(..., min_length=2, max_length=200)


class IaCAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200, description="Name of the project")
    iac_content: str = Field(..., min_length=10, description="Raw infrastructure or pipeline definition")
    format_hint: str = Field(default='auto', description="Optional IaC format hint")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    
    @field_validator('project_name')
    @classmethod
    def sanitize_project_name(cls, v):
        import re
        sanitized = re.sub(r'[<>"\'\\/;]', '', v)
        return sanitized.strip()

    @field_validator('format_hint')
    @classmethod
    def validate_format_hint(cls, v):
        if v not in ['auto', 'docker-compose', 'kubernetes', 'helm', 'helm-values', 'kustomize', 'terraform', 'terraform-plan', 'cloudformation', 'arm', 'bicep', 'pulumi', 'ci']:
            return 'auto'
        return v

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
        return v


class CodeAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    code_content: str = Field(..., min_length=1, max_length=500000)
    language: str = Field(default='auto', max_length=40)
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")

    @field_validator('project_name')
    @classmethod
    def sanitize_project_name(cls, v):
        return _sanitize_project_name(v)

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        return _normalize_analysis_mode(v)


class LLMAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=10, max_length=10000)
    llm_provider: str = Field(..., description="LLM provider")
    api_key: str = Field(..., min_length=10, description="API key for the LLM provider")
    model: Optional[str] = Field(default=None, description="Optional specific model to use")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        provider = v.lower()
        if provider not in supported_provider_ids():
            raise ValueError(f"Provider must be one of: {', '.join(supported_provider_ids())}")
        return provider

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
        return v.lower()


class APIKeyValidationRequest(BaseModel):
    provider: str = Field(..., description="LLM provider")
    api_key: str = Field(..., min_length=10)
    
    @field_validator('provider')
    @classmethod
    def validate_provider(cls, v):
        provider = v.lower()
        if provider not in supported_provider_ids():
            raise ValueError(f"Provider must be one of: {', '.join(supported_provider_ids())}")
        return provider


class LLMModelsRequest(APIKeyValidationRequest):
    pass


class RetrainLocalModelsResponse(BaseModel):
    message: str
    stats: dict


class TTLAnalysisCache:
    def __init__(self, max_entries: int = 100, ttl_seconds: int = 900):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._store: "OrderedDict[str, Tuple[float, AnalysisResult]]" = OrderedDict()

    def _purge_expired(self):
        now = time.time()
        expired = [key for key, (expires_at, _) in self._store.items() if expires_at <= now]
        for key in expired:
            self._store.pop(key, None)

    def get(self, key: str):
        self._purge_expired()
        item = self._store.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at <= time.time():
            self._store.pop(key, None)
            return None
        self._store.move_to_end(key)
        return value

    def set(self, key: str, value: AnalysisResult):
        self._purge_expired()
        self._store[key] = (time.time() + self.ttl_seconds, value)
        self._store.move_to_end(key)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def clear(self) -> int:
        count = len(self._store)
        self._store.clear()
        return count


class LatestByProject:
    """Most recent result per project, used to produce a diff on the next run.

    Bounded because the key is caller-supplied: an unbounded dict keyed by
    project name grows for as long as the process runs.
    """

    def __init__(self, max_entries: int = MAX_TRACKED_PROJECTS):
        self.max_entries = max_entries
        self._store: "OrderedDict[str, AnalysisResult]" = OrderedDict()

    def get(self, project_name: str) -> Optional[AnalysisResult]:
        result = self._store.get(project_name)
        if result is not None:
            self._store.move_to_end(project_name)
        return result

    def __setitem__(self, project_name: str, result: AnalysisResult) -> None:
        self._store[project_name] = result
        self._store.move_to_end(project_name)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def clear(self) -> None:
        self._store.clear()


T = TypeVar("T")


async def _run_analysis(work: Callable[[], T], operation: str) -> T:
    """Run a synchronous analysis off the event loop, under a time limit.

    Analysis is CPU-bound and can take minutes on a large model. Running it
    inline would stall every other request, including the health check and any
    streaming client. The timeout releases the caller; the worker thread cannot
    be interrupted, so it finishes in the background rather than being killed.
    """
    from .services.analysis_workers import AnalysisBusy, analysis_workers
    try:
        return await analysis_workers.run(work, timeout=ANALYSIS_TIMEOUT_SECONDS)
    except AnalysisBusy as exc:
        raise HTTPException(status_code=503, detail=str(exc), headers={"Retry-After": "5"}) from exc
    except asyncio.TimeoutError:
        logger.warning("%s exceeded %ss", operation, ANALYSIS_TIMEOUT_SECONDS)
        raise HTTPException(
            status_code=504,
            detail=(
                f"{operation} exceeded the {ANALYSIS_TIMEOUT_SECONDS}s limit. "
                "Reduce the size of the input or raise AEGIS_THREAT_ANALYSIS_TIMEOUT_SECONDS."
            ),
        )


def _failure(error: Exception, operation: str) -> HTTPException:
    """Log the detail, return a reference.

    Exception text from this process can carry file paths, provider responses,
    and occasionally credential material, none of which belongs in an HTTP body.
    """
    reference = uuid.uuid4().hex[:12]
    logger.exception("%s failed [ref=%s]", operation, reference)
    return HTTPException(
        status_code=500,
        detail=f"{operation} failed. Quote reference {reference} when reporting this.",
    )


_analysis_cache = TTLAnalysisCache()
_latest_analysis_by_project = LatestByProject()


def _stable_cache_key(*parts) -> str:
    payload = json.dumps(parts, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _build_diff_summary(previous: Optional[AnalysisResult], current: AnalysisResult) -> Optional[dict]:
    if previous is None:
        return None
    previous_threats = {threat.id: threat for threat in previous.threats}
    current_threats = {threat.id: threat for threat in current.threats}
    previous_ids = set(previous_threats)
    current_ids = set(current_threats)
    new_ids = sorted(current_ids - previous_ids)
    resolved_ids = sorted(previous_ids - current_ids)
    score_delta = current.score - previous.score
    component_delta = len(current.architecture.components) - len(previous.architecture.components)
    flow_delta = len(current.architecture.flows) - len(previous.architecture.flows)

    # A reviewer who just amended the model is asking whether the thing they
    # added arrived, so name the components rather than only counting them.
    previous_components = {item.id: item.name for item in previous.architecture.components}
    current_components = {item.id: item.name for item in current.architecture.components}
    added_components = sorted(
        current_components[item] for item in set(current_components) - set(previous_components)
    )
    removed_components = sorted(
        previous_components[item] for item in set(previous_components) - set(current_components)
    )

    severity_changes = []
    finding_score_changes = []
    for threat_id in sorted(previous_ids & current_ids):
        previous_threat = previous_threats[threat_id]
        current_threat = current_threats[threat_id]
        if previous_threat.severity != current_threat.severity or previous_threat.tier != current_threat.tier:
            severity_changes.append({
                "id": threat_id,
                "title": current_threat.title,
                "from_severity": previous_threat.severity,
                "to_severity": current_threat.severity,
                "from_tier": previous_threat.tier,
                "to_tier": current_threat.tier,
            })
        factor_changes = {}
        factor_keys = set(previous_threat.risk_factors or {}) | set(current_threat.risk_factors or {})
        for key in sorted(factor_keys):
            old_value = (previous_threat.risk_factors or {}).get(key)
            new_value = (current_threat.risk_factors or {}).get(key)
            if old_value != new_value:
                factor_changes[key] = {"from": old_value, "to": new_value}
        if previous_threat.risk_score != current_threat.risk_score or factor_changes:
            finding_score_changes.append({
                "id": threat_id,
                "title": current_threat.title,
                "from_score": previous_threat.risk_score,
                "to_score": current_threat.risk_score,
                "delta": (current_threat.risk_score or 0) - (previous_threat.risk_score or 0),
                "factor_changes": factor_changes,
            })

    score_delta_explanation = []
    if new_ids:
        score_delta_explanation.append(f"{len(new_ids)} new finding(s) entered the risk register.")
    if resolved_ids:
        score_delta_explanation.append(f"{len(resolved_ids)} previous finding(s) are no longer present.")
    if severity_changes:
        score_delta_explanation.append(f"{len(severity_changes)} finding(s) changed severity or evidence tier.")
    if finding_score_changes:
        score_delta_explanation.append(f"{len(finding_score_changes)} retained finding(s) changed score inputs or score.")
    if not score_delta_explanation and score_delta:
        score_delta_explanation.append("The aggregate score changed because architecture coverage or score weighting changed.")

    if not any((new_ids, resolved_ids, severity_changes, finding_score_changes, added_components, removed_components,
                score_delta, component_delta, flow_delta)):
        return {
            "compared_to_project": previous.project_name,
            "new_threats": [],
            "resolved_threats": [],
            "severity_changes": [],
            "finding_score_changes": [],
            "score_delta_explanation": [],
            "added_components": [],
            "removed_components": [],
            "score_delta": 0,
            "component_delta": 0,
            "flow_delta": 0,
            "changed": False,
        }
    return {
        "compared_to_project": previous.project_name,
        "new_threats": [
            {
                "id": threat_id,
                "title": current_threats[threat_id].title,
                "severity": current_threats[threat_id].severity,
                "tier": current_threats[threat_id].tier,
            }
            for threat_id in new_ids
        ],
        "resolved_threats": [
            {
                "id": threat_id,
                "title": previous_threats[threat_id].title,
                "severity": previous_threats[threat_id].severity,
                "tier": previous_threats[threat_id].tier,
            }
            for threat_id in resolved_ids
        ],
        "severity_changes": severity_changes,
        "finding_score_changes": finding_score_changes,
        "score_delta_explanation": score_delta_explanation,
        "added_components": added_components,
        "removed_components": removed_components,
        "score_delta": score_delta,
        "component_delta": component_delta,
        "flow_delta": flow_delta,
        "changed": True,
    }


def _require_admin(request: Request):
    if ENVIRONMENT != "production" and not ADMIN_API_TOKEN:
        return
    provided = request.headers.get("x-admin-token")
    if not ADMIN_API_TOKEN or provided != ADMIN_API_TOKEN:
        raise HTTPException(status_code=403, detail="Admin token required")


def get_shared_analyzer(request_or_socket) -> ThreatAnalyzer:
    """Return the warmed shared analyzer, or fall back to constructing one."""
    analyzer = getattr(request_or_socket.app.state, "threat_analyzer", None)
    return analyzer or ThreatAnalyzer()


def _sanitize_project_name(value: str) -> str:
    import re
    sanitized = re.sub(r'[<>"\'\\/;]', '', value or "")
    return sanitized.strip()


def _normalize_analysis_mode(value: str) -> str:
    return value if value in ['fast', 'standard', 'deep'] else 'standard'


def _normalize_domain_profile(value: str) -> str:
    return value if value in ['general', 'saas', 'fintech', 'healthcare', 'ai', 'platform'] else 'general'


def _analyze_text_payload(
    analyzer: ThreatAnalyzer,
    description: str,
    project_name: str,
    use_local_slm: bool = True,
    analysis_mode: str = "standard",
    domain_profile: str = "general",
    source_documents: Optional[list] = None,
) -> AnalysisResult:
    previous_result = _latest_analysis_by_project.get(project_name)
    result = analyzer.analyze_from_text(
        description,
        project_name,
        use_local_slm=use_local_slm,
        analysis_mode=analysis_mode,
        domain_profile=domain_profile,
        source_documents=source_documents,
    )
    result.diff_summary = _build_diff_summary(previous_result, result)

    if source_documents:
        coverage = result.coverage or {}
        coverage["source_documents"] = source_documents
        coverage["document_driven_analysis"] = True
        result.coverage = coverage

        metadata = result.architecture.metadata or {}
        metadata["source_documents"] = source_documents
        result.architecture.metadata = metadata

    _latest_analysis_by_project[project_name] = result
    return result


@app.post("/model-review/sources")
async def review_sources(files: list[UploadFile] = File(...)):
    """Extract once; retain the source text and extraction warnings in the draft."""
    try:
        from .engine.parser import ArchitectureParser
        text, documents = await extract_documents(files, max_files=MAX_UPLOAD_FILES, max_total_bytes=MAX_UPLOAD_TOTAL_BYTES)
        bodies = ArchitectureParser._analysis_sources(text)
        return {'sources': [
            {'id': uuid.uuid4().hex, 'name': doc['filename'], 'kind': doc['type'],
             'text': '\n\n'.join(item['body'] for item in bodies if item['document'] == doc['filename']),
             'included': True, 'environment': doc.get('environment') or 'unspecified',
             'version': doc.get('document_version') or '', 'metadata': doc}
            for doc in documents
        ]}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _failure(exc, 'Source extraction')


@app.post("/model-review/prepare")
async def review_prepare(request: Request, payload: ModelReviewRequest):
    try:
        return await _run_analysis(lambda: prepare_model(payload), 'Model preparation')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise _failure(exc, 'Model preparation')


@app.post("/model-review/analyze", response_model=AnalysisResult)
async def review_analyze(request: Request, payload: ModelReviewRequest):
    try:
        analyzer = get_shared_analyzer(request)

        def execute():
            prepared = prepare_model(payload)
            architecture = SystemArchitecture.model_validate(prepared['architecture'])
            if not architecture.components:
                raise ValueError('No components were modeled; correct the input before analyzing.')
            result = analyzer.analyze(architecture, payload.project_name,
                use_local_slm=payload.use_local_slm, analysis_mode=payload.analysis_mode,
                domain_profile=payload.domain_profile)
            result.engine_status['input_review'] = prepared['readiness']
            # Diffs are computed against the client's explicit immutable revision,
            # never another user's most recent result sharing the project name.
            result.diff_summary = None
            return result

        return await _run_analysis(execute, 'Reviewed model analysis')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise _failure(exc, 'Reviewed model analysis')


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: Request, payload: AnalyzeRequest):
    """
    Analyze a system architecture description for potential security threats.
    
    - Uses STRIDE methodology for threat categorization
    - Returns threats with confidence levels and remediation advice
    """
    try:
        # Cache key includes the effective analysis settings.
        cache_key = _stable_cache_key(
            payload.description,
            payload.project_name,
            payload.use_local_slm,
            payload.analysis_mode,
            payload.domain_profile
        )
        
        cached = _analysis_cache.get(cache_key)
        if cached is not None:
            return cached
        
        analyzer = get_shared_analyzer(request)
        result = await _run_analysis(
            lambda: _analyze_text_payload(
                analyzer,
                payload.description,
                payload.project_name,
                use_local_slm=payload.use_local_slm,
                analysis_mode=payload.analysis_mode,
                domain_profile=payload.domain_profile,
            ),
            "Analysis",
        )
        
        _analysis_cache.set(cache_key, result)
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise _failure(e, "Analysis")


@app.post("/analyze-documents", response_model=AnalysisResult)
async def analyze_documents(
    request: Request,
    project_name: str = Form(...),
    use_local_slm: bool = Form(True),
    analysis_mode: str = Form("standard"),
    domain_profile: str = Form("general"),
    context_text: str = Form(""),
    files: list[UploadFile] = File(...),
):
    """
    Analyze uploaded design artifacts such as requirements docs, architecture notes, Markdown, or PDFs.
    """
    try:
        project_name = _sanitize_project_name(project_name)
        analysis_mode = _normalize_analysis_mode(analysis_mode)
        domain_profile = _normalize_domain_profile(domain_profile)
        context_text = (context_text or "").strip()

        extracted_text, source_documents = await extract_documents(
            files, max_files=MAX_UPLOAD_FILES, max_total_bytes=MAX_UPLOAD_TOTAL_BYTES,
        )
        # Incomplete extraction is carried through to the quality gate, which
        # names the documents and pages that were not read and marks the report
        # for review. It is deliberately not a hard stop: the pages that were
        # read still produce findings worth having, and refusing the whole
        # analysis over an embedded diagram loses more than it protects.
        design_docs = [doc for doc in source_documents if doc.get("role") != "reference_report"]
        reference_docs = [doc for doc in source_documents if doc.get("role") == "reference_report"]

        combined_description = extracted_text
        if design_docs:
            design_names = {doc["filename"] for doc in design_docs}
            sections = []
            for section in extracted_text.split("\n\n---\n\n"):
                if any(f"Document: {name}\n" in section for name in design_names):
                    sections.append(section)
            combined_description = "\n\n---\n\n".join(sections)

        if context_text:
            combined_description = f"User Context:\n{context_text}\n\n---\n\n{combined_description}"

        if domain_profile == "general":
            lowered_description = combined_description.lower()
            if any(token in lowered_description for token in ("fhir", "hipaa", "protected health information", "phi")):
                domain_profile = "healthcare"
            elif any(token in lowered_description for token in ("payment gateway", "paymentintent", "stripe", "pci dss")):
                domain_profile = "fintech"
            elif any(token in lowered_description for token in ("llm", "bedrock", "rag", "model endpoint")):
                domain_profile = "ai"

        AnalyzeRequest.validate_description(combined_description)

        cache_key = _stable_cache_key(
            combined_description,
            project_name,
            use_local_slm,
            analysis_mode,
            domain_profile,
            tuple((doc["filename"], doc["type"], doc["characters"]) for doc in source_documents),
        )
        cached = _analysis_cache.get(cache_key)
        if cached is not None:
            return cached

        analyzer = get_shared_analyzer(request)
        result = await _run_analysis(
            lambda: _analyze_text_payload(
                analyzer,
                combined_description,
                project_name,
                use_local_slm=use_local_slm,
                analysis_mode=analysis_mode,
                domain_profile=domain_profile,
                source_documents=source_documents,
            ),
            "Document analysis",
        )
        authoritative_counts = (result.architecture.metadata or {}).get("authoritative_record_counts")
        if authoritative_counts:
            technical_components = sum(
                1 for component in result.architecture.components
                if (component.properties or {}).get("source_record_id", "").startswith("C")
            )
            if technical_components != authoritative_counts.get("components"):
                raise ValueError("Authoritative component records were not modeled completely; analysis was stopped.")
            if len(result.architecture.flows) != authoritative_counts.get("flows"):
                raise ValueError("Authoritative data-flow records were not modeled completely; analysis was stopped.")
            if len((result.architecture.metadata or {}).get("known_issues", [])) != authoritative_counts.get("known_issues"):
                raise ValueError("Known-issue records were not modeled completely; analysis was stopped.")
        if reference_docs:
            coverage = result.coverage or {}
            coverage["reference_reports"] = reference_docs
            result.coverage = coverage
        _analysis_cache.set(cache_key, result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise _failure(e, "Document analysis")


@app.post("/analyze-iac", response_model=AnalysisResult)
async def analyze_iac(request: Request, payload: IaCAnalyzeRequest):
    """
    Analyze Infrastructure-as-Code (Docker Compose, Kubernetes, Terraform, or CloudFormation).
    """
    try:
        from .engine.iac_parser import IaCParser

        cache_key = _stable_cache_key(
            "iac", payload.project_name, payload.analysis_mode,
            payload.format_hint, payload.iac_content,
        )
        cached = _analysis_cache.get(cache_key)
        if cached is not None:
            return cached
        
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)

        def work():
            architecture = IaCParser().parse(payload.iac_content, payload.format_hint)
            if not architecture.components and not (architecture.metadata or {}).get("iac_findings"):
                raise ValueError("No supported resources or services found in the provided IaC file.")
            return analyzer.analyze(architecture, payload.project_name, analysis_mode=payload.analysis_mode)

        result = await _run_analysis(work, "IaC analysis")
        result.diff_summary = _build_diff_summary(previous_result, result)
        _latest_analysis_by_project[payload.project_name] = result
        _analysis_cache.set(cache_key, result)
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise _failure(e, "IaC analysis")


@app.post("/analyze-iac-project", response_model=AnalysisResult)
async def analyze_iac_project(
    request: Request,
    project_name: str = Form(...),
    analysis_mode: str = Form("standard"),
    files: list[UploadFile] = File(...),
):
    """Analyze a related set of IaC, deployment, and CI files as one project."""
    try:
        from .engine.iac_parser import IaCParser

        project_name = _sanitize_project_name(project_name)
        analysis_mode = _normalize_analysis_mode(analysis_mode)
        if not files or len(files) > MAX_UPLOAD_FILES:
            raise ValueError(f"Provide between 1 and {MAX_UPLOAD_FILES} IaC files.")

        inputs = []
        total_bytes = 0
        for upload in files:
            raw = await upload.read()
            total_bytes += len(raw)
            if total_bytes > MAX_UPLOAD_TOTAL_BYTES:
                raise ValueError(f"IaC project exceeds the {MAX_UPLOAD_TOTAL_BYTES // (1024 * 1024)} MB upload limit.")
            inputs.append({
                "filename": upload.filename or f"input-{len(inputs) + 1}",
                "content": raw.decode("utf-8", errors="replace"),
            })

        cache_key = _stable_cache_key(
            "iac-project", project_name, analysis_mode,
            tuple((item["filename"], item["content"]) for item in inputs),
        )
        cached = _analysis_cache.get(cache_key)
        if cached is not None:
            return cached

        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(project_name)

        def work():
            architecture = IaCParser().parse_project(inputs)
            if not architecture.components and not (architecture.metadata or {}).get("iac_findings"):
                raise ValueError("No supported resources or pipeline definitions were found in the uploaded project.")
            return analyzer.analyze(architecture, project_name, analysis_mode=analysis_mode)

        result = await _run_analysis(work, "IaC project analysis")
        result.diff_summary = _build_diff_summary(previous_result, result)
        _latest_analysis_by_project[project_name] = result
        _analysis_cache.set(cache_key, result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise _failure(e, "IaC project analysis")


@app.post("/analyze-code", response_model=AnalysisResult)
async def analyze_code(request: Request, payload: CodeAnalyzeRequest):
    """Run evidence-backed checks for common source-code vulnerability patterns."""
    try:
        from .engine.code_security import CodeSecurityAnalyzer

        findings = CodeSecurityAnalyzer().analyze(payload.code_content)
        architecture = SystemArchitecture(
            components=[Component(
                id="source",
                name="Uploaded Source",
                type="Service",
                properties={"language": payload.language, "source_analysis": True},
            )],
            flows=[],
            metadata={
                "source": "code",
                "security_findings": findings,
                "security_findings_count": len(findings),
            },
        )
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)
        result = analyzer.analyze(
            architecture,
            payload.project_name,
            analysis_mode=payload.analysis_mode,
        )
        result.diff_summary = _build_diff_summary(previous_result, result)
        _latest_analysis_by_project[payload.project_name] = result
        return result
    except Exception as e:
        raise _failure(e, "Code analysis")


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring."""
    # Report NLP/DL capabilities
    ml_features = {
        'nlp_parser': False,
        'semantic_matching': False,
        'attack_chains': False,
    }
    try:
        from .engine.nlp_processor import nlp_runtime_ready
        ml_features['nlp_parser'] = nlp_runtime_ready()
    except ImportError:
        pass
    try:
        from .engine.embedding_service import EMBEDDINGS_AVAILABLE, FAISS_AVAILABLE
        ml_features['semantic_matching'] = EMBEDDINGS_AVAILABLE
        ml_features['vector_search'] = FAISS_AVAILABLE
    except ImportError:
        pass
    try:
        from .engine.attack_chain import NX_AVAILABLE
        ml_features['attack_chains'] = NX_AVAILABLE
    except ImportError:
        pass
    
    return {
        "status": "ok",
        "version": "2.3.1",
        "environment": ENVIRONMENT,
        "ml_features": ml_features,
        "retrieval": retrieval_monitor.snapshot(),
    }


@app.post("/feedback/findings")
def record_finding_feedback(payload: FindingFeedbackRequest):
    """Record a review decision without automatically trusting it for training."""
    try:
        return RetrievalFeedbackStore().record(payload.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/admin/retrieval-feedback/approve")
def approve_retrieval_feedback(request: Request, payload: FeedbackApprovalRequest):
    """Approve one reviewed decision and build candidate thresholds, without activating them."""
    _require_admin(request)
    store = RetrievalFeedbackStore()
    try:
        approval = store.approve(payload.feedback_id, payload.approved_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="feedback record not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    calibration = RetrievalCalibrator().fit(store.approved_training_records())
    return {"approval": approval, "calibration": calibration}


@app.get("/admin/retrieval-metrics")
def retrieval_metrics(request: Request):
    _require_admin(request)
    return {
        **retrieval_monitor.snapshot(),
        "review_feedback": RetrievalFeedbackStore().summary(),
    }


@app.delete("/cache")
async def clear_cache(request: Request):
    """Clear the analysis cache (admin endpoint)."""
    _require_admin(request)
    count = _analysis_cache.clear()
    _latest_analysis_by_project.clear()
    return {"message": f"Cleared {count} cached entries"}


@app.post("/admin/retrain-local-models", response_model=RetrainLocalModelsResponse)
async def retrain_local_models(request: Request):
    """Reload KB data and rebuild local semantic/classifier artifacts."""
    try:
        _require_admin(request)
        analyzer = get_shared_analyzer(request)
        stats = analyzer.reload_local_intelligence()
        return {
            "message": "Local knowledge base and models rebuilt successfully",
            "stats": stats,
        }
    except Exception as e:
        raise _failure(e, "Local retraining")


@app.websocket("/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    """
    WebSocket endpoint for streaming analysis progress.
    
    Client sends: {"description": "...", "project_name": "..."}
    Server streams: {"type": "progress", "phase": "...", "progress": 0-100, "message": "..."}
    Final message:  {"type": "result", "data": <full analysis result>}
    """
    await websocket.accept()
    
    try:
        # Receive analysis request
        data = await websocket.receive_text()
        payload = json.loads(data)
        
        description = payload.get('description', '')
        project_name = payload.get('project_name', 'Untitled Project')
        use_local_slm = payload.get('use_local_slm', True)
        analysis_mode = payload.get('analysis_mode', 'standard')
        domain_profile = payload.get('domain_profile', 'general')
        
        if not description or len(description) < 10:
            await websocket.send_json({
                "type": "error",
                "message": "Description must be at least 10 characters"
            })
            await websocket.close()
            return
        
        # Create streaming analyzer with WebSocket callback
        from .engine.streaming_analyzer import StreamingAnalyzer
        
        async def send_progress(event):
            try:
                await websocket.send_json(event)
            except Exception:
                pass  # Client may have disconnected
        
        shared_analyzer = get_shared_analyzer(websocket)
        streaming_analyzer = StreamingAnalyzer(
            progress_callback=send_progress,
            analyzer=shared_analyzer
        )
        previous_result = _latest_analysis_by_project.get(project_name)
        result = await streaming_analyzer.analyze_streaming(
            description,
            project_name,
            use_local_slm=use_local_slm,
            analysis_mode=analysis_mode,
            domain_profile=domain_profile
        )
        # This is the path the UI uses first, and the one a re-analysis of an
        # amended model arrives on, so it is the path where the reviewer most
        # needs to be told what their edit changed.
        result.diff_summary = _build_diff_summary(previous_result, result)
        _latest_analysis_by_project[project_name] = result

        # Send final result
        result_dict = result.model_dump() if hasattr(result, 'model_dump') else result.dict()
        await websocket.send_json({
            "type": "result",
            "data": result_dict
        })
        
    except WebSocketDisconnect:
        pass  # Client disconnected
    except json.JSONDecodeError:
        await websocket.send_json({
            "type": "error",
            "message": "Invalid JSON payload"
        })
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"Analysis failed: {str(e)}"
            })
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.post("/analyze-with-llm", response_model=AnalysisResult)
async def analyze_with_llm(request: Request, payload: LLMAnalyzeRequest):
    return await _run_analysis(lambda: _analyze_with_llm_sync(request, payload), "AI-enhanced analysis")


def _analyze_with_llm_sync(request: Request, payload: LLMAnalyzeRequest):
    """
    Analyze architecture with LLM enhancement (OpenAI, Claude, or Gemini).
    
    - Runs both rule-based and LLM analysis
    - Uses RAG: retrieves relevant KB threats to include in LLM prompt
    - Semantic deduplication when merging threats
    - LLM threats marked with [AI] prefix
    """
    try:
        # Run rule-based analysis (includes NLP + semantic matching)
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)
        rule_based_result = analyzer.analyze_from_text(
            payload.description,
            payload.project_name,
            analysis_mode=payload.analysis_mode
        )
        
        # RAG: Retrieve relevant KB threats for LLM context
        kb_context = None
        try:
            from .engine.semantic_matcher import get_semantic_matcher
            matcher = get_semantic_matcher()
            results = matcher.find_threats_for_architecture(payload.description, top_k=10)
            kb_context = [
                {
                    'threat_name': meta.get('threat_name', ''),
                    'category': meta.get('category', ''),
                    'severity': meta.get('severity', ''),
                    'score': score
                }
                for meta, score in results
                if score > 0.4
            ]
        except Exception:
            pass  # RAG is optional
        
        ai_error = None
        try:
            llm_threats = LLMAnalyzer.analyze_with_llm(
                architecture_description=payload.description,
                project_name=payload.project_name,
                provider=payload.llm_provider,
                api_key=payload.api_key,
                model=payload.model,
                kb_context=kb_context,
                architecture_model=rule_based_result.system_model,
                stride_coverage=rule_based_result.stride_coverage,
            )
            llm_threats = LLMAnalyzer.validate_llm_threats(
                llm_threats, rule_based_result.architecture, payload.description,
            )

            merged_threats = LLMAnalyzer.merge_threats(rule_based_result.threats, llm_threats)
            rule_based_result.threats = merged_threats
            rule_based_result = analyzer.refresh_result_artifacts(
                rule_based_result,
                domain_profile="general",
                analysis_mode=payload.analysis_mode,
                use_local_slm=True,
            )
            rule_based_result.summary = (
                f"Analysis complete with {payload.llm_provider.upper()} enhancement. "
                f"{len(merged_threats)} threats identified "
                f"(RAG context: {len(kb_context) if kb_context else 0} KB threats)."
            )
            rule_based_result.ml_enhanced = {
                **(rule_based_result.ml_enhanced or {}),
                "llm_provider": payload.llm_provider,
                "llm_model": payload.model,
                "llm_enhancement_applied": True,
                "llm_threats_detected": len(llm_threats),
                "rag_context_threats": len(kb_context) if kb_context else 0,
            }
        except Exception as llm_exc:
            ai_error = str(llm_exc)
            logger.exception(
                "AI enhancement failed; returning local analysis only for provider=%s model=%s project=%s",
                payload.llm_provider,
                payload.model,
                payload.project_name,
            )
            rule_based_result = analyzer.refresh_result_artifacts(
                rule_based_result,
                domain_profile="general",
                analysis_mode=payload.analysis_mode,
                use_local_slm=True,
            )
            rule_based_result.summary = (
                f"Local analysis completed. AI enhancement via {payload.llm_provider.upper()} "
                f"could not be applied for model {payload.model or 'default'}."
            )
            rule_based_result.ml_enhanced = {
                **(rule_based_result.ml_enhanced or {}),
                "llm_provider": payload.llm_provider,
                "llm_model": payload.model,
                "llm_enhancement_applied": False,
                "llm_error": ai_error,
            }

        rule_based_result.diff_summary = _build_diff_summary(previous_result, rule_based_result)
        _latest_analysis_by_project[payload.project_name] = rule_based_result
        
        return rule_based_result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # The provider name is safe to log; the exception may quote the request,
        # which carries the caller's API key.
        logger.error(
            "LLM analysis failed for provider=%s model=%s project=%s",
            payload.llm_provider,
            payload.model,
            payload.project_name,
        )
        raise _failure(e, "LLM analysis")


@app.get("/llm/providers")
async def get_llm_providers():
    """Return supported external LLM providers and fallback model metadata."""
    return {"providers": provider_public_info()}


@app.post("/llm/models")
async def get_llm_models(payload: LLMModelsRequest):
    """Validate an API key and return available models for the selected provider."""
    try:
        is_valid = LLMAnalyzer.validate_api_key(payload.provider, payload.api_key)
        models = LLMAnalyzer.list_models(payload.provider, payload.api_key) if is_valid else []
        return {
            "valid": is_valid,
            "provider": payload.provider,
            "models": models,
        }
    except Exception:
        return {
            "valid": False,
            "provider": payload.provider,
            "models": [],
        }


@app.post("/validate-api-key")
async def validate_api_key(payload: APIKeyValidationRequest):
    """
    Validate an LLM API key.
    
    Returns:
        {"valid": true/false, "provider": "openai"/"claude"}
    """
    try:
        is_valid = LLMAnalyzer.validate_api_key(payload.provider, payload.api_key)
        models = LLMAnalyzer.list_models(payload.provider, payload.api_key) if is_valid else []
        return {
            "valid": is_valid,
            "provider": payload.provider,
            "models": models,
        }
    except Exception as e:
        return {
            "valid": False,
            "provider": payload.provider,
            "models": [],
            "error": "API key validation failed"
        }
