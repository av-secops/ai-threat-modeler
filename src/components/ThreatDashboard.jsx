import { useEffect, useMemo, useRef, useState } from 'react';
import AssuranceEvidence from './dashboard/AssuranceEvidence';
import { diagramQuality } from '../utils/diagramQuality';
import {
    BadgeCheck,
    BarChart3,
    Download,
    FileText,

    LayoutDashboard,
    Network,

    ShieldAlert,

    Copy,
    ClipboardCheck,
    ShieldCheck,
    ZoomIn,
    ZoomOut,
    RotateCcw,
    Maximize2,
    Minimize2,
    Focus,
    Pencil,
} from 'lucide-react';
import { clsx } from 'clsx';
import RiskMatrix from './RiskMatrix';
import StrideChart from './StrideChart';
import ArchitectureModelEditor from './dashboard/ArchitectureModelEditor';
import EvidenceRequests from './dashboard/EvidenceRequests';
import ReanalysisDiff from './dashboard/ReanalysisDiff';
import {
    AISecurityLensCard,
    DetailSection,
    EmptyInsight,
    MetricCard,
    SeverityBadge,
} from './dashboard/InsightCards';
import { RiskDetailsModal } from './dashboard/RiskRegister';
import FindingsWorkspace from './dashboard/FindingsWorkspace';
import ReportOverview from './dashboard/ReportOverview';
import { insightCardBase, reviewStateMeta, severityOrder } from './dashboard/theme';
import { useToast } from '../hooks/useToast';
import { loadAnnotations, saveAnnotations } from '../utils/annotations';
import AnalystWorkbench from './AnalystWorkbench';
import AnalysisCopilot from './AnalysisCopilot';
import { recordFindingFeedback } from '../services/retrievalFeedback';
import { enterprise } from '../services/enterprise';
import { API_BASE_URL } from '../config';
import SecurityReports from './dashboard/SecurityReports';
import RiskReviewForm from './dashboard/RiskReviewForm';
import ArchitectureFlowTable from './dashboard/ArchitectureFlowTable';
import { canonicalDiagramId, clampDiagramZoom, fitDiagramZoom, flowKey, focusedDiagram, isAssumedFlow, MAX_DIAGRAM_ZOOM, MIN_DIAGRAM_ZOOM } from '../utils/diagramViews';

const resultViews = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'architecture', label: 'Architecture', icon: Network },
    { id: 'register', label: 'Risk register', icon: ShieldAlert },
    { id: 'assurance', label: 'Security Reports', icon: BadgeCheck },
    { id: 'report', label: 'Report', icon: FileText },
];

const normalizeLabel = (value) => String(value || '').trim().toLowerCase();

const resizeDiagramSvg = (svgElement, zoom) => {
    if (!svgElement?.dataset.baseWidth || !svgElement?.dataset.baseHeight) return;
    svgElement.style.width = `${Number(svgElement.dataset.baseWidth) * zoom}px`;
    svgElement.style.height = `${Number(svgElement.dataset.baseHeight) * zoom}px`;
    svgElement.style.maxWidth = 'none';
    svgElement.style.maxHeight = 'none';
};

export default function ThreatDashboard({ data, projectName, onReanalyze, onReviewModel, onClarify, onProposeUpdate, annotationScope, isAnalyzing, darkMode = false, sidebarCollapsed = true, readOnly = false }) {
    const reviewKey = annotationScope || projectName;
    const mermaidRef = useRef(null);
    const diagramViewportRef = useRef(null);
    const diagramPanelRef = useRef(null);
    const zoomAnchor = useRef(null);
    const toast = useToast();
    const [copiedDiagram, setCopiedDiagram] = useState(false);
    const [reviewStates, setReviewStates] = useState({});
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [serverReviews, setServerReviews] = useState({ latest: {}, events: [] });
    const [reviewLoadError, setReviewLoadError] = useState('');
    const assessment = data?.engine_status?.assessment;
    const reportId = assessment?.report_id;
    const [diagramZoom, setDiagramZoom] = useState(1);
    const [diagramView, setDiagramView] = useState('system');
    const [focusedFlow, setFocusedFlow] = useState('');
    const [focusedComponent, setFocusedComponent] = useState('');
    const [diagramMode, setDiagramMode] = useState('diagram');
    const [expandedDiagram, setExpandedDiagram] = useState(false);
    const [diagramError, setDiagramError] = useState('');
    const focusedView = useMemo(() => focusedDiagram(data?.architecture, { flowId: focusedFlow, componentId: focusedComponent, threats: data?.threats }), [data, focusedFlow, focusedComponent]);
    const selectedDiagram = data?.engine_status?.diagram_views?.find(view => view.id === diagramView);
    const displayedDiagram = focusedView?.diagram || selectedDiagram?.diagram || data?.diagram;
    const diagramZoomRef = useRef(1);
    const [filters, setFilters] = useState({
        severity: 'all',
        category: 'all',
        tier: 'all',
        search: '',
    });

    const [activeView, setActiveView] = useState('overview');
    const [viewData, setViewData] = useState(data);

    if (viewData !== data) {
        setViewData(data);
        setActiveView('overview');
        setSelectedThreat(null);
        setFilters({ severity: 'all', category: 'all', tier: 'all', search: '' });
        setDiagramZoom(1);
        setFocusedFlow('');
        setFocusedComponent('');
        setDiagramView('system');
        setDiagramMode('diagram');
    }

    useEffect(() => {
        let cancelled = false;
        const renderDiagram = async () => {
            if (activeView !== 'architecture' || diagramMode !== 'diagram' || !displayedDiagram || !mermaidRef.current) return;

            try {
                const { default: mermaid } = await import('mermaid');
                if (cancelled || !mermaidRef.current) return;
                mermaid.initialize({
                    startOnLoad: false,
                    theme: darkMode ? 'dark' : 'default',
                    securityLevel: 'strict',
                    fontFamily: 'Inter, sans-serif',
                });

                mermaidRef.current.innerHTML = '';
                setDiagramError('');
                const diagramId = `mermaid-diagram-${crypto.randomUUID()}`;
                const { svg } = await mermaid.render(diagramId, displayedDiagram);
                if (cancelled || !mermaidRef.current) return;
                mermaidRef.current.innerHTML = svg;

                const svgElement = mermaidRef.current.querySelector('svg');
                if (svgElement) {
                    if (darkMode) {
                        // Mermaid applies generated theme styles as inline !important values.
                        svgElement.querySelectorAll('.cluster rect').forEach((node) => {
                            node.style.setProperty('fill', '#18202c', 'important');
                            node.style.setProperty('stroke', '#8897aa', 'important');
                        });
                        svgElement.querySelectorAll('.node rect, .node circle, .node ellipse, .node polygon, .node path').forEach((node) => {
                            const confirmed = node.closest('.dfdFinding') || ['#dc2626', 'rgb(220, 38, 38)'].includes(node.style.stroke);
                            node.style.setProperty('fill', '#252f3d', 'important');
                            node.style.setProperty('stroke', confirmed ? '#f87171' : '#cbd5e1', 'important');
                        });
                        svgElement.querySelectorAll('.nodeLabel, .nodeLabel *, .cluster-label, .cluster-label *, .edgeLabel, .edgeLabel *, text').forEach((node) => {
                            node.style.setProperty('color', '#f1f5f9', 'important');
                            node.style.setProperty('fill', '#f1f5f9', 'important');
                        });
                    }
                    const viewBox = (svgElement.getAttribute('viewBox') || '').split(/\s+/).map(Number);
                    const viewWidth = viewBox[2] || 900;
                    const viewHeight = viewBox[3] || 560;
                    // Zoom is relative to intrinsic SVG size, not an already-shrunken thumbnail.
                    svgElement.dataset.baseWidth = String(viewWidth);
                    svgElement.dataset.baseHeight = String(viewHeight);
                    svgElement.dataset.theme = darkMode ? 'dark' : 'light';
                    svgElement.removeAttribute('width');
                    svgElement.removeAttribute('height');
                    const initialZoom = 1;
                    zoomAnchor.current = null;
                    resizeDiagramSvg(svgElement, initialZoom);
                    diagramZoomRef.current = initialZoom;
                    setDiagramZoom(initialZoom);
                    diagramViewportRef.current?.scrollTo(0, 0);
                    const nodeBindings = focusedView?.nodes || await Promise.all((data.architecture?.components || []).map(async c => ({ element_id: c.id, diagram_id: await canonicalDiagramId(c.id) })));
                    if (cancelled) return;
                    svgElement.querySelectorAll('.node').forEach(node => {
                        const id = node.id.replace(`${diagramId}-`, '');
                        const binding = nodeBindings.find(item => id.startsWith(`flowchart-${item.diagram_id}-`));
                        if (!binding) return;
                        const focus = () => { setFocusedComponent(binding.element_id); setFocusedFlow(''); };
                        node.setAttribute('role', 'button'); node.setAttribute('tabindex', '0');
                        node.setAttribute('aria-label', `Focus component ${node.textContent.trim()}`);
                        node.style.cursor = 'pointer';
                        node.addEventListener('click', event => { event.stopPropagation(); focus(); });
                        node.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); focus(); } });
                    });
                    const indexes = focusedView?.indexes || data.engine_status?.diagram_views?.find(view => view.diagram === displayedDiagram)?.coverage?.flow_indexes || (data.architecture?.flows || []).map((_, i) => i);
                    const links = [...svgElement.querySelectorAll('.flowchart-link')];
                    links.forEach((link, index) => {
                        const flow = data.architecture?.flows?.[indexes[index]];
                        if (!flow) return;
                        const key = flowKey(flow, indexes[index]);
                        link.setAttribute('tabindex', '0'); link.setAttribute('role', 'button');
                        link.setAttribute('aria-label', `Inspect ${flow.flow_number || 'data flow'}`);
                        link.style.cursor = 'pointer';
                        link.addEventListener('click', event => { event.stopPropagation(); setFocusedFlow(key); setFocusedComponent(''); });
                        link.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); setFocusedFlow(key); setFocusedComponent(''); } });
                        link.style.setProperty('stroke', focusedFlow === key ? '#0d9488' : darkMode ? '#d4dee9' : '#475569', 'important');
                        if (key === focusedFlow) link.style.setProperty('stroke-width', '3px', 'important');
                    });
                    if (darkMode) svgElement.querySelectorAll('marker path, .arrowMarkerPath').forEach(node => {
                        node.style.setProperty('fill', '#d4dee9', 'important'); node.style.setProperty('stroke', '#d4dee9', 'important');
                    });
                }
            } catch (error) {
                console.error('Mermaid rendering error:', error);
                if (!cancelled) setDiagramError('The diagram could not be rendered. The flow list remains available.');
            }
        };

        renderDiagram();
        return () => { cancelled = true; };
    }, [activeView, data, darkMode, displayedDiagram, focusedFlow, focusedView, diagramMode]);

    useEffect(() => {
        diagramZoomRef.current = diagramZoom;
        resizeDiagramSvg(mermaidRef.current?.querySelector('svg'), diagramZoom);
        const anchor = zoomAnchor.current;
        if (anchor && diagramViewportRef.current) {
            diagramViewportRef.current.scrollLeft = anchor.left * diagramZoom / anchor.zoom - anchor.x;
            diagramViewportRef.current.scrollTop = anchor.top * diagramZoom / anchor.zoom - anchor.y;
            zoomAnchor.current = null;
        }
    }, [diagramZoom]);

    useEffect(() => {
        const viewport = diagramViewportRef.current;
        if (activeView !== 'architecture' || diagramMode !== 'diagram' || !viewport) return undefined;
        const wheel = (event) => {
            event.preventDefault();
            const rect = viewport.getBoundingClientRect();
            const x = event.clientX - rect.left; const y = event.clientY - rect.top;
            zoomAnchor.current = { left: viewport.scrollLeft + x, top: viewport.scrollTop + y, zoom: diagramZoomRef.current, x, y };
            setDiagramZoom(current => clampDiagramZoom(current * (event.deltaY < 0 ? 1.15 : 1 / 1.15)));
        };
        let drag;
        const down = (event) => {
            if (event.button !== 0 || event.target.closest('button, a, input, [role="button"]')) return;
            drag = { x: event.clientX, y: event.clientY, left: viewport.scrollLeft, top: viewport.scrollTop };
            viewport.setPointerCapture(event.pointerId);
        };
        const move = (event) => {
            if (!drag) return;
            viewport.scrollLeft = drag.left - (event.clientX - drag.x);
            viewport.scrollTop = drag.top - (event.clientY - drag.y);
        };
        const up = () => { drag = null; };
        viewport.addEventListener('wheel', wheel, { passive: false });
        viewport.addEventListener('pointerdown', down);
        viewport.addEventListener('pointermove', move);
        viewport.addEventListener('pointerup', up);
        viewport.addEventListener('pointercancel', up);
        return () => {
            viewport.removeEventListener('wheel', wheel);
            viewport.removeEventListener('pointerdown', down);
            viewport.removeEventListener('pointermove', move);
            viewport.removeEventListener('pointerup', up);
            viewport.removeEventListener('pointercancel', up);
        };
    }, [activeView, diagramMode]);

    useEffect(() => {
        const changed = () => setExpandedDiagram(document.fullscreenElement === diagramPanelRef.current && !!document.fullscreenElement);
        document.addEventListener('fullscreenchange', changed);
        return () => document.removeEventListener('fullscreenchange', changed);
    }, []);

    useEffect(() => {
        // A reviewer's decision outranks the engine's default. Re-analysis
        // reports every finding as open again, and without this a finding
        // already accepted or marked a false positive would come back demanding
        // the same judgement after every edit to the model.
        const stored = loadAnnotations(reviewKey).reviewStates;
        const nextStates = {};
        (data?.threats || []).forEach((threat) => {
            nextStates[threat.id] = reportId ? 'pending_review' : stored[threat.id] || threat.review_state || 'open';
        });
        queueMicrotask(() => setReviewStates(nextStates));
        let active = true;
        if (reportId) enterprise(`/assessment-reports/${reportId}/reviews`).then(result => {
            if (!active) return;
            setReviewLoadError('');
            setServerReviews(result);
            setReviewStates({ ...nextStates, ...Object.fromEntries(Object.entries(result.latest).map(([id, item]) => [id, item.status])) });
        }).catch(error => { if (active) setReviewLoadError(error.message); });
        return () => { active = false; };
    }, [data, reviewKey, reportId]);

    const updateReviewState = (threatId, state) => {
        if (readOnly) return;
        if (reportId) { setSelectedThreat((data?.threats || []).find(t => t.id === threatId)); return; }
        setReviewStates((prev) => {
            const next = { ...prev, [threatId]: state };
            saveAnnotations(reviewKey, { reviewStates: next });
            return next;
        });
        const threat = (data?.threats || []).find((item) => item.id === threatId);
        if (threat && state !== 'open') {
            recordFindingFeedback({ projectName, threat, decision: state }).catch((error) => {
                console.warn('Finding feedback could not be recorded:', error);
            });
        }
    };



    if (!data) return null;

    const systemModel = data.system_model || {};
    const strideCoverage = data.stride_coverage || {};
    const engineStatus = data.engine_status || {};
    const localIntelligence = engineStatus.local_intelligence || {};
    const retrievalEngine = localIntelligence.retrieval_engine || {};
    const knowledgeAudit = engineStatus.knowledge_base?.quality_audit || {};
    const knowledgeGovernance = engineStatus.knowledge_base?.governance;
    const qualityGate = engineStatus.quality_gate || {};
    const extraction = diagramQuality(data);
    const extractionIncomplete = !extraction.score_available;
    const scoreAvailable = !extractionIncomplete && Number.isFinite(data.score);
    const publicationBlocked = extractionIncomplete || qualityGate.publication_status === 'blocked' || qualityGate.status === 'blocked';
    const publicationLabel = publicationBlocked
        ? extractionIncomplete ? 'Draft - architecture extraction incomplete' : 'Draft - model integrity check failed'
        : qualityGate.publication_status === 'ready'
            ? 'Publication ready'
            : 'Technical review';
    const integrityViolations = qualityGate.integrity_violations || [];
    const completenessWarnings = qualityGate.completeness_warnings || [];
    const diagramCoverage = focusedView?.coverage || selectedDiagram?.coverage || engineStatus.diagram_coverage;
    const componentNames = new Map((data.architecture?.components || []).map(c => [c.id, c.name]));
    const selectedFlow = data.architecture?.flows?.find((flow, index) => flowKey(flow, index) === focusedFlow);
    const assumptions = data.coverage?.assumptions || [];
    const diffSummary = data.diff_summary;
    const followUpQuestions = data.follow_up_questions || [];
    const evidenceRequests = data.evidence_requests || null;
    const aiSecurityLens = data.ai_security_lens || { enabled: false, overview: '', items: [] };
    const aiLensGridClass = aiSecurityLens.items?.length === 1
        ? 'grid-cols-1'
        : aiSecurityLens.items?.length === 2
            ? 'md:grid-cols-2'
            : 'md:grid-cols-2 xl:grid-cols-3';

    // The header counted follow-up questions while the body showed evidence
    // requests as well, so the two disagreed about how much was outstanding.
    const openQuestionCount = followUpQuestions.length + (evidenceRequests?.requests?.length || 0);

    const allThreatsSorted = [...(data.threats || [])].sort((a, b) => {
        const severityDelta = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        if (severityDelta !== 0) return severityDelta;
        return (b.risk_score || 0) - (a.risk_score || 0);
    });


    const confirmedThreats = (data.threats || []).filter((threat) => (
        normalizeLabel(threat.tier) === 'confirmed' && reviewStates[threat.id] !== 'false_positive'
    ));
    const confirmedCount = confirmedThreats.length;
    // Counted across every finding, these read as a breakdown of the confirmed
    // total they sit under and so could exceed it. They describe the same set.
    const criticalCount = confirmedThreats.filter((threat) => normalizeLabel(threat.severity) === 'critical').length;
    const highCount = confirmedThreats.filter((threat) => normalizeLabel(threat.severity) === 'high').length;
    const mitigatedThreats = (data.threats || []).filter(threat => ['mitigated', 'accepted', 'verified_fixed', 'false_positive'].includes(reviewStates[threat.id])).length;
    const remediationPercent = data.threats?.length ? Math.round((mitigatedThreats / data.threats.length) * 100) : 0;
    const reviewSummary = (data.threats || []).reduce((summary, threat) => {
        const state = reviewStates[threat.id] || 'open';
        summary[state] = (summary[state] || 0) + 1;
        return summary;
    }, { open: 0, mitigated: 0, accepted: 0, false_positive: 0 });


    const handleRiskMatrixClick = (impact, likelihood) => {
        setFilters((prev) => ({
            ...prev,
            severity: 'all', impact, likelihood,
        }));
        setActiveView('register');

        toast.success(`Filtering by ${impact} impact and ${likelihood} likelihood`);
    };

    const changeDiagramZoom = (delta) => {
        const viewport = diagramViewportRef.current;
        if (viewport) zoomAnchor.current = { left: viewport.scrollLeft + viewport.clientWidth / 2, top: viewport.scrollTop + viewport.clientHeight / 2,
            zoom: diagramZoomRef.current, x: viewport.clientWidth / 2, y: viewport.clientHeight / 2 };
        setDiagramZoom(current => clampDiagramZoom(current * (delta > 0 ? 1.25 : .8)));
    };

    const fitDiagram = () => {
        const svg = mermaidRef.current?.querySelector('svg'); const viewport = diagramViewportRef.current;
        if (!svg || !viewport) return;
        zoomAnchor.current = null;
        setDiagramZoom(fitDiagramZoom(Number(svg.dataset.baseWidth), Number(svg.dataset.baseHeight), viewport.clientWidth - 48, viewport.clientHeight - 48));
        viewport.scrollTo(0, 0);
    };

    const expandDiagram = async () => {
        try {
            if (document.fullscreenElement === diagramPanelRef.current) await document.exitFullscreen();
            else await diagramPanelRef.current?.requestFullscreen();
        } catch { toast.error('Full screen is unavailable in this browser. Flow and component focus remain available.'); }
    };

    const traceFlow = id => { setFocusedFlow(id); setFocusedComponent(''); setDiagramView('system'); setDiagramMode('diagram'); };


    const copyDiagramCode = async () => {
        if (!data?.diagram) return;
        try {
            await navigator.clipboard.writeText(displayedDiagram);
            setCopiedDiagram(true);
            toast.success('Diagram code copied to clipboard');
            setTimeout(() => setCopiedDiagram(false), 2000);
        } catch {
            toast.error('Failed to copy diagram code');
        }
    };

    const downloadJSON = () => {
        try {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_threat_model.json`;
            a.click();
            toast.success('JSON file downloaded');
        } catch {
            toast.error('Failed to download JSON file');
        }
    };

    const downloadCSV = () => {
        try {
            const headers = ['ID', 'Tier', 'Severity', 'Confidence', 'Category', 'Title', 'Description', 'Mitigation'];
            const rows = data.threats.map((t) => [
                t.id,
                t.tier,
                t.severity,
                t.confidence,
                t.category,
                t.title,
                t.description,
                t.mitigation,
            ].map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','));

            const csv = [headers.join(','), ...rows].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_threat_model.csv`;
            a.click();
            toast.success('CSV file downloaded');
        } catch {
            toast.error('Failed to download CSV file');
        }
    };

    const downloadMarkdown = () => {
        if (publicationBlocked) {
            toast.error('Final report export is blocked until quality-gate failures are resolved.');
            return;
        }
        try {
            const blob = new Blob([data.report_markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_Threat_Report.md`;
            a.click();
            toast.success('Markdown report downloaded');
        } catch {
            toast.error('Failed to download markdown file');
        }
    };

    const exportDiagramAsPNG = async () => {
        try {
            const element = mermaidRef.current;
            if (!element) {
                toast.error('Diagram not available');
                return;
            }
            const { default: html2canvas } = await import('html2canvas');
            const bounds = element.getBoundingClientRect();
            const scale = Math.min(2, 8192 / Math.max(1, bounds.width), 8192 / Math.max(1, bounds.height), Math.sqrt(16000000 / Math.max(1, bounds.width * bounds.height)));
            const canvas = await html2canvas(element, { scale, backgroundColor: darkMode ? '#18202c' : '#ffffff' });
            const link = document.createElement('a');
            link.download = `${projectName.replace(/\s+/g, '_')}_architecture.png`;
            link.href = canvas.toDataURL();
            link.click();
            toast.success('Diagram exported as PNG');
        } catch {
            toast.error('Failed to export diagram');
        }
    };

    const handlePDFExport = async ({ draft = false } = {}) => {
        if (publicationBlocked && !draft) {
            toast.error('Final report export is blocked until quality-gate failures are resolved.');
            return;
        }
        try {
            const { generateReport } = await import('../utils/pdfGenerator');
            await generateReport({ ...data, risk_review: serverReviews }, projectName, reviewStates, { draft });
            toast.success(draft ? 'Draft PDF generated' : 'PDF report generated');
        } catch {
            toast.error('Failed to generate PDF report');
        }
    };



    return (
        <div className="technical-report mx-auto w-full max-w-6xl animate-fade-in-up bg-white px-2 pb-24 text-slate-900 transition-colors dark:bg-brand-900 dark:text-brand-100 sm:px-4">
            <section className="relative border-b border-brand-200 py-5 dark:border-brand-700">

                <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-3xl">
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Technical threat model</p>
                        <h1 className="mt-2 break-words text-2xl font-semibold text-slate-950 dark:text-white">
                            {projectName}
                        </h1>
                        {activeView === 'overview' && <p className="mt-3 max-w-3xl text-sm leading-7 text-brand-600 dark:text-brand-300">
                            {data.summary}
                        </p>}
                        <div className="mt-5 flex flex-wrap items-center gap-3 text-sm text-brand-500 dark:text-brand-400">
                            <span className={clsx('border px-2 py-1 text-xs font-semibold uppercase', publicationBlocked ? 'border-red-300 text-red-700 dark:text-red-300' : 'border-emerald-300 text-emerald-700 dark:text-emerald-300')}>
                                {publicationLabel}
                            </span>
                            <span>Generated {data.timestamp || new Date().toLocaleString()}</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.coverage?.analysis_mode || 'standard'} mode</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.threats?.length || 0} findings</span>
                            <span>{reportId ? `Questionnaire v${assessment.template_version} recorded` : 'Diagnostic / questionnaire not recorded'}</span>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                        <button
                            onClick={() => {
                                setActiveView('register');

                            }}
                            className="ui-button-secondary"
                        >
                            <span className="inline-flex items-center gap-2">
                                <ShieldAlert className="h-4 w-4" />
                                Findings
                            </span>
                        </button>
                        <button onClick={handlePDFExport} disabled={publicationBlocked} className="btn-brand disabled:cursor-not-allowed disabled:opacity-45" title={publicationBlocked ? 'Resolve quality-gate failures before final export' : 'Export final PDF'}>
                            <span className="inline-flex items-center gap-2"><Download className="h-4 w-4" /> Export PDF</span>
                        </button>
                        <details className="relative">
                            <summary className="ui-button-secondary cursor-pointer marker:content-none">
                                <span className="inline-flex items-center gap-2"><FileText className="h-4 w-4" /> Other formats</span>
                            </summary>
                            <div className="absolute right-0 z-20 mt-2 flex w-44 flex-col gap-1 rounded-md border border-slate-200 bg-white p-2 shadow-lg dark:border-brand-700 dark:bg-brand-800">
                                {publicationBlocked && <button onClick={() => handlePDFExport({ draft: true })} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-200 dark:hover:bg-brand-700">Draft PDF</button>}
                                <button onClick={downloadJSON} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-200 dark:hover:bg-brand-700">JSON</button>
                                <button onClick={downloadCSV} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-200 dark:hover:bg-brand-700">CSV</button>
                                {data.report_markdown && (
                                    <button onClick={downloadMarkdown} disabled={publicationBlocked} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 disabled:cursor-not-allowed disabled:opacity-45 dark:text-brand-200 dark:hover:bg-brand-700">Markdown</button>
                                )}
                            </div>
                        </details>
                    </div>
                </div>

                {activeView === 'overview' ? <div className="relative mt-6 grid gap-4 md:grid-cols-3">
                    <MetricCard label="Security score" value={scoreAvailable ? `${data.score}/100` : 'Not assessed'} tone={!scoreAvailable ? 'warning' : data.score < 40 ? 'danger' : data.score < 70 ? 'warning' : 'success'} detail={!scoreAvailable ? 'Architecture review required' : data.score < 40 ? 'Immediate response recommended' : data.score < 70 ? 'Address top findings next' : 'Strong baseline with focused follow-up'} />
                    <MetricCard label="Confirmed risks" value={confirmedCount} tone={criticalCount > 0 ? 'danger' : 'accent'} detail={`${criticalCount} critical, ${highCount} high`} />
                    <MetricCard label="Open questions" value={openQuestionCount} tone="warning" detail={openQuestionCount ? 'Answering these sharpens the model' : 'Architecture detail looks well covered'} />
                </div> : <dl className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-xs text-brand-600 dark:text-brand-300">
                    <div className="flex gap-2"><dt>Score</dt><dd className="font-semibold">{scoreAvailable ? `${data.score}/100` : 'Not assessed'}</dd></div>
                    <div className="flex gap-2"><dt>Confirmed</dt><dd className="font-semibold">{confirmedCount} ({criticalCount} critical, {highCount} high)</dd></div>
                    <div className="flex gap-2"><dt>Open questions</dt><dd className="font-semibold">{openQuestionCount}</dd></div>
                </dl>}
            </section>

            {extractionIncomplete && <section role="status" className="mt-4 border-l-4 border-amber-500 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:bg-amber-950/30 dark:text-amber-100">
                <h2 className="font-semibold">Architecture extraction incomplete</h2>
                <ul className="mt-1 list-disc pl-5">{extraction.reasons.map(reason => <li key={reason}>{reason}</li>)}</ul>
                <p className="mt-2">Findings are provisional. The security score and final report are unavailable until the diagram is reviewed.</p>
                {onReviewModel && <button type="button" className="ui-button-secondary mt-3" onClick={onReviewModel}><Pencil size={15} />Review architecture</button>}
            </section>}

            <nav className="sticky top-[68px] z-30 mt-4 overflow-x-auto border-y border-brand-200 bg-white/95 py-2 backdrop-blur dark:border-brand-700 dark:bg-brand-900/95" aria-label="Analysis result views">
                <div className="flex min-w-max gap-1">
                    {resultViews.map((view) => {
                        const Icon = view.icon;
                        const isActive = activeView === view.id;
                        return (
                            <button
                                key={view.id}
                                type="button"
                                onClick={() => setActiveView(view.id)}
                                className={clsx(
                                    'inline-flex h-11 items-center justify-center gap-2 border-b-2 px-4 text-sm font-semibold transition-colors',
                                    isActive
                                        ? 'border-brand-primary text-brand-primary dark:text-indigo-300'
                                        : 'border-transparent text-brand-600 hover:bg-brand-50 hover:text-brand-950 dark:text-brand-300 dark:hover:bg-brand-800 dark:hover:text-white',
                                )}
                                aria-current={isActive ? 'page' : undefined}
                            >
                                <Icon className="h-4 w-4 shrink-0" />
                                <span>{view.label}</span>
                            </button>
                        );
                    })}
                </div>
            </nav>



            {(activeView === 'overview' || activeView === 'assurance') && (
                <>
                    {(publicationBlocked || integrityViolations.length > 0) && (
                        <div className="mt-6 border-l-4 border-red-600 bg-white px-4 py-3 text-sm text-slate-700 dark:bg-red-950/20 dark:text-red-200">
                            <p className="font-semibold text-red-700 dark:text-red-300">{extractionIncomplete ? 'Complete architecture review before publishing a final report.' : 'This report contradicts itself and cannot be published as final.'}</p>
                            <ul className="mt-1 list-disc space-y-0.5 pl-5">
                                {integrityViolations.map((violation) => (
                                    <li key={violation.check}>{violation.detail} ({violation.count})</li>
                                ))}
                            </ul>
                        </div>
                    )}

                    {!publicationBlocked && completenessWarnings.length > 0 && (
                        <div className="mt-6 border-l-4 border-amber-500 bg-white px-4 py-3 text-sm text-slate-700 dark:bg-amber-950/20 dark:text-amber-200">
                            <p className="font-semibold text-amber-700 dark:text-amber-300">The findings stand; these gaps need a reviewer's eye before sign-off.</p>
                            <ul className="mt-1 list-disc space-y-0.5 pl-5">
                                {completenessWarnings.map((warning) => (
                                    <li key={warning.check}>{warning.detail} ({warning.count})</li>
                                ))}
                            </ul>
                        </div>
                    )}
                </>
            )}

            {activeView === 'overview' && <ReportOverview threats={allThreatsSorted} reviewStates={reviewStates} onSelect={setSelectedThreat} onOpenRegister={() => setActiveView('register')} onOpenAssurance={() => setActiveView('assurance')} evidenceRequests={evidenceRequests} />}

            {activeView === 'architecture' && <section className="mt-6">
                <div ref={diagramPanelRef} data-expanded={expandedDiagram} className={clsx(insightCardBase, 'mx-auto flex w-full min-w-0 flex-col p-4 sm:p-6', expandedDiagram ? 'h-full max-w-none overflow-y-auto rounded-none' : 'max-w-6xl')}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="min-w-0">
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture view</h3>
                            <div className="mt-2 flex gap-1" role="group" aria-label="Architecture display">{[['diagram', 'Diagram'], ['flows', 'Flow list']].map(([id, name]) => <button key={id} type="button" aria-pressed={diagramMode === id} className={`border-b-2 px-3 py-2 text-sm ${diagramMode === id ? 'border-brand-primary font-semibold' : 'border-transparent'}`} onClick={() => setDiagramMode(id)}>{name}</button>)}</div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                            {diagramMode === 'diagram' && <div className="flex items-center rounded-md border border-brand-200 bg-white dark:border-brand-700 dark:bg-brand-800">
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(-0.1)}
                                    disabled={diagramZoom <= MIN_DIAGRAM_ZOOM}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom out architecture diagram"
                                    title="Zoom out"
                                >
                                    <ZoomOut className="h-4 w-4" />
                                </button>
                                <output aria-label="Architecture zoom" className="w-14 text-center text-xs font-semibold tabular-nums text-brand-600 dark:text-brand-300">{diagramZoom < .1 ? (diagramZoom * 100).toFixed(1) : Math.round(diagramZoom * 100)}%</output>
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(0.1)}
                                    disabled={diagramZoom >= MAX_DIAGRAM_ZOOM}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom in architecture diagram"
                                    title="Zoom in"
                                >
                                    <ZoomIn className="h-4 w-4" />
                                </button>
                                <button
                                    type="button"
                                    onClick={fitDiagram}
                                    className="inline-flex h-9 w-9 items-center justify-center border-l border-brand-200 text-brand-600 hover:text-brand-primary dark:border-brand-700 dark:text-brand-300"
                                    aria-label="Fit architecture diagram"
                                    title="Fit entire diagram"
                                >
                                    <RotateCcw className="h-4 w-4" />
                                </button>
                                <button type="button" className="inline-flex h-9 w-9 items-center justify-center border-l border-brand-200 dark:border-brand-700" aria-label="Actual diagram size" title="Actual size (100%)" onClick={() => { zoomAnchor.current = null; setDiagramZoom(1); }}><Focus size={16} /></button>
                            </div>}
                            <button type="button" className="ui-button-secondary p-2" aria-label={expandedDiagram ? 'Exit full screen architecture' : 'Expand architecture'} title={expandedDiagram ? 'Exit full screen' : 'Full screen'} onClick={expandDiagram}>{expandedDiagram ? <Minimize2 size={16} /> : <Maximize2 size={16} />}</button>
                            <button
                                onClick={copyDiagramCode}
                                className="ui-button-secondary px-3 py-2 text-xs"
                                disabled={diagramMode !== 'diagram' || !!diagramError}
                            >
                                <span className="inline-flex items-center gap-1.5">
                                    {copiedDiagram ? <ClipboardCheck className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                                    {copiedDiagram ? 'Copied' : 'Code'}
                                </span>
                            </button>
                            <button
                                onClick={exportDiagramAsPNG}
                                className="ui-button-secondary px-3 py-2 text-xs"
                                disabled={diagramMode !== 'diagram' || !!diagramError}
                            >
                                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> PNG</span>
                            </button>
                        </div>
                    </div>
                    {diagramMode === 'diagram' && <div className="mt-4 grid min-w-0 gap-3 sm:grid-cols-3">
                        <label className="min-w-0 text-xs">Architecture scope<select aria-label="Architecture scope" className="input-brand mt-1 w-full min-w-0 text-sm" value={diagramView} onChange={e => { setDiagramView(e.target.value); setFocusedComponent(''); setFocusedFlow(''); }}>
                            {engineStatus.diagram_views?.length ? engineStatus.diagram_views.map(view => <option key={view.id} value={view.id}>{view.name}</option>) : <option value="system">System</option>}
                        </select></label>
                        <label className="min-w-0 text-xs">Component and connected flows<select aria-label="Focus architecture component" className="input-brand mt-1 w-full min-w-0 text-sm" value={focusedComponent} onChange={e => { setFocusedComponent(e.target.value); setFocusedFlow(''); setDiagramView('system'); }}><option value="">All components</option>{data.architecture?.components?.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
                        <label className="min-w-0 text-xs">Trace a flow<select aria-label="Trace DFD flow" className="input-brand mt-1 w-full min-w-0 text-sm" value={focusedFlow} onChange={e => traceFlow(e.target.value)}><option value="">All flows</option>{data.architecture?.flows?.map((flow, index) => <option key={flowKey(flow, index)} value={flowKey(flow, index)}>{flow.flow_number || `Flow ${index + 1}`}: {componentNames.get(flow.source_id) || flow.source_id} to {componentNames.get(flow.target_id) || flow.target_id}</option>)}</select></label>
                    </div>}
                    {diagramMode === 'flows' ? <ArchitectureFlowTable architecture={data.architecture} onSelect={traceFlow} /> : <><div
                        ref={diagramViewportRef}
                        className={clsx('architecture-diagram mt-4 w-full min-w-0 cursor-grab overflow-auto rounded-md border border-slate-200 bg-white p-4 active:cursor-grabbing dark:border-brand-700 dark:bg-brand-900 sm:p-6', expandedDiagram ? 'min-h-[280px] flex-1' : 'h-[560px] max-h-[70vh] min-h-[320px]')}
                        aria-label="Architecture diagram. Use the mouse wheel or zoom controls to change scale."
                    >
                        {diagramError && <p role="alert" className="text-sm">{diagramError}</p>}
                        <div ref={mermaidRef} hidden={!!diagramError} className="min-h-full w-max min-w-full" />
                    </div>
                    {diagramCoverage && (
                    <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                        {focusedView && 'Focused view: '}
                        {diagramCoverage.components_drawn} of {diagramCoverage.components_in_model} components and{' '}
                        {diagramCoverage.flows_drawn} of {diagramCoverage.flows_in_model} data flows are drawn.
                        {!!diagramCoverage.relationships_drawn && <> {diagramCoverage.relationships_drawn} separate relationship candidates are shown without flow arrows.</>}
                        {!!diagramCoverage.deployment_groups_drawn && <> Solid containers show deployment groups, not verified trust boundaries.</>}
                        {diagramCoverage.components_hidden_for_readability > 0 &&
                            ` ${diagramCoverage.components_hidden_for_readability} additional components exceed the diagram limit; the model and flow list are unchanged.`}
                        {diagramCoverage.flows_hidden_for_readability > 0 &&
                            ` ${diagramCoverage.flows_hidden_for_readability} additional flows are outside this diagram.`}
                        {diagramCoverage.components_excluded_as_non_flow > 0 &&
                            ` ${diagramCoverage.components_excluded_as_non_flow} components take no part in a data flow.`}
                        {' '}A dotted flow was assumed from component types rather than described; a bold red
                        outline marks a component with a confirmed finding.
                    </p>
                    )}
                    {selectedFlow && <section aria-label="Selected data flow" className="mt-4 border-t border-brand-200 pt-3 text-sm dark:border-brand-700">
                        <h4 className="break-words font-semibold">{selectedFlow.flow_number || 'Selected flow'}: {componentNames.get(selectedFlow.source_id) || selectedFlow.source_id} to {componentNames.get(selectedFlow.target_id) || selectedFlow.target_id}</h4>
                        {selectedFlow.description && <p className="mt-2 break-words">{selectedFlow.description}</p>}
                        <p className="mt-2 break-words text-xs">{selectedFlow.protocol || 'Unknown protocol'} / {selectedFlow.data_type || 'Unspecified data'} / {isAssumedFlow(selectedFlow) ? 'Assumed connection' : 'Not marked assumed'}</p>
                        {!!selectedFlow.evidence?.length && <details className="mt-2 text-xs"><summary className="cursor-pointer font-medium">Flow evidence ({selectedFlow.evidence.length})</summary>{selectedFlow.evidence.map((entry, index) => <p key={index} className="mt-2 break-words">{[entry.document || entry.source_ref, entry.line && `line ${entry.line}`, entry.statement].filter(Boolean).join(': ')}</p>)}</details>}
                    </section>}
                    </>}
                </div>

                <AnalystWorkbench
                    data={data}
                    projectName={projectName}
                    reviewStates={reviewStates}
                    annotationScope={reviewKey}
                    mode="architecture"
                    readOnly={readOnly}
                />

                {onReviewModel ? <button type="button" className="ui-button-secondary mt-5" onClick={onReviewModel} disabled={isAnalyzing}><Pencil size={16} />Edit modeled architecture</button> : !readOnly && onReanalyze && (
                    <section className="mt-8">
                        <ArchitectureModelEditor
                            document={data.architecture_document}
                            onReanalyze={onReanalyze}
                            isAnalyzing={isAnalyzing}
                        />
                    </section>
                )}
            </section>}

            {activeView === 'architecture' && focusedFlow && <section className="my-4 border-y border-brand-200 py-4 dark:border-brand-700"><h3 className="text-sm font-semibold">Risks linked to {selectedFlow?.flow_number || 'selected flow'}</h3>
                {(data.threats || []).filter(threat => threat.affected_flow_refs?.some(flow => flow.id === focusedFlow)).map(threat => <button type="button" key={threat.id} className="mt-2 block text-left text-sm text-brand-primary underline dark:text-indigo-300" onClick={() => setSelectedThreat(threat)}>{threat.title}</button>)}
                {!(data.threats || []).some(threat => threat.affected_flow_refs?.some(flow => flow.id === focusedFlow)) && <p className="mt-2 text-xs">No flow-specific findings are linked. Component-level findings remain in the risk register.</p>}
            </section>}
            {activeView === 'register' && <section className="mt-8">
                {reportId && <div className="mb-4 flex justify-end gap-2">{['csv', 'json'].map(format => <button key={format} className="ui-button-secondary" type="button" onClick={async () => {
                    try {
                        const token = sessionStorage.getItem('aegis-workspace-token');
                        const response = await fetch(`${API_BASE_URL}/enterprise/assessment-reports/${reportId}/register/${format}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
                        if (!response.ok) throw new Error('Register export failed.');
                        const url = URL.createObjectURL(await response.blob()); const link = document.createElement('a'); link.href = url; link.download = `risk-register.${format}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
                    } catch (error) { toast.error(error.message); }
                }}><Download size={16} />{format.toUpperCase()}</button>)}</div>}
                <FindingsWorkspace threats={data.threats || []} filters={filters} onFiltersChange={setFilters} reviewStates={reviewStates} onSelectThreat={setSelectedThreat} />
            </section>}

            {activeView === 'assurance' && <section className="mt-8 space-y-4">
                <SecurityReports assessment={assessment} architecture={data.architecture} readOnly={readOnly}>
                <AssuranceEvidence status={engineStatus} threats={allThreatsSorted} onSelect={setSelectedThreat} onClarify={onClarify} />
                <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Supporting detail</h2>

                {(evidenceRequests || followUpQuestions.length > 0) && (
                    <DetailSection
                        title="Open questions for the team"
                        summary={openQuestionCount ? `${openQuestionCount} answers would sharpen this model` : undefined}
                    >
                        <EvidenceRequests evidenceRequests={evidenceRequests} cardClassName="" onClarify={onClarify} />
                        {followUpQuestions.length > 0 && (
                            <div className="mt-4 space-y-3">
                                {followUpQuestions.slice(0, 4).map((item) => (
                                    <div key={item.id} className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                                        <div className="flex items-center gap-2">
                                            <span className={clsx(
                                                'rounded-full px-2 py-1 text-[10px] font-bold uppercase',
                                                item.priority === 'high'
                                                    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                                                    : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                                            )}>
                                                {item.priority}
                                            </span>
                                            {item.related_threat_count > 0 && (
                                                <span className="text-xs text-brand-500 dark:text-brand-400">{item.related_threat_count} linked findings</span>
                                            )}
                                        </div>
                                        <p className="mt-3 text-sm font-semibold text-brand-950 dark:text-white">{item.question}</p>
                                        <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{item.rationale}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </DetailSection>
                )}

                <DetailSection title="Risk distribution" summary="Where severity and STRIDE categories concentrate">
                    <div className="grid gap-6 lg:grid-cols-2">
                        <RiskMatrix threats={data.threats} onCellClick={handleRiskMatrixClick} />
                        <StrideChart threats={data.threats || []} />
                    </div>
                </DetailSection>

                <DetailSection
                    title="What was modeled and assessed"
                    summary={`${data.coverage?.components_analyzed ?? 0} components, ${strideCoverage.assessment_percent == null ? 'STRIDE assessment unavailable' : `${strideCoverage.assessment_percent}% STRIDE assessed`}`}
                >
                    <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
                        {[
                            ['Components', data.coverage?.components_analyzed ?? 0],
                            ['Data flows', data.coverage?.flows_analyzed ?? 0],
                            // The key here was trust_boundary_count, which the backend
                            // never emitted, so this read zero while the diagram drew
                            // the boundaries it had found.
                            ['Trust boundaries', data.coverage?.trust_boundaries_modeled ?? 0],
                            ['Public entry points', systemModel.public_entry_points?.length ?? 0],
                            ['Stated boundary crossings', systemModel.boundary_crossings?.length ?? 0],
                            ['Assumed boundary crossings', systemModel.inferred_boundary_crossings?.length ?? 0],
                            ['Cloud resources', systemModel.cloud_resources?.length ?? 0],
                        ].map(([label, value]) => (
                            <div key={label} className="rounded-lg border border-brand-200 px-4 py-3 dark:border-brand-700">
                                <p className="text-xs text-brand-500 dark:text-brand-400">{label}</p>
                                <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">{value}</p>
                            </div>
                        ))}
                    </div>
                    <p className="mt-5 text-sm text-brand-600 dark:text-brand-400">
                        STRIDE assessment covers modeled elements and implemented control checks, not every possible vulnerability.
                        {' '}{strideCoverage.unknown_cells ?? 0} cells are unresolved for lack of architecture evidence.
                    </p>
                    {engineStatus.reasoning_assurance && <dl className="mt-4 grid gap-3 border-y border-brand-200 py-4 text-sm dark:border-brand-700 sm:grid-cols-3">
                        <div><dt className="text-xs text-brand-500 dark:text-brand-300">Evidence-resolved assessments</dt><dd className="mt-1 font-semibold">{engineStatus.reasoning_assurance.evidence_resolved_cells} / {engineStatus.reasoning_assurance.applicable_cells}</dd></div>
                        <div><dt className="text-xs text-brand-500 dark:text-brand-300">Unresolved assessments</dt><dd className="mt-1 font-semibold">{engineStatus.reasoning_assurance.unresolved_cells}</dd></div>
                        <div><dt className="text-xs text-brand-500 dark:text-brand-300">Assumed data flows</dt><dd className="mt-1 font-semibold">{engineStatus.reasoning_assurance.assumed_flows}</dd></div>
                    </dl>}
                    {!!data.attack_chains?.hypothesis_count && <p className="mt-3 text-sm text-amber-800 dark:text-amber-200">{data.attack_chains.hypothesis_count} inferred attack routes require review and are excluded from evidence-backed path counts.</p>}
                    <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                        {(strideCoverage.categories || []).map((category) => {
                            const summary = strideCoverage.category_summary?.[category] || {};
                            return (
                                <div key={category} className="border-b border-brand-200 pb-3 dark:border-brand-700">
                                    <p className="text-sm font-semibold text-brand-950 dark:text-white">{category}</p>
                                    <p className="mt-1 text-xs leading-5 text-brand-500 dark:text-brand-400">
                                        {summary.finding || 0} findings · {summary.control_present || 0} controlled · {(summary.unknown || 0) + (summary.potential || 0)} unknown
                                    </p>
                                </div>
                            );
                        })}
                    </div>
                </DetailSection>

                {knowledgeGovernance && <DetailSection title="Knowledge coverage" summary={`${knowledgeGovernance.counts?.executable || 0} executable checks; ${knowledgeGovernance.counts?.retrieval_only || 0} retrieval-only references`}>
                    <dl className="grid gap-4 text-sm sm:grid-cols-2">
                        {[
                            ['Rules with test contracts', knowledgeGovernance.counts?.contract_testable || 0],
                            ['Quarantined rules', knowledgeGovernance.quarantined?.length || 0],
                            ['Rules awaiting independent review', knowledgeGovernance.counts?.independent_review_not_recorded || 0],
                            ['Rules without a primary reference', knowledgeGovernance.counts?.missing_primary_reference || 0],
                        ].map(([name, value]) => <div key={name} className="border-b border-brand-200 py-2 dark:border-brand-700"><dt className="text-brand-600 dark:text-brand-300">{name}</dt><dd className="mt-1 font-semibold text-brand-950 dark:text-white">{value}</dd></div>)}
                    </dl>
                    <p className="mt-4 text-sm text-brand-600 dark:text-brand-300">Automated rule tests do not establish independent accuracy or complete threat coverage.</p>
                </DetailSection>}

                {Object.keys(retrievalEngine).length > 0 && (
                    <DetailSection
                        title="Threat retrieval evidence"
                        summary={`${retrievalEngine.profile || 'local'} profile · ${localIntelligence.status || retrievalEngine.status || 'unknown'}`}
                    >
                        <div className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-3">
                            {[
                                ['Retrieval', retrievalEngine.strategy || 'Local retrieval'],
                                ['Embedding', `${retrievalEngine.embedding_model || 'Fallback'} · ${retrievalEngine.embedding_backend || 'unknown'}`],
                                ['Lexical matching', `BM25 · ${retrievalEngine.lexical_documents ?? 0} knowledge records`],
                                ['Reranker', `${retrievalEngine.reranker?.model || 'Security features'} · ${retrievalEngine.reranker?.backend || 'fallback'}`],
                                ['Runtime', `${retrievalEngine.monitoring?.queries ?? 0} queries · p95 ${retrievalEngine.monitoring?.latency_ms?.p95 ?? 0} ms · ${Math.round((retrievalEngine.monitoring?.fallback_rate ?? 0) * 100)}% fallback`],
                                ['Knowledge quality', `${knowledgeAudit.near_duplicate_count ?? 0} similarity reviews · ${knowledgeAudit.contradiction_count ?? 0} contradictions`],
                            ].map(([label, value]) => (
                                <div key={label} className="min-w-0 rounded-md border border-brand-200 px-4 py-3 dark:border-brand-700">
                                    <p className="text-xs font-semibold uppercase text-brand-500 dark:text-brand-400">{label}</p>
                                    <p className="mt-2 break-words leading-6 text-brand-800 dark:text-brand-200">{value}</p>
                                </div>
                            ))}
                        </div>
                        <p className="mt-4 text-xs leading-5 text-brand-500 dark:text-brand-400">
                            Dense weight {retrievalEngine.fusion_weights?.dense ?? 0}; BM25 weight {retrievalEngine.fusion_weights?.bm25 ?? 0}; vector cache {retrievalEngine.cache || 'unknown'}; {Object.keys(retrievalEngine.calibration?.thresholds || {}).length} calibrated scopes.
                        </p>
                    </DetailSection>
                )}

                {aiSecurityLens.items?.length > 0 && (
                    <DetailSection title="AI-specific risk" summary={aiSecurityLens.overview || undefined}>
                        <div className={clsx('grid gap-4', aiLensGridClass)}>
                            {aiSecurityLens.items.map((item) => (
                                <AISecurityLensCard key={item.id} item={item} />
                            ))}
                        </div>
                    </DetailSection>
                )}

                <DetailSection
                    title="Review progress and changes"
                    summary={`${mitigatedThreats} of ${data.threats?.length || 0} findings triaged (${remediationPercent}%)`}
                >
                    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                            <div key={state} className="rounded-lg border border-brand-200 px-4 py-3 dark:border-brand-700">
                                <div className={clsx('inline-flex rounded-full px-2 py-1 text-[10px] font-semibold', meta.className)}>{meta.label}</div>
                                <div className="mt-2 text-2xl font-black text-brand-950 dark:text-white">{reviewSummary[state] || 0}</div>
                            </div>
                        ))}
                    </div>
                    <div className="mt-5">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Since the last run</p>
                        <ReanalysisDiff diff={diffSummary} />
                    </div>
                </DetailSection>

                {assumptions.length > 0 && (
                    <DetailSection title="Assumptions still shaping the model" summary={`${assumptions.length} assumption${assumptions.length === 1 ? '' : 's'} in force`}>
                        <div className="grid gap-3 md:grid-cols-2">
                            {assumptions.slice(0, 4).map((assumption, index) => (
                                <div key={`${assumption.scope}-${index}`} className="rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 dark:border-yellow-900/40 dark:bg-yellow-950/20">
                                    <p className="text-sm leading-6 text-yellow-900 dark:text-yellow-300">{assumption.message}</p>
                                </div>
                            ))}
                        </div>
                    </DetailSection>
                )}
                <AnalystWorkbench
                    data={data}
                    projectName={projectName}
                    reviewStates={reviewStates}
                    annotationScope={reviewKey}
                    readOnly={readOnly}
                />
                </SecurityReports>
            </section>}

            {activeView === 'report' && (
                <section className={clsx(insightCardBase, 'mt-6 overflow-hidden')}>
                    <div className="flex flex-col gap-4 border-b border-brand-200 p-6 dark:border-brand-700 md:flex-row md:items-center md:justify-between">
                        <div>
                            <div className="flex items-center gap-2">
                                <BarChart3 className="h-5 w-5 text-brand-primary" />
                                <h2 className="text-lg font-bold text-brand-950 dark:text-white">Final report</h2>
                            </div>
                            <p className="mt-2 text-sm text-brand-600 dark:text-brand-400">
                                Review the concise management summary before exporting the full technical report.
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            <button onClick={handlePDFExport} disabled={publicationBlocked} className="btn-brand disabled:cursor-not-allowed disabled:opacity-45">
                                <span className="inline-flex items-center gap-2"><Download className="h-4 w-4" /> PDF</span>
                            </button>
                            {data.report_markdown && (
                                <button onClick={downloadMarkdown} disabled={publicationBlocked} className="ui-button-secondary disabled:cursor-not-allowed disabled:opacity-45">
                                    <span className="inline-flex items-center gap-2"><FileText className="h-4 w-4" /> Markdown</span>
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="p-6">
                        <div className="grid gap-5 border-b border-brand-200 pb-6 text-sm dark:border-brand-700 md:grid-cols-3">
                            <div>
                                <p className="text-xs font-semibold uppercase text-brand-500 dark:text-brand-400">Publication state</p>
                                <p className="mt-2 font-semibold text-brand-950 dark:text-white">{publicationLabel}</p>
                            </div>
                            <div>
                                <p className="text-xs font-semibold uppercase text-brand-500 dark:text-brand-400">Confirmed exposure</p>
                                <p className="mt-2 font-semibold text-brand-950 dark:text-white">{confirmedCount} risks, including {criticalCount} critical and {highCount} high</p>
                            </div>
                            <div>
                                <p className="text-xs font-semibold uppercase text-brand-500 dark:text-brand-400">Model coverage</p>
                                <p className="mt-2 font-semibold text-brand-950 dark:text-white">{data.coverage?.components_analyzed ?? 0} components, {data.coverage?.flows_analyzed ?? 0} flows</p>
                            </div>
                        </div>

                        <div className="border-b border-brand-200 py-6 dark:border-brand-700">
                            <h3 className="text-sm font-bold uppercase text-brand-500 dark:text-brand-400">Executive summary</h3>
                            <p className="mt-3 max-w-4xl text-sm leading-7 text-brand-700 dark:text-brand-200">{data.summary}</p>
                        </div>

                        <div className="py-6">
                            <div className="flex items-center justify-between gap-3">
                                <h3 className="text-sm font-bold uppercase text-brand-500 dark:text-brand-400">Confirmed risks requiring attention</h3>
                                <span className="text-xs font-semibold text-brand-500 dark:text-brand-400">{confirmedCount} total</span>
                            </div>
                            {confirmedThreats.length > 0 ? (
                                <div className="mt-4 divide-y divide-brand-200 border-y border-brand-200 dark:divide-brand-700 dark:border-brand-700">
                                    {confirmedThreats.slice(0, 8).map((threat) => (
                                        <button
                                            key={threat.id}
                                            type="button"
                                            onClick={() => setSelectedThreat(threat)}
                                            className="grid w-full gap-3 px-1 py-4 text-left hover:bg-brand-50 dark:hover:bg-brand-800/60 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-center"
                                        >
                                            <span className="font-semibold text-brand-950 dark:text-white">{threat.title}</span>
                                            <span className="text-sm text-brand-600 dark:text-brand-300">{threat.component || threat.affected_component || 'System'}</span>
                                            <SeverityBadge severity={threat.severity} />
                                        </button>
                                    ))}
                                </div>
                            ) : (
                                <div className="mt-4">
                                    <EmptyInsight
                                        icon={ShieldCheck}
                                        title="No confirmed risks"
                                        description="This analysis has no findings classified as confirmed after reviewer decisions."
                                    />
                                </div>
                            )}
                        </div>
                    </div>
                </section>
            )}

            <AnalysisCopilot
                key={`${projectName}-${data.timestamp || ''}`}
                data={data}
                sidebarCollapsed={sidebarCollapsed}
                onProposeUpdate={onProposeUpdate}
            />
            <RiskDetailsModal
                threat={selectedThreat}
                reviewState={selectedThreat ? reviewStates[selectedThreat.id] || 'open' : 'open'}
                onReviewStateChange={readOnly || reportId ? undefined : updateReviewState}
                onClose={() => setSelectedThreat(null)}
                onFlowSelect={id => { setSelectedThreat(null); traceFlow(id); setActiveView('architecture'); }}
            >
                {reviewLoadError && <p role="alert" className="p-5 text-sm text-red-700 dark:text-red-300">Review history unavailable: {reviewLoadError}</p>}
                {reportId && selectedThreat && <RiskReviewForm key={`${reportId}:${selectedThreat.id}:${serverReviews.latest[selectedThreat.id]?.version || 0}`} reportId={reportId} threat={selectedThreat} review={serverReviews.latest[selectedThreat.id]} events={serverReviews.events} readOnly={readOnly || !!reviewLoadError} onSaved={result => {
                    setServerReviews(result);
                    const states = { ...reviewStates, ...Object.fromEntries(Object.entries(result.latest).map(([id, item]) => [id, item.status])) };
                    setReviewStates(states); saveAnnotations(reviewKey, { reviewStates: states });
                }} />}
            </RiskDetailsModal>
        </div>
    );
}
