import { useEffect, useRef, useState } from 'react';
import AssuranceEvidence from './dashboard/AssuranceEvidence';
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

const resultViews = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'architecture', label: 'Architecture', icon: Network },
    { id: 'register', label: 'Risk register', icon: ShieldAlert },
    { id: 'assurance', label: 'Assurance', icon: BadgeCheck },
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
    const toast = useToast();
    const [copiedDiagram, setCopiedDiagram] = useState(false);
    const [reviewStates, setReviewStates] = useState({});
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [diagramZoom, setDiagramZoom] = useState(1);
    const [diagramView, setDiagramView] = useState('system');
    const selectedDiagram = data?.engine_status?.diagram_views?.find(view => view.id === diagramView);
    const displayedDiagram = selectedDiagram?.diagram || data?.diagram;
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
    }

    useEffect(() => {
        let cancelled = false;
        const renderDiagram = async () => {
            if (activeView !== 'architecture' || !data?.diagram || !mermaidRef.current) return;

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
                const diagramId = `mermaid-diagram-${Date.now()}`;
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
                    const availableWidth = Math.max(240, (diagramViewportRef.current?.clientWidth || 1020) - 48);
                    const availableHeight = Math.max(220, (diagramViewportRef.current?.clientHeight || 480) - 48);
                    const fitScale = Math.min(availableWidth / viewWidth, availableHeight / viewHeight, 1);
                    svgElement.dataset.baseWidth = String(Math.round(viewWidth * fitScale));
                    svgElement.dataset.baseHeight = String(Math.round(viewHeight * fitScale));
                    svgElement.removeAttribute('width');
                    svgElement.removeAttribute('height');
                    resizeDiagramSvg(svgElement, diagramZoomRef.current);
                }
            } catch (error) {
                console.error('Mermaid rendering error:', error);
                if (!cancelled && mermaidRef.current) mermaidRef.current.textContent = 'The architecture diagram could not be rendered.';
            }
        };

        renderDiagram();
        return () => { cancelled = true; };
    }, [activeView, data, darkMode, displayedDiagram]);

    useEffect(() => {
        diagramZoomRef.current = diagramZoom;
        resizeDiagramSvg(mermaidRef.current?.querySelector('svg'), diagramZoom);
    }, [diagramZoom]);

    useEffect(() => {
        const viewport = diagramViewportRef.current;
        if (activeView !== 'architecture' || !viewport) return undefined;
        const wheel = (event) => {
            event.preventDefault();
            setDiagramZoom((current) => Math.min(2.5, Math.max(0.5, Number((current + (event.deltaY < 0 ? 0.1 : -0.1)).toFixed(2)))));
        };
        let drag;
        const down = (event) => {
            if (event.button !== 0 || event.target.closest('button, a, input')) return;
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
    }, [activeView]);

    useEffect(() => {
        // A reviewer's decision outranks the engine's default. Re-analysis
        // reports every finding as open again, and without this a finding
        // already accepted or marked a false positive would come back demanding
        // the same judgement after every edit to the model.
        const stored = loadAnnotations(reviewKey).reviewStates;
        const nextStates = {};
        (data?.threats || []).forEach((threat) => {
            nextStates[threat.id] = stored[threat.id] || threat.review_state || 'open';
        });
        queueMicrotask(() => setReviewStates(nextStates));
    }, [data, reviewKey]);

    const updateReviewState = (threatId, state) => {
        if (readOnly) return;
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
    const qualityGate = engineStatus.quality_gate || {};
    const publicationBlocked = qualityGate.publication_status === 'blocked' || qualityGate.status === 'blocked';
    const publicationLabel = publicationBlocked
        ? 'Draft - model integrity check failed'
        : qualityGate.publication_status === 'ready'
            ? 'Publication ready'
            : 'Technical review';
    const integrityViolations = qualityGate.integrity_violations || [];
    const completenessWarnings = qualityGate.completeness_warnings || [];
    const diagramCoverage = selectedDiagram?.coverage || engineStatus.diagram_coverage;
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
    const mitigatedThreats = Object.values(reviewStates).filter((state) => state === 'mitigated' || state === 'accepted').length;
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
        setDiagramZoom((current) => Math.min(2.5, Math.max(0.5, Number((current + delta).toFixed(2)))));
    };


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
            const canvas = await html2canvas(element);
            const link = document.createElement('a');
            link.download = `${projectName.replace(/\s+/g, '_')}_architecture.png`;
            link.href = canvas.toDataURL();
            link.click();
            toast.success('Diagram exported as PNG');
        } catch {
            toast.error('Failed to export diagram');
        }
    };

    const handlePDFExport = async () => {
        if (publicationBlocked) {
            toast.error('Final report export is blocked until quality-gate failures are resolved.');
            return;
        }
        try {
            const { generateReport } = await import('../utils/pdfGenerator');
            await generateReport(data, projectName, reviewStates);
            toast.success('PDF report generated');
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
                    <MetricCard label="Security score" value={`${data.score}/100`} tone={data.score < 40 ? 'danger' : data.score < 70 ? 'warning' : 'success'} detail={data.score < 40 ? 'Immediate response recommended' : data.score < 70 ? 'Address top findings next' : 'Strong baseline with focused follow-up'} />
                    <MetricCard label="Confirmed risks" value={confirmedCount} tone={criticalCount > 0 ? 'danger' : 'accent'} detail={`${criticalCount} critical, ${highCount} high`} />
                    <MetricCard label="Open questions" value={openQuestionCount} tone="warning" detail={openQuestionCount ? 'Answering these sharpens the model' : 'Architecture detail looks well covered'} />
                </div> : <dl className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-xs text-brand-600 dark:text-brand-300">
                    <div className="flex gap-2"><dt>Score</dt><dd className="font-semibold">{data.score}/100</dd></div>
                    <div className="flex gap-2"><dt>Confirmed</dt><dd className="font-semibold">{confirmedCount} ({criticalCount} critical, {highCount} high)</dd></div>
                    <div className="flex gap-2"><dt>Open questions</dt><dd className="font-semibold">{openQuestionCount}</dd></div>
                </dl>}
            </section>

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
                            <p className="font-semibold text-red-700 dark:text-red-300">This report contradicts itself and cannot be published as final.</p>
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
                <div className={clsx(insightCardBase, 'mx-auto w-full max-w-6xl p-6')}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="text-center lg:text-left">
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture view</h3>
                            {engineStatus.diagram_views?.length > 1 && <select aria-label="Architecture scope" className="input-brand mt-2 text-sm" value={diagramView} onChange={e => setDiagramView(e.target.value)}>{engineStatus.diagram_views.map(view => <option key={view.id} value={view.id}>{view.name}</option>)}</select>}
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Trust boundaries and boundary-crossing flows are highlighted directly on the modeled system map.</p>
                        </div>
                        <div className="flex items-center justify-center gap-2">
                            <div className="flex items-center rounded-md border border-brand-200 bg-white dark:border-brand-700 dark:bg-brand-800">
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(-0.1)}
                                    disabled={diagramZoom <= 0.5}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom out architecture diagram"
                                    title="Zoom out"
                                >
                                    <ZoomOut className="h-4 w-4" />
                                </button>
                                <span className="w-12 text-center text-xs font-semibold text-brand-600 dark:text-brand-300">{Math.round(diagramZoom * 100)}%</span>
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(0.1)}
                                    disabled={diagramZoom >= 2.5}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom in architecture diagram"
                                    title="Zoom in"
                                >
                                    <ZoomIn className="h-4 w-4" />
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setDiagramZoom(1)}
                                    className="inline-flex h-9 w-9 items-center justify-center border-l border-brand-200 text-brand-600 hover:text-brand-primary dark:border-brand-700 dark:text-brand-300"
                                    aria-label="Reset architecture diagram zoom"
                                    title="Reset zoom"
                                >
                                    <RotateCcw className="h-4 w-4" />
                                </button>
                            </div>
                            <button
                                onClick={copyDiagramCode}
                                className="ui-button-secondary px-3 py-2 text-xs"
                            >
                                <span className="inline-flex items-center gap-1.5">
                                    {copiedDiagram ? <ClipboardCheck className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                                    {copiedDiagram ? 'Copied' : 'Code'}
                                </span>
                            </button>
                            <button
                                onClick={exportDiagramAsPNG}
                                className="ui-button-secondary px-3 py-2 text-xs"
                            >
                                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> PNG</span>
                            </button>
                        </div>
                    </div>
                    <div
                        ref={diagramViewportRef}
                        className="architecture-diagram mt-5 flex h-[480px] max-h-[65vh] min-h-[280px] w-full cursor-grab items-start justify-start overflow-auto rounded-md border border-slate-200 bg-white p-4 active:cursor-grabbing dark:border-brand-700 dark:bg-brand-900/55 sm:p-6"
                        aria-label="Architecture diagram. Use the mouse wheel or zoom controls to change scale."
                    >
                        <div ref={mermaidRef} className="flex min-h-full min-w-full w-max shrink-0 items-start justify-center" />
                    </div>
                </div>

                {diagramCoverage && (
                    <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                        {diagramCoverage.components_drawn} of {diagramCoverage.components_in_model} components and{' '}
                        {diagramCoverage.flows_drawn} of {diagramCoverage.flows_in_model} data flows are drawn.
                        {diagramCoverage.components_hidden_for_readability > 0 &&
                            ` ${diagramCoverage.components_hidden_for_readability} components are summarised for readability.`}
                        {diagramCoverage.components_excluded_as_non_flow > 0 &&
                            ` ${diagramCoverage.components_excluded_as_non_flow} components take no part in a data flow.`}
                        {' '}A dotted flow was assumed from component types rather than described; a bold red
                        outline marks a component with a confirmed finding.
                    </p>
                )}

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

            {activeView === 'register' && <section className="mt-8">
                <FindingsWorkspace threats={data.threats || []} filters={filters} onFiltersChange={setFilters} reviewStates={reviewStates} onSelectThreat={setSelectedThreat} />
            </section>}

            {activeView === 'assurance' && <section className="mt-8 space-y-4">
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
                    summary={`${data.coverage?.components_analyzed ?? 0} components, ${strideCoverage.assessment_percent ?? 100}% STRIDE assessed`}
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
                        Every modeled element is assessed against all six STRIDE categories.
                        {' '}{strideCoverage.unknown_cells ?? 0} cells are unresolved for lack of architecture evidence.
                    </p>
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
                onReviewStateChange={readOnly ? undefined : updateReviewState}
                onClose={() => setSelectedThreat(null)}
            />
        </div>
    );
}
