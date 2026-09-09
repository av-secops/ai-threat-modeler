import React, { Suspense, lazy, useState, useEffect, useRef } from 'react';
import ThreatInput from './components/ThreatInput';
import Sidebar from './components/Sidebar';
import { analyzeCode } from './services/mockAi';
import { extractReviewSources, prepareModel, analyzeReviewedModel } from './services/modelReview';
import { newWorkspace, saveWorkspace, loadWorkspace, draftSignature, commitRevision, annotationKey } from './utils/modelWorkspace';
import { loadAnnotations, saveAnnotations } from './utils/annotations';
import { useStreamingAnalysis } from './hooks/useStreamingAnalysis';
import { useAutomaticModelPreview } from './hooks/useAutomaticModelPreview';
import { saveAnalysis } from './utils/storage';
import { mapAnalysisResult } from './utils/analysisMapper';
import { RotateCcw, Zap, Sparkles, Clock, FileCode2, Pencil, Download, ArrowLeft, Plus } from 'lucide-react';
import { useToast } from './hooks/useToast';

const IacInput = lazy(() => import('./components/IacInput'));
const CodeInput = lazy(() => import('./components/CodeInput'));
const ThreatDashboard = lazy(() => import('./components/ThreatDashboard'));
const AIAnalysis = lazy(() => import('./components/AIAnalysis'));
const AnalysisHistory = lazy(() => import('./components/AnalysisHistory'));
const ModelReviewWorkspace = lazy(() => import('./components/ModelReviewWorkspace'));
const ProductsWorkspace = lazy(() => import('./components/ProductsWorkspace'));

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('products');
  const [productScope, setProductScope] = useState(null);
  const [productLocation, setProductLocation] = useState(null);
  const [isNavigating, setIsNavigating] = useState(false);
  const navigationPending = useRef(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [workspace, setWorkspace] = useState(null);
  const [reviewing, setReviewing] = useState(false);
  const [selectedRevision, setSelectedRevision] = useState(null);
  const [reviewTab, setReviewTab] = useState('architecture');
  const [suggestion, setSuggestion] = useState('');
  const [saveStatus, setSaveStatus] = useState('');
  const [saveConflict, setSaveConflict] = useState(null);
  const saveTimer = useRef(null);
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem('theme') === 'dark';
  });
  const toast = useToast();
  const streaming = useStreamingAnalysis();
  const livePreview = useAutomaticModelPreview(workspace, reviewing && !['history', 'products'].includes(activeTab) && !isAnalyzing && !isNavigating && !workspace?.readOnly, setWorkspace);

  useEffect(() => { window.scrollTo(0, 0); }, [activeTab, reviewing, workspace?.id]);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  useEffect(() => {
    if (!workspace || workspace.readOnly || saveConflict === workspace.id) return undefined;
    saveTimer.current = setTimeout(() => {
      saveWorkspace(workspace).then(() => setSaveStatus(workspace.server ? 'Saved to product workspace' : 'Draft saved locally')).catch((error) => {
        setSaveStatus(`Not synced: ${error.message}`);
        if (error.status === 409) setSaveConflict(workspace.id);
      });
    }, 600);
    return () => clearTimeout(saveTimer.current);
  }, [workspace, saveConflict]);

  const persistWorkspace = async (next) => {
    clearTimeout(saveTimer.current);
    const scoped = next.server || !productScope ? next : { ...next, productScope, server: { ...productScope, version: 0 } };
    let saved;
    try {
      saved = await saveWorkspace(scoped);
    } catch (error) {
      setSaveStatus(`Not synced: ${error.message}`);
      if (error.status === 409) {
        setWorkspace(scoped);
        setSaveConflict(scoped.id);
      }
      throw error;
    }
    setWorkspace(saved);
    setSaveStatus(saved.server ? 'Saved to product workspace' : 'Draft saved locally');
  };

  useEffect(() => {
    const listener = event => {
      if (!workspace?.server || workspace.readOnly || !event.detail.key.startsWith(`workspace:${workspace.id}:revision:`)) return;
      setWorkspace(current => ({ ...current, reviewAnnotations: { ...current.reviewAnnotations, [event.detail.key]: event.detail.annotations } }));
    };
    window.addEventListener('aegis-review-saved', listener);
    return () => window.removeEventListener('aegis-review-saved', listener);
  }, [workspace]);

  const handleAnalyze = async (description, name, useLocalSlm = true, options = {}) => {
    setProjectName(name);
    setIsAnalyzing(true);
    try {
      const sources = await extractReviewSources(options.files || []);
      if (description.trim()) sources.unshift({ id: crypto.randomUUID(), name: 'Architecture notes', text: description,
        kind: 'text', included: true, environment: 'unspecified', version: '', metadata: {} });
      const next = newWorkspace(name, { project_name: name, sources, baseline: null, edits: [], answers: [],
        use_local_slm: useLocalSlm, analysis_mode: useLocalSlm ? 'standard' : 'fast', domain_profile: options.domainProfile || 'general',
        environment: productScope?.environment || '', deployment_version: productScope?.release_name || '' });
      // Save sources before preparation so a failed parse can be corrected in place.
      await persistWorkspace(next);
      setData(null);
      setReviewTab('architecture');
      setSuggestion('');
      setReviewing(true);
      const preview = await prepareModel(next.draft.payload);
      await persistWorkspace({ ...next, draft: { ...next.draft, preview, preparedSignature: draftSignature(next.draft.payload) } });
    } catch (error) {
      toast.error(error.message || 'Could not prepare the architecture. Your existing report was not changed.', 'Preparation failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runReviewedAnalysis = async () => {
    if (workspace?.readOnly) return;
    if (!workspace?.draft.preview || workspace.draft.preparedSignature !== draftSignature(workspace.draft.payload)) return;
    setIsAnalyzing(true);
    try {
      const signature = draftSignature(workspace.draft.payload);
      const result = await analyzeReviewedModel(workspace.draft.payload, {
        jobId: workspace.activeJob?.signature === signature ? workspace.activeJob.id : undefined,
        onJob: id => {
          const next = { ...workspace, activeJob: { id, signature } };
          setWorkspace(next);
          return persistWorkspace(next);
        },
      });
      const previous = workspace.revisions.at(-1);
      const annotations = loadAnnotations(previous ? annotationKey(workspace.id, previous.number) : '');
      const next = commitRevision({ ...workspace, activeJob: null }, result, annotations);
      await persistWorkspace(next);
      const revision = next.revisions.at(-1);
      saveAnnotations(annotationKey(next.id, revision.number), revision.annotations);
      setSelectedRevision(revision.number);
      setData(revision.data);
      setReviewing(false);
      toast.success(`Revision ${revision.number} saved. ${result.threats.length} findings.`);
    } catch (error) {
      toast.error(error.message || 'Analysis failed. The draft and previous report are unchanged.', 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const uploadReviewSources = async (files, replaceId) => {
    if (!files.length) return;
    setIsAnalyzing(true);
    try {
      const sources = [];
      for (const file of files) {
        const kind = file.name.split('.').at(-1).toLowerCase();
        if (workspace.draft.payload.input_kind === 'iac' && !['pdf', 'docx'].includes(kind)) {
          if (file.size > 2000000) throw new Error(`${file.name} exceeds the review file size limit.`);
          sources.push({ id: crypto.randomUUID(), name: file.name, text: await file.text(), kind,
            included: true, environment: 'unspecified', version: '', metadata: { role: 'source_design' } });
        } else {
          sources.push(...await extractReviewSources([file]));
        }
      }
      const current = workspace.draft.payload.sources;
      const nextSources = replaceId
        ? current.map((s) => s.id === replaceId ? { ...sources[0], id: replaceId, environment: s.environment, version: s.version,
          metadata: { ...sources[0].metadata, ...Object.fromEntries(['deployment_version', 'tenant_id', 'cloud_account'].filter((key) => s.metadata?.[key] !== undefined).map((key) => [key, s.metadata[key]])) } } : s)
        : [...current, ...sources];
      await persistWorkspace({ ...workspace, draft: { ...workspace.draft, payload: { ...workspace.draft.payload, sources: nextSources } } });
    } catch (error) {
      toast.error(error.message, 'Upload failed; existing sources retained');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const openModelReview = async (tab = 'architecture', proposedText = '') => {
    if (isAnalyzing || workspace?.readOnly) return;
    setReviewTab(tab);
    setSuggestion(proposedText);
    if (workspace) { setReviewing(true); return; }
    setIsAnalyzing(true);
    try {
      const next = newWorkspace(projectName, { project_name: projectName, sources: [],
        baseline: data.architecture, edits: [], answers: [], use_local_slm: true,
        analysis_mode: 'standard', domain_profile: data.domain_context?.profile || 'general' });
      const preview = await prepareModel(next.draft.payload);
      next.draft = { ...next.draft, preview, preparedSignature: draftSignature(next.draft.payload) };
      const annotations = loadAnnotations(projectName);
      next.revisions = [{ number: 1, createdAt: new Date().toISOString(), data, annotations,
        payload: structuredClone(next.draft.payload), preview, sourceDigest: preview.source_digest }];
      await persistWorkspace(next);
      saveAnnotations(annotationKey(next.id, 1), annotations);
      setSelectedRevision(1);
      setReviewing(true);
    } catch (error) {
      toast.error(error.message, 'Could not open model review');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const exportWorkspace = () => {
    const snapshot = { ...workspace, revisions: workspace.revisions.map((r) => ({ ...r, annotations: loadAnnotations(annotationKey(workspace.id, r.number)) })) };
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${projectName.replace(/[^a-z0-9_-]/gi, '_')}_workspace.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const saveDraft = async () => {
    if (workspace?.readOnly) return;
    try {
      await saveWorkspace(workspace);
      // Saving a snapshot must not replace edits or a preview received meanwhile.
      setSaveStatus(workspace.server ? 'Saved to product workspace' : 'Draft saved locally');
    }
    catch (error) {
      setSaveStatus(`Not synced: ${error.message}`);
      if (error.status === 409) setSaveConflict(workspace.id);
      toast.error(error.message, 'Draft could not be synced');
    }
  };

  const loadRevision = (number) => {
    const revision = workspace.revisions.find((r) => r.number === number);
    if (revision) {
      setSelectedRevision(number);
      setData(revision.data);
      setReviewing(false);
    }
  };

  const handleIacAnalyze = async (iacContent, name, formatHint, projectFiles = []) => {
    setProjectName(name);
    setIsAnalyzing(true);
    try {
        const filename = formatHint === 'terraform' || /^\s*(resource|provider|variable|module)\s+"/m.test(iacContent) ? 'infrastructure.tf' : formatHint === 'bicep' ? 'main.bicep' : iacContent.trim().startsWith('{') ? 'infrastructure.json' : 'infrastructure.yml';
        const sources = [];
        for (const file of projectFiles.length ? projectFiles : [new File([iacContent], filename)]) {
          sources.push({ id: crypto.randomUUID(), name: file.name, text: projectFiles.length === 1 ? iacContent : await file.text(), kind: file.name.split('.').at(-1), included: true, environment: 'unspecified', version: '', metadata: { role: 'source_design', iac_format: projectFiles.length > 1 ? 'auto' : formatHint } });
        }
        const next = newWorkspace(name, { project_name: name, sources, baseline: null, edits: [], answers: [], input_kind: 'iac',
          use_local_slm: true, analysis_mode: 'standard', domain_profile: 'platform' });
        await persistWorkspace(next);
        setData(null);
        setReviewing(true);
        setReviewTab('architecture');
        setSuggestion('');
        const preview = await prepareModel(next.draft.payload);
        await persistWorkspace({ ...next, draft: { ...next.draft, preview, preparedSignature: draftSignature(next.draft.payload) } });
    } catch (error) {
        console.error('IaC Analysis failed', error);
        toast.error(
          error.message || 'Could not prepare the IaC model. Correct the saved sources and try again.',
          'Preparation failed'
        );
    } finally {
        setIsAnalyzing(false);
    }
  };

  const handleCodeAnalyze = async (codeContent, name, language) => {
    setProjectName(name);
    setData(null);
    setIsAnalyzing(true);
    try {
      const result = await analyzeCode(codeContent, name, language);
      setData(result);
      saveAnalysis(name, result);
      toast.success(`Code analysis complete! Found ${result.threats.length} security findings.`, 'Success');
    } catch (error) {
      console.error('Code analysis failed', error);
      toast.error(error.message || 'Failed to analyze source code.', 'Analysis Failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAIAnalysisComplete = (result, name) => {
    const mappedResult = mapAnalysisResult(result);
    setData(mappedResult);
    setProjectName(name);
    saveAnalysis(name, mappedResult);
  };

  const handleLoadFromHistory = async (analysisData, name, record) => {
    if (record?.workspaceId) {
      try {
        const saved = await loadWorkspace(record.workspaceId);
        if (!saved) throw new Error('Saved workspace was not found.');
        setWorkspace(saved);
        setProductScope(saved.productScope || null);
        const revision = saved.revisions.at(-1);
        setSelectedRevision(revision?.number || null);
        setData(revision?.data || null);
        setProjectName(saved.projectName);
        setReviewTab('architecture');
        setSuggestion('');
        setReviewing(!revision);
        setActiveTab('static');
        return;
      } catch (error) { toast.error(error.message); return; }
    }
    setWorkspace(null);
    setProductScope(null);
    setReviewing(false);
    setData(analysisData);
    setProjectName(name);
    setActiveTab('static');
    toast.success('Analysis loaded from history');
  };

  // Re-running an edited model is the ordinary analysis path with the model as
  // its input; the structured format parses without inference, so only what the
  // reviewer changed changes.
  const handleReanalyze = (architectureDocument) => {
    handleAnalyze(architectureDocument, projectName || 'Untitled', true);
  };

  const resetAnalysis = () => {
    setWorkspace(null);
    setReviewing(false);
    setSelectedRevision(null);
    setData(null);
    setProjectName('');
    setSaveConflict(null);
    setSaveStatus('');
    setSuggestion('');
  };

  const leaveAnalysis = async (navigate) => {
    if (isAnalyzing || navigationPending.current) return;
    navigationPending.current = true;
    setIsNavigating(true);
    clearTimeout(saveTimer.current);
    try {
      if (workspace && !workspace.readOnly) {
        if (saveConflict === workspace.id) throw new Error('Resolve the shared draft conflict before leaving.');
        await saveWorkspace(workspace);
      }
      navigate();
    } catch (error) {
      setSaveStatus(`Not synced: ${error.message}`);
      if (error.status === 409) setSaveConflict(workspace.id);
      toast.error(error.message, 'Your draft is still open');
    } finally {
      navigationPending.current = false;
      setIsNavigating(false);
    }
  };

  const handleNewAnalysis = () => leaveAnalysis(() => { resetAnalysis(); });

  const returnToRelease = (newModelScope = '') => leaveAnalysis(() => {
    setProductLocation({ product_id: productScope.product_id, release_id: productScope.release_id, newModelScope });
    resetAnalysis();
    setProductScope(null);
    setActiveTab('products');
  });

  const startReleaseModel = scope => {
    resetAnalysis();
    setProductScope(scope);
    setProductLocation({ product_id: scope.product_id, release_id: scope.release_id });
    setActiveTab('static');
  };

  // Page titles and icons for the header
  const openServerWorkspace = (row) => {
    const scope = row.productScope || row.workspace.productScope || null;
    const saved = { ...row.workspace, productScope: scope, readOnly: row.readOnly, server: { release_id: row.release_id,
      application_id: row.application_id, environment: row.environment, version: row.version } };
    const revision = saved.revisions.at(-1);
    for (const [key, value] of Object.entries(saved.reviewAnnotations || {})) saveAnnotations(key, value);
    setWorkspace(saved); setProductScope(scope); setProjectName(saved.projectName);
    setData(revision?.data || null); setSelectedRevision(revision?.number || null);
    setReviewing(!revision); setActiveTab('static');
    setReviewTab('architecture'); setSuggestion('');
    setSaveConflict(null);
  };

  const recoverWorkspace = async () => {
    setIsAnalyzing(true);
    clearTimeout(saveTimer.current);
    try {
      const { enterprise } = await import('./services/enterprise');
      const row = await enterprise(`/workspaces/${workspace.id}`);
      exportWorkspace();
      openServerWorkspace({ ...row, productScope, readOnly: workspace.readOnly });
    } catch (error) {
      toast.error(error.message, 'Could not reload workspace');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const pageInfo = {
    products: { title: 'Products', subtitle: 'Applications, releases and threat models', icon: FileCode2, color: 'text-brand-primary' },
    static: { title: 'Static Analysis', subtitle: 'Rule-based + NLP + Semantic threat detection', icon: Zap, color: 'text-brand-primary' },
    code: { title: 'Code Security', subtitle: 'Evidence-backed checks for common source vulnerabilities', icon: FileCode2, color: 'text-brand-primary' },
    iac: { title: 'Infrastructure-as-Code', subtitle: 'Analyze cloud, container, pipeline, and multi-file IaC projects', icon: Zap, color: 'text-brand-success' },
    ai: { title: 'AI Analysis', subtitle: 'LLM-enhanced analysis with RAG', icon: Sparkles, color: 'text-brand-secondary' },
    history: { title: 'Analysis History', subtitle: 'Previous analyses saved locally', icon: Clock, color: 'text-brand-secondary' },
  };

  const currentPage = pageInfo[activeTab];
  const PageIcon = currentPage.icon;
  const reviewProps = {
    onReviewModel: workspace?.readOnly ? undefined : () => openModelReview(),
    onClarify: workspace?.readOnly ? undefined : () => openModelReview('questions'),
    onProposeUpdate: workspace?.readOnly ? undefined : (text) => openModelReview('sources', text),
    readOnly: !!workspace?.readOnly,
    annotationScope: workspace && selectedRevision ? annotationKey(workspace.id, selectedRevision) : undefined,
  };

  return (
    <div className="min-h-screen text-brand-900 dark:text-brand-100 selection:bg-brand-primary selection:text-white transition-colors duration-300">
      {/* Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={tab => {
          if (isAnalyzing || isNavigating) return;
          if (tab === 'products' && activeTab !== 'products') {
            leaveAnalysis(() => { resetAnalysis(); setProductScope(null); setActiveTab(tab); });
          } else setActiveTab(tab);
        }}
        darkMode={darkMode}
        onToggleDarkMode={() => setDarkMode(!darkMode)}
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
      />

      {/* Main Content — offset by sidebar width */}
      <div className={`${sidebarCollapsed ? 'ml-[68px]' : 'ml-[220px]'} transition-all duration-300`}>
        {/* Top Bar */}
        <header className="sticky top-0 z-40 border-b border-brand-200 bg-white/95 dark:border-brand-700 dark:bg-brand-900/95">
          <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-2 px-3 py-3 sm:px-8 sm:py-3.5">
            <div className="flex min-w-0 items-center gap-2 sm:gap-3">
              <div className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-brand-200 bg-brand-50 dark:border-brand-700 dark:bg-brand-800 sm:flex">
                <PageIcon className={`w-5 h-5 ${currentPage.color}`} />
              </div>
              <div className="min-w-0">
                <h1 className="text-base font-semibold text-brand-950 dark:text-white sm:text-lg">{currentPage.title}</h1>
                <p className="hidden text-xs text-brand-500 dark:text-brand-400 md:block">{currentPage.subtitle}</p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2 sm:gap-3">
              {(data || workspace) && !productScope && !['products', 'history'].includes(activeTab) && (
                <button
                  onClick={handleNewAnalysis}
                  disabled={isAnalyzing || isNavigating}
                  className="ui-button-secondary h-9 px-2 sm:px-3.5"
                  title="Start a new analysis"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">New Analysis</span>
                </button>
              )}
              <div className="ui-chip hidden font-mono sm:inline-flex">
                v2.3.2
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="mx-auto max-w-[1440px] px-3 py-5 sm:px-8 sm:py-7">
          <Suspense fallback={<div className="panel-soft px-6 py-14 text-center text-sm text-brand-500 dark:text-brand-400">Loading analysis workspace...</div>}>
          {productScope?.product_id && !['products', 'history'].includes(activeTab) && <nav aria-label="Release navigation" className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <button type="button" className="ui-button-secondary" disabled={isAnalyzing || isNavigating} onClick={() => returnToRelease()}><ArrowLeft size={16} />Back to release</button>
            {data && !reviewing && !workspace?.readOnly && <button type="button" className="btn-brand gap-2" disabled={isAnalyzing || isNavigating} onClick={() => returnToRelease('application')}><Plus size={16} />Add another application</button>}
          </nav>}
          {workspace?.activeJob && activeTab !== 'products' && !isAnalyzing && <div className="mb-3 flex flex-wrap items-center gap-3 text-sm"><span>Saved analysis job</span><button className="ui-button-secondary" onClick={runReviewedAnalysis} disabled={!!workspace.readOnly}>Resume analysis</button></div>}
          {productScope && !['products', 'history'].includes(activeTab) && <div className="mb-4 flex flex-wrap gap-x-4 gap-y-2 border-b border-brand-200 pb-3 text-sm dark:border-brand-700">
            <span className="font-semibold">{productScope.product_name} / {productScope.release_name}</span>
            <span>{productScope.application_id ? `Ad hoc application: ${productScope.application_name}` : 'Complete release product'}</span>
            <span>{productScope.environment}</span>
          </div>}
          {workspace && !['history', 'products'].includes(activeTab) && <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-brand-200 pb-3 dark:border-brand-700">
            <div className="flex flex-wrap items-center gap-3 text-sm">{workspace.revisions.length > 0 && <label className="flex items-center gap-2">Report revision<select aria-label="Report revision" disabled={isAnalyzing} className="input-brand text-sm" value={selectedRevision || workspace.revisions.at(-1).number} onChange={(e) => loadRevision(Number(e.target.value))}>{workspace.revisions.map((r) => <option key={r.number} value={r.number}>Revision {r.number}{r.number === workspace.revisions.at(-1).number ? ' (latest)' : ''}</option>)}</select></label>}<span className="text-xs text-brand-500 dark:text-brand-400">{reviewing ? 'Draft' : selectedRevision === workspace.revisions.at(-1)?.number ? 'Latest report' : 'Historical report'}</span></div>
            <div className="flex gap-2">{!reviewing && !workspace.readOnly && <button type="button" className="ui-button-secondary" disabled={isAnalyzing} onClick={() => openModelReview()}><Pencil size={16} />Update this model</button>}<button type="button" className="ui-button-secondary" onClick={exportWorkspace}><Download size={16} />Export workspace</button></div>
            </div>}
          {workspace && saveConflict === workspace.id && <div role="alert" className="mb-4 flex flex-wrap items-center justify-between gap-3 border border-amber-500 p-3 text-sm">
            <p>This shared draft changed elsewhere. Your local copy is preserved; server sync is paused.</p>
            <button type="button" className="ui-button-secondary" disabled={isAnalyzing} onClick={recoverWorkspace}><RotateCcw size={16} />Export draft and reload latest</button>
          </div>}
          {activeTab === 'products' ? <ProductsWorkspace darkMode={darkMode} initialLocation={productLocation} onLocationChange={setProductLocation} onOpen={openServerWorkspace} onHistory={() => { setProductScope(null); setActiveTab('history'); }} onStart={startReleaseModel} /> : workspace && reviewing && activeTab !== 'history' ? <ModelReviewWorkspace key={`${workspace.id}-${reviewTab}-${suggestion}`} workspace={workspace} onChange={(next) => { setWorkspace(next); setSaveStatus('Unsaved draft changes'); }} onPrepare={livePreview.retry} previewUpdating={livePreview.updating} previewError={livePreview.error} onAnalyze={runReviewedAnalysis} onUpload={uploadReviewSources} onSave={saveDraft} onBack={workspace.revisions.length ? () => loadRevision(workspace.revisions.at(-1).number) : productScope?.product_id ? undefined : handleNewAnalysis} busy={isAnalyzing || isNavigating} saveStatus={saveStatus} darkMode={darkMode} initialTab={reviewTab} suggestion={suggestion} /> : activeTab === 'static' ? (
            <>
              {!data && <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing || streaming.isAnalyzing} />}

              {activeTab === 'static' && (isAnalyzing || streaming.isAnalyzing) && (
                <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-center space-y-6 px-6 py-14 animate-fade-in-up panel-soft">
                  {/* Live progress bar */}
                  <div className="w-full max-w-md px-8 pt-10">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-sm font-mono font-medium text-brand-primary capitalize">
                        {streaming.phase?.replace(/_/g, ' ') || 'Connecting...'}
                      </span>
                      <span className="text-xs font-mono text-brand-500 dark:text-brand-400">
                        {Math.round(streaming.progress || 0)}%
                      </span>
                    </div>
                    <div className="h-2 bg-brand-100 dark:bg-brand-800 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-brand-primary transition-all duration-500 ease-out"
                        style={{ width: `${streaming.progress || 2}%` }}
                      />
                    </div>
                    <p className="text-xs text-brand-500 dark:text-brand-400 mt-2 text-center">
                      {streaming.message || 'Initializing analysis pipeline...'}
                    </p>
                  </div>
                  {/* Spinner */}
                  <div className="w-10 h-10 mb-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-primary rounded-full animate-spin" />
                </div>
              )}

              {data && (
                <div className="w-full">
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    sidebarCollapsed={sidebarCollapsed}
                    onReanalyze={handleReanalyze}
                    {...reviewProps}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
                </div>
              )}
            </>
          ) : activeTab === 'code' ? (
            <>
              {!data && <CodeInput onAnalyze={handleCodeAnalyze} isAnalyzing={isAnalyzing} />}
              {isAnalyzing && (
                <div className="mx-auto flex w-full max-w-6xl items-center justify-center gap-3 px-6 py-14 panel-soft text-sm text-brand-500 dark:text-brand-400">
                  <FileCode2 className="h-5 w-5 animate-pulse text-brand-primary" />
                  Analyzing source code...
                </div>
              )}
              {data && <div className="w-full"><ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    sidebarCollapsed={sidebarCollapsed}
                    onReanalyze={handleReanalyze}
                    {...reviewProps}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  /></div>}
            </>
          ) : activeTab === 'iac' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="mx-auto mb-7 w-full max-w-6xl animate-fade-in-up panel-soft px-6 py-5">
                  <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-brand-success/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-brand-success">
                    Infrastructure
                  </div>
                  <h2 className="mb-2 text-2xl font-semibold tracking-tight text-brand-950 dark:text-white">
                    IaC Architecture Parser
                  </h2>
                  <p className="max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                    Parse related Terraform, Kubernetes, Helm, cloud templates, Pulumi, Compose, and CI files as one technical model.
                  </p>
                </div>
              )}

              {!data && <IacInput onAnalyze={handleIacAnalyze} isAnalyzing={isAnalyzing} />}

              {isAnalyzing && (
                <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-center space-y-6 px-6 py-14 animate-fade-in-up panel-soft">
                  <div className="w-10 h-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-success rounded-full animate-spin" />
                  <p className="text-sm font-mono text-brand-500 dark:text-brand-400 pb-10">Parsing Infrastructure-as-Code...</p>
                </div>
              )}

              {data && (
                <div className="w-full">
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    sidebarCollapsed={sidebarCollapsed}
                    onReanalyze={handleReanalyze}
                    {...reviewProps}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
                </div>
              )}
            </>
          ) : activeTab === 'ai' ? (
            <>
              {!data && (
                <AIAnalysis onAnalysisComplete={handleAIAnalysisComplete} />
              )}
              {data && (
                <div className="w-full">
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    sidebarCollapsed={sidebarCollapsed}
                    onReanalyze={handleReanalyze}
                    {...reviewProps}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
                </div>
              )}
            </>
          ) : (
            <AnalysisHistory onLoadAnalysis={handleLoadFromHistory} />
          )}
          </Suspense>
        </main>

        {/* Footer */}
        <footer className="mt-auto border-t border-brand-200 py-4 text-center text-xs text-brand-400 dark:border-brand-700 dark:text-brand-500">
          <p>&copy; 2026 AITM v2.3.2 • NLP &bull; Semantic Search &bull; Attack Chains &bull; Multi-LLM</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
