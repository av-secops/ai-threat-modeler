import { useState } from 'react';
import { ArrowLeft, ArrowRight, Check, Eye, FileText, HelpCircle, LoaderCircle, Network, Plus, RefreshCw, Save, Trash2, Upload } from 'lucide-react';
import ReviewDiagram from './dashboard/ReviewDiagram';
import SourceEvidenceDialog from './dashboard/SourceEvidenceDialog';
import { draftSignature } from '../utils/modelWorkspace';

const TYPES = ['Service', 'API', 'API Gateway', 'WebClient', 'Identity Provider', 'Database', 'Object Storage', 'Compute', 'Queue', 'ML Service', 'Secrets Manager', 'External Entity'];
const TRUST = ['unknown', 'public', 'external', 'internal', 'restricted'];
const DATA = ['unknown', 'public', 'internal', 'confidential', 'pii', 'phi', 'financial', 'credentials'];
const PROTOCOLS = ['unknown', 'HTTPS', 'TLS', 'mTLS', 'HTTP', 'TCP', 'WSS', 'WS', 'gRPCS'];
const SOURCE_FORMATS = '.txt,.md,.pdf,.docx,.yaml,.yml,.json,.tf,.hcl,.csv';
const IAC_SOURCE_FORMATS = `${SOURCE_FORMATS},.tfvars,.bicep,.ts,.js,.py,.go,.cs`;
const fieldClass = 'input-brand w-full min-w-0 text-sm';
const tabs = [{ id: 'architecture', label: 'Architecture', Icon: Network }, { id: 'questions', label: 'Clarifications', Icon: HelpCircle }, { id: 'sources', label: 'Sources', Icon: FileText }];

function Choice({ value, values, onChange, label, disabled }) {
  return <select aria-label={label} disabled={disabled} value={value || 'unknown'} onChange={(e) => onChange(e.target.value)} className={fieldClass}>
    {[...new Set([value || 'unknown', ...values])].map((v) => <option key={v} value={v}>{v}</option>)}
  </select>;
}

function AnswerForm({ question, payload, preview, onAnswer }) {
  const saved = payload.answers.find((a) => a.element_id === question.element_id && a.control === question.control);
  const [state, setState] = useState(saved?.state || 'unknown');
  const [value, setValue] = useState(saved?.value || question.options?.[0] || '');
  const [note, setNote] = useState(saved?.note || '');
  const [reviewer, setReviewer] = useState(saved?.reviewer || 'Architecture owner');
  const [source, setSource] = useState(saved?.source_ids?.[0] || '');
  const submit = (event) => {
    event.preventDefault();
    onAnswer({ element_id: question.element_id, control: question.control, state, value, note, reviewer,
      source_ids: source ? [source] : [], source_digests: source ? { [source]: preview.source_digests?.[source] || '' } : {}, source_digest: preview.source_digest, evidence_digest: question.evidence_digest || '', answered_at: new Date().toISOString() });
  };
  return <form onSubmit={submit} className="border-b border-brand-200 py-5 dark:border-brand-700">
    <div className="flex flex-wrap items-center gap-2 text-xs text-brand-500 dark:text-brand-400"><span>{question.priority} priority</span><span>{question.categories.join(', ')}</span></div>
    <h3 className="mt-1 text-sm font-semibold">{question.question}</h3>
    <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label className="text-xs">Control state<select aria-label={`State: ${question.id}`} value={state} onChange={(e) => setState(e.target.value)} className={`${fieldClass} mt-1`}>
        <option value="unknown">Unknown</option><option value="present">Present / specified</option>{!['protocol', 'data_sensitivity'].includes(question.control) && <option value="absent">Absent</option>}<option value="not_applicable">Proposed out of scope</option>
      </select></label>
      {question.options?.length > 0 && state === 'present' && <label className="text-xs">Configuration<Choice label={`Value: ${question.id}`} value={value} values={question.options} onChange={setValue} /></label>}
      <label className="text-xs">Supporting source<select aria-label={`Source: ${question.id}`} value={source} onChange={(e) => setSource(e.target.value)} className={`${fieldClass} mt-1`}>
        <option value="">Owner statement</option>{payload.sources.filter((s) => s.included).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
      </select></label>
      <label className="text-xs">Recorded by<input aria-label={`Reviewer: ${question.id}`} value={reviewer} onChange={(e) => setReviewer(e.target.value)} maxLength={200} className={`${fieldClass} mt-1`} /></label>
    </div>
    <label className="mt-3 block text-xs">Evidence or explanation<textarea aria-label={`Explanation: ${question.id}`} className={`${fieldClass} mt-1 h-20`} maxLength={3000} value={note} onChange={(e) => setNote(e.target.value)} required={state !== 'unknown'} minLength={state !== 'unknown' ? 3 : undefined} /></label>
    {state === 'not_applicable' && <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">Scope exception pending review. This does not suppress a detector.</p>}
    <div className="mt-3 flex flex-wrap items-center justify-between gap-2"><span className="text-xs text-brand-500 dark:text-brand-400">{saved ? 'Recorded owner statement; not runtime verified.' : question.element_name}</span><button className="ui-button-secondary" type="submit"><Check size={16} />{saved ? 'Update answer' : 'Record answer'}</button></div>
  </form>;
}

export default function ModelReviewWorkspace({ workspace, onChange, onPrepare, onAnalyze, onUpload, onSave, onBack, busy, saveStatus, darkMode, previewUpdating = false, previewError = '', initialTab = 'architecture', suggestion = '' }) {
  const [tab, setTab] = useState(initialTab);
  const [context, setContext] = useState(suggestion);
  const [componentName, setComponentName] = useState('');
  const [componentType, setComponentType] = useState('Service');
  const [flowSource, setFlowSource] = useState('');
  const [flowTarget, setFlowTarget] = useState('');
  const [questionPage, setQuestionPage] = useState(0);
  const [evidenceSelection, setEvidenceSelection] = useState(null);
  const [openedSource, setOpenedSource] = useState('');
  const { payload, preview, preparedSignature } = workspace.draft;
  const sourceFormats = payload.input_kind === 'iac' ? IAC_SOURCE_FORMATS : SOURCE_FORMATS;
  const stale = preparedSignature !== draftSignature(payload);
  const change = (patch, immediate = false) => onChange({ ...workspace, updatedAt: new Date().toISOString(), draft: { ...workspace.draft, previewDelay: immediate ? 0 : 350, payload: { ...payload, ...patch } } });
  const edit = (elementId, field, value) => change({ edits: [...payload.edits.filter((e) => e.element_id !== elementId || e.field !== field), { element_id: elementId, field, value, reason: `Architecture owner corrected ${field} for ${elementId}.` }] }, !['name', 'description', 'aliases'].includes(field));
  const valueFor = (id, field, fallback) => payload.edits.find((e) => e.element_id === id && e.field === field)?.value ?? fallback;
  const questions = preview?.questions || [];
  const componentIds = new Set((preview?.architecture.components || []).map((c) => c.id));
  const pages = Math.max(1, Math.ceil(questions.length / 5));
  const page = Math.min(questionPage, pages - 1);
  const answer = (record) => change({ answers: [...payload.answers.filter((a) => a.element_id !== record.element_id || a.control !== record.control), record] }, true);
  const updateSource = (id, patch) => change({ sources: payload.sources.map((s) => s.id === id ? { ...s, ...patch } : s) });
  const addContext = () => {
    if (!context.trim()) return;
    change({ sources: [...payload.sources, { id: crypto.randomUUID(), name: `Additional context ${payload.sources.length + 1}`, text: context.trim(), kind: 'text', included: true, environment: 'unspecified', version: '', metadata: {} }] }, true);
    setContext('');
  };
  return <section className="mx-auto w-full max-w-6xl" aria-label="Model review workspace">
    <header className="border-b border-brand-200 pb-5 dark:border-brand-700">
      <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs uppercase text-brand-500 dark:text-brand-400">{workspace.revisions.length ? `Revision ${workspace.revisions.length + 1} draft` : 'Architecture review'}</p><h2 className="mt-1 break-words text-2xl font-semibold">{workspace.projectName}</h2></div>
        <div className="flex flex-wrap gap-2">{onBack && <button type="button" className="ui-button-secondary" onClick={onBack} disabled={busy}><ArrowLeft size={16} />{workspace.revisions.length ? 'Back to report' : 'Back to input'}</button>}<button type="button" className="ui-button-secondary" onClick={onSave} disabled={busy}><Save size={16} />Save draft</button></div></div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-brand-500 dark:text-brand-400"><span role="status">{saveStatus}</span><span>{payload.sources.filter((s) => s.included).length} included sources</span><span>{preview?.readiness.assumed_flows || 0} assumed flows</span><span>{questions.length} open questions</span><span>Not deployment-verified</span></div>
    </header>
    <nav aria-label="Model review sections" className="flex overflow-x-auto border-b border-brand-200 dark:border-brand-700">{tabs.map((item) => <button key={item.id} type="button" aria-current={tab === item.id ? 'page' : undefined} onClick={() => setTab(item.id)} className={`flex shrink-0 items-center gap-2 border-b-2 px-4 py-3 text-sm ${tab === item.id ? 'border-brand-primary text-brand-primary' : 'border-transparent text-brand-500 dark:text-brand-300'}`}><item.Icon size={16} />{item.label}</button>)}</nav>
    {stale && <div role={previewError ? 'alert' : 'status'} className="mt-4 flex flex-wrap items-center justify-between gap-3 border-l-4 border-amber-500 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:bg-amber-950/20 dark:text-amber-200">
      <span className="flex min-w-0 items-center gap-2">{previewUpdating && <LoaderCircle size={16} className="shrink-0 animate-spin" />}<span>{previewError ? `${previewError} Draft changes are retained; the previous preview is shown.` : 'Updating architecture...'}</span></span>
      {previewError && <button type="button" className="ui-button-secondary" onClick={onPrepare} disabled={busy}><RefreshCw size={16} />Retry update</button>}
    </div>}
    {!!preview?.warnings.length && <details className="my-4 border-l-4 border-amber-500 px-4 py-2"><summary className="cursor-pointer text-sm font-semibold">{preview.warnings.length} items need review</summary><ul className="mt-2 space-y-2 text-sm text-brand-600 dark:text-brand-300">{preview.warnings.map((w, i) => <li key={`${w.type}-${i}`}>{w.message}</li>)}</ul></details>}
    <fieldset disabled={busy} className="min-w-0">
      {tab === 'architecture' && <>
        {preview?.diagram && <ReviewDiagram code={preview.diagram} darkMode={darkMode} bindings={preview.diagram_bindings} onSelect={(ids) => setEvidenceSelection({ ids })} />}
        <h3 className="my-3 text-sm font-semibold">Components ({preview?.architecture.components.length || 0})</h3>
        <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-brand-50 text-xs text-brand-500 dark:bg-brand-800 dark:text-brand-300"><tr>{['Name', 'Type', 'Trust', 'Data', 'Basis', ''].map((h, i) => <th key={i} className="px-2 py-2">{h}</th>)}</tr></thead><tbody>
          {(preview?.architecture.components || []).map((c) => <tr key={c.id} className="border-b border-brand-200 dark:border-brand-700">
            <td className="min-w-[170px] p-2"><input aria-label={`Name: ${c.id}`} className={fieldClass} value={valueFor(c.id, 'name', c.name)} onChange={(e) => edit(c.id, 'name', e.target.value)} maxLength={200} /></td>
            <td className="p-2"><Choice label={`Type: ${c.id}`} value={valueFor(c.id, 'type', c.type)} values={TYPES} onChange={(v) => edit(c.id, 'type', v)} /></td>
            <td className="p-2"><Choice label={`Trust: ${c.id}`} value={valueFor(c.id, 'trust_level', c.trust_level)} values={TRUST} onChange={(v) => edit(c.id, 'trust_level', v)} /></td>
            <td className="p-2"><Choice label={`Data: ${c.id}`} value={valueFor(c.id, 'data_sensitivity', c.properties?.data_sensitivity)} values={DATA} onChange={(v) => edit(c.id, 'data_sensitivity', v)} /></td>
            <td className="max-w-[220px] p-2"><details><summary className="cursor-pointer text-xs">{c.properties?.reviewer_declared ? 'Owner correction' : c.properties?.evidence_status === 'explicit' ? 'Source statement' : 'Assumption'}</summary>{c.evidence?.map((e, i) => <p key={i} className="mt-2 break-words text-xs text-brand-500 dark:text-brand-300">{e.document || e.source_ref}: {e.statement}</p>)}</details></td>
            <td className="p-2"><div className="flex gap-1"><button type="button" className="ui-button-secondary p-2" title={`Evidence: ${c.name}`} aria-label={`Evidence: ${c.name}`} onClick={() => setEvidenceSelection({ ids: [c.id] })}><Eye size={16} /></button><button type="button" className="ui-button-secondary p-2" title={`Exclude ${c.name}`} aria-label={`Exclude ${c.name}`} onClick={() => edit(c.id, 'remove', true)}><Trash2 size={16} /></button></div></td>
          </tr>)}
        </tbody></table></div>
        <div className="my-4 flex flex-wrap items-center gap-2"><input aria-label="New component name" value={componentName} onChange={(e) => setComponentName(e.target.value)} placeholder="Component name" maxLength={200} className="input-brand min-w-0 flex-1 text-sm" /><select aria-label="New component type" value={componentType} onChange={(e) => setComponentType(e.target.value)} className="input-brand text-sm">{TYPES.map((t) => <option key={t}>{t}</option>)}</select><button type="button" className="ui-button-secondary" disabled={!componentName.trim()} onClick={() => { const id = `review-${crypto.randomUUID()}`; edit(id, 'add_component', { id, name: componentName.trim(), type: componentType, trust_level: 'unknown', properties: {} }); setComponentName(''); }}><Plus size={16} />Add component</button></div>
        <h3 className="mb-3 mt-6 text-sm font-semibold">Data flows ({preview?.flows.length || 0})</h3>
        <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-brand-50 text-xs text-brand-500 dark:bg-brand-800 dark:text-brand-300"><tr>{['Connection', 'Protocol', 'Data', 'Evidence', ''].map((h, i) => <th key={i} className="p-2">{h}</th>)}</tr></thead><tbody>{(preview?.flows || []).map((f) => <tr key={f.review_id} className="border-b border-brand-200 dark:border-brand-700">
          <td className="min-w-[190px] space-y-1 p-2">{['source_id', 'target_id'].map((field) => <select key={field} aria-label={`${field === 'source_id' ? 'Flow source' : 'Flow target'}: ${f.review_id}`} className={fieldClass} value={valueFor(f.review_id, field, f[field])} onChange={(e) => edit(f.review_id, field, e.target.value)}>{preview.architecture.components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>)}</td>
          <td className="p-2"><Choice label={`Protocol: ${f.review_id}`} values={PROTOCOLS} value={valueFor(f.review_id, 'protocol', f.protocol)} onChange={(v) => edit(f.review_id, 'protocol', v)} /></td><td className="p-2"><Choice label={`Flow data: ${f.review_id}`} values={DATA} value={valueFor(f.review_id, 'data_type', f.data_type)} onChange={(v) => edit(f.review_id, 'data_type', v)} /></td><td className="p-2"><label className="flex items-center gap-2 text-xs"><input type="checkbox" aria-label={`Confirm flow: ${f.review_id}`} checked={!valueFor(f.review_id, 'assumed', f.assumed)} onChange={(e) => edit(f.review_id, 'assumed', !e.target.checked)} />Stated connection</label></td><td className="p-2"><button type="button" className="ui-button-secondary p-2" title={`Exclude flow ${f.source_id} to ${f.target_id}`} aria-label={`Exclude flow ${f.source_id} to ${f.target_id}`} onClick={() => edit(f.review_id, 'remove', true)}><Trash2 size={16} /></button></td>
        </tr>)}</tbody></table></div>
        <div className="my-4 flex flex-wrap gap-2">{[['Source component', flowSource, setFlowSource], ['Target component', flowTarget, setFlowTarget]].map(([label, value, setter]) => <select key={label} aria-label={label} value={componentIds.has(value) ? value : ''} onChange={(e) => setter(e.target.value)} className="input-brand min-w-0 flex-1 text-sm"><option value="">{label}</option>{preview?.architecture.components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>)}<button type="button" className="ui-button-secondary" disabled={!componentIds.has(flowSource) || !componentIds.has(flowTarget)} onClick={() => { edit(`flow:new-${crypto.randomUUID()}`, 'add_flow', { source_id: flowSource, target_id: flowTarget, protocol: 'unknown', data_type: 'application_data', assumed: false }); setFlowSource(''); setFlowTarget(''); }}><Plus size={16} />Add flow</button></div>
      </>}
      {tab === 'questions' && <div className="py-4">
        <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-sm font-semibold">Priority clarifications ({questions.length})</h3><span className="text-xs text-brand-500 dark:text-brand-400">Unknown answers are allowed</span></div>
        {questions.slice(page * 5, page * 5 + 5).map((q) => <AnswerForm key={`${q.id}-${preview.source_digest}`} question={q} payload={payload} preview={preview} onAnswer={answer} />)}
        {!questions.length && <p className="py-6 text-sm text-brand-500 dark:text-brand-400">No additional control questions for the current modeled elements.</p>}
        <div className="my-4 flex items-center justify-end gap-3"><button className="ui-button-secondary p-2" type="button" aria-label="Previous clarification page" title="Previous clarification page" disabled={page === 0} onClick={() => setQuestionPage(page - 1)}><ArrowLeft size={16} /></button><span className="text-xs">Page {page + 1} of {pages}</span><button type="button" className="ui-button-secondary p-2" aria-label="Next clarification page" title="Next clarification page" disabled={page === pages - 1} onClick={() => setQuestionPage(page + 1)}><ArrowRight size={16} /></button></div>
        <details className="border-t border-brand-200 py-4 dark:border-brand-700"><summary className="cursor-pointer text-sm font-semibold">Recorded answers ({payload.answers.length})</summary>{payload.answers.map((a) => <div key={`${a.element_id}:${a.control}`} className="mt-3 border-b border-brand-200 pb-3 text-sm dark:border-brand-700"><p>{a.element_id}: {a.control.replaceAll('_', ' ')} = {a.state}{a.value && a.state === 'present' ? ` (${a.value})` : ''}</p><p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{a.reviewer} | {a.answered_at ? new Date(a.answered_at).toLocaleString() : 'Date unspecified'}</p><p className="mt-1">{a.note}</p><button type="button" className="mt-2 ui-button-secondary" onClick={() => change({ answers: payload.answers.filter((item) => item !== a) })}><Trash2 size={14} />Withdraw answer</button></div>)}</details>
      </div>}
      {tab === 'sources' && <div className="py-5">
        <div className="mb-5 grid gap-3 sm:grid-cols-2"><label className="text-xs">Model environment<input aria-label="Model environment" value={payload.environment || ''} maxLength={100} onChange={(e) => change({ environment: e.target.value })} className={`${fieldClass} mt-1`} /></label><label className="text-xs">Deployment release<input aria-label="Deployment release" value={payload.deployment_version || ''} maxLength={100} onChange={(e) => change({ deployment_version: e.target.value })} className={`${fieldClass} mt-1`} /></label></div>
        {!!preview?.correlation?.unresolved_claims?.length && <details className="mb-4 border-l-4 border-amber-500 pl-3"><summary className="text-sm">Unassigned control statements ({preview.correlation.unresolved_claims.length})</summary>{preview.correlation.unresolved_claims.map((claim) => <p key={claim.id} className="my-2 text-xs">{claim.document}: {claim.statement}</p>)}</details>}
        <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-sm font-semibold">Source material</h3><label className="ui-button-secondary cursor-pointer"><Upload size={16} />Add files<input aria-label="Add review files" type="file" multiple accept={sourceFormats} className="hidden" onChange={(e) => { onUpload([...e.target.files]); e.target.value = ''; }} /></label></div>
        {payload.baseline && <div className="my-4 border-l-4 border-amber-500 px-4 py-2"><p className="text-sm">A saved architecture snapshot is included in this draft.</p><button type="button" className="ui-button-secondary mt-2" disabled={!payload.sources.some((s) => s.included && s.text.trim())} onClick={() => change({ baseline: null })}><RefreshCw size={14} />Rebuild from included sources</button></div>}
        {payload.sources.map((s) => <details key={s.id} open={openedSource === s.name || undefined} className="border-b border-brand-200 py-4 dark:border-brand-700"><summary className="cursor-pointer break-words text-sm font-semibold">{s.name} <span className="ml-2 text-xs font-normal text-brand-500 dark:text-brand-400">{s.included ? 'Included' : 'Excluded'} | {s.metadata?.extraction_quality || 'Text statement'}</span></summary><div className="mt-3 flex flex-wrap items-center gap-3"><label className="flex gap-2 text-xs"><input type="checkbox" aria-label={`Include ${s.name}`} checked={s.included} onChange={(e) => updateSource(s.id, { included: e.target.checked })} />In scope</label><input aria-label={`Environment: ${s.name}`} value={s.environment || ''} onChange={(e) => updateSource(s.id, { environment: e.target.value })} placeholder="Environment" className="input-brand text-xs" maxLength={100} /><input aria-label={`Version: ${s.name}`} value={s.version || ''} onChange={(e) => updateSource(s.id, { version: e.target.value })} placeholder="Source version" className="input-brand text-xs" maxLength={100} /><input aria-label={`Deployment release: ${s.name}`} value={s.metadata?.deployment_version || ''} onChange={(e) => updateSource(s.id, { metadata: { ...s.metadata, deployment_version: e.target.value } })} placeholder="Deployment release" className="input-brand text-xs" maxLength={100} /><label className="ui-button-secondary cursor-pointer"><Upload size={14} />Replace file<input aria-label={`Replace ${s.name}`} type="file" accept={sourceFormats} className="hidden" onChange={(e) => { onUpload([...e.target.files], s.id); e.target.value = ''; }} /></label></div>{s.metadata?.warning && <p className="mt-2 text-sm text-amber-700 dark:text-amber-300">{s.metadata.warning}</p>}<textarea aria-label={`Source text: ${s.name}`} value={s.text} onChange={(e) => updateSource(s.id, { text: e.target.value, metadata: { ...s.metadata, reviewer_edited: true } })} className={`${fieldClass} mt-3 h-48 font-mono`} maxLength={500000} /></details>)}
        {!!payload.edits.length && <details className="border-b border-brand-200 py-4 dark:border-brand-700"><summary className="cursor-pointer text-sm font-semibold">Model corrections ({payload.edits.length})</summary>{payload.edits.map((item) => <div key={`${item.element_id}:${item.field}`} className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm"><span className="break-words">{item.element_id}: {item.field.replaceAll('_', ' ')}</span><button type="button" className="ui-button-secondary" onClick={() => change({ edits: payload.edits.filter((e) => e !== item) })}><Trash2 size={14} />Withdraw correction</button></div>)}</details>}
        <label className="mt-5 block text-sm font-semibold">Additional context<textarea aria-label="Additional architecture context" className={`${fieldClass} mt-2 h-28`} value={context} onChange={(e) => setContext(e.target.value)} maxLength={10000} /></label>
        <div className="mt-2 flex flex-wrap gap-2">{(payload.domain_profile === 'fintech' ? ['Refund approval', 'Payment confirmation'] : payload.domain_profile === 'ai' ? ['Tool execution approval', 'Retrieval tenant isolation'] : payload.domain_profile === 'healthcare' ? ['Patient record access', 'Emergency access'] : ['Login and password reset', 'Tenant switching', 'Administrative access']).map((label) => <button key={label} type="button" className="ui-button-secondary text-xs" onClick={() => setContext((old) => `${old}${old ? '\n' : ''}${label}: `)}><Plus size={12} />{label}</button>)}</div>
        <button type="button" className="ui-button-secondary mt-3" disabled={!context.trim()} onClick={addContext}><Plus size={16} />Add context to draft</button>
      </div>}
    </fieldset>
    {evidenceSelection && preview && <SourceEvidenceDialog selection={evidenceSelection} preview={preview} relatedRisks={workspace.revisions.at(-1)?.data?.threats || []} onClose={() => setEvidenceSelection(null)} onAliases={(id, aliases) => edit(id, 'aliases', aliases)} onSource={(fact) => { setOpenedSource(fact.document); setTab('sources'); setEvidenceSelection(null); }} />}
    <footer className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-brand-200 py-5 dark:border-brand-700"><span className="text-xs text-brand-500 dark:text-brand-400">{preview?.readiness.status === 'preliminary' ? 'Preliminary assessment: unresolved questions or assumptions remain.' : 'Ready for architecture-owner review.'}</span><button type="button" className="btn-brand" disabled={busy || stale || !preview?.architecture.components.length} onClick={onAnalyze}><ArrowRight size={16} />{busy ? 'Working...' : 'Analyze reviewed model'}</button></footer>
  </section>;
}
