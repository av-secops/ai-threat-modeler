import { useEffect, useState } from 'react';
import { ArrowRight, ArrowUp, ArrowDown, Check, ChevronLeft, ChevronRight, Settings2, Save, Plus, Trash2, X, Copy } from 'lucide-react';
import { enterprise } from '../services/enterprise';
import { applicationTypes } from '../utils/assessmentCatalog';
import { confirmProposals, explanationPlaceholder, groupAnswers, mergeQuestionAnswers, pendingQuestion, questionGroups } from '../utils/questionnaire';

const field = 'input-brand w-full min-w-0 text-sm';

function QuestionnaireAdmin({ onClose }) {
  const [templates, setTemplates] = useState([]);
  const [draft, setDraft] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { enterprise('/questionnaires').then(setTemplates).catch(e => setError(e.message)); }, []);
  const act = async (work) => {
    setBusy(true); setError('');
    try { await work(); setTemplates(await enterprise('/questionnaires')); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const save = () => act(async () => {
    const { name, questions } = draft;
    const result = await enterprise(`/questionnaires${draft.version ? `/${draft.version}` : ''}`, draft.version ? 'PUT' : 'POST', { name, questions, expected_revision: draft.revision || 0 });
    setDraft(result);
  });
  const update = (index, patch) => setDraft(old => ({ ...old, questions: old.questions.map((q, i) => i === index ? { ...q, ...patch } : q) }));
  const move = (index, offset) => setDraft(old => {
    const questions = [...old.questions];
    [questions[index], questions[index + offset]] = [questions[index + offset], questions[index]];
    return { ...old, questions };
  });
  return <section aria-label="Questionnaire administration" className="border-y border-brand-200 py-5 dark:border-brand-700">
    <header className="flex items-center justify-between gap-3"><h3 className="font-semibold">Questionnaire administration</h3><button type="button" className="ui-button-secondary" title="Close administration" aria-label="Close questionnaire administration" onClick={onClose}><X size={16} /></button></header>
    {error && <p role="alert" className="my-3 text-sm text-red-700 dark:text-red-300">{error}</p>}
    <div className="my-4 flex flex-wrap gap-3">{templates.map(t => <div className="flex items-center gap-2 border-b border-brand-200 py-2 text-xs dark:border-brand-700" key={t.version}>
      <span>{t.name} v{t.version} / {t.status}</span>
      <button type="button" className="ui-button-secondary" disabled={busy} title="Clone as a new draft" onClick={() => setDraft({ name: t.name, questions: structuredClone(t.questions) })}><Copy size={14} /><span className="sr-only">Clone version {t.version}</span></button>
      {t.status === 'draft' && <button type="button" className="ui-button-secondary" onClick={() => setDraft(t)}>Edit draft</button>}
      {t.status === 'published' && <button type="button" className="ui-button-secondary" disabled={busy} onClick={() => act(() => enterprise(`/questionnaires/${t.version}/retired`, 'POST', { expected_revision: t.revision }))}>Retire</button>}
    </div>)}</div>
    {draft && <fieldset disabled={busy} className="min-w-0 space-y-4">
      <label className="block text-xs">Template name<input className={field} value={draft.name} maxLength={200} onChange={e => setDraft({ ...draft, name: e.target.value })} /></label>
      {draft.questions.map((q, i) => <div key={i} className="grid gap-3 border-t border-brand-200 py-3 dark:border-brand-700 sm:grid-cols-2">
        <label className="text-xs">Question key<input aria-label={`Question key ${i + 1}`} className={field} value={q.key} onChange={e => update(i, { key: e.target.value })} /></label>
        <label className="text-xs">Section<input className={field} value={q.section || 'Architecture'} onChange={e => update(i, { section: e.target.value })} /></label>
        <label className="text-xs sm:col-span-2">Question<input aria-label={`Question text ${i + 1}`} className={field} value={q.text} maxLength={1000} onChange={e => update(i, { text: e.target.value })} /></label>
        <label className="text-xs">Answer type<select className={field} value={q.answer_type} onChange={e => update(i, { answer_type: e.target.value })}>{['control', 'text', 'choice', 'number'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label className="text-xs">Choices (comma separated)<input className={field} value={(q.options || []).join(', ')} onChange={e => update(i, { options: e.target.value.split(',').map(v => v.trim()).filter(Boolean) })} /></label>
        <label className="text-xs">Component types (empty means assessment)<input className={field} value={(q.component_types || []).join(', ')} onChange={e => update(i, { component_types: e.target.value.split(',').map(v => v.trim()).filter(Boolean) })} /></label>
        <label className="text-xs">Control key (optional)<input className={field} value={q.control || ''} onChange={e => update(i, { control: e.target.value })} /></label>
        <label className="text-xs">Application types<select multiple className={field} value={q.application_types || []} onChange={e => update(i, { application_types: [...e.target.selectedOptions].map(o => o.value) })}>{Object.entries(applicationTypes).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
        <label className="text-xs">Priority<select className={field} value={q.priority || 'normal'} onChange={e => update(i, { priority: e.target.value })}>{['high', 'normal', 'low'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label className="text-xs">Relevant technologies (comma separated)<input className={field} value={(q.technologies || []).join(', ')} onChange={e => update(i, { technologies: e.target.value.split(',').map(v => v.trim()).filter(Boolean) })} /></label>
        <label className="text-xs">Follow-up to<select aria-label={`Question dependency ${i+1}`} className={field} value={q.when?.question_key || ''} onChange={e => update(i, { when: e.target.value ? { question_key: e.target.value, scope: 'assessment', values: ['present'] } : null })}><option value="">No answer dependency</option>{draft.questions.slice(0, i).filter(parent => ['choice', 'control'].includes(parent.answer_type)).map(parent => <option key={parent.key} value={parent.key}>{parent.key}</option>)}</select></label>
        {q.when && <><label className="text-xs">Triggering answers (comma separated)<input className={field} value={q.when.values.join(', ')} onChange={e => update(i, { when: { ...q.when, values: e.target.value.split(',').map(v => v.trim()).filter(Boolean) } })} /></label><label className="text-xs">Dependency scope<select className={field} value={q.when.scope} onChange={e => update(i, { when: { ...q.when, scope: e.target.value } })}><option value="assessment">Assessment</option><option value="same_component">Same component</option></select></label></>}
        <div className="flex flex-wrap items-center gap-3"><label className="text-sm"><input type="checkbox" checked={q.required} onChange={e => update(i, { required: e.target.checked })} /> Required</label><button type="button" className="ui-button-secondary" title="Move question up" aria-label={`Move question ${i + 1} up`} disabled={!i} onClick={() => move(i, -1)}><ArrowUp size={16} /></button><button type="button" className="ui-button-secondary" title="Move question down" aria-label={`Move question ${i + 1} down`} disabled={i === draft.questions.length - 1} onClick={() => move(i, 1)}><ArrowDown size={16} /></button><button type="button" title="Remove question from draft" className="ui-button-secondary" onClick={() => setDraft({ ...draft, questions: draft.questions.filter((_, index) => index !== i) })}><Trash2 size={16} /></button></div>
      </div>)}
      <div className="flex flex-wrap gap-2"><button type="button" className="ui-button-secondary" onClick={() => setDraft({ ...draft, questions: [...draft.questions, { key: `question-${draft.questions.length + 1}`, text: '', section: 'Architecture', answer_type: 'text', required: true, application_types: [], component_types: [], options: [], control: '' }] })}><Plus size={16} />Question</button>
        <button type="button" className="ui-button-secondary" onClick={save}><Save size={16} />Save draft</button>
        {draft.version && draft.status === 'draft' && <button type="button" className="btn-brand" onClick={() => act(async () => {
          const saved = await enterprise(`/questionnaires/${draft.version}`, 'PUT', { name: draft.name, questions: draft.questions, expected_revision: draft.revision });
          await enterprise(`/questionnaires/${saved.version}/published`, 'POST', { expected_revision: saved.revision }); setDraft(null);
        })}>Publish version</button>}
      </div>
    </fieldset>}
  </section>;
}

function ResponseForm({ question: q, sources, onAnswer, administrator }) {
  const [value, setValue] = useState(q.response?.value || '');
  const [note, setNote] = useState(q.response?.note || '');
  const [source, setSource] = useState(q.response?.source_ids?.[0] || '');
  const choices = q.answer_type === 'control' ? ['present', 'absent', 'partial', 'unknown', 'not_applicable'] : [...(q.options || []), 'unknown'];
  return <form className="border-b border-brand-200 py-5 dark:border-brand-700" onSubmit={e => { e.preventDefault(); onAnswer({ question_id: q.id, value, note, evidence_digest: q.evidence_digest, source_ids: source ? [source] : [] }); }}>
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-brand-500 dark:text-brand-300"><span>{q.section} / {q.element_name}{q.required ? ' / Required' : ''}</span><span>{q.status === 'answered' ? `Recorded by ${q.recorded_by}` : q.status === 'stale' ? 'Reconfirmation required' : 'Unanswered'}</span></div>
    <h3 className="mt-2 text-sm font-semibold">{q.text}</h3>
    {q.conflicting && <p className="mt-2 text-sm text-amber-800 dark:text-amber-200">Conflicting evidence requires individual review. Changing this answer does not erase the source conflict.</p>}
    {q.suggestion && <div className="mt-2 flex items-center gap-3 text-xs"><span>Source suggests: {q.suggestion}</span><button type="button" className="ui-button-secondary" onClick={() => { setValue(q.suggestion); setNote(q.evidence?.[0]?.statement || 'Confirmed for the component and scope stated above.'); }}>Use suggestion</button></div>}
    {!!q.evidence?.length && <details className="mt-2 text-xs"><summary className="cursor-pointer">Source evidence</summary>{q.evidence.map((v, i) => <p key={i} className="mt-2 break-words">{[v.document, v.locator, v.statement].filter(Boolean).join(': ')}</p>)}</details>}
    <div className="mt-3 grid gap-3 sm:grid-cols-2"><label className="text-xs">Answer
      {['control', 'choice'].includes(q.answer_type) ? <select required className={`${field} mt-1`} aria-label={`Answer: ${q.id}`} value={value} onChange={e => setValue(e.target.value)}><option value="">Select answer</option>{choices.map(v => <option key={v} value={v} disabled={v === 'not_applicable' && !administrator}>{v.replaceAll('_', ' ')}</option>)}</select>
        : <input required className={`${field} mt-1`} aria-label={`Answer: ${q.id}`} value={value} maxLength={3000} placeholder={q.answer_type === 'number' ? 'Number or unknown' : ''} onChange={e => setValue(e.target.value)} />}</label>
      <label className="text-xs">Supporting source<select className={`${field} mt-1`} value={source} onChange={e => setSource(e.target.value)}><option value="">Owner statement</option>{sources.filter(s => s.included).map(s => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
    </div>
    <label className="mt-3 block text-xs">Brief explanation (required)<textarea required minLength={3} maxLength={3000} className={`${field} mt-1 h-20`} aria-label={`Brief explanation: ${q.id}`} placeholder={explanationPlaceholder(value, q.answer_type)} value={note} onChange={e => setNote(e.target.value)} /></label>
    <button type="submit" className="ui-button-secondary mt-3" disabled={!value || note.trim().length < 3}><Check size={16} />{q.status === 'answered' ? 'Update answer' : 'Record answer'}</button>
  </form>;
}

function SuggestedAnswers({ questions, onConfirm, busy }) {
  const [selected, setSelected] = useState([]);
  const candidates = questions.filter(q => pendingQuestion(q) && q.proposal && !q.conflicting);
  return <section aria-label="Suggested questionnaire answers" className="space-y-4 py-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={candidates.length > 0 && selected.length === candidates.length} disabled={busy || !candidates.length} onChange={e => setSelected(e.target.checked ? candidates.map(q => q.id) : [])} />Select listed proposals</label><button className="ui-button-secondary" disabled={busy || !selected.length} onClick={() => onConfirm(confirmProposals(candidates, selected))}><Check size={16} />Confirm selected answers ({selected.length})</button></div>
    {candidates.map(q => <div key={q.id} className="border-b border-brand-200 pb-4 dark:border-brand-700">
      <label className="flex items-start gap-3"><input type="checkbox" className="mt-1" aria-label={`Confirm proposal: ${q.id}`} disabled={busy} checked={selected.includes(q.id)} onChange={e => setSelected(current => e.target.checked ? [...current, q.id] : current.filter(id => id !== q.id))} /><span className="min-w-0"><span className="block text-sm font-semibold">{q.element_name}: {q.text}</span><span className="mt-2 block whitespace-pre-wrap break-words text-sm">{q.proposal.value.replaceAll('_', ' ')}</span></span></label>
      <div className="ml-7 mt-2 space-y-1 text-xs text-brand-600 dark:text-brand-300">{q.proposal.basis === 'carry_forward' && <p>Previous release proposal / {q.proposal.previous?.reviewer} / {q.proposal.previous?.answered_at}</p>}{q.proposal.evidence.map((e, i) => <p key={i} className="whitespace-pre-wrap break-words"><span className="font-semibold">{e.document}{e.line ? `, line ${e.line}` : ''}: </span>{e.statement}</p>)}</div>
    </div>)}
    {!candidates.length && <p className="text-sm text-brand-600 dark:text-brand-300">No source-backed or unchanged-release proposals await confirmation.</p>}
  </section>;
}

function GroupResponseForm({ group, onAnswer, administrator, busy }) {
  const questions = group.questions;
  const first = questions[0];
  const [selected, setSelected] = useState(questions.length === 1 ? [first.id] : []);
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [owner, setOwner] = useState('');
  const choices = first.answer_type === 'control' ? ['present', 'absent', 'partial', 'unknown', 'not_applicable'] : [...(first.options || []), 'unknown'];
  return <form className="border-b border-brand-200 py-5 dark:border-brand-700" onSubmit={e => { e.preventDefault(); onAnswer(groupAnswers(questions, selected, value, note, owner)); }}>
    <fieldset disabled={busy} className="min-w-0 space-y-3">
      <legend className="text-sm font-semibold">{group.text}</legend>
      <p className="pt-2 text-xs text-brand-600 dark:text-brand-300">{first.section} / {group.priority || 'normal'} priority / {questions.some(q => q.required) ? 'Required' : 'Optional'}{questions.some(q => q.status === 'stale') ? ' / Reconfirmation required' : ''}</p>
      {first.conflicting && <p className="text-sm text-amber-800 dark:text-amber-200">Conflicting source evidence. Record an individual assessment; source conflicts remain visible.</p>}
      {questions.length > 1 && <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={selected.length === questions.length} onChange={e => setSelected(e.target.checked ? questions.map(q => q.id) : [])} />Select all listed components</label>}
      <div className="flex flex-wrap gap-x-6 gap-y-2">{questions.map(q => <label key={q.id} className="flex min-w-0 items-center gap-2 text-sm"><input type="checkbox" aria-label={`Apply answer: ${q.id}`} checked={selected.includes(q.id)} onChange={e => setSelected(current => e.target.checked ? [...current, q.id] : current.filter(id => id !== q.id))} /><span className="break-words">{q.element_name}</span></label>)}</div>
      {questions.some(q => q.evidence?.length) && <details className="text-xs"><summary className="cursor-pointer font-medium">Scoped evidence and exceptions</summary>{questions.map(q => <div key={q.id} className="mt-2"><p className="font-semibold">{q.element_name}</p>{q.evidence.map((e, i) => <p key={i} className="break-words">{e.document}: {e.statement} ({e.scope_status || e.state || 'owner statement'})</p>)}</div>)}</details>}
      <div className="grid gap-3 sm:grid-cols-2"><label className="text-xs">Answer{['control', 'choice'].includes(first.answer_type) ? <select aria-label={`Group answer: ${group.id}`} required className={`${field} mt-1`} value={value} onChange={e => setValue(e.target.value)}><option value="">Select answer</option>{choices.map(v => <option key={v} value={v} disabled={v === 'not_applicable' && !administrator}>{v.replaceAll('_', ' ')}</option>)}</select> : <textarea aria-label={`Group answer: ${group.id}`} required maxLength={3000} className={`${field} mt-1 min-h-20`} value={value} onChange={e => setValue(e.target.value)} />}</label>
      <label className="text-xs">Who can confirm this? (optional)<input aria-label={`Who can confirm this: ${group.id}`} className={`${field} mt-1`} value={owner} maxLength={200} onChange={e => setOwner(e.target.value)} /></label></div>
      {value === 'unknown' && <label className="block text-xs">Why are you unsure?<select aria-label={`Why are you unsure: ${group.id}`} className={`${field} mt-1`} value={['Not documented in the available sources.', 'Awaiting confirmation from the component owner.', 'Deployment configuration has not been reviewed.'].includes(note) ? note : ''} onChange={e => setNote(e.target.value)}><option value="">Choose a reason or enter one below</option>{['Not documented in the available sources.', 'Awaiting confirmation from the component owner.', 'Deployment configuration has not been reviewed.'].map(v => <option key={v}>{v}</option>)}</select></label>}
      <label className="block text-xs">Brief explanation (required)<textarea aria-label={`Brief explanation: ${group.id}`} required minLength={3} maxLength={3000} className={`${field} mt-1 min-h-20`} placeholder={explanationPlaceholder(value, first.answer_type)} value={note} onChange={e => setNote(e.target.value)} /></label>
      <button className="ui-button-secondary" type="submit" disabled={!selected.length || !value.trim() || note.trim().length < 3}><Check size={16} />Record for selected ({selected.length})</button>
    </fieldset>
  </form>;
}

export default function QuestionnairePanel({ payload, preview, onChange, onGenerate, busy }) {
  const [settings, setSettings] = useState(null);
  const [error, setError] = useState('');
  const [admin, setAdmin] = useState(false);
  const [page, setPage] = useState(0);
  const [view, setView] = useState('input');
  useEffect(() => { enterprise('/assessment-settings').then(setSettings).catch(e => setError(e.message)); }, []);
  const questionnaire = preview?.questionnaire;
  const questions = questionnaire?.questions || [];
  const pending = questions.filter(pendingQuestion);
  const clarification = questionGroups(pending.filter(q => !q.proposal));
  const required = clarification.filter(g => g.questions.some(q => q.required));
  const optional = clarification.filter(g => !g.questions.some(q => q.required));
  const proposals = pending.filter(q => q.proposal);
  const answered = questions.filter(q => q.status === 'answered');
  const list = view === 'input' ? required : view === 'answered' ? answered : questions;
  const pages = Math.max(1, Math.ceil(list.length / 5));
  const current = Math.min(page, pages - 1);
  const answerMany = records => { if (!busy && records.length) onChange({ questionnaire_answers: mergeQuestionAnswers(payload.questionnaire_answers || [], records) }, true); };
  const answer = record => answerMany([record]);
  return <div className="py-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="font-semibold">Pre-DFD questionnaire{questionnaire ? ` / v${questionnaire.template_version}` : ''}</h3>
      {settings?.can_manage_questionnaires && <button type="button" className="ui-button-secondary" onClick={() => setAdmin(!admin)}><Settings2 size={16} />Manage questions</button>}</div>
    {error && <p role="alert" className="mt-3 text-red-700 dark:text-red-300">{error}</p>}
    {admin && <QuestionnaireAdmin onClose={() => setAdmin(false)} />}
    <fieldset className="my-5 border-b border-brand-200 pb-5 dark:border-brand-700"><legend className="mb-2 text-sm font-medium">Select Application Type</legend>
      <div className="flex flex-wrap gap-4">{Object.entries(applicationTypes).map(([id, name]) => <label key={id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={(payload.application_types || []).includes(id)} onChange={e => onChange({ application_types: e.target.checked ? [...(payload.application_types || []), id] : payload.application_types.filter(v => v !== id) }, true)} />{name}</label>)}</div>
      {payload.application_types?.includes('other') && <label className="mt-3 block text-xs">Other application type<input className={`${field} mt-1`} maxLength={200} value={payload.other_application_type || ''} onChange={e => onChange({ other_application_type: e.target.value })} /></label>}
    </fieldset>
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-brand-600 dark:text-brand-300"><span role="status">{answered.length} of {questions.length} checks answered / {questionnaire?.questionnaire_summary?.required_remaining ?? pending.length} required remaining</span><span>Owner statements, not deployment verification</span></div>
    <nav aria-label="Questionnaire views" className="mt-4 flex flex-wrap gap-2 border-b border-brand-200 dark:border-brand-700">{[['input', `Needs input (${required.length})`], ['suggested', `Suggested answers (${proposals.length})`], ['answered', `Answered (${answered.length})`], ['all', `All checks (${questions.length})`]].map(([id, label]) => <button key={id} type="button" aria-pressed={view === id} className={`border-b-2 px-3 py-3 text-sm ${view === id ? 'border-brand-primary font-semibold text-brand-primary dark:text-indigo-300' : 'border-transparent'}`} onClick={() => { setView(id); setPage(0); }}>{label}</button>)}</nav>
    {questionnaire?.scope_errors?.map(item => <p key={item} className="mt-2 text-sm text-amber-800 dark:text-amber-200">{item}</p>)}
    {view === 'suggested' ? <SuggestedAnswers key={proposals.map(q => q.proposal.digest).join(':')} questions={proposals} busy={busy} onConfirm={answerMany} /> : view === 'input' ? <>
      {required.slice(current * 5, current * 5 + 5).map(group => <GroupResponseForm key={group.questions.map(q => q.id + q.evidence_digest).join(':')} group={group} busy={busy} onAnswer={answerMany} administrator={settings?.can_manage_questionnaires} />)}
      {!required.length && <p className="py-5 text-sm">{proposals.length ? 'No additional required clarification prompts. Suggested answers still need confirmation.' : 'No required clarification prompts remain.'}</p>}
      {!!optional.length && <details className="border-y border-brand-200 py-4 dark:border-brand-700"><summary className="cursor-pointer text-sm font-semibold">Optional detail ({optional.length} prompts)</summary>{optional.map(group => <GroupResponseForm key={group.questions.map(q => q.id + q.evidence_digest).join(':')} group={group} busy={busy} onAnswer={answerMany} administrator={settings?.can_manage_questionnaires} />)}</details>}
    </> : <fieldset disabled={busy} className="min-w-0">{list.slice(current * 5, current * 5 + 5).map(q => q.status === 'not_triggered' ? <p key={q.id} className="border-b py-4 text-sm">{q.element_name}: {q.text} / Not triggered by the current parent answer.</p> : <ResponseForm key={`${q.id}:${q.evidence_digest}:${JSON.stringify(q.response)}`} question={q} sources={payload.sources} onAnswer={answer} administrator={settings?.can_manage_questionnaires} />)}</fieldset>}
    {view !== 'suggested' && <div className="mt-4 flex items-center justify-end gap-3 text-sm"><button type="button" className="ui-button-secondary" aria-label="Previous questions" title="Previous questions" disabled={!current} onClick={() => setPage(current - 1)}><ChevronLeft size={16} /></button><span>Page {current + 1} of {pages}</span><button type="button" className="ui-button-secondary" aria-label="Next questions" title="Next questions" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}><ChevronRight size={16} /></button></div>}
    <div className="mt-5 flex justify-end"><button type="button" className="btn-brand" disabled={busy || !questionnaire?.complete} onClick={onGenerate}><ArrowRight size={16} />Generate DFD</button></div>
  </div>;
}
