import { useState } from 'react';
import { Link, Save, Trash2 } from 'lucide-react';
import { enterprise } from '../../services/enterprise';

export default function ExternalReportReview({ report, assessment, architecture, readOnly, onSaved }) {
  const [status, setStatus] = useState(report.status);
  const [remarks, setRemarks] = useState('');
  const previousRevision = report.model_report_id && report.model_report_id !== assessment?.report_id;
  const [links, setLinks] = useState(previousRevision ? [] : report.links || []);
  const [finding, setFinding] = useState('');
  const [component, setComponent] = useState('');
  const [flow, setFlow] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async event => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const updated = await enterprise(`/assessments/${assessment.id}/security-reports/${report.id}/review`, 'POST', {
        status, remarks, links, model_report_id: assessment.report_id, expected_revision: report.revision || 1,
      });
      await onSaved(updated);
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  return <form onSubmit={submit} className="mt-5 border-t border-brand-200 pt-4 dark:border-brand-700" aria-label="External report review">
    <h4 className="text-sm font-semibold">Product-team review and model links</h4>
    {previousRevision && <p className="mt-2 text-xs text-amber-800 dark:text-amber-200">Saved links belong to another model revision. Select current components and flows to relink; earlier links remain in review history.</p>}
    {error && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{error}</p>}
    <fieldset disabled={readOnly || busy || !assessment?.report_id} className="mt-3 grid min-w-0 gap-3 sm:grid-cols-2">
      <label className="text-xs">Report review status<select aria-label="External report status" className="input-brand mt-1 w-full text-sm" value={status} onChange={e => setStatus(e.target.value)}>{['imported', 'under_review', 'reviewed'].map(value => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></label>
      <label className="text-xs sm:col-span-2">Remarks<textarea aria-label="External report remarks" required minLength={3} maxLength={3000} className="input-brand mt-1 h-20 w-full text-sm" value={remarks} onChange={e => setRemarks(e.target.value)} /></label>
      {!!report.findings?.length && <>
        <label className="text-xs sm:col-span-2">Imported finding<select aria-label="Imported finding to link" className="input-brand mt-1 w-full text-sm" value={finding} onChange={e => setFinding(e.target.value)}><option value="">Select finding</option>{report.findings.map(item => <option key={item.import_id} value={item.import_id}>{item.title}</option>)}</select></label>
        <label className="text-xs">Affected component<select aria-label="Linked component" className="input-brand mt-1 w-full text-sm" value={component} onChange={e => setComponent(e.target.value)}><option value="">None</option>{architecture?.components?.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label className="text-xs">Affected flow<select aria-label="Linked flow" className="input-brand mt-1 w-full text-sm" value={flow} onChange={e => setFlow(e.target.value)}><option value="">None</option>{architecture?.flows?.map(item => <option key={item.id} value={item.id}>{item.flow_number}: {item.description || `${item.source_id} to ${item.target_id}`}</option>)}</select></label>
        <label className="text-xs sm:col-span-2">Link evidence<input aria-label="Link evidence" maxLength={1000} className="input-brand mt-1 w-full text-sm" value={reason} onChange={e => setReason(e.target.value)} /></label>
        <div className="sm:col-span-2"><button type="button" className="ui-button-secondary" disabled={!finding || (!component && !flow) || reason.trim().length < 3} onClick={() => { setLinks([...links.filter(item => item.finding_id !== finding), { finding_id: finding, component_ids: component ? [component] : [], flow_ids: flow ? [flow] : [], reason }]); setFinding(''); setReason(''); }}><Link size={16} />Add model link</button></div>
        <ul className="space-y-2 text-xs sm:col-span-2">{links.map(item => <li key={item.finding_id} className="flex items-center justify-between gap-3"><span className="min-w-0 break-words">{report.findings.find(f => f.import_id === item.finding_id)?.title}: {[...item.component_ids.map(id => architecture?.components?.find(c => c.id === id)?.name || id), ...item.flow_ids.map(id => architecture?.flows?.find(f => f.id === id)?.flow_number || id)].join(', ')}<br />{item.reason}</span><button type="button" title="Remove model link" aria-label="Remove model link" className="ui-button-secondary" onClick={() => setLinks(links.filter(v => v.finding_id !== item.finding_id))}><Trash2 size={14} /></button></li>)}</ul>
      </>}
      <div className="sm:col-span-2"><button type="submit" className="ui-button-secondary" disabled={remarks.trim().length < 3}><Save size={16} />{busy ? 'Saving...' : 'Save report review'}</button></div>
    </fieldset>
    <ol className="mt-4 space-y-3">{report.review_history?.map(event => <li key={event.version} className="border-l-2 border-brand-200 pl-3 text-xs dark:border-brand-600"><p className="font-semibold">{event.author} / {event.author_role} / {event.status.replaceAll('_', ' ')} / {new Date(event.created_at * 1000).toLocaleString()}</p><p className="mt-1 whitespace-pre-wrap break-words">{event.remarks}</p></li>)}</ol>
  </form>;
}
