import { useState } from 'react';
import { Save, RefreshCw } from 'lucide-react';
import { enterprise } from '../../services/enterprise';
import { reviewStatuses } from '../../utils/assessmentCatalog';

function localDateTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function RiskReviewForm({ reportId, threat, review, events, onSaved, readOnly }) {
  const [status, setStatus] = useState(review?.status || 'pending_review');
  const [remarks, setRemarks] = useState('');
  const [owner, setOwner] = useState(review?.owner || '');
  const [targetDate, setTargetDate] = useState((review?.target_date || '').slice(0, 10));
  const [acceptanceExpiry, setAcceptanceExpiry] = useState(localDateTime(review?.acceptance_expires_at));
  const [evidence, setEvidence] = useState('');
  const [verificationMethod, setVerificationMethod] = useState('test');
  const [checkedAt, setCheckedAt] = useState('');
  const [criterion, setCriterion] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const submit = async event => {
    event.preventDefault(); setSaving(true); setError('');
    try {
      const updated = await enterprise(`/assessment-reports/${reportId}/reviews/${encodeURIComponent(threat.id)}`, 'POST', {
        expected_version: review?.version || 0, status, remarks, owner, target_date: targetDate, verification_evidence: evidence,
        acceptance_expires_at: status === 'accepted' ? new Date(acceptanceExpiry).toISOString() : '',
        acceptance_criteria: status === 'verified_fixed' ? [criterion] : [],
        verification: status === 'verified_fixed' ? [{ method: verificationMethod, reference: evidence, result: 'passed', checked_at: new Date(checkedAt).toISOString() }] : [],
      });
      onSaved(updated); setRemarks(''); setEvidence('');
    } catch (e) { setError(e.message); } finally { setSaving(false); }
  };
  return <section className="border-t border-brand-200 px-5 py-5 dark:border-brand-700 sm:px-7" aria-label="Product team review">
    <h3 className="text-sm font-semibold">Product Architect / Product Team review</h3>
    {review?.acceptance_expired && <p role="status" className="mt-2 text-sm text-amber-800 dark:text-amber-200">Risk acceptance expired. This finding is pending review again.</p>}
    {review?.overdue && <p className="mt-2 text-sm text-amber-800 dark:text-amber-200">The target date has passed.</p>}
    {error && <div role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300"><p>{error}</p><button type="button" className="ui-button-secondary mt-2" onClick={async () => { try { onSaved(await enterprise(`/assessment-reports/${reportId}/reviews`)); setError(''); } catch (e) { setError(e.message); } }}><RefreshCw size={16} />Reload review history</button></div>}
    <form onSubmit={submit} className="mt-4"><fieldset disabled={readOnly || saving} className="grid min-w-0 gap-3 sm:grid-cols-2">
      <label className="text-xs">Review status<select aria-label="Product review status" className="input-brand mt-1 w-full text-sm" value={status} onChange={e => setStatus(e.target.value)}>{Object.entries(reviewStatuses).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      <label className="text-xs">Owner<input required={status === 'accepted' || status === 'verified_fixed'} className="input-brand mt-1 w-full text-sm" maxLength={200} value={owner} onChange={e => setOwner(e.target.value)} /></label>
      <label className="text-xs">Target date<input type="date" className="input-brand mt-1 w-full text-sm" value={targetDate} onChange={e => setTargetDate(e.target.value)} /></label>
      {status === 'accepted' && <label className="text-xs">Acceptance expires<input aria-label="Acceptance expires" required type="datetime-local" min={localDateTime(new Date().toISOString())} max={localDateTime(new Date(Date.now() + 366 * 86400000).toISOString())} className="input-brand mt-1 w-full text-sm" value={acceptanceExpiry} onChange={e => setAcceptanceExpiry(e.target.value)} /></label>}
      <label className="text-xs sm:col-span-2">Remarks<textarea aria-label="Product team remarks" required minLength={3} maxLength={6000} className="input-brand mt-1 h-24 w-full text-sm" value={remarks} onChange={e => setRemarks(e.target.value)} /></label>
      {status === 'verified_fixed' && <>
        <label className="text-xs">Verification method<select className="input-brand mt-1 w-full text-sm" value={verificationMethod} onChange={e => setVerificationMethod(e.target.value)}><option value="test">Security test</option><option value="configuration_review">Configuration review</option><option value="code_review">Code review</option><option value="independent_report">Independent report</option></select></label>
        <label className="text-xs">Verified on<input required type="datetime-local" max={localDateTime(new Date().toISOString())} className="input-brand mt-1 w-full text-sm" value={checkedAt} onChange={e => setCheckedAt(e.target.value)} /></label>
        <label className="text-xs sm:col-span-2">Acceptance criterion satisfied<textarea aria-label="Acceptance criterion satisfied" required minLength={3} maxLength={3000} className="input-brand mt-1 h-20 w-full text-sm" value={criterion} onChange={e => setCriterion(e.target.value)} /></label>
        <label className="text-xs sm:col-span-2">Passing verification evidence<textarea aria-label="Verification evidence" required minLength={3} maxLength={3000} className="input-brand mt-1 h-20 w-full text-sm" value={evidence} onChange={e => setEvidence(e.target.value)} /></label>
      </>}
      <div className="sm:col-span-2"><button type="submit" className="ui-button-secondary" disabled={remarks.trim().length < 3}><Save size={16} />{saving ? 'Saving...' : 'Record review'}</button></div>
    </fieldset></form>
    <ol className="mt-5 space-y-4">{events.filter(e => e.finding_id === threat.id).map(event => <li key={event.version} className="border-l-2 border-brand-200 pl-3 dark:border-brand-600">
      <p className="text-xs font-semibold">{event.author} / {event.author_role} / {reviewStatuses[event.status]} / {new Date(event.created_at * 1000).toLocaleString()}</p>
      <p className="mt-1 whitespace-pre-wrap break-words text-sm">{event.remarks}</p>
      {event.acceptance_expires_at && <p className="mt-1 text-xs">Acceptance expiry: {new Date(event.acceptance_expires_at).toLocaleString()}</p>}
      {event.verification_evidence && <p className="mt-1 break-words text-xs">Verification: {event.verification_evidence}</p>}
      {!!event.verification?.length && <details className="mt-2 text-xs"><summary className="cursor-pointer font-medium">Verification records ({event.verification.length})</summary>
        <ul className="mt-2 space-y-2">{event.verification.map((check, index) => <li key={index} className="break-words">{check.method?.replaceAll('_', ' ')} / {check.result} / {new Date(check.checked_at).toLocaleString()}<p>{check.reference}</p></li>)}</ul>
        {!!event.acceptance_criteria?.length && <ul className="mt-2 list-inside list-disc space-y-1">{event.acceptance_criteria.map((item, index) => <li key={index} className="break-words">{item}</li>)}</ul>}
      </details>}
    </li>)}</ol>
  </section>;
}
