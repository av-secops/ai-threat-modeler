import { useEffect, useState } from 'react';
import { Eye, Upload, X, RefreshCw } from 'lucide-react';
import { API_BASE_URL } from '../../config';
import { enterprise } from '../../services/enterprise';
import { reportTypes } from '../../utils/assessmentCatalog';
import ExternalReportReview from './ExternalReportReview';

export default function SecurityReports({ assessment, architecture, readOnly, children }) {
  const [reports, setReports] = useState([]);
  const [category, setCategory] = useState('threat_modeling');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [file, setFile] = useState(null);
  const [metadata, setMetadata] = useState({ title: '', source: '', report_date: '', environment: assessment?.environment || '', deployment_version: assessment?.deployment_version || '', image_digest: '' });
  const load = async () => { if (assessment?.id) { const rows = (await enterprise(`/assessments/${assessment.id}/security-reports`)).reports; setReports(rows); setSelected(previous => rows.find(row => row.id === previous?.id) || previous); setError(''); } };
  useEffect(() => {
    let active = true;
    if (assessment?.id) enterprise(`/assessments/${assessment.id}/security-reports`).then(result => { if (active) setReports(result.reports); }).catch(e => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [assessment?.id]);
  const submit = async event => {
    event.preventDefault(); if (!file || !assessment?.id) return;
    setBusy(true); setError('');
    try {
      const body = new FormData(); body.append('file', file); body.append('metadata', JSON.stringify({ ...metadata, category }));
      const token = sessionStorage.getItem('aegis-workspace-token');
      const response = await fetch(`${API_BASE_URL}/enterprise/assessments/${assessment.id}/security-reports`, { method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {}, body });
      const value = await response.json(); if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'Report import failed.');
      setSelected(value); await load();
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const scopeMismatch = report => !report.native && ((assessment?.environment && report.environment !== assessment.environment) || (assessment?.deployment_version && report.deployment_version !== assessment.deployment_version));
  return <section className="space-y-5" aria-label="Security Reports">
    <header className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold">Security Reports</h2><div className="flex gap-2"><label className="sr-only" htmlFor="assessment-category">Security assessment</label><select id="assessment-category" className="input-brand text-sm" value={category} onChange={e => { setCategory(e.target.value); setSelected(null); }}>{Object.entries(reportTypes).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select><button className="ui-button-secondary" type="button" title="Refresh reports" aria-label="Refresh reports" onClick={() => load().catch(e => setError(e.message))}><RefreshCw size={16} /></button></div></header>
    {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
    {category === 'threat_modeling' ? children : <>
      <p className="text-sm text-brand-600 dark:text-brand-300">External assessment records. Importing a report does not run a scanner or verify its findings.</p>
      {!assessment?.id && <p className="text-sm text-amber-800 dark:text-amber-200">Update this legacy model to create a governed assessment before importing reports.</p>}
      <div className="overflow-x-auto"><table className="w-full min-w-[650px] text-left text-sm"><thead><tr>{['Report', 'Source', 'Date', 'Scope', 'Status', ''].map((heading, i) => <th key={i} className="border-b border-brand-200 px-3 py-3 dark:border-brand-700">{heading}</th>)}</tr></thead><tbody>
        {reports.filter(r => r.category === category).map(report => <tr key={report.id} className="border-b border-brand-200 dark:border-brand-700"><td className="p-3">{report.title}</td><td className="p-3">{report.source}</td><td className="p-3">{report.report_date}</td><td className="p-3">{report.environment} / {report.deployment_version}{report.image_digest && <p className="max-w-64 break-all text-xs">{report.image_digest}</p>}</td><td className="p-3">{scopeMismatch(report) ? 'Scope mismatch' : report.status.replaceAll('_', ' ')}</td><td className="p-3"><button type="button" className="ui-button-secondary" aria-label={`Open ${report.title}`} title="Report details" onClick={() => setSelected(report)}><Eye size={16} /></button></td></tr>)}
        {!reports.some(r => r.category === category) && <tr><td colSpan={6} className="p-5 text-brand-500 dark:text-brand-300">Not Assessed: no report recorded.</td></tr>}
      </tbody></table></div>
      <details className="border-b border-brand-200 pb-4 dark:border-brand-700"><summary className="cursor-pointer text-sm font-semibold">Import {reportTypes[category]} report</summary>
        <form onSubmit={submit} className="mt-4"><fieldset disabled={busy || readOnly || !assessment?.id} className="grid min-w-0 gap-3 sm:grid-cols-2">
          {['title', 'source', 'report_date', 'environment', 'deployment_version', ...(category === 'container_security' ? ['image_digest'] : [])].map(key => <label key={key} className="text-xs capitalize">{key === 'image_digest' ? 'Image digest or tag' : key.replaceAll('_', ' ')}<input required type={key === 'report_date' ? 'date' : 'text'} maxLength={500} className="input-brand mt-1 w-full text-sm" value={metadata[key]} onChange={e => setMetadata({ ...metadata, [key]: e.target.value })} /></label>)}
          <label className="text-xs">Report file<input aria-label="Security report file" required type="file" accept={category === 'secret_detection' ? '.json' : '.json,.sarif,.pdf,.docx,.txt,.md,.xml'} className="mt-1 block w-full text-sm" onChange={e => setFile(e.target.files[0])} /></label>
          <div className="flex items-end"><button type="submit" className="ui-button-secondary"><Upload size={16} />{busy ? 'Importing...' : 'Import report'}</button></div>
        </fieldset></form>
      </details>
      {selected && <section className="border-y border-brand-200 py-4 dark:border-brand-700" aria-label="Imported report details"><div className="flex items-center justify-between gap-3"><h3 className="font-semibold">{selected.title}</h3><button className="ui-button-secondary" type="button" title="Close report details" aria-label="Close report details" onClick={() => setSelected(null)}><X size={16} /></button></div><p className="mt-2 break-words text-xs">{selected.warning}</p><p className="mt-2 break-all text-xs">SHA-256: {selected.artifact_hash}</p>
        <p className="mt-2 text-xs">{selected.findings?.length || 0} imported findings / {selected.inventory?.length || 0} inventory entries / {selected.links?.length || 0} linked findings</p>
        {selected.text && <pre className="mt-4 max-h-96 overflow-auto whitespace-pre-wrap break-words text-xs">{selected.text}</pre>}
        {!!selected.findings?.length && <ul className="mt-4 max-h-96 space-y-3 overflow-auto text-sm">{selected.findings.map((item, i) => <li key={i} className="border-b border-brand-200 pb-2 dark:border-brand-700"><span className="font-semibold">{item.title}</span><p className="text-xs">{item.severity} / {item.location}{item.line ? `:${item.line}` : ''}</p></li>)}</ul>}
        {!!selected.inventory?.length && <ul className="mt-4 max-h-96 overflow-auto text-xs">{selected.inventory.map((item, i) => <li className="py-1" key={i}>{item.name} / {item.version} / {JSON.stringify(item.licenses)}</li>)}</ul>}
        <ExternalReportReview key={`${selected.id}:${selected.revision}`} report={selected} assessment={assessment} architecture={architecture} readOnly={readOnly} onSaved={async value => { setSelected(value); await load(); }} />
      </section>}
    </>}
  </section>;
}
