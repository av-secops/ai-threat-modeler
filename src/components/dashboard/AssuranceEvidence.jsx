import { useState } from 'react';
import { CircleHelp } from 'lucide-react';

export default function AssuranceEvidence({ status, threats, onSelect, onClarify }) {
  const [query, setQuery] = useState('');
  const inventory = status.issue_inventory;
  const issues = (inventory?.issues || []).filter(r => r.statement.toLowerCase().includes(query.toLowerCase()));
  return <section className="space-y-4 border-y border-brand-200 py-5 dark:border-brand-700">
    <div className="flex flex-wrap justify-between gap-3"><h3 className="font-semibold">Source issue accountability</h3><span className="text-sm">{inventory?.reported || 0} reported / {inventory?.declared || 0} declared</span></div>
    <input aria-label="Search source issues" className="input-brand text-sm" placeholder="Search source issues" value={query} onChange={e => setQuery(e.target.value)} />
    <div className="max-h-96 overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th className="py-2">Source statement</th><th>Status</th><th>Disposition</th></tr></thead><tbody>{issues.map(issue => <tr key={issue.id} className="border-t border-brand-200 align-top dark:border-brand-700"><td className="max-w-lg break-words py-3 pr-4">{issue.statement}<p className="mt-1 text-xs text-brand-500">{issue.document}{issue.line ? ` / line ${issue.line}` : ''}</p></td><td className="py-3 pr-3">{{ reported: 'Reported', out_of_scope: 'Outside scope', needs_review: 'Needs review' }[issue.status] || 'Needs review'}</td><td className="py-3">{issue.finding_ids.map(id => <button key={id} className="mb-1 block text-left underline" onClick={() => onSelect(threats.find(t => t.id === id))}>{threats.find(t => t.id === id)?.title || id}</button>)}<span className="text-xs">{issue.reason}</span></td></tr>)}</tbody></table>{!issues.length && <p className="py-4 text-sm text-brand-500">No matching declared issues in the inventory.</p>}</div>
    {onClarify && (status.evidence_validation?.requires_review > 0 || inventory?.unaccounted > 0) && <button className="ui-button-secondary" onClick={onClarify}><CircleHelp size={16} />Review unresolved evidence</button>}
    {!!status.policy_evaluations?.length && <details><summary className="text-sm font-medium">Cloud policy evaluations ({status.policy_evaluations.length})</summary>{status.policy_evaluations.map((row, i) => <div className="border-b border-brand-200 py-3 text-sm dark:border-brand-700" key={i}><p>{row.component}: {row.request.action} - {row.decision}</p><p className="mt-1 text-xs">{row.limits.join('; ')}</p></div>)}</details>}
    {!!status.workflow_assessments?.length && <details><summary className="text-sm font-medium">Business workflow controls</summary>{status.workflow_assessments.map((row, i) => <p className="py-1 text-sm" key={i}>{row.workflow}: {row.control} - {row.state}</p>)}</details>}
  </section>;
}
