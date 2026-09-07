import { useEffect, useRef } from 'react';
import { FileText, X } from 'lucide-react';

export default function SourceEvidenceDialog({ selection, preview, onClose, onSource, onAliases, relatedRisks = [] }) {
  const dialog = useRef(null);
  useEffect(() => {
    dialog.current.showModal();
  }, []);
  const ids = selection.ids;
  const component = preview.architecture.components.find((item) => ids.includes(item.id));
  const facts = (preview.correlation?.facts || preview.architecture.metadata?.source_correlation?.facts || []).filter((fact) => ids.includes(fact.element_id));
  const controls = component?.properties?.correlated_controls || {};
  const risks = relatedRisks.filter((risk) => (risk.affected_components || [risk.component_id]).some((id) => ids.includes(id)));
  return <dialog ref={dialog} onCancel={onClose} onClick={(event) => { if (event.target === dialog.current) onClose(); }} aria-labelledby="source-evidence-title" style={{ width: 'calc(100% - 32px)' }} className="m-auto max-w-[720px] max-h-[85vh] overflow-y-auto rounded-lg border border-brand-200 bg-white p-5 text-brand-950 shadow-xl backdrop:bg-black/40 dark:border-brand-700 dark:bg-brand-900 dark:text-brand-100">
    <header className="flex items-start justify-between gap-3 border-b border-brand-200 pb-3 dark:border-brand-700"><div><h2 id="source-evidence-title" className="text-lg font-semibold">{component?.name || 'Data flow'}: evidence</h2><p className="mt-1 text-xs text-brand-500 dark:text-brand-300">Source statements and owner decisions. Not deployment-verified.</p></div><button type="button" className="ui-button-secondary p-2" aria-label="Close source evidence" title="Close source evidence" onClick={onClose}><X size={18} /></button></header>
    {component && <form className="my-4 flex flex-wrap items-end gap-2" onSubmit={(event) => { event.preventDefault(); onAliases(component.id, new FormData(event.currentTarget).get('aliases')); }}><label className="min-w-0 flex-1 text-xs">Component aliases<input key={component.id} name="aliases" aria-label="Component aliases" defaultValue={(component.properties?.aliases || []).join(', ')} maxLength={500} className="input-brand mt-1 w-full text-sm" /></label><button className="ui-button-secondary" type="submit">Apply aliases</button></form>}
    {!!Object.keys(controls).length && <table className="my-4 w-full text-left text-sm"><thead><tr><th className="py-2">Control</th><th>Assessment</th></tr></thead><tbody>{Object.entries(controls).map(([name, value]) => <tr key={name} className="border-t border-brand-200 dark:border-brand-700"><td className="py-2 break-words">{name.replaceAll('_', ' ')}</td><td className={value.state === 'conflicting' ? 'text-red-700 dark:text-red-300' : ''}>{value.state}</td></tr>)}</tbody></table>}
    {facts.map((fact, index) => <article key={`${fact.id}-${index}`} className="border-t border-brand-200 py-4 dark:border-brand-700"><div className="flex flex-wrap gap-2 text-xs text-brand-500 dark:text-brand-300"><span>{fact.control?.replaceAll('_', ' ') || fact.kind}</span><strong>{fact.state || fact.basis}</strong>{fact.scope_status && <span>{fact.scope_status.replaceAll('_', ' ')}</span>}</div><p className="mt-2 break-words text-sm">{fact.statement || `${fact.source_component} to ${fact.target_component}: ${fact.protocol}`}</p><p className="mt-2 break-words text-xs text-brand-500 dark:text-brand-300">{[fact.document || fact.source_ref, fact.locator, fact.line && `line ${fact.line}`, fact.document_version && `document ${fact.document_version}`, fact.scope?.environment, fact.scope?.deployment_version, ...(fact.scope?.endpoints || [])].filter(Boolean).join(' | ')}</p>{fact.document && <button type="button" className="ui-button-secondary mt-2 text-xs" onClick={() => onSource(fact)}><FileText size={14} />Open source</button>}</article>)}
    {!facts.length && <p className="py-5 text-sm">No source passage is attached to this element. Review its model basis before relying on it.</p>}
    {!!risks.length && <section className="border-t border-brand-200 py-4 dark:border-brand-700"><h3 className="text-sm font-semibold">Related findings from the last report</h3><ul className="mt-2 space-y-2 text-sm">{risks.map((risk) => <li key={risk.id}>{risk.severity}: {risk.title}</li>)}</ul></section>}
  </dialog>;
}
