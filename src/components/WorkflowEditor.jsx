import { Plus, Trash2 } from 'lucide-react';

const CONTROLS = {
  atomic_debit: 'Atomic balance check and debit', replay_protection: 'Replay protection',
  tenant_binding: 'Tenant-bound execution', separation_of_duties: 'Independent approval',
  delegated_authority: 'Delegated action scope', state_transition_validation: 'Valid state transitions',
};

export default function WorkflowEditor({ workflows = [], components, onChange }) {
  const update = (id, patch) => onChange(workflows.map(w => w.id === id ? { ...w, ...patch } : w));
  return <section className="space-y-5 py-5" aria-label="Business workflows">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h3 className="text-sm font-semibold">Business workflows ({workflows.length})</h3>
      <button type="button" className="ui-button-secondary" disabled={workflows.length >= 100} onClick={() => onChange([...workflows, {
        id: `workflow-${crypto.randomUUID()}`, name: 'New workflow', components: [], invariants: {}, evidence: [],
      }])}><Plus size={16} />Workflow</button>
    </div>
    {workflows.map(workflow => <div key={workflow.id} className="space-y-4 border-b border-brand-200 pb-5 dark:border-brand-700">
      <div className="flex items-end gap-3">
        <label className="grid min-w-0 flex-1 gap-1 text-xs">Workflow name<input aria-label={`Workflow name: ${workflow.id}`} maxLength={200} className="input-brand text-sm" value={workflow.name} onChange={e => update(workflow.id, { name: e.target.value })} /></label>
        <button type="button" className="ui-button-secondary" title="Remove workflow" aria-label={`Remove ${workflow.name}`} onClick={() => onChange(workflows.filter(w => w.id !== workflow.id))}><Trash2 size={16} /></button>
      </div>
      <fieldset className="flex flex-wrap gap-4"><legend className="mb-2 text-xs">Affected components</legend>{components.map(c => <label key={c.id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={workflow.components.includes(c.id)} onChange={e => update(workflow.id, { components: e.target.checked ? [...workflow.components, c.id] : workflow.components.filter(id => id !== c.id) })} />{c.name}</label>)}</fieldset>
      {!workflow.components.length && <p className="text-xs text-amber-700 dark:text-amber-300">Affected components not selected.</p>}
      <div className="space-y-3">{Object.entries(CONTROLS).map(([control, label]) => {
        const evidence = workflow.evidence.find(e => e.control === control);
        const value = workflow.invariants[control];
        return <div key={control} className="grid gap-2 sm:grid-cols-[220px_minmax(0,1fr)]">
          <label className="grid gap-1 text-xs">{label}<select aria-label={`${label}: ${workflow.id}`} className="input-brand text-sm" value={value === true ? 'present' : value === false ? 'absent' : 'unknown'} onChange={e => update(workflow.id, { invariants: { ...workflow.invariants, [control]: e.target.value === 'unknown' ? null : e.target.value === 'present' } })}><option value="unknown">Unknown</option><option value="present">Present</option><option value="absent">Absent</option></select></label>
          <label className="grid gap-1 text-xs">Owner evidence<textarea aria-label={`Evidence for ${label}: ${workflow.id}`} maxLength={3000} rows={2} className="input-brand text-sm" value={evidence?.statement || ''} onChange={e => update(workflow.id, { evidence: [...workflow.evidence.filter(item => item.control !== control), ...(e.target.value.trim() ? [{ control, statement: e.target.value, source_type: 'reviewer_clarification', source_ref: workflow.id, confidence: 'High', runtime_verified: false }] : [])] })} /></label>
        </div>;
      })}</div>
    </div>)}
  </section>;
}
