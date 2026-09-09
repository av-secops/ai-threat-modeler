import React, { useEffect, useMemo, useState } from 'react';
import { Download, Layers3, ListTodo, MessageSquareQuote, Users } from 'lucide-react';
import { clsx } from 'clsx';
import { loadAnnotations, orphanedAnnotations, saveAnnotations } from '../utils/annotations';

const domainTone = {
  general: 'bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300',
  saas: 'bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
  fintech: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  healthcare: 'bg-rose-50 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
  ai: 'bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  platform: 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
};

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function AnalystWorkbench({ data, projectName, reviewStates, annotationScope, mode = 'assurance', readOnly = false }) {
  const reviewKey = annotationScope || projectName;
  const [owners, setOwners] = useState(() => loadAnnotations(reviewKey).owners);
  const [notes, setNotes] = useState(() => loadAnnotations(reviewKey).notes);
  const [componentNotes, setComponentNotes] = useState(() => loadAnnotations(reviewKey).componentNotes);

  // Re-analysis replaces the findings but not the review of them, so what the
  // reviewer wrote is reloaded and reattached by finding id. Adjusting during
  // render rather than in an effect keeps one project's notes from being shown
  // against another for a frame, and avoids the save effect below writing them
  // back under the new project name.
  const [loadedProject, setLoadedProject] = useState(reviewKey);
  if (reviewKey !== loadedProject) {
    const stored = loadAnnotations(reviewKey);
    setLoadedProject(reviewKey);
    setOwners(stored.owners);
    setNotes(stored.notes);
    setComponentNotes(stored.componentNotes);
  }

  useEffect(() => {
    if (!readOnly) saveAnnotations(reviewKey, { owners, notes, componentNotes });
  }, [reviewKey, owners, notes, componentNotes, readOnly]);

  const orphans = useMemo(
    () => orphanedAnnotations({ owners, notes }, (data.threats || []).map((threat) => threat.id)),
    [owners, notes, data.threats],
  );

  const actionRows = useMemo(() => {
    return (data.threats || []).slice(0, 8).map((threat) => ({
      id: threat.id,
      title: threat.title,
      severity: threat.severity,
      tier: threat.tier,
      owner: owners[threat.id] || '',
      note: notes[threat.id] || '',
      reviewState: reviewStates[threat.id] || 'open',
    }));
  }, [data.threats, notes, owners, reviewStates]);

  const exportActionRegister = () => {
    const headers = ['ID', 'Title', 'Severity', 'Tier', 'Review State', 'Owner', 'Note'];
    const rows = actionRows.map((row) =>
      [row.id, row.title, row.severity, row.tier, row.reviewState, row.owner, row.note]
        .map((cell) => `"${String(cell || '').replace(/"/g, '""')}"`)
        .join(',')
    );
    downloadBlob(`${projectName.replace(/\s+/g, '_')}_action_register.csv`, [headers.join(','), ...rows].join('\n'), 'text/csv');
  };

  const exportActionBrief = () => {
    const lines = [
      `# ${projectName} Action Register`,
      '',
      `Domain: ${data.domain_context?.label || 'General'}`,
      '',
      ...actionRows.map((row) => [
        `## ${row.title}`,
        `- Severity: ${row.severity}`,
        `- Tier: ${row.tier}`,
        `- Review state: ${row.reviewState}`,
        `- Owner: ${row.owner || 'Unassigned'}`,
        `- Note: ${row.note || 'No note yet'}`,
        '',
      ].join('\n')),
    ];
    downloadBlob(`${projectName.replace(/\s+/g, '_')}_action_register.md`, lines.join('\n'), 'text/markdown');
  };

  if (mode === 'architecture') {
    return (
      <section className="mt-6">
        <div className="border-y border-brand-200 py-5 dark:border-brand-700">
          <div className="flex items-center gap-2">
            <Layers3 className="h-5 w-5 text-brand-primary" />
            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture workbench</h3>
          </div>
          <div className="mt-4 divide-y divide-brand-200 dark:divide-brand-700">
            {(data.architecture?.components || []).map((component) => (
              <details key={component.id} className="py-3">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-brand-950 dark:text-white">{component.name}</p>
                    <p className="text-xs text-brand-500 dark:text-brand-400">{component.type}</p>
                  </div>
                  <span className={clsx('rounded-full px-2.5 py-1 text-[10px] font-semibold', domainTone[data.domain_context?.profile || 'general'])}>
                    {component.trust_level || component.properties?.trust_boundary || 'unknown'}
                  </span>
                </summary>
                <textarea
                  aria-label={`Validation note for ${component.name}`}
                  readOnly={readOnly}
                  value={componentNotes[component.id] || ''}
                  onChange={(e) => setComponentNotes((prev) => ({ ...prev, [component.id]: e.target.value }))}
                  placeholder="Validation note for this component..."
                  className="input-brand mt-3 h-20 w-full resize-none text-sm"
                />
              </details>
            ))}
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="mt-8 grid min-w-0 grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="min-w-0 border-y border-brand-200 py-5 dark:border-brand-700">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <MessageSquareQuote className="h-5 w-5 text-brand-primary" />
              <h3 className="text-lg font-bold text-brand-950 dark:text-white">Domain lens</h3>
            </div>
            <span className={clsx('rounded-full px-3 py-1 text-xs font-semibold', domainTone[data.domain_context?.profile || 'general'])}>
              {data.domain_context?.label || 'General'}
            </span>
          </div>
          <p className="mt-3 text-sm leading-7 text-brand-700 dark:text-brand-300">
            {data.domain_context?.headline || 'No domain-specific context was attached to this run.'}
          </p>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="ui-subpanel">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Priority controls</p>
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-300">
                {(data.domain_context?.priority_controls || []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div className="ui-subpanel">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">High-risk areas</p>
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-300">
                {(data.domain_context?.high_risk_areas || []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
        <div className="min-w-0 border-y border-brand-200 py-5 dark:border-brand-700">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ListTodo className="h-5 w-5 text-brand-primary" />
              <h3 className="text-lg font-bold text-brand-950 dark:text-white">Action register</h3>
            </div>
            <div className="flex gap-2">
              <button onClick={exportActionRegister} className="ui-button-secondary px-3 py-2 text-xs">
                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> CSV</span>
              </button>
              <button onClick={exportActionBrief} className="ui-button-secondary px-3 py-2 text-xs">
                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> Brief</span>
              </button>
            </div>
          </div>
          {orphans.length > 0 && (
            <p className="mt-3 rounded-lg border border-brand-warning/40 bg-brand-warning/10 px-3 py-2 text-xs leading-5 text-brand-700 dark:text-brand-300">
              {orphans.length} note{orphans.length === 1 ? '' : 's'} you wrote
              {orphans.length === 1 ? ' is' : ' are'} attached to findings this run no longer
              reports. The notes are kept, and will reattach if the finding returns.
            </p>
          )}
          <div className="mt-4 space-y-3">
            {actionRows.map((row) => (
              <div key={row.id} className="ui-subpanel">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-brand-950 dark:text-white">{row.title}</p>
                    <p className="text-xs text-brand-500 dark:text-brand-400">{row.severity} · {row.tier} · {row.reviewState}</p>
                  </div>
                  <Users className="h-4 w-4 text-brand-400" />
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-[0.7fr_1.3fr]">
                  <input
                    value={owners[row.id] || ''}
                    onChange={(e) => setOwners((prev) => ({ ...prev, [row.id]: e.target.value }))}
                    readOnly={readOnly}
                    placeholder="Owner"
                    className="input-brand text-sm"
                  />
                  <input
                    value={notes[row.id] || ''}
                    onChange={(e) => setNotes((prev) => ({ ...prev, [row.id]: e.target.value }))}
                    readOnly={readOnly}
                    placeholder="Action note or next step"
                    className="input-brand text-sm"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
    </section>
  );
}
