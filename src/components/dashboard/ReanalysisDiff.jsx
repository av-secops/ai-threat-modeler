import React from 'react';
import { ArrowRight, Minus, Plus } from 'lucide-react';

/**
 * What changed between this analysis and the previous one.
 *
 * The counts alone cannot answer the question a reviewer actually has after
 * amending a model, which is whether the thing they added made any difference.
 * "+1 component" does not say that adding the audit archive surfaced an
 * unmonitored write path, and the finding that appeared is the answer.
 */

const severityTone = {
  Critical: 'text-brand-danger',
  High: 'text-brand-danger',
  Medium: 'text-brand-warning',
  Low: 'text-brand-500',
};

function FindingLine({ finding, tone }) {
  const Icon = tone === 'added' ? Plus : Minus;
  return (
    <li className="flex items-start gap-2 py-1">
      <Icon
        className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${
          tone === 'added' ? 'text-brand-danger' : 'text-brand-success'
        }`}
      />
      <span className="min-w-0 text-sm leading-5 text-brand-700 dark:text-brand-300">
        {finding.title}
        {finding.reason && <span className="mt-1 block text-xs text-brand-500 dark:text-brand-400">{finding.reason}</span>}
        <span className={`ml-2 text-xs font-semibold ${severityTone[finding.severity] || 'text-brand-500'}`}>
          {finding.severity}
        </span>
      </span>
    </li>
  );
}

export default function ReanalysisDiff({ diff }) {
  if (!diff) {
    return (
      <p className="mt-3 text-sm leading-6 text-brand-600 dark:text-brand-400">
        Run this project again after a design change to see what moved.
      </p>
    );
  }

  if (!diff.changed) {
    return (
      <p className="mt-3 text-sm leading-6 text-brand-600 dark:text-brand-400">
        Nothing changed compared with the previous analysis of this project.
      </p>
    );
  }

  const added = diff.new_threats || [];
  const resolved = diff.resolved_threats || [];
  const severityChanges = diff.severity_changes || [];
  const addedComponents = diff.added_components || [];
  const removedComponents = diff.removed_components || [];

  return (
    <div className="mt-3 space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
          <p className="text-xs text-brand-500 dark:text-brand-400">Score movement</p>
          <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">
            {diff.score_delta > 0 ? '+' : ''}{diff.score_delta || 0}
          </p>
        </div>
        <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
          <p className="text-xs text-brand-500 dark:text-brand-400">Findings</p>
          <p className="mt-1 text-sm font-semibold text-brand-950 dark:text-white">
            {added.length} appeared, {resolved.length} went away
          </p>
        </div>
      </div>

      {(addedComponents.length > 0 || removedComponents.length > 0) && (
        <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 text-sm dark:border-brand-700 dark:bg-brand-800/60">
          <p className="text-xs text-brand-500 dark:text-brand-400">Model</p>
          <div className="mt-1 space-y-1">
            {addedComponents.length > 0 && (
              <p className="text-brand-700 dark:text-brand-300">
                <span className="font-semibold text-brand-950 dark:text-white">Added:</span>{' '}
                {addedComponents.join(', ')}
              </p>
            )}
            {removedComponents.length > 0 && (
              <p className="text-brand-700 dark:text-brand-300">
                <span className="font-semibold text-brand-950 dark:text-white">No longer present:</span>{' '}
                {removedComponents.join(', ')}
              </p>
            )}
          </div>
        </div>
      )}

      {added.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">
            New findings
          </p>
          <ul className="mt-1">
            {added.map((finding) => (
              <FindingLine key={finding.id} finding={finding} tone="added" />
            ))}
          </ul>
        </div>
      )}

      {resolved.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">
            No longer reported
          </p>
          <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">This is not evidence that a vulnerability was fixed.</p>
          <ul className="mt-1">
            {resolved.map((finding) => (
              <FindingLine key={finding.id} finding={finding} tone="resolved" />
            ))}
          </ul>
        </div>
      )}

      {!!diff.revalidation_required?.length && <p className="border-l-2 border-amber-500 pl-3 text-sm text-amber-800 dark:text-amber-300">{diff.revalidation_required.length} retained findings need review again because their evidence or assessment changed. Previous decisions remain in the earlier revision.</p>}

      {severityChanges.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">
            Re-rated
          </p>
          <ul className="mt-1 space-y-1">
            {severityChanges.map((change) => (
              <li
                key={change.id}
                className="flex flex-wrap items-center gap-2 text-sm text-brand-700 dark:text-brand-300"
              >
                <span className="min-w-0">{change.title}</span>
                <span className="inline-flex items-center gap-1 text-xs font-semibold">
                  <span className={severityTone[change.from_severity] || 'text-brand-500'}>
                    {change.from_severity}
                  </span>
                  <ArrowRight className="h-3 w-3 text-brand-400" />
                  <span className={severityTone[change.to_severity] || 'text-brand-500'}>
                    {change.to_severity}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
