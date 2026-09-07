import React from 'react';
import { clsx } from 'clsx';

import { aiLensTone, severityTheme } from './theme';

/** A severity, spelled the same way everywhere it appears. */
export const SeverityBadge = ({ severity }) => {
    const theme = severityTheme[severity] || severityTheme.Low;
    return (
        <span className={clsx('inline-flex items-center rounded-full border px-2 py-1 text-[11px] font-bold uppercase tracking-normal', theme.badge)}>
            {severity}
        </span>
    );
};

/**
 * What a section shows when it has nothing to show.
 *
 * An empty section has to say why it is empty. "No findings" and "no findings
 * matching your filter" mean very different things to someone reviewing a
 * design, and a blank panel says neither.
 */
export const EmptyInsight = ({ icon, title, description }) => (
    <div className="rounded-lg border border-dashed border-brand-300 bg-brand-50 px-5 py-8 text-center dark:border-brand-700 dark:bg-brand-900/35">
        <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg bg-white text-brand-600 dark:bg-brand-800 dark:text-brand-300">
            {React.createElement(icon, { className: 'h-5 w-5' })}
        </div>
        <h4 className="text-base font-semibold text-brand-900 dark:text-white">{title}</h4>
        <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{description}</p>
    </div>
);

/**
 * Supporting material, folded away until asked for.
 *
 * The dashboard answers three questions on sight: how bad is it, what should be
 * fixed first, and what was found. Coverage tables, matrices and assumptions are
 * how those answers were reached, which matters when a reader challenges a
 * finding and is noise the rest of the time. Native details/summary is used so
 * the content stays in the page for browser search and for printing.
 */
export const DetailSection = ({ title, summary, children, defaultOpen = false }) => (
    <details open={defaultOpen} className="group rounded-md border border-slate-200 bg-white shadow-sm dark:border-brand-700 dark:bg-brand-800">
        <summary className="flex cursor-pointer items-center justify-between gap-4 px-6 py-4 text-left marker:content-none">
            <div>
                <h3 className="text-base font-semibold text-brand-950 dark:text-white">{title}</h3>
                {summary && <p className="mt-1 text-sm text-brand-500 dark:text-brand-400">{summary}</p>}
            </div>
            <span className="shrink-0 text-xs font-semibold uppercase tracking-wide text-brand-500 group-open:hidden dark:text-brand-400">Show</span>
            <span className="hidden shrink-0 text-xs font-semibold uppercase tracking-wide text-brand-500 group-open:inline dark:text-brand-400">Hide</span>
        </summary>
        <div className="border-t border-slate-200 px-6 py-5 dark:border-brand-700">{children}</div>
    </details>
);

export const MetricCard = ({ label, value, tone = 'default', detail }) => {
    const toneMap = {
        default: 'bg-white border-slate-200 dark:bg-brand-900/45 dark:border-brand-700',
        danger: 'bg-white border-red-300 dark:bg-red-950/20 dark:border-red-900/60',
        warning: 'bg-white border-amber-300 dark:bg-amber-950/20 dark:border-amber-900/60',
        success: 'bg-white border-emerald-300 dark:bg-emerald-950/20 dark:border-emerald-900/60',
        accent: 'bg-white border-sky-300 dark:bg-sky-950/20 dark:border-sky-900/60',
    };

    return (
        <div className={clsx('rounded-lg border border-brand-200 p-5 dark:border-brand-700', toneMap[tone] || toneMap.default)}>
            <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">{label}</p>
            <div className="mt-3 flex items-end justify-between gap-3">
                <div className="text-3xl font-black tracking-tight text-brand-950 dark:text-white">{value}</div>
                {detail && <div className="max-w-[8rem] text-right text-xs leading-5 text-brand-500 dark:text-brand-400">{detail}</div>}
            </div>
        </div>
    );
};

export const AISecurityLensCard = ({ item }) => (
    <div className={clsx('rounded-lg border p-4', aiLensTone[item.level] || aiLensTone.low)}>
        <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
                <p className="text-base font-semibold leading-6">{item.label}</p>
                <p className="mt-2 text-2xl font-bold tracking-tight">{item.count}</p>
            </div>
            <span className="shrink-0 rounded-full bg-white/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide text-current dark:bg-black/10">
                {item.level}
            </span>
        </div>
        <p className="mt-3 text-sm leading-6 opacity-90">{item.summary}</p>
    </div>
);

export const PriorityActionCard = ({ action, index }) => (
    <div className="rounded-lg border border-brand-200 bg-brand-50 p-5 dark:border-brand-700 dark:bg-brand-900/35">
        <div className="flex flex-col items-start gap-3 sm:flex-row sm:justify-between">
            <div className="flex min-w-0 items-start gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-brand-primary text-sm font-bold text-white">
                    {index + 1}
                </div>
                <div className="min-w-0">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Fix first</p>
                    <h4 className="mt-1 break-words text-base font-bold text-brand-950 dark:text-white">{action.title}</h4>
                </div>
            </div>
            <SeverityBadge severity={action.priority} />
        </div>
        <p className="mt-4 text-sm leading-6 text-brand-700 dark:text-brand-300">{action.why_now}</p>
        <div className="mt-4 rounded-lg border border-brand-200 bg-white px-4 py-3 text-sm font-medium leading-6 text-brand-800 dark:border-brand-700 dark:bg-brand-800/60 dark:text-brand-200">
            {action.action}
        </div>
        {action.focus_area?.length > 0 && (
            <p className="mt-3 text-xs leading-5 text-brand-500 dark:text-brand-400">
                Focus area: {action.focus_area.join(', ')}
            </p>
        )}
    </div>
);
