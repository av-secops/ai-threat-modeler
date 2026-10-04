/**
 * Shared vocabulary for the dashboard's sections.
 *
 * Severity and review state are rendered in several places, and the report is
 * read by people deciding what to fix, so a finding has to look the same
 * wherever it appears. Keeping the classes here rather than inline is what
 * makes that true by construction instead of by review.
 */

export const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };

export const severityTheme = {
    Critical: {
        badge: 'bg-red-50 text-red-700 border-red-400 dark:bg-red-900/30 dark:text-red-300',
        accent: 'from-red-500 to-rose-500',
        border: 'border-red-200 dark:border-red-900/50',
        surface: 'bg-red-50/80 dark:bg-red-950/20',
        label: 'Critical exposure',
    },
    High: {
        badge: 'bg-orange-50 text-orange-700 border-orange-400 dark:bg-orange-900/30 dark:text-orange-300',
        accent: 'from-orange-500 to-amber-500',
        border: 'border-orange-200 dark:border-orange-900/50',
        surface: 'bg-orange-50/80 dark:bg-orange-950/20',
        label: 'High priority',
    },
    Medium: {
        badge: 'bg-yellow-50 text-yellow-700 border-yellow-400 dark:bg-yellow-900/30 dark:text-yellow-300',
        accent: 'from-yellow-400 to-amber-400',
        border: 'border-yellow-200 dark:border-yellow-900/50',
        surface: 'bg-yellow-50/80 dark:bg-yellow-950/20',
        label: 'Needs planning',
    },
    Low: {
        badge: 'bg-sky-50 text-sky-700 border-sky-400 dark:bg-sky-900/30 dark:text-sky-300',
        accent: 'from-sky-400 to-cyan-400',
        border: 'border-sky-200 dark:border-sky-900/50',
        surface: 'bg-sky-50/80 dark:bg-sky-950/20',
        label: 'Monitor',
    },
};

export const reviewStateMeta = {
    pending_review: { label: 'Pending Review', className: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200' },
    in_review: { label: 'In Review', className: 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200' },
    action_required: { label: 'Action Required', className: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200' },
    mitigation_proposed: { label: 'Mitigation Proposed', className: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200' },
    verified_fixed: { label: 'Verified Fixed', className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200' },
    open: {
        label: 'Open',
        className: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    },
    mitigated: {
        label: 'Mitigated',
        className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
    },
    accepted: {
        label: 'Accepted',
        className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    },
    false_positive: {
        label: 'False Positive',
        className: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    },
};

export const insightCardBase = 'rounded-md border border-slate-200 bg-white shadow-sm dark:border-brand-700 dark:bg-brand-800';

export const aiLensTone = {
    high: 'border-red-200 bg-red-50/80 text-red-900 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-200',
    medium: 'border-amber-200 bg-amber-50/80 text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/20 dark:text-amber-200',
    low: 'border-emerald-200 bg-emerald-50/80 text-emerald-900 dark:border-emerald-900/40 dark:bg-emerald-950/20 dark:text-emerald-200',
};

/** The components a finding applies to, however the engine happened to scope it. */
export const affectedComponents = (threat) => {
    const components = threat.explanation?.impacted_components?.length
        ? threat.explanation.impacted_components
        : threat.affected_components?.length
            ? threat.affected_components
            : [threat.affected_component || threat.component].filter(Boolean);
    return components.length ? components.join(', ') : 'Not specified';
};
