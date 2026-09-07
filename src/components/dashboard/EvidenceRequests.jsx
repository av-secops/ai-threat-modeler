import { useState } from 'react';
import { ClipboardList, ChevronDown, ChevronRight, CheckCircle2 } from 'lucide-react';
import clsx from 'clsx';

const priorityStyles = {
    Critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    High: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    Medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    Low: 'bg-brand-100 text-brand-700 dark:bg-brand-800 dark:text-brand-300',
};

const exposureLabels = {
    internet_reachable: 'internet reachable',
    crosses_trust_boundary: 'crosses a trust boundary',
    holds_sensitive_data: 'holds sensitive data',
    internal: 'internal',
    unknown: 'exposure unknown',
};

/**
 * The questions to take back to the architecture owner.
 *
 * Most STRIDE cells resolve to "the design does not say". Grouped by the control
 * they wait on, a hundred unresolved cells become a handful of questions, and
 * answering one resolves many.
 */
export default function EvidenceRequests({ evidenceRequests, cardClassName, onClarify }) {
    const [expanded, setExpanded] = useState(() => new Set());

    const requests = evidenceRequests?.requests || [];
    if (!requests.length) return null;

    const toggle = (id) => {
        setExpanded((current) => {
            const next = new Set(current);
            if (next.has(id)) next.delete(id); else next.add(id);
            return next;
        });
    };

    return (
        <div className={clsx(cardClassName, 'p-6')}>
            <div className="flex items-center gap-2">
                <ClipboardList className="h-5 w-5 text-brand-primary" />
                <h3 className="text-lg font-bold text-brand-950 dark:text-white">Evidence requests</h3>
                {onClarify && <button type="button" className="ui-button-secondary ml-auto" onClick={onClarify}><CheckCircle2 size={16} />Answer questions</button>}
            </div>
            <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">
                {evidenceRequests.summary}
            </p>

            <div className="mt-4 space-y-3">
                {requests.map((request) => {
                    const isOpen = expanded.has(request.id);
                    return (
                        <div
                            key={request.id}
                            className="rounded-lg border border-brand-200 bg-brand-50 dark:border-brand-700 dark:bg-brand-900/35"
                        >
                            <button
                                type="button"
                                onClick={() => toggle(request.id)}
                                aria-expanded={isOpen}
                                className="flex w-full items-start gap-3 p-4 text-left"
                            >
                                {isOpen
                                    ? <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-brand-500" />
                                    : <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-brand-500" />}
                                <div className="min-w-0 flex-1">
                                    <div className="flex flex-wrap items-center gap-2">
                                        <span className={clsx(
                                            'rounded-full px-2 py-1 text-[10px] font-bold uppercase',
                                            priorityStyles[request.priority] || priorityStyles.Low,
                                        )}>
                                            {request.priority}
                                        </span>
                                        <span className="text-sm font-semibold text-brand-950 dark:text-white">
                                            {request.title}
                                        </span>
                                        <span className="text-xs text-brand-500 dark:text-brand-400">
                                            resolves {request.resolves_cells} STRIDE cell{request.resolves_cells === 1 ? '' : 's'}
                                            {' '}across {request.elements.length} element{request.elements.length === 1 ? '' : 's'}
                                        </span>
                                    </div>
                                    <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                        {request.question}
                                    </p>
                                </div>
                            </button>

                            {isOpen && (
                                <div className="border-t border-brand-200 px-4 py-4 dark:border-brand-700">
                                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">
                                        Waiting on an answer
                                    </p>
                                    <ul className="mt-2 space-y-1">
                                        {request.elements.map((element) => (
                                            <li key={element.id} className="text-sm text-brand-700 dark:text-brand-300">
                                                <span className="font-medium">{element.label}</span>
                                                <span className="text-brand-500 dark:text-brand-400">
                                                    {' '}&middot; {exposureLabels[element.exposure] || element.exposure}
                                                    {' '}&middot; {element.stride_categories.join(', ')}
                                                </span>
                                            </li>
                                        ))}
                                    </ul>

                                    <p className="mt-4 text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">
                                        Evidence that would close this
                                    </p>
                                    <ul className="mt-2 space-y-1">
                                        {request.accepted_evidence.map((item) => (
                                            <li key={item} className="flex gap-2 text-sm text-brand-700 dark:text-brand-300">
                                                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-brand-primary" />
                                                <span>{item}</span>
                                            </li>
                                        ))}
                                    </ul>

                                    <p className="mt-4 text-sm leading-6 text-brand-600 dark:text-brand-400">
                                        {request.why_it_matters}
                                    </p>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
