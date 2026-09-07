import { ArrowRight, CircleHelp, Eye } from 'lucide-react';
import { SeverityBadge } from './InsightCards';
import { affectedComponents } from './theme';

export default function ReportOverview({ threats, reviewStates, onSelect, onOpenRegister, onOpenAssurance, evidenceRequests }) {
    const actionable = threats.filter((threat) => threat.finding_type !== 'validation_question' && !['false_positive', 'mitigated', 'accepted'].includes(reviewStates[threat.id]));
    const requests = (evidenceRequests?.requests || []).slice(0, 3);
    return <div className="grid gap-8 py-6 lg:grid-cols-[minmax(0,1.8fr)_minmax(240px,1fr)]">
        <section className="min-w-0">
            <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="text-lg font-semibold text-brand-950 dark:text-white">Priority findings</h2>
                <button onClick={onOpenRegister} className="flex items-center gap-2 text-sm font-medium text-brand-primary dark:text-indigo-300">View all<ArrowRight className="h-4 w-4" /></button>
            </div>
            <div className="divide-y divide-brand-200 border-y border-brand-200 dark:divide-brand-700 dark:border-brand-700">
                {actionable.slice(0, 5).map((threat) => <button key={threat.id} onClick={() => onSelect(threat)}
                    className="group flex w-full items-start gap-3 px-1 py-4 text-left transition-colors hover:bg-brand-50 dark:hover:bg-brand-800">
                    <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={threat.severity} /><span className="text-xs text-brand-500 dark:text-brand-300">{threat.explanation?.evidence_basis === 'user_declared' ? 'User-declared' : threat.tier}</span></span>
                        <span className="mt-2 block break-words text-sm font-semibold text-brand-950 dark:text-white">{threat.title}</span>
                        <span className="mt-1 block break-words text-xs text-brand-600 dark:text-brand-300">{affectedComponents(threat)}</span>
                    </span><Eye className="mt-1 h-4 w-4 shrink-0 text-brand-500 group-hover:text-brand-primary" />
                </button>)}
                {!actionable.length && <p className="py-6 text-sm text-brand-600 dark:text-brand-300">No unreviewed findings in this view.</p>}
            </div>
        </section>
        <section className="min-w-0">
            <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-brand-950 dark:text-white"><CircleHelp className="h-4 w-4 text-amber-600" />Evidence needed</h2>
            <div className="divide-y divide-brand-200 border-y border-brand-200 dark:divide-brand-700 dark:border-brand-700">
                {requests.map((request, index) => <button key={request.id || index} onClick={onOpenAssurance} className="w-full py-4 text-left hover:bg-brand-50 dark:hover:bg-brand-800">
                    <span className="block text-sm font-medium text-brand-900 dark:text-brand-100">{request.title}</span>
                    <span className="mt-1 block text-xs text-brand-500 dark:text-brand-300">{request.resolves_cells || 0} unresolved assessments</span>
                </button>)}
                {!requests.length && <p className="py-6 text-sm text-brand-600 dark:text-brand-300">No grouped evidence requests.</p>}
            </div>
            <button onClick={onOpenAssurance} className="mt-4 flex items-center gap-2 text-sm font-medium text-brand-primary dark:text-indigo-300">Review assurance<ArrowRight className="h-4 w-4" /></button>
        </section>
    </div>;
}
