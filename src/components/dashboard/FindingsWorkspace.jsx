import { useMemo, useState } from 'react';
import { ArrowDownWideNarrow, ChevronLeft, ChevronRight, RotateCcw, Search } from 'lucide-react';
import { ThreatSection } from './RiskRegister';
import { affectedComponents, reviewStateMeta, severityOrder } from './theme';

const groups = [
    ['all', 'All findings'], ['evidenced', 'Evidenced'],
    ['potential', 'Potential'], ['questions', 'Questions'],
];
const kindOf = (threat) => threat.finding_type === 'validation_question' ? 'questions' : threat.tier === 'Confirmed' ? 'evidenced' : 'potential';

export default function FindingsWorkspace({ threats, filters, onFiltersChange, reviewStates, onSelectThreat }) {
    const [sortBy, setSortBy] = useState('severity');
    const [page, setPage] = useState(0);
    const [review, setReview] = useState('all');
    const [group, setGroup] = useState('all');
    const filtered = useMemo(() => threats.filter((threat) => {
        const categories = threat.affected_stride_categories?.length ? threat.affected_stride_categories : [threat.stride_category || threat.category];
        const haystack = `${threat.title} ${threat.description} ${affectedComponents(threat)} ${(threat.cwe || []).join(' ')} ${threat.id}`.toLowerCase();
        return (!filters.search || haystack.includes(filters.search.toLowerCase()))
            && (filters.severity === 'all' || threat.severity === filters.severity)
            && (filters.category === 'all' || categories.includes(filters.category))
            && (filters.tier === 'all' || threat.tier === filters.tier)
            && (!filters.impact || threat.impact === filters.impact)
            && (!filters.likelihood || threat.likelihood === filters.likelihood)
            && (group === 'all' || kindOf(threat) === group)
            && (review === 'all' || (reviewStates[threat.id] || 'open') === review);
    }).sort((a, b) => sortBy === 'name' ? a.title.localeCompare(b.title)
        : sortBy === 'component' ? affectedComponents(a).localeCompare(affectedComponents(b))
            : (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0) || (b.risk_score || 0) - (a.risk_score || 0)),
    [threats, filters, group, review, reviewStates, sortBy]);
    const pages = Math.max(1, Math.ceil(filtered.length / 25));
    const currentPage = Math.min(page, pages - 1);
    const update = (key, value) => { setPage(0); onFiltersChange({ ...filters, [key]: value }); };
    const clear = () => {
        onFiltersChange({ severity: 'all', category: 'all', tier: 'all', search: '' });
        setReview('all'); setGroup('all'); setPage(0);
    };
    const categories = [...new Set(threats.flatMap((threat) => threat.affected_stride_categories?.length ? threat.affected_stride_categories : [threat.stride_category || threat.category]))].filter(Boolean).sort();
    return <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-1 border-b border-brand-200 dark:border-brand-700" aria-label="Finding evidence filters">
            {groups.map(([id, label]) => <button key={id} type="button" aria-pressed={group === id}
                onClick={() => { setGroup(id); setPage(0); }}
                className={`flex min-h-11 items-center gap-2 border-b-2 px-3 text-sm font-medium ${group === id ? 'border-brand-primary text-brand-primary dark:text-indigo-300' : 'border-transparent text-brand-600 dark:text-brand-300'}`}>
                {label}<span className="text-xs tabular-nums">{id === 'all' ? threats.length : threats.filter((threat) => kindOf(threat) === id).length}</span>
            </button>)}
        </div>
        <div className="grid items-end gap-3 sm:grid-cols-2 lg:grid-cols-[minmax(200px,2fr)_1fr_1.4fr_1fr_auto]">
            <label className="text-xs font-medium text-brand-600 dark:text-brand-300">Search
                <span className="relative mt-1 block"><Search className="pointer-events-none absolute left-3 top-3 h-4 w-4" />
                    <input aria-label="Search findings" className="input-brand w-full pl-9 text-sm" placeholder="Risk, component, CWE..." value={filters.search} onChange={(event) => update('search', event.target.value)} />
                </span>
            </label>
            <label className="text-xs font-medium text-brand-600 dark:text-brand-300">Severity
                <select className="input-brand mt-1 w-full text-sm" value={filters.severity} onChange={(event) => update('severity', event.target.value)}>
                    <option value="all">All severities</option>{Object.keys(severityOrder).map((value) => <option key={value}>{value}</option>)}
                </select>
            </label>
            <label className="text-xs font-medium text-brand-600 dark:text-brand-300">STRIDE
                <select className="input-brand mt-1 w-full text-sm" value={filters.category} onChange={(event) => update('category', event.target.value)}>
                    <option value="all">All categories</option>{categories.map((value) => <option key={value}>{value}</option>)}
                </select>
            </label>
            <label className="text-xs font-medium text-brand-600 dark:text-brand-300">Review status
                <select className="input-brand mt-1 w-full text-sm" value={review} onChange={(event) => { setReview(event.target.value); setPage(0); }}>
                    <option value="all">All statuses</option>{Object.entries(reviewStateMeta).map(([value, meta]) => <option value={value} key={value}>{meta.label}</option>)}
                </select>
            </label>
            <button type="button" className="ui-button-secondary h-10 justify-center" title="Reset filters" aria-label="Reset finding filters" onClick={clear}><RotateCcw className="h-4 w-4" /></button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-brand-600 dark:text-brand-300">
            <span role="status" aria-live="polite">{filtered.length} of {threats.length} findings{filters.impact && ` / ${filters.impact} impact, ${filters.likelihood} likelihood`}</span>
            <label className="flex items-center gap-2"><ArrowDownWideNarrow className="h-4 w-4" /><span className="sr-only">Sort findings</span>
                <select aria-label="Sort findings" className="input-brand text-sm" value={sortBy} onChange={(event) => { setSortBy(event.target.value); setPage(0); }}>
                    <option value="severity">Severity</option><option value="name">Risk name</option><option value="component">Component</option>
                </select>
            </label>
        </div>
        <ThreatSection threats={filtered.slice(currentPage * 25, (currentPage + 1) * 25)} onSelectThreat={onSelectThreat} compact />
        <div className="flex items-center justify-end gap-3 text-sm text-brand-600 dark:text-brand-300">
            <span>Page {currentPage + 1} of {pages}</span>
            <button className="ui-button-secondary disabled:opacity-40" aria-label="Previous findings page" title="Previous page" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}><ChevronLeft className="h-4 w-4" /></button>
            <button className="ui-button-secondary disabled:opacity-40" aria-label="Next findings page" title="Next page" disabled={currentPage + 1 >= pages} onClick={() => setPage(currentPage + 1)}><ChevronRight className="h-4 w-4" /></button>
        </div>
    </div>;
}
