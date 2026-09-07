import { useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { ArrowUpRight, Eye, ShieldCheck, X } from 'lucide-react';

import { EmptyInsight, SeverityBadge } from './InsightCards';
import { affectedComponents, insightCardBase, reviewStateMeta, severityTheme } from './theme';

const noFlowReason = {
    no_flows_modeled: 'No data flows are modeled for this architecture, so no path was assessed.',
    component_isolated: 'The architecture models no flow reaching this component.',
};

/**
 * Which data flows this finding relates to, or why none are shown.
 *
 * A blank flow list has two very different meanings: the finding is local to a
 * component, or the architecture never described any path at all. The second is
 * a gap in the model the analyst needs to close, so it is named rather than
 * shown as an absence of impact.
 */
const FlowContext = ({ threat }) => {
    const scoped = threat.affected_data_flows || [];
    const related = threat.explanation?.component_flows || [];
    const heading = scoped.length ? 'Data flows' : related.length ? 'Flows touching this component' : 'Data flows';

    return (
        <div>
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">{heading}</p>
            {scoped.length > 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">{scoped.join(', ')}</p>
            )}
            {scoped.length === 0 && related.length > 0 && (
                <ul className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {related.map((flow) => (
                        <li key={`${flow.reference}-${flow.direction}`} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{flow.label}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {flow.direction}
                                {flow.protocol ? ` · ${flow.protocol}` : ''}
                                {flow.crosses_trust_boundary ? ' · crosses a trust boundary' : ''}
                                {flow.assumed ? ' · assumed' : ''}
                            </span>
                        </li>
                    ))}
                </ul>
            )}
            {scoped.length === 0 && related.length === 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {noFlowReason[threat.explanation?.flow_context] || 'No flow-specific impact noted'}
                </p>
            )}
        </div>
    );
};

/**
 * Which document, page and line each piece of evidence came from.
 *
 * With several uploads the first question an analyst asks about a finding is
 * which file said so, because that decides who they go and talk to. A finding
 * resting only on inference says that instead of naming a document.
 */
const EvidenceSources = ({ threat }) => {
    const cited = [];
    const seen = new Set();
    let inferred = 0;

    for (const detail of threat.evidence_details || []) {
        if (!detail?.cite) {
            if (detail?.source_type === 'inference') inferred += 1;
            continue;
        }
        if (seen.has(detail.cite)) continue;
        seen.add(detail.cite);
        cited.push(detail);
    }

    if (cited.length === 0 && inferred === 0) return null;

    return (
        <div className="mt-3">
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Cited in</p>
            {cited.length > 0 ? (
                <ul className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {cited.map((detail) => (
                        <li key={detail.cite} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{detail.document}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {[detail.locator, detail.line ? `line ${detail.line}` : null]
                                    .filter(Boolean)
                                    .join(' · ')}
                            </span>
                        </li>
                    ))}
                </ul>
            ) : (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    Inferred from architecture context; no document states this directly.
                </p>
            )}
        </div>
    );
};

const pathStatusNote = {
    partially_inferred: 'Some hops on this route were assumed rather than described.',
    unresolved_entry_path: 'No route from a modeled entry point reaches this component.',
    unmapped: 'This finding is not tied to a component in the architecture graph.',
};

/**
 * How an attacker gets here, and what it opens up once they do.
 *
 * A finding on its own says a component is weak. The route says whether anyone
 * outside can reach it, and the onward reach says whether reaching it matters,
 * which is the difference between a bug and an incident.
 */
const AttackRoute = ({ threat }) => {
    const path = threat.attack_path;
    if (!path) return null;

    const hops = path.hops || [];
    const reached = path.sensitive_data_reached || [];

    return (
        <div>
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Route in</p>
            {hops.length > 0 ? (
                <ol className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    <li className="text-xs text-brand-500 dark:text-brand-400">Starts at {path.entry_point}</li>
                    {hops.map((hop, index) => (
                        <li key={`${hop.source}-${hop.target}-${index}`} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{hop.source} → {hop.target}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {hop.protocol}
                                {hop.evidence_status === 'inferred' ? ' · assumed' : ''}
                            </span>
                        </li>
                    ))}
                </ol>
            ) : (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {pathStatusNote[path.path_status] || `Reached directly at ${path.entry_point}.`}
                </p>
            )}
            {reached.length > 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    Onward reach: sensitive data held by {reached.join(', ')}.
                </p>
            )}
        </div>
    );
};

/**
 * One finding in full: why it was raised, what it touches, and what to do.
 *
 * The narrative and the evidence sit beside each other deliberately. A finding
 * an analyst cannot trace back to a line of the design is one they will not
 * act on, so the report never states a conclusion without showing its basis.
 */
export const ThreatCard = ({ threat, reviewState = 'open', onReviewStateChange }) => {
    const theme = severityTheme[threat.severity] || severityTheme.Low;
    const evidencePreview = threat.explanation?.evidence_summary?.length
        ? threat.explanation.evidence_summary
        : (threat.evidence || []).slice(0, 2);

    return (
        <article className={clsx('relative overflow-hidden rounded-lg border bg-white p-6 shadow-sm transition-colors dark:bg-brand-800', theme.border)}>
            <div className={clsx('absolute inset-x-0 top-0 h-1', theme.accent.replace('from-', 'bg-').split(' ')[0])} />

            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="max-w-3xl">
                    <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={threat.severity} />
                        <span className={clsx(
                            'inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.14em]',
                            threat.tier === 'Confirmed'
                                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                                : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        )}>
                            {threat.tier}
                        </span>
                        <span className="text-xs font-medium text-brand-500 dark:text-brand-400">Confidence {threat.confidence}</span>
                        <span className="rounded-full bg-brand-100 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-brand-700 dark:bg-brand-700 dark:text-brand-200">{(threat.finding_type || 'architecture').replaceAll('_', ' ')}</span>
                        <span className={clsx('rounded-full px-2.5 py-1 text-[11px] font-semibold', reviewStateMeta[reviewState]?.className || reviewStateMeta.open.className)}>
                            {reviewStateMeta[reviewState]?.label || 'Open'}
                        </span>
                    </div>

                    <h4 className="mt-4 text-xl font-bold tracking-tight text-brand-950 dark:text-white">{threat.title}</h4>
                    <p className="mt-2 text-sm font-medium text-brand-500 dark:text-brand-400">
                        {threat.category}
                        {threat.stride_category && threat.stride_category !== threat.category && ` -> ${threat.stride_category}`}
                    </p>
                    <p className="mt-4 max-w-3xl text-[15px] leading-7 text-brand-700 dark:text-brand-300">{threat.description}</p>
                </div>

                <div className={clsx('min-w-[220px] rounded-lg border p-4', theme.surface, theme.border)}>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-brand-500 dark:text-brand-400">Narrative</p>
                    <p className="mt-3 text-sm leading-6 text-brand-700 dark:text-brand-300">
                        {threat.explanation?.why_flagged || 'This finding was raised from the current architecture signals and rule matches.'}
                    </p>
                    {threat.explanation?.remediation_priority && (
                        <div className="mt-4 flex items-center gap-2 text-sm font-semibold text-brand-900 dark:text-white">
                            <ArrowUpRight className="h-4 w-4 text-brand-primary" />
                            {threat.explanation.remediation_priority}
                        </div>
                    )}
                </div>
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-[1.3fr_0.9fr]">
                <div className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Signals</p>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                        <div>
                            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Evidence highlights</p>
                            {evidencePreview.length > 0 ? (
                                <ul className="mt-2 space-y-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {evidencePreview.map((ev, i) => (
                                        <li key={i} className="rounded-lg border border-brand-200 bg-white px-3 py-2 dark:border-brand-700 dark:bg-brand-800/60">{ev}</li>
                                    ))}
                                </ul>
                            ) : (
                                <p className="mt-2 text-sm text-brand-500 dark:text-brand-400">No explicit evidence captured for this finding.</p>
                            )}
                            <EvidenceSources threat={threat} />
                        </div>
                        <div className="space-y-3">
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Impacted components</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {threat.explanation?.impacted_components?.length
                                        ? threat.explanation.impacted_components.join(', ')
                                        : threat.affected_components?.join(', ') || 'Not specified'}
                                </p>
                            </div>
                            <FlowContext threat={threat} />
                            <AttackRoute threat={threat} />
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Risk inputs</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    Exposure {threat.risk_factors?.exposure || threat.exposure || 'unspecified'}; evidence {threat.risk_factors?.evidence_confidence || threat.confidence}
                                    {typeof threat.risk_factors?.blast_radius === 'number' && (
                                        <>; reaches {threat.risk_factors.blast_radius} component{threat.risk_factors.blast_radius === 1 ? '' : 's'}</>
                                    )}
                                    {threat.risk_factors?.crosses_trust_boundary && <>; sits on a trust boundary</>}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/20">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-600 dark:text-emerald-400">Recommended next move</p>
                    <p className="mt-3 text-sm leading-6 text-emerald-900 dark:text-emerald-300">{threat.mitigation}</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                            <button
                                key={state}
                                onClick={() => onReviewStateChange?.(threat.id, state)}
                                className={clsx(
                                    'rounded-full px-3 py-1.5 text-[11px] font-semibold transition-colors',
                                    reviewState === state
                                        ? meta.className
                                        : 'bg-white text-brand-600 hover:bg-brand-100 dark:bg-brand-800 dark:text-brand-300 dark:hover:bg-brand-700'
                                )}
                            >
                                {meta.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>
        </article>
    );
};

/** Every finding at a glance, ordered by severity and risk score. */
export const ThreatSection = ({ threats, onSelectThreat, compact = false }) => (
    <section className={clsx(insightCardBase, 'overflow-hidden')}>
        {!compact && <div className="flex items-center justify-between gap-4 border-b border-brand-200 px-5 py-4 dark:border-brand-700">
            <div>
                <h3 className="text-lg font-bold text-brand-950 dark:text-white">Risk register</h3>
                <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Technical findings ordered by severity and risk score.</p>
            </div>
            <span className="text-sm font-semibold text-brand-600 dark:text-brand-300">{threats.length} risks</span>
        </div>}

        {threats.length === 0 ? (
            <div className="p-6">
                <EmptyInsight icon={ShieldCheck} title="No matching risks" description="No findings match the current filters." />
            </div>
        ) : (
            <div className="overflow-x-auto">
                <table className="w-full table-fixed border-collapse text-left md:min-w-[720px] md:table-auto">
                    <thead className="bg-brand-50 text-xs font-semibold uppercase text-brand-500 dark:bg-brand-900/50 dark:text-brand-400">
                        <tr>
                            <th className="px-2 py-3 md:px-5">Risk name</th>
                            <th className="w-20 px-1 py-3 md:w-28 md:px-4">Severity</th>
                            <th className="hidden w-44 px-4 py-3 md:table-cell">Affected STRIDE</th>
                            <th className="hidden w-48 px-4 py-3 md:table-cell">Affected component</th>
                            <th className="w-10 px-1 py-3 text-center md:w-20 md:px-4"><span className="sr-only md:not-sr-only">Details</span></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-brand-200 dark:divide-brand-700">
                        {threats.map((threat) => (
                            <tr key={threat.id} className="bg-white hover:bg-brand-50/70 dark:bg-brand-800 dark:hover:bg-brand-700/45">
                                <td className="px-2 py-4 md:px-5">
                                    <button onClick={() => onSelectThreat(threat)} className="max-w-md break-words text-left text-sm font-semibold text-brand-950 underline-offset-4 hover:underline dark:text-white">{threat.title}</button>
                                    <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{threat.tier} | {(threat.finding_type || 'architecture').replaceAll('_', ' ')}</p>
                                    <p className="mt-1 break-words text-xs text-brand-600 dark:text-brand-300 md:hidden">{affectedComponents(threat)}</p>
                                </td>
                                <td className="px-1 py-4 md:px-4"><SeverityBadge severity={threat.severity} /></td>
                                <td className="hidden px-4 py-4 text-sm font-medium text-brand-700 dark:text-brand-300 md:table-cell">{(threat.affected_stride_categories?.length ? threat.affected_stride_categories : [threat.stride_category || threat.category]).join(', ')}</td>
                                <td className="hidden px-4 py-4 text-sm text-brand-600 dark:text-brand-300 md:table-cell">{affectedComponents(threat)}</td>
                                <td className="px-1 py-4 text-center md:px-4">
                                    <button
                                        type="button"
                                        onClick={() => onSelectThreat(threat)}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-brand-200 text-brand-600 hover:border-brand-primary hover:text-brand-primary dark:border-brand-600 dark:text-brand-300"
                                        aria-label={`View details for ${threat.title}`}
                                        title="View risk details"
                                    >
                                        <Eye className="h-4 w-4" />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        )}
    </section>
);

function RiskDetailContent({ threat, reviewState, onReviewStateChange }) {
    const [tab, setTab] = useState('summary');
    const explanation = threat.explanation || {};
    const references = explanation.rule_provenance?.references || explanation.references || [];
    return <div className="px-5 pb-6 pt-5 sm:px-7">
        <div className="pr-10"><SeverityBadge severity={threat.severity} />
            <h2 className="mt-3 break-words text-xl font-semibold text-brand-950 dark:text-white">{threat.title}</h2>
            <p className="mt-2 text-sm text-brand-600 dark:text-brand-300">{threat.stride_category || threat.category} / {affectedComponents(threat)}</p>
        </div>
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-y border-brand-200 py-3 dark:border-brand-700">
            <span className="text-xs text-brand-600 dark:text-brand-300">{(explanation.evidence_basis || threat.tier || 'unspecified').replaceAll('_', ' ')} / Confidence: {threat.confidence || 'Unspecified'}</span>
            <label className="flex items-center gap-2 text-xs text-brand-600 dark:text-brand-300">Review
                <select aria-label="Finding review status" className="input-brand text-sm" value={reviewState} onChange={(event) => onReviewStateChange(threat.id, event.target.value)}>
                    {Object.entries(reviewStateMeta).map(([key, meta]) => <option value={key} key={key}>{meta.label}</option>)}
                </select>
            </label>
        </div>
        <nav className="mt-3 flex gap-2 border-b border-brand-200 dark:border-brand-700" aria-label="Risk detail views">
            {['summary', 'evidence', 'remediation'].map((name) => <button key={name} type="button" onClick={() => setTab(name)} aria-pressed={tab === name}
                className={`border-b-2 px-3 py-3 text-sm font-medium capitalize ${tab === name ? 'border-brand-primary text-brand-primary dark:text-indigo-300' : 'border-transparent text-brand-600 dark:text-brand-300'}`}>{name}</button>)}
        </nav>
        <div className="min-h-52 space-y-5 pt-5 text-sm leading-6 text-brand-700 dark:text-brand-200">
            {tab === 'summary' && <>
                <p className="break-words">{threat.description}</p>
                {(explanation.why_flagged || threat.root_cause) && <section><h3 className="mb-1 font-semibold text-brand-950 dark:text-white">Why this applies</h3><p>{explanation.why_flagged || threat.root_cause}</p></section>}
                <FlowContext threat={threat} /><AttackRoute threat={threat} />
                <section><h3 className="mb-1 font-semibold text-brand-950 dark:text-white">Verification status</h3><p>Based on submitted evidence. Exploitability has not been verified against a live deployment.</p></section>
            </>}
            {tab === 'evidence' && <>
                <EvidenceSources threat={threat} />
                {(threat.evidence_details || []).map((item, index) => <section key={index} className="border-l-2 border-brand-200 pl-4 dark:border-brand-600">
                    <p className="break-words">{item.statement}</p><p className="mt-1 break-words text-xs text-brand-500 dark:text-brand-300">{[item.document, item.locator, item.line ? `Line ${item.line}` : null, item.source_type?.replaceAll('_', ' ')].filter(Boolean).join(' / ')}</p>
                </section>)}
                {!threat.evidence_details?.length && <p>No source-level evidence was captured.</p>}
                {!!explanation.correlated_evidence?.length && <details className="border-t border-brand-200 pt-3 dark:border-brand-700"><summary className="cursor-pointer font-semibold">Cross-source control evidence ({explanation.correlated_evidence.length})</summary>{explanation.correlated_evidence.map((claim) => <section key={claim.id} className="mt-3 border-l-2 border-brand-200 pl-3 dark:border-brand-600"><p className="text-xs font-semibold">{claim.control.replaceAll('_', ' ')}: {claim.state}{claim.scope_status === 'scope_unconfirmed' ? ' (scope unconfirmed)' : ''}</p><p className="break-words">{claim.statement}</p><p className="break-words text-xs text-brand-500 dark:text-brand-300">{[claim.document, claim.locator, claim.line && `Line ${claim.line}`, claim.scope?.environment, ...(claim.scope?.endpoints || [])].filter(Boolean).join(' | ')}</p></section>)}</details>}
                <p className="break-words text-xs">{[...(threat.cwe || []), ...(threat.owasp_top_10 || [])].join(' / ')}</p>
                {explanation.framework_mappings?.length > 0 && <section aria-label="Versioned framework references">
                    <h3 className="mb-2 font-semibold text-brand-950 dark:text-white">Framework references</h3>
                    <ul className="space-y-2">{explanation.framework_mappings.map((item) => <li key={`${item.framework}-${item.version}-${item.id}`} className="break-words text-xs">
                        <a href={/^https:\/\//i.test(item.url || '') ? item.url : undefined} target="_blank" rel="noopener noreferrer" className="text-brand-primary underline dark:text-indigo-300">{item.framework_name} {item.version}: {item.id} / {item.name}</a>
                    </li>)}</ul>
                    <p className="mt-2 text-xs text-brand-500 dark:text-brand-300">Taxonomy alignment, not a compliance certification.</p>
                </section>}
                {explanation.framework_mapping_issues?.length > 0 && <p className="text-xs text-amber-800 dark:text-amber-200">Some legacy references could not be verified against the pinned framework versions.</p>}
                {explanation.rule_provenance && <p className="break-words text-xs">Rule {explanation.rule_provenance.id} / Version {explanation.rule_provenance.version} / {(explanation.rule_provenance.review_status || 'Review unspecified').replaceAll('_', ' ')}</p>}
                {references.filter((url) => /^https?:\/\//i.test(url)).map((url) => <a key={url} href={url} target="_blank" rel="noopener noreferrer" className="block break-all text-brand-primary underline dark:text-indigo-300">{url}</a>)}
            </>}
            {tab === 'remediation' && <>
                <section><h3 className="mb-2 font-semibold text-brand-950 dark:text-white">Recommended change</h3><p className="whitespace-pre-wrap break-words">{threat.mitigation}</p></section>
                {threat.implementation_detail && threat.implementation_detail !== threat.mitigation && <pre className="overflow-x-auto whitespace-pre-wrap break-words border-y border-brand-200 py-4 text-xs dark:border-brand-700">{threat.implementation_detail}</pre>}
                <section><h3 className="mb-2 font-semibold text-brand-950 dark:text-white">Verify the fix</h3><p>{explanation.verification || 'Verify the control on the affected component, run an authorized negative test, and reanalyze the updated evidence.'}</p></section>
            </>}
        </div>
    </div>;
}

export const RiskDetailsModal = ({ threat, reviewState, onReviewStateChange, onClose }) => {
    const dialogRef = useRef(null);
    useEffect(() => {
        if (!threat) return undefined;
        const opener = document.activeElement;
        dialogRef.current?.querySelector('button')?.focus();
        const handleKeyDown = (event) => {
            if (event.key === 'Escape') onClose();
            if (event.key === 'Tab') {
                const items = Array.from(dialogRef.current?.querySelectorAll('button:not([disabled]), select, input, a[href]') || []);
                const first = items[0], last = items.at(-1);
                if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
                if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
            }
        };
        const previousOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        window.addEventListener('keydown', handleKeyDown);
        return () => {
            document.body.style.overflow = previousOverflow;
            window.removeEventListener('keydown', handleKeyDown);
            if (opener?.isConnected) opener.focus();
        };
    }, [threat, onClose]);

    if (!threat) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/45 p-4 pt-[6vh]" role="presentation" onMouseDown={onClose}>
            <div
                ref={dialogRef}
                className="relative max-h-[88vh] w-full max-w-4xl overflow-y-auto rounded-lg bg-white p-2 shadow-2xl dark:bg-brand-900"
                role="dialog"
                aria-modal="true"
                aria-label={`Risk details: ${threat.title}`}
                onMouseDown={(event) => event.stopPropagation()}
            >
                <button
                    type="button"
                    onClick={onClose}
                    className="absolute right-4 top-4 z-10 inline-flex h-9 w-9 items-center justify-center rounded-md border border-brand-200 bg-white text-brand-600 hover:text-brand-950 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-300 dark:hover:text-white"
                    aria-label="Close risk details"
                    title="Close"
                >
                    <X className="h-4 w-4" />
                </button>
                <RiskDetailContent key={threat.id} threat={threat} reviewState={reviewState} onReviewStateChange={onReviewStateChange} />
            </div>
        </div>
    );
};
