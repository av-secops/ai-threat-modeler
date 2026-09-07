import React, { useState, useEffect } from 'react';
import { Clock, Trash2, Eye, GitCompare, X, ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { loadAnalyses, deleteAnalysis, clearAllAnalyses } from '../utils/storage';
import { useToast } from '../hooks/useToast';
import { loadWorkspaces, deleteWorkspace, clearWorkspaces } from '../utils/modelWorkspace';

async function historyEntries() {
    const workspaces = await loadWorkspaces();
    return [...loadAnalyses(), ...workspaces.map((w) => ({ id: w.id, workspaceId: w.id, projectName: w.projectName,
        timestamp: w.updatedAt, data: w.revisions.at(-1)?.data || null, revisionCount: w.revisions.length }))]
        .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

const AnalysisHistory = ({ onLoadAnalysis }) => {
    const [analyses, setAnalyses] = useState(() => loadAnalyses());
    const [compareMode, setCompareMode] = useState(false);
    const [selectedForCompare, setSelectedForCompare] = useState([]);
    const [comparison, setComparison] = useState(null);
    const [historyError, setHistoryError] = useState('');
    const toast = useToast();

    useEffect(() => {
        let cancelled = false;
        historyEntries().then((entries) => { if (!cancelled) setAnalyses(entries); }).catch(() => { if (!cancelled) setHistoryError('Saved workspaces could not be loaded.'); });
        return () => { cancelled = true; };
    }, []);

    const refresh = async () => setAnalyses(await historyEntries());

    const handleDelete = async (id) => {
        try {
            if (analyses.find((a) => a.id === id)?.workspaceId) await deleteWorkspace(id);
            else deleteAnalysis(id);
            await refresh();
            toast.success('Analysis deleted');
        } catch { toast.error('The analysis could not be deleted.'); }
    };

    const handleClearAll = async () => {
        if (window.confirm('Delete all saved analyses? This cannot be undone.')) {
            try {
                await clearWorkspaces();
                clearAllAnalyses();
                await refresh();
                toast.success('All analyses cleared');
            } catch { toast.error('Saved analyses could not be cleared.'); }
        }
    };

    const handleLoad = (analysis) => {
        onLoadAnalysis(analysis.data, analysis.projectName, analysis);
    };

    const toggleCompareSelect = (analysis) => {
        if (!analysis.data) { toast.error('Analyze this draft before comparing reports.'); return; }
        if (selectedForCompare.find(a => a.id === analysis.id)) {
            setSelectedForCompare(selectedForCompare.filter(a => a.id !== analysis.id));
        } else if (selectedForCompare.length < 2) {
            setSelectedForCompare([...selectedForCompare, analysis]);
        }
    };

    const runComparison = () => {
        if (selectedForCompare.length !== 2) return;
        const [older, newer] = [...selectedForCompare].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        const olderThreats = older.data?.threats || [];
        const newerThreats = newer.data?.threats || [];

        const olderTitles = new Set(olderThreats.map(t => t.title));
        const newerTitles = new Set(newerThreats.map(t => t.title));

        const newThreats = newerThreats.filter(t => !olderTitles.has(t.title));
        const resolvedThreats = olderThreats.filter(t => !newerTitles.has(t.title));
        const persistentThreats = newerThreats.filter(t => olderTitles.has(t.title));

        setComparison({
            older: { name: older.projectName, date: older.timestamp, score: older.data?.score, threatCount: olderThreats.length },
            newer: { name: newer.projectName, date: newer.timestamp, score: newer.data?.score, threatCount: newerThreats.length },
            newThreats,
            resolvedThreats,
            persistentThreats,
            scoreDelta: (newer.data?.score || 0) - (older.data?.score || 0),
        });
    };

    const formatDate = (ts) => {
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    };

    if (comparison) {
        return (
            <div className="mx-auto w-full max-w-6xl animate-fade-in-up">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-semibold text-brand-950 dark:text-white">Analysis Comparison</h2>
                    <button onClick={() => { setComparison(null); setSelectedForCompare([]); setCompareMode(false); }}
                        className="ui-button-secondary">
                        <X className="w-4 h-4" /> Close
                    </button>
                </div>

                {/* Score comparison */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="ui-panel p-4">
                        <div className="text-xs text-brand-500 font-mono mb-1">OLDER</div>
                        <div className="font-bold dark:text-white">{comparison.older.name}</div>
                        <div className="text-sm text-brand-500">{formatDate(comparison.older.date)}</div>
                        <div className="mt-2 text-2xl font-bold text-brand-primary">{comparison.older.score}/100</div>
                        <div className="text-sm text-brand-600 dark:text-brand-400">{comparison.older.threatCount} threats</div>
                    </div>
                    <div className="ui-panel p-4">
                        <div className="text-xs text-brand-500 font-mono mb-1">NEWER</div>
                        <div className="font-bold dark:text-white">{comparison.newer.name}</div>
                        <div className="text-sm text-brand-500">{formatDate(comparison.newer.date)}</div>
                        <div className="mt-2 text-2xl font-bold text-brand-primary">{comparison.newer.score}/100</div>
                        <div className="text-sm text-brand-600 dark:text-brand-400">{comparison.newer.threatCount} threats</div>
                    </div>
                </div>

                {/* Score delta */}
                <div className={`flex items-center justify-center gap-2 p-3 rounded-lg mb-6 ${comparison.scoreDelta > 0 ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                    : comparison.scoreDelta < 0 ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
                        : 'bg-gray-50 dark:bg-brand-700 text-brand-600 dark:text-brand-300'}`}>
                    {comparison.scoreDelta > 0 ? <ArrowUpRight className="w-5 h-5" /> :
                        comparison.scoreDelta < 0 ? <ArrowDownRight className="w-5 h-5" /> :
                            <Minus className="w-5 h-5" />}
                    <span className="font-bold text-lg">Score {comparison.scoreDelta > 0 ? '+' : ''}{comparison.scoreDelta} points</span>
                </div>

                {/* New threats */}
                {comparison.newThreats.length > 0 && (
                    <div className="mb-4">
                        <h3 className="font-bold text-red-600 dark:text-red-400 mb-2">🆕 New Threats ({comparison.newThreats.length})</h3>
                        <div className="space-y-1">
                            {comparison.newThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-red-50 dark:bg-red-900/20 rounded border-l-3 border-red-500 dark:text-brand-300">
                                    <span className="font-mono text-xs bg-red-100 dark:bg-red-800 px-1 rounded mr-2">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Resolved threats */}
                {comparison.resolvedThreats.length > 0 && (
                    <div className="mb-4">
                        <h3 className="font-bold text-brand-600 dark:text-brand-300 mb-2">No longer reported ({comparison.resolvedThreats.length})</h3>
                        <p className="mb-2 text-xs text-brand-500 dark:text-brand-400">Absence from a later report does not verify remediation.</p>
                        <div className="space-y-1">
                            {comparison.resolvedThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-green-50 dark:bg-green-900/20 rounded border-l-3 border-green-500 dark:text-brand-300 line-through opacity-75">
                                    <span className="font-mono text-xs bg-green-100 dark:bg-green-800 px-1 rounded mr-2 no-underline">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Persistent threats */}
                {comparison.persistentThreats.length > 0 && (
                    <div>
                        <h3 className="font-bold text-brand-600 dark:text-brand-400 mb-2">🔄 Persistent Threats ({comparison.persistentThreats.length})</h3>
                        <div className="space-y-1">
                            {comparison.persistentThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-brand-50 dark:bg-brand-700 rounded dark:text-brand-300">
                                    <span className="font-mono text-xs bg-brand-100 dark:bg-brand-600 px-1 rounded mr-2">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="mx-auto w-full max-w-6xl">
            <div className="panel-soft mb-6 px-6 py-5">
                <h2 className="mb-2 text-2xl font-semibold text-brand-950 dark:text-white">Analysis History</h2>
                <p className="text-sm leading-6 text-brand-600 dark:text-brand-400">Browse, load, or compare your past threat analyses.</p>
            </div>
            {historyError && <p role="alert" className="my-3 text-sm text-red-600 dark:text-red-300">{historyError}</p>}

            {analyses.length === 0 ? (
                <div className="text-center py-16 text-brand-500 dark:text-brand-400">
                    <Clock className="w-12 h-12 mx-auto mb-3 opacity-40" />
                    <p className="text-lg">No saved analyses yet</p>
                    <p className="text-sm">Run your first analysis to see it here</p>
                </div>
            ) : (
                <>
                    <div className="flex items-center justify-between mb-4">
                        <span className="text-sm text-brand-500 dark:text-brand-400">{analyses.length} saved analyses</span>
                        <div className="flex gap-2">
                            <button
                                onClick={() => { setCompareMode(!compareMode); setSelectedForCompare([]); }}
                                className={`flex items-center gap-1 rounded-lg border px-3 py-1.5 text-sm transition-colors ${compareMode
                                    ? 'border-brand-primary bg-brand-primary/10 text-brand-primary'
                                    : 'border-brand-300 dark:border-brand-600 text-brand-600 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-700'}`}
                            >
                                <GitCompare className="w-3.5 h-3.5" />
                                {compareMode ? 'Cancel Compare' : 'Compare'}
                            </button>
                            <button onClick={handleClearAll}
                                className="text-sm px-3 py-1.5 rounded-lg border border-red-200 dark:border-red-800 text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20">
                                Clear All
                            </button>
                        </div>
                    </div>

                    {compareMode && (
                        <div className="mb-4 flex items-center justify-between rounded-lg border border-brand-primary/25 bg-brand-primary/10 p-3 text-sm text-brand-primary">
                            <span>Select 2 analyses to compare ({selectedForCompare.length}/2 selected)</span>
                            {selectedForCompare.length === 2 && (
                                <button onClick={runComparison}
                                    className="rounded-lg bg-brand-primary px-3 py-1 font-semibold text-white hover:bg-brand-primary/90">
                                    Compare Now
                                </button>
                            )}
                        </div>
                    )}

                    <div className="space-y-3">
                        {[...analyses].reverse().map((analysis) => {
                            const isSelected = selectedForCompare.find(a => a.id === analysis.id);
                            return (
                                <div
                                    key={analysis.id}
                                    className={`ui-panel border p-4 shadow-sm transition-colors ${compareMode
                                        ? isSelected
                                            ? 'border-brand-primary ring-2 ring-brand-primary/15'
                                            : 'cursor-pointer hover:border-brand-primary/60'
                                        : 'border-brand-200 dark:border-brand-700 hover:shadow-md'}`}
                                    onClick={compareMode ? () => toggleCompareSelect(analysis) : undefined}
                                >
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="font-bold text-brand-900 dark:text-white">{analysis.projectName}</h3>
                                            {analysis.workspaceId && <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{analysis.revisionCount ? `${analysis.revisionCount} report revision${analysis.revisionCount === 1 ? '' : 's'} and a saved draft` : 'Saved architecture draft'}</p>}
                                            <div className="flex items-center gap-3 mt-1 text-sm text-brand-500 dark:text-brand-400">
                                                <span className="flex items-center gap-1">
                                                    <Clock className="w-3.5 h-3.5" />
                                                    {formatDate(analysis.timestamp)}
                                                </span>
                                                {analysis.data?.threats && (
                                                    <span className="font-mono">{analysis.data.threats.length} threats</span>
                                                )}
                                                {analysis.data?.score !== undefined && (
                                                    <span className="font-mono font-bold text-brand-primary">Score: {analysis.data.score}</span>
                                                )}
                                            </div>
                                        </div>
                                        {!compareMode && (
                                            <div className="flex items-center gap-2">
                                                <button onClick={() => handleLoad(analysis)}
                                                    className="p-2 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-700 text-brand-primary" title="Load analysis">
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                                <button onClick={(e) => { e.stopPropagation(); handleDelete(analysis.id); }}
                                                    className="p-2 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 text-red-400 hover:text-red-600" title="Delete">
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        )}
                                        {compareMode && (
                                            <div className={`flex h-5 w-5 items-center justify-center rounded-full border-2 ${isSelected ? 'border-brand-primary bg-brand-primary' : 'border-brand-300 dark:border-brand-600'}`}>
                                                {isSelected && <span className="text-white text-xs">✓</span>}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </>
            )}
        </div>
    );
};

export default AnalysisHistory;
