import { useState, useCallback, useRef } from 'react';
import { WS_BASE_URL } from '../config';
import { mapAnalysisResult } from '../utils/analysisMapper';
import { workspaceToken } from '../services/workspaceAuth';

const WS_URL = `${WS_BASE_URL}/ws/analyze`;
const getAnalysisMode = (useLocalSlm = true) => (useLocalSlm ? 'standard' : 'fast');

/**
 * React hook for streaming threat analysis via WebSocket.
 * 
 * Returns:
 *   analyze(description, projectName) - start analysis
 *   progress - 0-100 percentage
 *   phase - current phase label
 *   message - current status message
 *   result - final analysis result (null until complete)
 *   error - error message if failed
 *   isAnalyzing - whether analysis is in progress
 *   cancel - cancel the analysis
 */
export function useStreamingAnalysis() {
    const [progress, setProgress] = useState(0);
    const [phase, setPhase] = useState('');
    const [message, setMessage] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const wsRef = useRef(null);
    const completedRef = useRef(false);

    const cancel = useCallback(() => {
        if (wsRef.current) {
            wsRef.current.close();
            wsRef.current = null;
        }
        setIsAnalyzing(false);
        setProgress(0);
        setPhase('');
        setMessage('Cancelled');
    }, []);

    const analyze = useCallback((description, projectName = 'Untitled Project', useLocalSlm = true, options = {}) => {
        return new Promise((resolve, reject) => {
            // Reset state
            setProgress(0);
            setPhase('Connecting...');
            setMessage('Establishing connection...');
            setResult(null);
            setError(null);
            setIsAnalyzing(true);
            completedRef.current = false;

            const ws = new WebSocket(WS_URL);
            wsRef.current = ws;

            ws.onopen = () => {
                setPhase('Connected');
                setMessage('Sending architecture for analysis...');
                ws.send(JSON.stringify({
                    access_token: workspaceToken() || undefined,
                    description,
                    project_name: projectName,
                    use_local_slm: useLocalSlm,
                    analysis_mode: getAnalysisMode(useLocalSlm),
                    domain_profile: options.domainProfile || 'general'
                }));
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    if (data.type === 'progress') {
                        setProgress(data.progress || 0);
                        setPhase(data.label || data.phase || '');
                        setMessage(data.message || '');
                    } else if (data.type === 'result') {
                        completedRef.current = true;
                        setProgress(100);
                        setPhase('complete');
                        setMessage('Analysis complete!');
                        setIsAnalyzing(false);

                        const mapped = mapAnalysisResult(data.data);

                        setResult(mapped);
                        resolve(mapped);
                    } else if (data.type === 'error') {
                        setError(data.message);
                        setIsAnalyzing(false);
                        reject(new Error(data.message));
                    }
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e);
                }
            };

            ws.onerror = () => {
                if (completedRef.current) return;
                setError('WebSocket connection failed. Falling back to REST API...');
                setIsAnalyzing(false);
                reject(new Error('WebSocket connection failed'));
            };

            ws.onclose = (event) => {
                wsRef.current = null;
                if (!completedRef.current) {
                    setIsAnalyzing(false);
                    const message = event.code === 1008 ? 'Workspace access was denied. Check your access settings.' : 'Analysis connection closed before a result was received.';
                    setError(message);
                    reject(new Error(message));
                }
            };
        });
    }, []);

    return {
        analyze,
        progress,
        phase,
        message,
        result,
        error,
        isAnalyzing,
        cancel,
    };
}
