import React, { useEffect, useMemo, useState } from 'react';
import { AlertCircle, CheckCircle2, Key, Loader2, RefreshCw, Sparkles, X } from 'lucide-react';
import { useToast } from '../hooks/useToast';
import { API_BASE_URL } from '../config';
import { workspaceAuthHeaders } from '../services/workspaceAuth';

const DEFAULT_PROVIDERS = [
    {
        id: 'openai',
        label: 'OpenAI',
        description: 'GPT models',
        key_hint: 'sk-...',
        default_model: 'gpt-4o-mini',
        fallback_models: [{ id: 'gpt-4o-mini', label: 'GPT-4o Mini', recommended: true }],
    },
    {
        id: 'claude',
        label: 'Claude',
        description: 'Anthropic models',
        key_hint: 'sk-ant-...',
        default_model: 'claude-sonnet-4-20250514',
        fallback_models: [{ id: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4', recommended: true }],
    },
    {
        id: 'gemini',
        label: 'Gemini',
        description: 'Google models',
        key_hint: 'AIza...',
        default_model: 'gemini-2.0-flash',
        fallback_models: [{ id: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', recommended: true }],
    },
    {
        id: 'nvidia',
        label: 'NVIDIA',
        description: 'NIM models',
        key_hint: 'nvapi-...',
        default_model: 'meta/llama-3.1-70b-instruct',
        fallback_models: [{ id: 'meta/llama-3.1-70b-instruct', label: 'Llama 3.1 70B Instruct', recommended: true }],
    },
];

const providerTone = {
    openai: 'border-brand-primary bg-brand-primary/5 text-brand-primary',
    claude: 'border-brand-primary bg-brand-primary/5 text-brand-primary',
    gemini: 'border-brand-primary bg-brand-primary/5 text-brand-primary',
    nvidia: 'border-brand-primary bg-brand-primary/5 text-brand-primary',
};

const AIAnalysis = ({ onAnalysisComplete }) => {
    const [providers, setProviders] = useState(DEFAULT_PROVIDERS);
    const [provider, setProvider] = useState(DEFAULT_PROVIDERS[0].id);
    const [models, setModels] = useState(DEFAULT_PROVIDERS[0].fallback_models);
    const [model, setModel] = useState(DEFAULT_PROVIDERS[0].default_model);
    const [apiKey, setApiKey] = useState('');
    const [description, setDescription] = useState('');
    const [projectName, setProjectName] = useState('');
    const [isLoadingProviders, setIsLoadingProviders] = useState(false);
    const [isValidating, setIsValidating] = useState(false);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [keyValid, setKeyValid] = useState(null);
    const toast = useToast();

    const selectedProvider = useMemo(
        () => providers.find((item) => item.id === provider) || providers[0],
        [providers, provider]
    );

    useEffect(() => {
        const loadProviders = async () => {
            setIsLoadingProviders(true);
            try {
                const response = await fetch(`${API_BASE_URL}/llm/providers`, { headers: workspaceAuthHeaders() });
                if (!response.ok) throw new Error('Provider loading failed');
                const payload = await response.json();
                if (Array.isArray(payload.providers) && payload.providers.length) {
                    setProviders(payload.providers);
                    const current = payload.providers[0];
                    setProvider(current.id);
                    setModels(current.fallback_models || []);
                    setModel(current.default_model || current.fallback_models?.[0]?.id || '');
                }
            } catch {
                setProviders(DEFAULT_PROVIDERS);
            } finally {
                setIsLoadingProviders(false);
            }
        };

        loadProviders();
    }, []);

    const setFallbackModels = (nextProvider) => {
        const fallback = nextProvider.fallback_models || [];
        setModels(fallback);
        setModel(nextProvider.default_model || fallback[0]?.id || '');
    };

    const handleProviderChange = (nextProviderId) => {
        const nextProvider = providers.find((item) => item.id === nextProviderId);
        if (!nextProvider) return;
        setProvider(nextProvider.id);
        setFallbackModels(nextProvider);
        setKeyValid(null);
    };

    const clearApiKey = () => {
        setApiKey('');
        setKeyValid(null);
        setFallbackModels(selectedProvider);
    };

    const validateAndLoadModels = async () => {
        if (!apiKey || apiKey.length < 10) {
            toast.error('Enter a valid API key first');
            return;
        }

        setIsValidating(true);
        try {
            const response = await fetch(`${API_BASE_URL}/llm/models`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...workspaceAuthHeaders() },
                body: JSON.stringify({ provider, api_key: apiKey }),
            });

            const result = await response.json();
            if (!response.ok) {
                throw new Error('Model loading failed');
            }

            if (result.valid) {
                const loadedModels = Array.isArray(result.models) && result.models.length
                    ? result.models
                    : selectedProvider.fallback_models || [];
                const recommended = loadedModels.find((item) => item.recommended) || loadedModels[0];
                setModels(loadedModels);
                setModel(recommended?.id || '');
                setKeyValid(true);
                toast.success(`${selectedProvider.label} key validated and models loaded`);
            } else {
                setKeyValid(false);
                setFallbackModels(selectedProvider);
                toast.error(`Invalid ${selectedProvider.label} API key`);
            }
        } catch (error) {
            setKeyValid(false);
            toast.error(error.message || 'Failed to validate API key');
        } finally {
            setIsValidating(false);
        }
    };

    const handleAnalyze = async () => {
        if (!projectName || !description) {
            toast.error('Fill in project name and architecture description');
            return;
        }

        if (!apiKey || keyValid !== true || !model) {
            toast.error('Validate the API key and select a model first');
            return;
        }

        setIsAnalyzing(true);
        try {
            const response = await fetch(`${API_BASE_URL}/analyze-with-llm`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...workspaceAuthHeaders() },
                body: JSON.stringify({
                    project_name: projectName,
                    description,
                    llm_provider: provider,
                    api_key: apiKey,
                    model,
                    analysis_mode: 'standard',
                }),
            });

            if (!response.ok) {
                const errData = await response.json();
                const msg = typeof errData.detail === 'string'
                    ? errData.detail
                    : Array.isArray(errData.detail)
                        ? errData.detail.map((item) => item.msg).join(', ')
                        : 'Analysis failed';
                throw new Error(msg);
            }

            const result = await response.json();
            toast.success(`AI analysis complete. Found ${result.threats?.length || 0} threats`);
            onAnalysisComplete(result, projectName);
        } catch (error) {
            toast.error(error.message || 'AI analysis failed');
        } finally {
            setIsAnalyzing(false);
        }
    };

    return (
        <div className="mx-auto w-full max-w-6xl space-y-5">
            <div className="panel-soft px-6 py-5">
                <div className="mb-2 flex items-center gap-3">
                    <Sparkles className="h-5 w-5 text-brand-secondary" />
                    <h2 className="text-2xl font-semibold text-brand-950 dark:text-white">AI-Powered Threat Analysis</h2>
                </div>
                <p className="max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                    Select a provider, validate your key, choose a loaded model, then run the analysis.
                </p>
            </div>

            <div className="ui-panel p-6">
                <div className="mb-3 flex items-center justify-between gap-3">
                    <label className="text-sm font-semibold text-brand-950 dark:text-white">
                        AI Provider
                    </label>
                    {isLoadingProviders && (
                        <span className="flex items-center gap-2 text-xs text-brand-500 dark:text-brand-400">
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            Loading providers
                        </span>
                    )}
                </div>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    {providers.map((item) => (
                        <button
                            key={item.id}
                            type="button"
                            onClick={() => handleProviderChange(item.id)}
                            className={`min-h-[84px] rounded-lg border p-4 text-left transition-colors ${
                                provider === item.id
                                    ? providerTone[item.id] || 'border-brand-primary bg-brand-primary/10'
                                    : 'border-brand-200 bg-brand-50 hover:border-brand-300 dark:border-brand-700 dark:bg-brand-900/35 dark:hover:border-brand-500'
                            }`}
                        >
                            <div className="text-base font-semibold dark:text-white">{item.label}</div>
                            <div className="mt-1 text-sm text-brand-600 dark:text-brand-400">{item.description}</div>
                        </button>
                    ))}
                </div>
            </div>

            <div className="ui-panel p-6">
                <label className="mb-2 block text-sm font-semibold text-brand-950 dark:text-white">
                    <Key className="inline w-4 h-4 mr-1" />
                    API Key
                </label>
                <div className="flex flex-col gap-2 sm:flex-row">
                    <input
                        type="password"
                        value={apiKey}
                        onChange={(event) => {
                            setApiKey(event.target.value);
                            setKeyValid(null);
                        }}
                        placeholder={selectedProvider.key_hint}
                        className="input-brand min-w-0 flex-1"
                    />
                    <div className="flex gap-2">
                        <button
                            type="button"
                            onClick={validateAndLoadModels}
                            disabled={isValidating || !apiKey}
                            className="btn-brand gap-2"
                        >
                            {isValidating ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                            OK
                        </button>
                        <button
                            type="button"
                            onClick={clearApiKey}
                            disabled={!apiKey && keyValid === null}
                            className="ui-button-secondary px-3"
                            title="Clear API key"
                        >
                            <X className="h-4 w-4" />
                        </button>
                    </div>
                </div>
                {keyValid === true && (
                    <div className="mt-2 flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                        <CheckCircle2 className="h-4 w-4" />
                        Key validated. {models.length} model{models.length === 1 ? '' : 's'} loaded.
                    </div>
                )}
                {keyValid === false && (
                    <div className="mt-2 flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                        <AlertCircle className="h-4 w-4" />
                        Key validation failed.
                    </div>
                )}
            </div>

            <div className="grid gap-5 lg:grid-cols-[0.8fr_1fr]">
            <div className="ui-panel p-6">
                <label className="mb-2 block text-sm font-semibold text-brand-950 dark:text-white">
                    Model
                </label>
                <select
                    value={model}
                    onChange={(event) => setModel(event.target.value)}
                    disabled={!models.length || isValidating}
                    className="input-brand w-full disabled:cursor-not-allowed disabled:opacity-60"
                >
                    {models.map((option) => (
                        <option key={option.id} value={option.id}>
                            {option.label || option.id}{option.recommended ? ' (Recommended)' : ''}
                        </option>
                    ))}
                </select>
            </div>

            <div className="ui-panel p-6">
                <label className="mb-2 block text-sm font-semibold text-brand-950 dark:text-white">Project Name</label>
                <input
                    type="text"
                    value={projectName}
                    onChange={(event) => setProjectName(event.target.value)}
                    placeholder="e.g., E-Commerce Platform"
                    className="input-brand w-full"
                />
            </div>
            </div>

            <div className="ui-panel p-6">
                <label className="mb-2 block text-sm font-semibold text-brand-950 dark:text-white">System Architecture Description</label>
                <textarea
                    value={description}
                    onChange={(event) => setDescription(event.target.value)}
                    placeholder={`Describe your system architecture in detail. Include:
- Microservices and their tech stacks
- Databases and data stores
- Third-party integrations
- Security controls
- Known issues or concerns`}
                    rows={12}
                    className="input-brand w-full font-mono text-sm leading-6"
                />
            </div>

            <button
                type="button"
                onClick={handleAnalyze}
                disabled={isAnalyzing || !projectName || !description || !apiKey || keyValid !== true || !model}
                className="btn-brand w-full gap-2 py-3 text-base"
            >
                {isAnalyzing ? (
                    <>
                        <Loader2 className="h-5 w-5 animate-spin" />
                        Analyzing with {selectedProvider.label}
                    </>
                ) : (
                    <>
                        <Sparkles className="h-5 w-5" />
                        Analyze with AI
                    </>
                )}
            </button>
        </div>
    );
};

export default AIAnalysis;
