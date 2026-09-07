// Backend API Service
import { API_BASE_URL } from '../config';
import { mapAnalysisResult } from '../utils/analysisMapper';

const getAnalysisMode = (useLocalSlm = true) => (useLocalSlm ? 'standard' : 'fast');

export const analyzeSystem = async (systemDescription, projectName = "Untitled Project", useLocalSlm = true, options = {}) => {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                description: systemDescription,
                project_name: projectName,
                use_local_slm: useLocalSlm,
                analysis_mode: getAnalysisMode(useLocalSlm),
                domain_profile: options.domainProfile || 'general',
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        return mapAnalysisResult(result);
    } catch (error) {
        console.error("Backend connection failed, falling back to offline mode for demo purposes.", error);
        // Fallback or re-throw depending on preference.
        throw error;
    }
};

export const analyzeDocuments = async (
    files,
    projectName = "Untitled Project",
    useLocalSlm = true,
    options = {}
) => {
    try {
        const formData = new FormData();
        formData.append('project_name', projectName);
        formData.append('use_local_slm', String(useLocalSlm));
        formData.append('analysis_mode', getAnalysisMode(useLocalSlm));
        formData.append('domain_profile', options.domainProfile || 'general');
        formData.append('context_text', options.contextText || '');

        for (const file of files || []) {
            formData.append('files', file);
        }

        const response = await fetch(`${API_BASE_URL}/analyze-documents`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => null);
            throw new Error(errorPayload?.detail || `API error: ${response.status}`);
        }

        const result = await response.json();
        return mapAnalysisResult(result);
    } catch (error) {
        console.error("Backend connection failed for document analysis.", error);
        throw error;
    }
};

export const analyzeIac = async (iacContent, projectName = "Untitled Project", formatHint = 'auto') => {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-iac`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                iac_content: iacContent,
                project_name: projectName,
                format_hint: formatHint,
                analysis_mode: 'standard'
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        return mapAnalysisResult(result);
    } catch (error) {
        console.error("Backend connection failed for IaC Analysis.", error);
        throw error;
    }
};

export const analyzeIacProject = async (files, projectName = "Untitled IaC Project") => {
    const formData = new FormData();
    formData.append('project_name', projectName);
    formData.append('analysis_mode', 'standard');
    for (const file of files || []) {
        formData.append('files', file);
    }
    const response = await fetch(`${API_BASE_URL}/analyze-iac-project`, {
        method: 'POST',
        body: formData,
    });
    if (!response.ok) {
        const errorPayload = await response.json().catch(() => null);
        throw new Error(errorPayload?.detail || `API error: ${response.status}`);
    }
    return mapAnalysisResult(await response.json());
};

export const analyzeCode = async (codeContent, projectName = "Source Security Audit", language = 'auto') => {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-code`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code_content: codeContent,
                project_name: projectName,
                language,
                analysis_mode: 'standard',
            }),
        });

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => null);
            throw new Error(errorPayload?.detail || `API error: ${response.status}`);
        }

        return mapAnalysisResult(await response.json());
    } catch (error) {
        console.error("Backend connection failed for code analysis.", error);
        throw error;
    }
};
