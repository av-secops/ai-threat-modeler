import React, { useState } from 'react';
import { Send, FileCode, Upload, Code } from 'lucide-react';

const IacInput = ({ onAnalyze, isAnalyzing }) => {
    const [iacContent, setIacContent] = useState('');
    const [projectName, setProjectName] = useState('My IaC Audit');
    const [formatHint, setFormatHint] = useState('auto');
    const [projectFiles, setProjectFiles] = useState([]);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (iacContent.trim()) {
            onAnalyze(iacContent, projectName, formatHint, projectFiles);
        }
    };

    const handleKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (iacContent.trim() && !isAnalyzing) {
                onAnalyze(iacContent, projectName, formatHint, projectFiles);
            }
        }
    };

    const handleFileUpload = (e) => {
        const files = Array.from(e.target.files || []);
        const file = files[0];
        if (!file) return;
        setProjectFiles(files);

        // Auto-detect format from filename.
        const filename = file.name.toLowerCase();
        if (filename.endsWith('.tf') || filename.endsWith('.tfvars')) {
            setFormatHint('terraform');
        } else if (filename.includes('cloudformation') || filename.includes('cfn')) {
            setFormatHint('cloudformation');
        } else if (filename.includes('compose')) {
            setFormatHint('docker-compose');
        } else if (filename.endsWith('.bicep')) {
            setFormatHint('bicep');
        } else if (filename.includes('jenkins') || filename.includes('gitlab')) {
            setFormatHint('ci');
        } else if (filename.endsWith('.yaml') || filename.endsWith('.yml')) {
            setFormatHint('auto');
        }

        const reader = new FileReader();
        reader.onload = (evt) => {
            setIacContent(evt.target.result);
        };
        reader.readAsText(file);
    };

    return (
        <div className="mx-auto mb-10 w-full max-w-6xl animate-fade-in-up">
            <div className="glass-panel p-6">
                <div className="mb-5 border-b border-brand-200 pb-4 dark:border-brand-700">
                    <h2 className="flex items-center gap-2 text-2xl font-semibold text-brand-950 dark:text-white">
                        <FileCode className="h-5 w-5 text-brand-success" />
                        Infrastructure-as-Code Analysis
                    </h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                        Upload one file or a related IaC project. Terraform references are resolved across files and every finding keeps its source filename.
                    </p>
                </div>
                
                <div className="mb-4">
                    <label className="ui-label">Project Name</label>
                    <input
                        type="text"
                        aria-label="IaC project name"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Cluster Production Config"
                    />
                </div>

                <div className="mb-4 grid gap-4 md:grid-cols-[1fr_220px]">
                    <div className="flex-1">
                        <label className="ui-label">Upload File</label>
                        <label className="flex h-11 w-full cursor-pointer items-center justify-center rounded-lg border border-dashed border-brand-300 bg-white px-4 transition hover:border-brand-primary dark:border-brand-600 dark:bg-brand-900/55">
                            <span className="flex items-center space-x-2">
                                <Upload className="w-4 h-4 text-brand-500" />
                                <span className="text-sm font-medium text-brand-600 dark:text-brand-300">
                                    {projectFiles.length > 1 ? `${projectFiles.length} project files selected` : projectFiles[0]?.name || 'Drop IaC files or click to browse'}
                                </span>
                            </span>
                            <input type="file" name="file_upload" className="hidden" multiple accept=".yaml,.yml,.json,.tf,.tfvars,.hcl,.bicep,.ts,.js,.py" onChange={handleFileUpload} />
                        </label>
                    </div>
                    
                    <div>
                        <label className="ui-label">Format Hint</label>
                        <select 
                            aria-label="IaC format"
                            value={formatHint} 
                            onChange={(e) => setFormatHint(e.target.value)}
                            className="input-brand w-full font-mono text-sm py-2"
                        >
                            <option value="auto">Auto-detect</option>
                            <option value="docker-compose">Docker Compose</option>
                            <option value="kubernetes">Kubernetes</option>
                            <option value="helm">Helm template</option>
                            <option value="terraform">Terraform</option>
                            <option value="terraform-plan">Terraform plan JSON</option>
                            <option value="cloudformation">CloudFormation</option>
                            <option value="arm">Azure ARM</option>
                            <option value="bicep">Bicep</option>
                            <option value="pulumi">Pulumi</option>
                            <option value="ci">CI pipeline</option>
                        </select>
                    </div>
                </div>

                <p className="mb-4 text-sm text-brand-600 dark:text-brand-400">
                    Or paste an IaC manifest below:
                </p>
                
                <form onSubmit={handleSubmit} className="relative">
                    <div className="relative">
                        <div className="absolute top-2 right-2 text-brand-400">
                            <Code className="w-4 h-4" />
                        </div>
                        <textarea
                            aria-label="IaC source"
                            className="input-brand h-72 w-full resize-y bg-brand-50 font-mono text-sm leading-relaxed dark:bg-brand-900/50"
                            placeholder={'resource "aws_s3_bucket" "uploads" {\n  bucket = "customer-uploads"\n}\n'}
                            value={iacContent}
                            onChange={(e) => setIacContent(e.target.value)}
                            onKeyDown={handleKeyDown}
                            disabled={isAnalyzing}
                            spellCheck="false"
                        />
                    </div>

                    <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <span className="text-xs font-medium uppercase tracking-wide text-brand-400">Ctrl+Enter to submit</span>
                        <button
                            type="submit"
                            disabled={isAnalyzing || (!iacContent.trim() && projectFiles.length === 0)}
                            className={`inline-flex items-center justify-center gap-2 rounded-lg bg-brand-success px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-green-600 ${isAnalyzing ? 'cursor-not-allowed opacity-50' : ''}`}
                        >
                            {isAnalyzing ? (
                                <>Parsing IaC...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Review infrastructure
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default IacInput;
