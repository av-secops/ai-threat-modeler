import { useEffect, useRef, useState } from 'react';
import { Bot, Send, X, Pencil } from 'lucide-react';

import { answerAnalysisQuestion } from '../utils/analysisCopilot';

export default function AnalysisCopilot({ data, sidebarCollapsed = true, onProposeUpdate }) {
  const panelRef = useRef(null);
  const [isOpen, setIsOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState(() => answerAnalysisQuestion('', data));

  useEffect(() => {
    if (!isOpen) return undefined;
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setIsOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen]);

  const ask = () => {
    setAnswer(answerAnalysisQuestion(question, data));
  };

  const submit = (event) => {
    event.preventDefault();
    ask();
  };

  const leftClass = sidebarCollapsed ? 'left-[84px]' : 'left-[236px]';

  return (
    <div className={`fixed bottom-5 z-50 transition-[left] duration-300 ${leftClass}`}>
      {isOpen && (
        <section
          ref={panelRef}
          className="mb-3 w-[min(380px,calc(100vw-104px))] overflow-hidden rounded-lg border border-brand-200 bg-white shadow-2xl dark:border-brand-700 dark:bg-brand-800"
          role="dialog"
          aria-label="Threat modeling Copilot"
        >
          <header className="flex items-center justify-between border-b border-brand-200 px-4 py-3 dark:border-brand-700">
            <div className="flex min-w-0 items-center gap-2.5">
              <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-brand-primary text-white">
                <Bot className="h-4 w-4" />
              </span>
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-brand-950 dark:text-white">Analysis Copilot</h2>
                <p className="truncate text-xs text-brand-500 dark:text-brand-400">Answers from this threat model</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-brand-500 hover:bg-brand-100 hover:text-brand-900 dark:text-brand-300 dark:hover:bg-brand-700 dark:hover:text-white"
              aria-label="Close Analysis Copilot"
              title="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </header>

          <div className="max-h-[52vh] overflow-y-auto p-4">
            <p className="text-xs font-semibold uppercase text-brand-500 dark:text-brand-400">{answer.title}</p>
            <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-200">{answer.answer}</p>
            {answer.bullets?.length > 0 && (
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-200">
                {answer.bullets.map((bullet, index) => (
                  <li key={`${bullet}-${index}`} className="border-l-2 border-brand-primary/40 pl-3 leading-6">{bullet}</li>
                ))}
              </ul>
            )}
          </div>

          <form onSubmit={submit} className="flex gap-2 border-t border-brand-200 p-3 dark:border-brand-700">
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="What should I fix first?"
              className="input-brand min-w-0 flex-1 text-sm"
              aria-label="Question for Analysis Copilot"
            />
            <button
              type="submit"
              className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-brand-primary text-white hover:opacity-90"
              aria-label="Ask Analysis Copilot"
              title="Ask"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
          {onProposeUpdate && question.trim() && <div className="border-t border-brand-200 p-3 dark:border-brand-700"><button type="button" className="ui-button-secondary w-full" onClick={() => { onProposeUpdate(question); setIsOpen(false); }}><Pencil size={16} />Review this as a model update</button></div>}
        </section>
      )}

      <button
        type="button"
        onClick={() => setIsOpen((current) => !current)}
        className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-brand-primary/30 bg-brand-primary text-white shadow-lg transition-transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-brand-primary focus:ring-offset-2 dark:ring-offset-brand-900"
        aria-expanded={isOpen}
        aria-label={isOpen ? 'Close Analysis Copilot' : 'Open Analysis Copilot'}
        title="Analysis Copilot"
      >
        {isOpen ? <X className="h-5 w-5" /> : <Bot className="h-5 w-5" />}
      </button>
    </div>
  );
}
