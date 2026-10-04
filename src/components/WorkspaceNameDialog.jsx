import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

export default function WorkspaceNameDialog({ title, label = 'Name', value, onChange, onSubmit, onClose, busy, error, password = false, action, context, placeholder, confirmOnly = false }) {
  const dialog = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    (dialog.current?.querySelector('input') || dialog.current?.querySelector('button'))?.focus();
    return () => { document.body.style.overflow = overflow; if (previous?.isConnected) previous.focus(); };
  }, []);
  useEffect(() => {
    if (error && !busy) dialog.current?.querySelector('input')?.focus();
  }, [error, busy]);
  const keyDown = event => {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); onClose(); }
    if (event.key !== 'Tab') return;
    const nodes = [...dialog.current.querySelectorAll('button, input')].filter(node => !node.disabled);
    if (!nodes.length) { event.preventDefault(); return; }
    const first = nodes[0], last = nodes.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  };
  return <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/45 p-4">
    <form ref={dialog} role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title" aria-describedby={context ? 'workspace-dialog-context' : undefined} aria-busy={busy} onKeyDown={keyDown} onSubmit={onSubmit} className="max-h-[calc(100dvh-2rem)] w-full max-w-md space-y-5 overflow-y-auto rounded-lg border border-brand-200 bg-white p-5 text-brand-900 shadow-xl dark:border-brand-700 dark:bg-brand-900 dark:text-white sm:p-6">
      <div className="flex items-start justify-between gap-4"><h2 id="workspace-dialog-title" className="min-w-0 break-words text-lg font-semibold">{title}</h2><button type="button" disabled={busy} aria-label="Close dialog" title="Close" className="ui-button-secondary shrink-0 p-2" onClick={onClose}><X size={16} /></button></div>
      {context && <p id="workspace-dialog-context" className="break-words text-sm text-brand-600 dark:text-brand-300">{context}</p>}
      {!confirmOnly && <label className="grid gap-2 text-sm font-medium">{label}<input required maxLength={password ? 500 : 200} disabled={busy} type={password ? 'password' : 'text'} autoComplete={password ? 'off' : undefined} aria-invalid={!!error} aria-describedby={error ? 'workspace-name-error' : undefined} placeholder={placeholder} className="input-brand w-full min-w-0" value={value} onChange={event => onChange(event.target.value)} /></label>}
      {error && <p id="workspace-name-error" role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
      <div className="flex flex-wrap justify-end gap-3 border-t border-brand-200 pt-4 dark:border-brand-700"><button type="button" className="ui-button-secondary" disabled={busy} onClick={onClose}>Cancel</button><button disabled={busy || (!confirmOnly && !value.trim())} className="btn-brand" type="submit">{busy ? 'Saving...' : action}</button></div>
    </form>
  </div>;
}
