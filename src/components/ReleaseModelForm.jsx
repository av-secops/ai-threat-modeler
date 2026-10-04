import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Layers3, AppWindow, LoaderCircle } from 'lucide-react';
import { normalizedName } from '../utils/productWorkspace';

const environments = ['production', 'staging', 'test', 'development'];

export default function ReleaseModelForm({ product, release, initialScope = '', busy, disabled, error, onSubmit, onCancel }) {
  const [scope, setScope] = useState(initialScope);
  const [choice, setChoice] = useState('new');
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [customEnvironment, setCustomEnvironment] = useState('');
  const heading = useRef(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const applications = [...(product.applications || [])].sort((a, b) => a.name.localeCompare(b.name));
  const existing = applications.find(a => normalizedName(a.name) === normalizedName(name));
  const resolvedEnvironment = environment === 'other' ? customEnvironment.trim() : environment;
  const valid = scope && resolvedEnvironment && (scope === 'release' || (choice !== 'new' || (name.trim() && !existing)));
  const submit = event => {
    event.preventDefault();
    if (!valid || busy || disabled) return;
    onSubmit({ modelScope: scope, applicationChoice: choice,
      applicationName: choice === 'new' ? name.trim() : applications.find(a => a.id === choice)?.name,
      environment: resolvedEnvironment });
  };

  return <section className="border-y border-brand-200 py-6 dark:border-brand-700" aria-labelledby="new-model-title">
    <h2 ref={heading} tabIndex={-1} id="new-model-title" className="text-lg font-semibold outline-none">New threat model</h2>
    <form onSubmit={submit} className="mt-6 max-w-2xl space-y-6" aria-busy={busy}>
      <fieldset disabled={disabled || busy} className="min-w-0 space-y-6">
        <fieldset className="min-w-0">
          <legend className="mb-3 text-sm font-semibold">What are you assessing?</legend>
          <div className="flex flex-col gap-3 sm:flex-row sm:gap-8">
            {[['release', 'Full release', Layers3], ['application', 'One application', AppWindow]].map(([value, label, icon]) => {
              const Icon = icon;
              return (
              <label key={value} className="flex min-h-11 cursor-pointer items-center gap-3 text-sm">
                <input className="h-4 w-4 accent-brand-primary" type="radio" name="model-scope" value={value} checked={scope === value} onChange={() => setScope(value)} />
                <Icon size={18} aria-hidden="true" className="text-brand-500 dark:text-brand-300" /><span>{label}</span>
              </label>);
            })}
          </div>
        </fieldset>
        {scope === 'application' && <div className="grid min-w-0 gap-5 sm:grid-cols-2">
          <label className="grid min-w-0 content-start gap-2 text-sm font-medium">Application
            <select aria-label="Application" className="input-brand w-full min-w-0 text-sm" value={choice} onChange={event => { setChoice(event.target.value); setName(''); }}>
              <option value="new">New application</option>
              {!!applications.length && <optgroup label="Existing applications">{applications.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}</optgroup>}
            </select>
          </label>
          {choice === 'new' && <div className="min-w-0">
            <label className="grid gap-2 text-sm font-medium">Application name
              <input aria-label="Application name" className="input-brand w-full min-w-0 text-sm" required maxLength={200} placeholder="e.g. Customer portal" value={name} onChange={event => setName(event.target.value)} aria-describedby={existing ? 'existing-application' : undefined} />
            </label>
            {existing && <p id="existing-application" className="mt-2 text-sm text-brand-600 dark:text-brand-300">{existing.name} already exists. <button type="button" className="font-semibold underline underline-offset-4" onClick={() => { setChoice(existing.id); setName(''); }}>Use existing application</button></p>}
          </div>}
        </div>}
        {scope && <div className="grid min-w-0 gap-5 sm:grid-cols-2">
          <label className="grid min-w-0 gap-2 text-sm font-medium">Environment
            <select aria-label="Environment" className="input-brand w-full min-w-0 text-sm" value={environment} onChange={event => setEnvironment(event.target.value)}>
              {environments.map(value => <option value={value} key={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
              <option value="other">Other environment</option>
            </select>
          </label>
          {environment === 'other' && <label className="grid min-w-0 gap-2 text-sm font-medium">Environment name
            <input className="input-brand w-full min-w-0 text-sm" required maxLength={100} placeholder="e.g. Customer acceptance" value={customEnvironment} onChange={event => setCustomEnvironment(event.target.value)} />
          </label>}
        </div>}
      </fieldset>
      {error && <p role="alert" className="border-l-4 border-red-500 pl-3 text-sm text-red-700 dark:text-red-300">{error}</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-brand-200 pt-5 dark:border-brand-700">
        <button type="submit" className="btn-brand gap-2" disabled={!valid || busy || disabled}>
          {busy ? <LoaderCircle size={16} className="animate-spin" /> : <ArrowRight size={16} />} {busy ? 'Opening assessment...' : 'Continue to architecture'}
        </button>
        <button type="button" className="ui-button-secondary" disabled={busy} onClick={onCancel}>Cancel</button>
      </div>
      <dl className="grid gap-3 text-xs text-brand-600 dark:text-brand-300 sm:grid-cols-2">
        <div><dt className="font-medium">Product</dt><dd className="mt-1 break-words">{product.name}</dd></div>
        <div><dt className="font-medium">Release</dt><dd className="mt-1 break-words">{release.name}</dd></div>
      </dl>
    </form>
  </section>;
}
