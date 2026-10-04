import { API_BASE_URL } from '../config';
import { workspaceAuthHeaders } from './workspaceAuth';

export const setWorkspaceToken = token => sessionStorage.setItem('aegis-workspace-token', token);

export async function enterprise(path, method = 'GET', body, options = {}) {
  const response = await fetch(`${API_BASE_URL}/enterprise${path}`, { method,
    headers: { 'Content-Type': 'application/json', ...workspaceAuthHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body), signal: options.signal, cache: 'no-store' });
  const value = response.ok && options.text ? await response.text() : await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(typeof value?.detail === 'string' ? value.detail : `Workspace request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return value;
}

export async function waitForJob(id) {
  for (;;) {
    const job = await enterprise(`/jobs/${id}`);
    if (job.state === 'completed') return job.result;
    if (['failed', 'interrupted'].includes(job.state)) throw new Error(job.error || 'Analysis interrupted. Resume it to retry.');
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}
