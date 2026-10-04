import { API_BASE_URL } from '../config';
import { mapAnalysisResult } from '../utils/analysisMapper';
import { workspaceAuthHeaders as authHeaders } from './workspaceAuth';

async function responseJSON(response) {
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = body?.detail;
    throw new Error(Array.isArray(detail) ? detail.map((item) => item.msg).join('; ') : detail || `Request failed (${response.status})`);
  }
  return body;
}

export async function extractReviewSources(files, { diagram = false, existingSources = [] } = {}) {
  if (!files.length) return [];
  const hashes = new Set(existingSources.filter(source => source.kind !== 'pdf' || !!source.metadata?.diagram_model === diagram).map(source => source.metadata?.artifact_hash).filter(Boolean));
  const unique = [];
  for (const file of files) {
    if (file.size > 8_000_000) throw new Error(`${file.name} exceeds the 8 MB upload limit.`);
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()))].map(value => value.toString(16).padStart(2, '0')).join('');
    if (!hashes.has(hash)) { unique.push(file); hashes.add(hash); }
  }
  if (!unique.length) return [];
  const body = new FormData();
  unique.forEach((file) => body.append('files', file));
  body.append('diagram', String(diagram));
  return (await responseJSON(await fetch(`${API_BASE_URL}/model-review/sources`, { method: 'POST', headers: authHeaders(), body }))).sources;
}

export async function prepareModel(payload, { signal } = {}) {
  const preview = await responseJSON(await fetch(`${API_BASE_URL}/model-review/prepare`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(payload), signal,
  }));
  if (!Array.isArray(preview?.architecture?.components) || !Array.isArray(preview?.flows) || !preview?.readiness) {
    throw new Error('The server returned an incomplete architecture preview. Your draft has been retained.');
  }
  return preview;
}

export async function analyzeReviewedModel(payload, { jobId, onJob } = {}) {
  const { enterprise, waitForJob } = await import('./enterprise');
  let job;
  if (jobId) {
    job = await enterprise(`/jobs/${jobId}`);
    if (['failed', 'interrupted'].includes(job.state)) job = await enterprise(`/jobs/${jobId}/retry`, 'POST');
  } else job = await enterprise('/jobs', 'POST', payload);
  await onJob?.(job.id);
  return mapAnalysisResult(await waitForJob(job.id));
}
