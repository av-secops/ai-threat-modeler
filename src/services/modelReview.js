import { API_BASE_URL } from '../config';
import { mapAnalysisResult } from '../utils/analysisMapper';

async function responseJSON(response) {
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = body?.detail;
    throw new Error(Array.isArray(detail) ? detail.map((item) => item.msg).join('; ') : detail || `Request failed (${response.status})`);
  }
  return body;
}

export async function extractReviewSources(files) {
  if (!files.length) return [];
  const body = new FormData();
  files.forEach((file) => body.append('files', file));
  return (await responseJSON(await fetch(`${API_BASE_URL}/model-review/sources`, { method: 'POST', body }))).sources;
}

export async function prepareModel(payload, { signal } = {}) {
  const preview = await responseJSON(await fetch(`${API_BASE_URL}/model-review/prepare`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal,
  }));
  if (!Array.isArray(preview?.architecture?.components) || !Array.isArray(preview?.flows) || !preview?.readiness) {
    throw new Error('The server returned an incomplete architecture preview. Your draft has been retained.');
  }
  return preview;
}

export async function analyzeReviewedModel(payload) {
  return mapAnalysisResult(await responseJSON(await fetch(`${API_BASE_URL}/model-review/analyze`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  })));
}
