import assert from 'node:assert/strict';
import test from 'node:test';
import { releaseStatus, releaseScopes, formatWorkspaceDate } from '../src/utils/releasePresentation.js';

test('release status distinguishes unstarted drafts and saved reports', () => {
  assert.equal(releaseStatus({ model_count: 0 }), 'Not started');
  assert.equal(releaseStatus({ model_count: 1, reported_models: 0, draft_models: 1 }), 'Draft only');
  assert.equal(releaseStatus({ model_count: 2, reported_models: 1, draft_models: 1 }), 'Reports and drafts');
  assert.equal(releaseStatus({ model_count: 1, reported_models: 1, draft_models: 0 }), 'Report available');
});

test('scope summarizes actual release models rather than product application names', () => {
  assert.deepEqual(releaseScopes({}), []);
  assert.deepEqual(releaseScopes({ release_models: 2 }), ['Complete release product']);
  assert.deepEqual(releaseScopes({ application_models: 1 }), ['Ad hoc application']);
  assert.deepEqual(releaseScopes({ release_models: 1, application_models: 1 }), ['Complete release product', 'Ad hoc application']);
});

test('timestamps use recorded dates and never invent missing historical dates', () => {
  assert.equal(formatWorkspaceDate(null), 'Not recorded');
  assert.equal(formatWorkspaceDate('not a date'), 'Not recorded');
  assert.equal(formatWorkspaceDate(1788940800), formatWorkspaceDate('2026-09-09T08:00:00Z'));
});
