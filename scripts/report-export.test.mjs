import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'vite';

test('final PDF rejects incomplete diagrams, invalid scores and integrity failures', async () => {
  const server = await createServer({ server: { middlewareMode: true, hmr: false, ws: false, watch: null }, appType: 'custom', logLevel: 'silent' });
  const originalError = console.error;
  console.error = () => {};
  try {
    const { generateReport } = await server.ssrLoadModule('/src/utils/pdfGenerator.js');
    await assert.rejects(generateReport(null, 'Test'), /No data/);
    await assert.rejects(generateReport({ score: null }, 'Test'), /extraction incomplete/);
    await assert.rejects(generateReport({ score: 90, architecture: { components: [
      { id: 'image', properties: { diagram_review_required: true } },
    ] } }, 'Test'), /extraction incomplete/);
    await assert.rejects(generateReport({ score: 90, engine_status: { quality_gate: {
      publication_status: 'blocked', integrity_violations: [{ detail: 'Contradictory evidence' }],
    } } }, 'Test'), /Contradictory evidence/);
  } finally {
    console.error = originalError;
    await server.close();
  }
});
