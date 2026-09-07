import { useCallback, useEffect, useMemo, useState } from 'react';
import { prepareModel } from '../services/modelReview';
import { applyPreparedPreview, draftSignature } from '../utils/modelWorkspace';

export function useAutomaticModelPreview(workspace, enabled, setWorkspace) {
  const payload = workspace?.draft.payload;
  const workspaceId = workspace?.id;
  const preparedSignature = workspace?.draft.preparedSignature;
  const delay = workspace?.draft.previewDelay ?? 350;
  const signature = useMemo(() => payload ? draftSignature(payload) : null, [payload]);
  const [attempt, setAttempt] = useState(0);
  const [failure, setFailure] = useState(null);
  const stale = !!payload && preparedSignature !== signature;

  useEffect(() => {
    if (!enabled || !stale) return undefined;
    const controller = new AbortController();
    let current = true;
    const timer = setTimeout(async () => {
      try {
        const preview = await prepareModel(payload, { signal: controller.signal });
        if (current) setWorkspace((latest) => applyPreparedPreview(latest, workspaceId, signature, preview));
      } catch (error) {
        if (current && error.name !== 'AbortError') {
          setFailure({ workspaceId, signature, attempt, message: error.message || 'Could not update the architecture.' });
        }
      }
    }, delay);
    // Aborting the client is not enough: a response may already be queued or
    // the server may finish cancelled work. Both guards keep newer edits intact.
    return () => { current = false; clearTimeout(timer); controller.abort(); };
  }, [enabled, stale, workspaceId, signature, payload, delay, attempt, setWorkspace]);

  const error = enabled && stale && failure?.workspaceId === workspaceId
    && failure.signature === signature && failure.attempt === attempt ? failure.message : '';
  const retry = useCallback(() => setAttempt((value) => value + 1), []);
  return { updating: enabled && stale && !error, error, retry };
}
