export const pendingQuestion = q => !['answered', 'not_triggered'].includes(q.status);

export function explanationPlaceholder(value, answerType) {
  if (value === 'unknown') return 'For example: I need to check with the application owner.';
  if (answerType === 'control') {
    switch (value) {
      case 'present': return 'For example: The design document confirms this is enabled for these services.';
      case 'absent': return 'For example: This has not been set up yet.';
      case 'partial': return 'For example: Login requests are protected, but password resets are not.';
      case 'not_applicable': return 'For example: This application does not store data, so this storage control does not apply.';
      default: break;
    }
  }
  return 'For example: Confirmed with the application owner or in the design document.';
}

export function questionGroups(questions) {
  const groups = new Map();
  for (const q of questions) {
    const key = q.conflicting || q.requires_individual_review ? `${q.group_key}:${q.id}` : q.group_key || q.id;
    if (!groups.has(key)) groups.set(key, { id: key, text: q.text, priority: q.priority, questions: [] });
    groups.get(key).questions.push(q);
    groups.get(key).reviewScore = Math.max(groups.get(key).reviewScore || 0, q.review_priority?.score || 0);
  }
  const priorities = { high: 0, normal: 1, low: 2 };
  return [...groups.values()].sort((a, b) => b.reviewScore - a.reviewScore ||
    (priorities[a.priority] ?? 1) - (priorities[b.priority] ?? 1));
}

export function mergeQuestionAnswers(previous, answers) {
  const merged = new Map(previous.map(a => [a.question_id, a]));
  for (const answer of answers) merged.set(answer.question_id, answer);
  return [...merged.values()];
}

export function confirmProposals(questions, selected) {
  return questions.filter(q => selected.includes(q.id) && pendingQuestion(q) && q.proposal && !q.conflicting).map(q => ({
    question_id: q.id, value: q.proposal.value, note: q.proposal.note,
    evidence_digest: q.evidence_digest, source_ids: q.proposal.source_ids,
    basis: q.proposal.basis, proposal_digest: q.proposal.digest,
  }));
}

export function groupAnswers(questions, selected, value, note, owner = '') {
  return questions.filter(q => selected.includes(q.id) && q.status !== 'not_triggered').map(q => ({
    question_id: q.id, value, note, owner, evidence_digest: q.evidence_digest, source_ids: [], basis: 'manual',
  }));
}
