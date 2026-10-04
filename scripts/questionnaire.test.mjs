import test from 'node:test';

test('source conflicts and exposed scope are prioritized without adding questions', () => {
  const rows = [
    { id: 'normal', priority: 'high', group_key: 'a', review_priority: { score: 30 } },
    { id: 'conflict', priority: 'normal', group_key: 'b', conflicting: true, review_priority: { score: 120 } },
  ];
  const ordered = questionGroups(rows);
  assert.equal(ordered.length, 2);
  assert.equal(ordered[0].questions[0].id, 'conflict');
});
import assert from 'node:assert/strict';
import { questionGroups, confirmProposals, explanationPlaceholder, groupAnswers, mergeQuestionAnswers, pendingQuestion } from '../src/utils/questionnaire.js';

test('plain-language explanation examples match the answer without inventing a saved response', () => {
  assert.match(explanationPlaceholder('unknown', 'control'), /check with the application owner/);
  assert.match(explanationPlaceholder('present', 'control'), /design document confirms/);
  assert.match(explanationPlaceholder('absent', 'control'), /not been set up/);
  assert.match(explanationPlaceholder('partial', 'control'), /protected, but/);
  assert.match(explanationPlaceholder('not_applicable', 'control'), /does not apply/);
  assert.equal(explanationPlaceholder('present', 'text'), explanationPlaceholder('', 'text'));
  assert.equal(typeof explanationPlaceholder('__proto__', 'control'), 'string');
});

const question = (id, extra = {}) => ({ id, group_key: 'auth:production', text: 'Is authentication enforced?',
  priority: 'high', status: 'unanswered', evidence_digest: `digest-${id}`, ...extra });

test('shared questions keep exceptions and different trust scopes separate', () => {
  const groups = questionGroups([question('a'), question('b'), question('c', { conflicting: true }),
    question('d', { requires_individual_review: true }), question('e', { group_key: 'auth:other-tenant' })]);
  assert.equal(groups.length, 4);
  assert.deepEqual(groups[0].questions.map(q => q.id), ['a', 'b']);
});

test('priorities sort stably without changing component records', () => {
  const groups = questionGroups([question('a', { group_key: 'low', priority: 'low' }), question('b'), question('c')]);
  assert.equal(groups[0].priority, 'high');
  assert.equal(groups[0].questions.length, 2);
});

test('group answers apply only to explicitly selected active components', () => {
  const questions = [question('a'), question('b'), question('c', { status: 'not_triggered' })];
  assert.deepEqual(groupAnswers(questions, [], 'present', 'Owned scope'), []);
  const answers = groupAnswers(questions, ['b', 'c'], 'unknown', 'Awaiting review', 'Identity team');
  assert.equal(answers.length, 1);
  assert.equal(answers[0].question_id, 'b');
  assert.equal(answers[0].owner, 'Identity team');
  assert.equal(answers[0].basis, 'manual');
});

test('batch confirmation retains server evidence and never silently selects rows', () => {
  const proposal = { value: 'present', note: 'Design.md:1: API requires authentication.', source_ids: ['design'], basis: 'source', digest: 'proof' };
  const questions = [question('a', { proposal }), question('b', { proposal, conflicting: true }),
    question('c', { proposal, status: 'answered' }), question('d')];
  assert.deepEqual(confirmProposals(questions, []), []);
  const answers = confirmProposals(questions, ['a', 'b', 'c', 'd']);
  assert.equal(answers.length, 1);
  assert.equal(answers[0].proposal_digest, 'proof');
  assert.deepEqual(answers[0].source_ids, ['design']);
});

test('merging answers preserves unrelated answers and replaces rather than duplicates', () => {
  assert.deepEqual(mergeQuestionAnswers([{ question_id: 'a', value: 'unknown' }, { question_id: 'b', value: 'absent' }],
    [{ question_id: 'a', value: 'present' }]), [{ question_id: 'a', value: 'present' }, { question_id: 'b', value: 'absent' }]);
  assert.equal(pendingQuestion(question('a', { status: 'stale' })), true);
  assert.equal(pendingQuestion(question('a', { status: 'not_triggered' })), false);
});
