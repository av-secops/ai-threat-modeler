"""Human-authored evaluation intake; no synthetic fixtures become accuracy claims."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..engine.evaluation_governance import detection_metrics, fingerprint
from .contracts import Severity, StrideCategory
from .releases import content_digest


DOMAINS = ('web', 'identity', 'aws', 'azure', 'gcp', 'kubernetes', 'saas', 'payments', 'ai', 'agents', 'mcp')
STRIDE = ('Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege')


class EvidenceLabel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_ref: str = Field(min_length=1)
    quote: str = Field(min_length=1)


class ExpectedRisk(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    components: list[str] = Field(min_length=1)
    stride: StrideCategory
    severity: Severity
    rationale: str = Field(min_length=1)
    evidence: list[EvidenceLabel] = Field(min_length=1)


class HoldoutScenario(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1)
    query: str = Field(min_length=20)
    architecture_family: str = Field(min_length=1)
    domains: list[str] = Field(min_length=1)
    split: Literal['holdout'] = 'holdout'
    source: Literal['human_authored', 'redacted_real_architecture']
    author: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    documents: dict[str, str] = Field(default_factory=dict)
    expected_findings: list[ExpectedRisk]
    assessed_stride: list[StrideCategory]
    label_completeness: Literal['complete_for_stated_scope', 'partial']
    negative_case_reason: str = ''
    review: dict = Field(default_factory=dict)

    @model_validator(mode='after')
    def labels_match_sources(self):
        if not self.query.strip() or not self.author.strip() or not self.architecture_family.strip():
            raise ValueError('Scenario identity, author, architecture family and input must be meaningful.')
        if 'input' in self.documents:
            raise ValueError('The reserved source input is the scenario query, not an uploaded document.')
        if len({finding.id for finding in self.expected_findings}) != len(self.expected_findings):
            raise ValueError('Expected finding IDs must be unique within a scenario.')
        if not self.expected_findings and not self.negative_case_reason.strip():
            raise ValueError('A no-risk case requires a reviewer explanation of its assessed scope.')
        sources = {'input': self.query, **self.documents}
        for finding in self.expected_findings:
            if finding.stride not in self.assessed_stride or any(not name.strip() for name in finding.components):
                raise ValueError('Each label needs named components and an assessed STRIDE category.')
            for evidence in finding.evidence:
                if evidence.source_ref not in sources or not evidence.quote.strip() or evidence.quote not in sources[evidence.source_ref]:
                    raise ValueError('Expected-risk evidence must quote the actual supplied source.')
        return self


def scenario_digest(record):
    """Review changes do not change the scenario; labels and source text do."""
    parsed = HoldoutScenario.model_validate(record).model_dump()
    parsed.pop('review')
    return content_digest(parsed)


def record_review(record, *, reviewer, reason):
    """Called only after an authenticated reviewer actually approves the labels."""
    parsed = HoldoutScenario.model_validate(record).model_dump()
    if not isinstance(reviewer, str) or not reviewer.strip() or not isinstance(reason, str) or not reason.strip():
        raise ValueError('Review requires a named reviewer and a reason.')
    if reviewer.strip().casefold() == parsed['author'].strip().casefold():
        raise ValueError('The scenario author cannot supply the independent label review.')
    parsed['review'] = {'decision': 'approved', 'reviewer': reviewer.strip(), 'reason': reason.strip(),
        'reviewed_at': datetime.now(timezone.utc).isoformat(), 'content_digest': scenario_digest(parsed)}
    return parsed


def _review_errors(review, digest, *, author=None):
    if not isinstance(review, dict):
        return ['missing_content_bound_review']
    errors = []
    if (review.get('decision') != 'approved' or not str(review.get('reviewer') or '').strip()
            or not str(review.get('reason') or '').strip() or review.get('content_digest') != digest):
        errors.append('missing_content_bound_review')
    if author and str(review.get('reviewer') or '').strip().casefold() == author.strip().casefold():
        errors.append('self_review_not_independent')
    try:
        timestamp = datetime.fromisoformat(str(review.get('reviewed_at')).replace('Z', '+00:00'))
        if timestamp.tzinfo is None or timestamp > datetime.now(timezone.utc):
            errors.append('invalid_review_timestamp')
    except (TypeError, ValueError):
        errors.append('invalid_review_timestamp')
    return errors


def validate_holdout(records, *, training=(), minimum_scenarios=100, required_domains=DOMAINS,
                     required_stride=STRIDE):
    """Check independence attestations and leakage, not the truth of expert labels.

    Every real training/validation row must be supplied to perform leakage checks.
    An empty training inventory is deliberately insufficient for production use.
    """
    if not isinstance(records, list) or not isinstance(minimum_scenarios, int) or isinstance(minimum_scenarios, bool) or minimum_scenarios < 1:
        raise ValueError('Provide a scenario list and a positive minimum_scenarios.')
    rows, issues = [], []
    for index, record in enumerate(records):
        try:
            parsed = HoldoutScenario.model_validate(record).model_dump()
            rows.append(parsed)
            codes = _review_errors(parsed['review'], scenario_digest(parsed), author=parsed['author'])
            if parsed['label_completeness'] != 'complete_for_stated_scope':
                codes.append('partial_labels_cannot_measure_recall')
            issues.extend({'scenario_id': parsed['id'], 'code': code} for code in codes)
        except (ValidationError, ValueError, TypeError) as exc:
            issues.append({'scenario_id': record.get('id') if isinstance(record, dict) else f'row-{index}',
                'code': 'invalid_scenario_contract', 'detail': str(exc)})
    training = list(training)
    training_hashes = set()
    training_families = set()
    for item in training:
        if not isinstance(item, dict) or not str(item.get('query') or '').strip() or not str(item.get('architecture_family') or '').strip():
            issues.append({'scenario_id': None, 'code': 'incomplete_training_inventory'})
            continue
        training_hashes.add(fingerprint(item['query']))
        training_families.add(fingerprint(item['architecture_family']))
    if not training:
        issues.append({'scenario_id': None, 'code': 'training_inventory_not_supplied'})
    seen_ids, seen_inputs, seen_families = set(), set(), set()
    for row in rows:
        query_hash, family_hash = fingerprint(row['query']), fingerprint(row['architecture_family'])
        for value, seen, code in ((row['id'], seen_ids, 'duplicate_scenario_id'),
                (query_hash, seen_inputs, 'duplicate_input'), (family_hash, seen_families, 'duplicate_architecture_family')):
            if value in seen:
                issues.append({'scenario_id': row['id'], 'code': code})
            seen.add(value)
        if query_hash in training_hashes or family_hash in training_families:
            issues.append({'scenario_id': row['id'], 'code': 'training_leakage'})
    domains = sorted({domain for row in rows for domain in row['domains']})
    stride = sorted({category for row in rows for category in row['assessed_stride']})
    missing_domains, missing_stride = sorted(set(required_domains) - set(domains)), sorted(set(required_stride) - set(stride))
    if len(rows) < minimum_scenarios:
        issues.append({'scenario_id': None, 'code': 'insufficient_scenarios', 'required': minimum_scenarios, 'actual': len(rows)})
    if missing_domains:
        issues.append({'scenario_id': None, 'code': 'missing_domain_coverage', 'domains': missing_domains})
    if missing_stride:
        issues.append({'scenario_id': None, 'code': 'missing_stride_assessments', 'stride': missing_stride})
    return {'schema_version': 'aegis-reviewed-holdout-1', 'eligible': not issues,
        'acceptance_policy': {'minimum_scenarios': minimum_scenarios, 'required_domains': list(required_domains),
            'required_stride': list(required_stride)},
        'content_digest': content_digest(sorted(rows, key=lambda row: row['id'])),
        'scenarios': len(rows), 'architecture_families': len(seen_families), 'issues': issues,
        'domains': domains, 'assessed_stride': stride, 'independent_accuracy_established': False,
        'notice': 'Content-bound reviewer attestations are checked, not independently authenticated here. '
            'Passing intake is not a measured accuracy score; label correctness and training inventory completeness require human audit.'}


def judgment_digest(scenario, predictions, matches):
    """Bind manual match decisions to exact expected and actual findings."""
    return content_digest({'scenario_digest': scenario_digest(scenario), 'predictions': predictions, 'matches': matches})


def score_holdout(records, predictions, judgments, *, training, minimum_scenarios=100,
                  required_domains=DOMAINS, required_stride=STRIDE):
    """Score only complete, manually adjudicated predictions, never title similarity.

    predictions maps scenario IDs to [{id, ...actual finding fields}]. judgments
    maps scenario IDs to {matches: [{expected_id, prediction_id}], review: {...}}.
    Unmatched expected labels count as FN; unmatched predictions count as FP.
    """
    gate = validate_holdout(records, training=training, minimum_scenarios=minimum_scenarios,
        required_domains=required_domains, required_stride=required_stride)
    if not gate['eligible']:
        return {'eligible': False, 'intake': gate, 'metrics': None, 'independent_accuracy_established': False}
    identifiers = {record['id'] for record in records}
    if not isinstance(predictions, dict) or not isinstance(judgments, dict) or set(predictions) != identifiers or set(judgments) != identifiers:
        raise ValueError('Predictions and reviewed judgments must cover exactly the holdout scenario IDs.')
    results = []
    for record in records:
        predicted, judgment = predictions[record['id']], judgments[record['id']]
        if not isinstance(predicted, list) or any(not isinstance(item, dict) or not str(item.get('id') or '').strip() for item in predicted):
            raise ValueError('Every predicted finding needs an ID.')
        prediction_ids = {item['id'] for item in predicted}
        if len(prediction_ids) != len(predicted):
            raise ValueError('Duplicate predicted finding IDs are not allowed.')
        matches = judgment.get('matches') if isinstance(judgment, dict) else None
        if not isinstance(matches, list):
            raise ValueError('Each judgment must include the reviewed matches list, including empty lists.')
        if _review_errors(judgment.get('review'), judgment_digest(record, predicted, matches)):
            raise ValueError('Prediction matching requires a current content-bound human review.')
        expected = {item['id'] for item in record['expected_findings']}
        matched_expected, matched_predictions = set(), set()
        for match in matches:
            if not isinstance(match, dict):
                raise ValueError('Each reviewed match must be an object.')
            left, right = match.get('expected_id'), match.get('prediction_id')
            if left not in expected or right not in prediction_ids or left in matched_expected or right in matched_predictions:
                raise ValueError('Reviewed matches must reference existing, unique expected and predicted findings.')
            matched_expected.add(left)
            matched_predictions.add(right)
        tp, fp, fn = len(matches), len(prediction_ids - matched_predictions), len(expected - matched_expected)
        results.append({'scenario_id': record['id'], 'domains': record['domains'], **detection_metrics(tp, fp, fn)})
    counts = [sum(row[key] for row in results) for key in ('true_positive', 'false_positive', 'false_negative')]
    return {'eligible': True, 'intake': gate, 'metrics': detection_metrics(*counts), 'by_scenario': results,
        'evaluation_digest': content_digest({'intake': gate['content_digest'], 'predictions': predictions, 'judgments': judgments}),
        'reviewed_evaluation_completed': True, 'independent_accuracy_established': False,
        'notice': 'Metrics describe this reviewed corpus only. They are not proof of completeness or production accuracy.'}
