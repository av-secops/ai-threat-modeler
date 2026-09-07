"""Dataset independence and release gates, separate from retrieval scores."""

import hashlib
import math
import re


def fingerprint(text):
    normalized = re.sub(r'\W+', ' ', str(text).lower()).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()


def audit_splits(records):
    partitions = {}
    families = {}
    for row in records:
        split = row.get('split')
        if split not in {'train', 'validation', 'holdout'}:
            raise ValueError('Every training record needs an explicit train, validation or holdout split.')
        partitions.setdefault(fingerprint(row.get('query')), set()).add(split)
        family = row.get('architecture_family') or row.get('rule_family') or row.get('positive_id')
        if not family:
            raise ValueError('Every training record needs an architecture or rule family.')
        families.setdefault(family, set()).add(split)
    overlapping_queries = sum(len(splits) > 1 for splits in partitions.values())
    overlapping_families = sum(len(splits) > 1 for splits in families.values())
    return {'valid': not (overlapping_queries or overlapping_families),
        'overlapping_queries': overlapping_queries, 'overlapping_families': overlapping_families,
        'families': len(families), 'queries': len(partitions)}


def holdout_gate(corpus, training=(), minimum_scenarios=100):
    training_hashes = {fingerprint(item.get('query')) for item in training}
    training_families = {item.get('architecture_family') for item in training if item.get('architecture_family')}
    reasons = []
    if len(corpus) < minimum_scenarios:
        reasons.append(f'At least {minimum_scenarios} reviewed scenarios are required.')
    if len({fingerprint(item.get('query')) for item in corpus}) != len(corpus):
        reasons.append('Repeated queries do not count as independent scenarios.')
    if any(not str(item.get('query') or '').strip() for item in corpus):
        reasons.append('Evaluation queries must not be empty.')
    if any(item.get('source') in {'validated_canonical_knowledge_base', 'rule_generated'} for item in corpus):
        reasons.append('Rule-generated lookup examples are not independent evaluation.')
    if any(item.get('review_status') != 'approved' or not item.get('reviewed_by') or not item.get('architecture_family') for item in corpus):
        reasons.append('Every scenario needs an approved reviewer record and architecture family.')
    if any(fingerprint(item.get('query')) in training_hashes for item in corpus):
        reasons.append('Holdout queries overlap training.')
    if any(item.get('architecture_family') in training_families for item in corpus):
        reasons.append('Holdout architecture families overlap training.')
    return {'eligible': not reasons, 'reasons': reasons, 'scenarios': len(corpus),
        'families': len({item.get('architecture_family') for item in corpus if item.get('architecture_family')})}


def wilson_interval(successes, total):
    if not total:
        return [0.0, 1.0]
    z, p = 1.96, successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0, center - half), 4), round(min(1, center + half), 4)]


def detection_metrics(tp, fp, fn):
    return {'true_positive': tp, 'false_positive': fp, 'false_negative': fn,
        'precision': tp / (tp + fp) if tp + fp else None,
        'recall': tp / (tp + fn) if tp + fn else None,
        'precision_interval_95': wilson_interval(tp, tp + fp),
        'recall_interval_95': wilson_interval(tp, tp + fn)}
