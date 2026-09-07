from app.engine.evaluation_governance import audit_splits, holdout_gate, detection_metrics


def test_paraphrase_family_cannot_span_splits():
    assert not audit_splits([
        {'query': 'First wording', 'split': 'train', 'architecture_family': 'payments'},
        {'query': 'Different wording', 'split': 'validation', 'architecture_family': 'payments'},
    ])['valid']


def test_familiar_lookup_examples_cannot_promote_a_model():
    corpus = [{'query': f'Rule title {i}', 'source': 'rule_generated'} for i in range(150)]
    assert not holdout_gate(corpus)['eligible']


def test_perfect_small_sample_is_not_certain_accuracy():
    result = detection_metrics(5, 0, 0)
    assert result['precision'] == 1
    assert result['precision_interval_95'][0] < 0.8
    assert detection_metrics(0, 0, 0)['precision'] is None
